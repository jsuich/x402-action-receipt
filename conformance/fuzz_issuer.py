#!/usr/bin/env python3
"""
fuzz_issuer.py — differential and end-to-end fuzzing of action-receipt issuers.

Generates exchanges by mutating a valid one (four realistic bases: EVM `exact`,
SVM `exact`, Solana `batch-settlement`, Cloudflare), runs each through every
issuer adapter (ISSUER ADAPTER PROTOCOL in CONFORMANCE.md), and reports:

  * DISAGREEMENTS  two issuers differ on whether to issue, on the refusal
                   reason, or on the payload bytes.
  * PROPERTY VIOLATIONS, evaluated on EVERY issuer's results:
        Q1  the issuer never answers issuer_fault, self_check_failed or
            invalid_input to a JSON exchange, and every refusal is a §6.2 reason
        Q2  an issued payload is in the receipt grammar (spec §4.6, §5.3)
        Q3  an issued payload, signed with issuer.sign() (randomized ECDSA,
            low-s normalized) and verified in the context of its own exchange by
            EVERY verifier adapter, passes with exactly the report §6.3 promises
        Q4  the same exchange with a different receiptId yields a payload that
            differs in receiptId only, with a different receiptRef
        Q5  an issued payload copies its sources (§4.1, §6.3) — checked with
            the independent `rfc8785` canonicalizer, not either issuer's: success
            is true; accepted is byte-equal to an entry of accepts; network,
            resourceUrl, settlementRef, the action and the status are copied;
            requirementsDigest is the digest of accepted

    python3 conformance/fuzz_issuer.py --seed 1 --n 2000
    python3 conformance/fuzz_issuer.py --issuer mine="java -jar my-issuer.jar"

Fewer than 500 cases per run is VOID (exit 2): it cannot have exercised the
operators. Exit 1 on any disagreement or violation, if fewer cases were
generated than requested, if no receipt was round-tripped, or if a refusal
reason was never hit. Exit 0 otherwise.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import random
import shlex
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "conformance"))
import action_receipt as A  # noqa: E402
import issuer as I  # noqa: E402
import fuzz as V  # noqa: E402  (verifier adapters, value pools)

try:
    import rfc8785 as _rfc8785
except ImportError:            # Q5 then cannot run, and says so
    _rfc8785 = None

MIN_N = 500
ISSUERS = {
    "python": [sys.executable, "-B", str(ROOT / "issuer.py"), "--batch"],
    "node": ["node", str(ROOT / "issuer.mjs")],
}
VERIFIERS = {
    "python": [sys.executable, "-B", str(ROOT / "conformance" / "adapters" / "python_adapter.py")],
    "node": ["node", str(ROOT / "conformance" / "adapters" / "node_adapter.mjs")],
}

JUNK = [None, True, False, 0, 1, -1, 1.5, 2**53, "", "x", [], {}, [1], {"a": 1}]
SURROGATES = ["\ud800", "x\udfff", "0x\ud800" + "ab" * 31, "\udc00\ud800"]


# --- bases ------------------------------------------------------------------------

def _from_suite(name):
    return copy.deepcopy(next(x for n, x, _ in I.SUITE if n == name))


def base(r) -> dict:
    return _from_suite(r.choices(["issue_basic", "issue_svm_exact", "issue_solana_batch_settlement",
                                  "issue_network_cloudflare", "issue_advertised"],
                                 [5, 2, 2, 1, 2])[0])


def mirror(r, x, p=0.75):
    """With probability p the edited `accepted` is also what was offered."""
    acc = x["paymentPayload"].get("accepted")
    if isinstance(acc, dict) and r.random() < p:
        x["paymentRequired"]["accepts"] = [copy.deepcopy(acc)] + (
            [copy.deepcopy(A.ACCEPTED)] if r.random() < 0.3 else [])


# --- operators: each edits an exchange dict in place --------------------------

def x_none(r, x): pass


def x_success(r, x): x["settlementResponse"]["success"] = r.choice([False, None, "true", 1, 0])


def x_transaction(r, x):
    x["settlementResponse"]["transaction"] = r.choice(V.TXS + [None, 1, "0x1234", "0X" + "Ab" * 32])


def x_reference(r, x):
    x["settlementReference"] = r.choice([A.BATCH_REF, "", None, 1, "batch:other", " ", I.UPPER_REF,
                                         A.COMMITMENT_ID, A.COMMITMENT_ID.upper()])


def x_no_tx_with_ref(r, x):
    x["settlementResponse"]["transaction"] = ""
    x["settlementReference"] = r.choice([A.BATCH_REF, I.UPPER_REF, ""])


CASE_NET = "solana:5EYKT4USFV8P8NJDTREPY1VZQKQZKVDP"     # SOL_NET with the reference in upper case


def x_resp_network(r, x):
    x["settlementResponse"]["network"] = r.choice(V.NETWORKS + [None, 1, "cloudflare:402", CASE_NET,
                                                                "hedera:main_net"])
def x_resp_payer(r, x): x["settlementResponse"]["payer"] = r.choice(V.ADDRS + [None, "", 1, I.SOL_PAYER])


def x_resp_surrogate(r, x):
    """C-F1: a response string with an unpaired surrogate is absent on both sides."""
    c = r.randrange(4)
    if c == 0:
        x["settlementResponse"]["transaction"] = r.choice(SURROGATES)
        if r.random() < 0.6:
            x["settlementReference"] = A.BATCH_REF
    elif c == 1:
        x["settlementResponse"]["payer"] = r.choice(SURROGATES)
    elif c == 2:
        x["settlementReference"] = r.choice(SURROGATES)
    else:
        p = x["paymentPayload"].get("payload")
        if isinstance(p, dict):
            p.setdefault("authorization", {})["from"] = r.choice(SURROGATES)
        x["settlementResponse"].pop("payer", None)


def x_resp_delete(r, x):
    d = x["settlementResponse"]
    d.pop(r.choice(sorted(d)), None)


def x_resp_shape(r, x): x["settlementResponse"] = r.choice(JUNK)


def x_auth_from(r, x):
    p = x["paymentPayload"]
    c = r.randrange(5)
    if c == 0 and isinstance(p.get("payload"), dict):
        p["payload"].setdefault("authorization", {})["from"] = r.choice(V.ADDRS + [None, "", 1, I.PAYER_MIXED])
    elif c == 1:
        p["payload"] = r.choice([{"signature": "0x00"}, I._PERMIT2_PAYLOAD, I._SVM_PAYLOAD])
    elif c == 2:
        p["payload"] = r.choice(JUNK)
    elif c == 3:
        x["settlementResponse"].pop("payer", None)
    else:
        x["settlementResponse"].pop("payer", None)
        if isinstance(p.get("payload"), dict):
            p["payload"].setdefault("authorization", {})["from"] = r.choice(V.ADDRS + [I.PAYER_MIXED])


def x_accepted_shape(r, x): x["paymentPayload"]["accepted"] = r.choice(JUNK)


def x_accepted_network(r, x):
    x["paymentPayload"]["accepted"]["network"] = r.choice(V.NETWORKS + [None, 1, "a" * 32 + ":x", "a" * 33 + ":x",
                                                                       "hedera:main_net", I.SOL_NET])
    mirror(r, x)
    if r.random() < 0.5:
        x["settlementResponse"]["network"] = r.choice([x["paymentPayload"]["accepted"]["network"], None])


def x_accepted_payto(r, x):
    x["paymentPayload"]["accepted"]["payTo"] = r.choice(V.ADDRS + ["merchant", None, "", 1])
    mirror(r, x)


def x_accepted_member(r, x):
    acc = x["paymentPayload"]["accepted"]
    c = r.randrange(5)
    if c == 0:
        acc.pop(r.choice(sorted(acc)), None)
    elif c == 1:
        acc["maxTimeoutSeconds"] = r.choice([60.0, 60.5, 2**53, -1, "60", 0])
    elif c == 2:
        acc["extra"] = r.choice([None, {}, {"n": 1.5}, {"n": 2.0}, {"deep": [[[[[[[1]]]]]]]},
                                 {"deep": [[[[[[1]]]]]]}, {"é": "x"}, {"s": "\ud800"}])
    elif c == 3:
        acc[r.choice(["x", "", "é"])] = r.choice(JUNK)
    else:
        acc["amount"] = r.choice(["1", "0", 10000, ""])
    mirror(r, x)


def x_accepts(r, x):
    """Step 4: what was offered."""
    req = x["paymentRequired"]
    acc = x["paymentPayload"].get("accepted")
    c = r.randrange(9)
    if c == 0:
        req.pop("accepts", None)
    elif c == 1:
        req["accepts"] = r.choice(JUNK)
    elif c == 2:
        req["accepts"] = []
    elif c == 3 and isinstance(acc, dict):      # changed by value: amount, payTo, extra, member
        k = r.choice(["amount", "payTo", "extra", "added"])
        changed = copy.deepcopy(acc)
        changed[k if k != "added" else "note"] = r.choice(["1", "0x" + "11" * 20, {"v": "3"}, "x"])
        req["accepts"] = [changed]
    elif c == 4 and isinstance(acc, dict):      # equal by value, spelled differently; or true vs 1
        spelled = copy.deepcopy(acc)
        if isinstance(spelled.get("maxTimeoutSeconds"), int):
            spelled["maxTimeoutSeconds"] = float(spelled["maxTimeoutSeconds"])
        if r.random() < 0.4:
            acc["flag"], spelled["flag"] = r.choice([(True, 1), (False, 0), (1, 1.0)])
        req["accepts"] = [dict(reversed(list(spelled.items())))]
    elif c == 5 and isinstance(acc, dict):      # several offers, accepted among them
        req["accepts"] = r.sample([copy.deepcopy(acc), I.EXTRA_OFFER, copy.deepcopy(A.ACCEPTED_SOL)], 3)
    elif c == 6 and isinstance(acc, dict):      # an out-of-domain entry beside it
        req["accepts"] = [dict(acc, amount=1.5), "junk", copy.deepcopy(acc)]
    elif c == 7 and isinstance(acc, dict):      # casing of payTo differs
        req["accepts"] = [dict(acc, payTo=str(acc.get("payTo")).lower())]
    else:
        req["accepts"] = [copy.deepcopy(acc)] if isinstance(acc, dict) else [acc]


def x_non_evm(r, x):
    net, payer, pay_to, tx = I.SOL_NET, I.SOL_PAYER, I.SOL_PAYTO, I.SOL_TX
    x["paymentPayload"]["accepted"].update(network=net, payTo=r.choice([pay_to, pay_to.upper(), ""]))
    x["settlementResponse"].update(network=r.choice([net, net, "solana"]), payer=r.choice([payer, None]),
                                   transaction=r.choice([tx, tx.upper(), ""]))
    mirror(r, x, 0.9)


def x_resource(r, x):
    c = r.randrange(5)
    if c == 0:
        x["paymentRequired"]["resource"]["url"] = r.choice(
            ["", None, 1, A.RESOURCE + "/", "https://other.example/x", A.RESOURCE.upper(),
             " " + A.RESOURCE + "\t", A.RESOURCE + "\ud800"])
    elif c == 1:
        x["paymentRequired"]["resource"] = r.choice(JUNK)
    elif c == 2:
        x["paymentRequired"] = r.choice(JUNK)
    elif c == 3:
        del x["paymentRequired"]["resource"]["url"]
    else:
        x["paymentRequired"]["resource"]["url"] = r.choice(V.STRINGS)


def x_statement_ids(r, x):
    st = x["statement"]
    c = r.randrange(4)
    if c == 0:
        st["receiptId"] = r.choice(V.RECEIPT_IDS + [None, 1, "A" * 22 + "\n", "A" * 64 + "\n"])
    elif c == 1:
        st["issuedAt"] = r.choice([0, -1, 2**53 - 1, 2**53, float(A.ISSUED_AT), 1.5, "1", None,
                                   True, A.ISSUED_AT + 7, -0.0])
    elif c == 2:
        st["supersedes"] = r.choice(V.DIGESTS + [None, ""])
    else:
        st["reversalTransaction"] = r.choice(["0x" + "ef" * 32, "0X" + "EF" * 32, "", None, "has space",
                                              "café", "x" * 1025, "x" * 1024, I.SOL_REVERSAL, "0x1234"])


def x_statement_types(r, x):
    """§6.1: the statement is read strictly; a given optional member of the wrong type refuses."""
    st = x["statement"]
    k = r.choice(["supersedes", "reversalTransaction", "bindings", "settlementStatus", "receiptId"])
    st[k] = r.choice([5, False, True, [], {}, "\ud800", 1.5] + ([None] if r.random() < 0.3 else []))


def x_statement_action(r, x):
    st = x["statement"]
    c = r.randrange(5)
    if c == 0:
        st["action"][r.choice(["agent", "actionType", "scope", "outcome"])] = r.choice(JUNK + V.STRINGS)
    elif c == 1:
        st["action"].pop(r.choice(sorted(st["action"])), None)
    elif c == 2:
        st["action"] = r.choice(JUNK)
    elif c == 3:
        st["settlementStatus"] = r.choice(sorted(A.SETTLEMENT_STATUSES) + ["Settled", "", None, 1])
    else:
        st["action"]["outcome"] = r.choice(sorted(A.OUTCOMES) + ["Delivered", "refused", "disputed"])
        st["action"]["extra"] = 1


def x_statement_unicode(r, x):
    """Strings a statement may carry: non-ASCII, NFC/NFD, astral, and unpaired surrogates."""
    x["statement"]["action"][r.choice(["agent", "actionType", "scope"])] = r.choice(V.STRINGS)


def x_statement_shape(r, x):
    x["statement"] = r.choice(JUNK) if r.random() < 0.5 else x["statement"]
    if isinstance(x["statement"], dict) and r.random() < 0.5:
        x["statement"].pop(r.choice(sorted(x["statement"])), None)


def x_bindings(r, x):
    c = r.randrange(7)
    if c == 0:
        x["statement"]["bindings"] = r.choice([None, {}, "x", 0, [1], [None]])
    elif c == 1:
        x["statement"]["bindings"] = [V.pick_binding(r) for _ in range(r.choice([1, 2, 3]))]
    elif c == 2:
        pool = ["a:one", "b:two", "c:three", "https://example.org/x#y", "z:z"]
        items = [{"type": t, "value": "1"} for t in r.sample(pool, r.choice([2, 3, 4]))]
        if r.random() < 0.3:
            items.append(dict(items[0], value="2"))
        x["statement"]["bindings"] = items
    elif c == 3:
        n = r.choice([13, 14, 15, 16, 17])
        x["statement"]["bindings"] = [{"type": f"n:{i:02d}", "value": "1"} for i in range(n)]
        if r.random() < 0.5:
            x["statement"]["reversalTransaction"] = "0x" + "ef" * 32
    elif c == 4:
        x["statement"]["bindings"] = [{"type": r.choice([A.BT_ADVERTISED, A.BT_REVERSAL_TX, "action-receipt:x"]),
                                       "value": "sha256:" + "00" * 32}]
    elif c == 5:
        x["statement"]["bindings"] = [{"type": "a:one", "value": "1", "note": "x"}]
    else:
        x["statement"]["bindings"] = [{"type": "a:one"}, {"value": "1"}, ["a:one", "1"]][r.randrange(3):][:1]


def x_advertise(r, x):
    info = copy.deepcopy(I.ADVERT_INFO)
    c = r.randrange(11)
    if c == 1:
        info["scope"] = "write:model-x"
    elif c == 2:
        info["actionType"] = "other"
    elif c == 3:
        info["scope"] = r.choice([1, None, ["read:model-x"]])
    elif c == 4:
        info["weight"] = r.choice([1.5, 2.0, 2**53])
    elif c == 5:
        del info["scope"]
    elif c == 6:
        info = r.choice([None, [], "x", 1])
    elif c == 9:
        info["actionType"] = r.choice([None, 5])
    elif c == 10:
        info = r.choice([{}, {"willIssueReceipt": False}, {"d": [[[[[[[[1]]]]]]]]}])
    ext = {"info": info, "schema": I.ADVERT_SCHEMA}
    if c == 7:
        ext = r.choice([None, [], "x", {}, {"schema": {}}])
    if c == 8:
        x["paymentRequired"]["extensions"] = r.choice([None, [], "x"])
        return
    x["paymentRequired"]["extensions"] = {"action-receipt": ext}
    # the client's echo (core §5.1.2) is never what the issuer commits
    x["paymentPayload"]["extensions"] = {"action-receipt": {"info": r.choice([info, {"scope": "x"}])}}
    if r.random() < 0.3:
        x["statement"]["action"][r.choice(["scope", "actionType"])] = r.choice(["other", "write:model-x"])


def x_top(r, x):
    k = r.choice(sorted(x))
    if r.random() < 0.5:
        del x[k]
    else:
        x[k] = r.choice(JUNK)


OPERATORS = [
    (x_none, 4), (x_success, 2), (x_transaction, 4), (x_reference, 3), (x_no_tx_with_ref, 2),
    (x_resp_network, 3), (x_resp_payer, 3), (x_resp_surrogate, 4), (x_resp_delete, 2), (x_resp_shape, 1),
    (x_auth_from, 3), (x_accepted_shape, 1), (x_accepted_network, 3), (x_accepted_payto, 3),
    (x_accepted_member, 4), (x_accepts, 5), (x_non_evm, 2), (x_resource, 3), (x_statement_ids, 6),
    (x_statement_types, 4), (x_statement_action, 6), (x_statement_shape, 2), (x_bindings, 6),
    (x_advertise, 6), (x_top, 1), (x_statement_unicode, 3),
]


def generate(seed: int, n: int):
    """Exactly n cases (a case whose operators cannot apply is regenerated)."""
    rng = random.Random(seed)
    ops, weights = zip(*OPERATORS)
    cases, applied = [], Counter()
    i = 0
    while len(cases) < n:
        x = base(rng)
        names = []
        for op in rng.choices(ops, weights, k=rng.choice([1, 1, 2, 2, 3])):
            try:
                op(rng, x)
                names.append(op.__name__[2:])
            except (KeyError, TypeError, AttributeError, IndexError, ValueError):
                names.append(op.__name__[2:] + "!skipped")
        whole = rng.choice([None, [], "x"]) if rng.random() < 0.005 else x
        i += 1
        try:
            json.dumps(whole, allow_nan=False)
        except ValueError:
            continue
        applied.update(nm for nm in names if not nm.endswith("!skipped"))
        cases.append({"id": f"{seed}:{i}:{'+'.join(names)}", "exchange": whole})
    return cases, applied


def run_issuer(name: str, cases: list) -> dict:
    data = "\n".join(json.dumps(c) for c in cases) + "\n"
    r = subprocess.run(ISSUERS[name], input=data.encode(), capture_output=True)
    if r.returncode != 0:
        sys.exit(f"issuer adapter {name} failed (exit {r.returncode}):\n{r.stderr.decode()[-2000:]}")
    out = {}
    for line in r.stdout.decode().split("\n"):
        if line.strip():
            o = json.loads(line)
            out[o["id"]] = o
    if set(out) != {c["id"] for c in cases}:
        sys.exit(f"issuer adapter {name} returned {len(out)} results for {len(cases)} cases")
    return out


def run_verifier(name: str, cases: list, registry: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="action-receipt-ifuzz-") as d:
        kf = pathlib.Path(d) / "keys.json"
        kf.write_text(json.dumps(registry))
        r = subprocess.run(VERIFIERS[name] + [str(kf)],
                           input=("\n".join(json.dumps(c) for c in cases) + "\n").encode(), capture_output=True)
    if r.returncode != 0:
        sys.exit(f"verifier adapter {name} failed (exit {r.returncode}):\n{r.stderr.decode()[-2000:]}")
    out = {}
    for line in r.stdout.decode().split("\n"):
        if line.strip():
            o = json.loads(line)
            out[o["id"]] = (o["verdict"], o["reason"], o["report"])
    if set(out) != {c["id"] for c in cases}:
        sys.exit(f"verifier adapter {name} returned {len(out)} results for {len(cases)} cases")
    return out


def key_of(result) -> str:
    """Comparable form: refusal reason, or the canonical bytes of the payload."""
    if not result.get("issued"):
        return "refuse:" + str(result.get("reason"))
    try:
        return "issue:" + V.loose(result.get("payload"))
    except TypeError:
        return "issue:<unserializable>"


def _rjcs(v) -> bytes | None:
    """The independent canonicalizer (the `rfc8785` package), or None outside its domain."""
    if not A.in_domain(v):
        return None
    try:
        return _rfc8785.dumps(v)
    except Exception:  # noqa: BLE001
        return None


def copies_sources(exchange, payload) -> list[str]:
    """Q5: what §4.1/§6.3 say an issued payload must copy, from the exchange."""
    x = I._obj(exchange)
    out = []
    resp, req, pay, st = (I._obj(x.get(k)) for k in ("settlementResponse", "paymentRequired", "paymentPayload",
                                                      "statement"))
    if resp.get("success") is not True:
        out.append("issued although success is not true")
    acc = pay.get("accepted")
    acc_b = _rjcs(acc) if isinstance(acc, dict) else None
    if acc_b is None:
        out.append("issued for accepted outside the value domain")
        return out
    accepts = req.get("accepts")
    if not (isinstance(accepts, list) and any(_rjcs(e) == acc_b for e in accepts)):
        out.append("issued for accepted that is not an offered entry")
    if payload.get("requirementsDigest") != "sha256:" + hashlib.sha256(acc_b).hexdigest():
        out.append("requirementsDigest is not the digest of accepted")
    if payload.get("network") != acc.get("network"):
        out.append("network not copied from accepted")
    if payload.get("resourceUrl") != I._obj(req.get("resource")).get("url"):
        out.append("resourceUrl not copied verbatim")
    ref = x.get("settlementReference")
    want_ref = ref if A._has(ref) else ""
    if payload.get("settlementRef") != want_ref:
        out.append("settlementRef not copied verbatim")
    if payload.get("settlementStatus") != st.get("settlementStatus") or payload.get("receiptId") != st.get("receiptId"):
        out.append("status or receiptId not copied")
    if ({k: I._obj(payload.get("action")).get(k) for k in A.ACTION_KEYS}
            != {k: I._obj(st.get("action")).get(k) for k in A.ACTION_KEYS}):
        out.append("action not copied")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--issuers", default="python,node", help="comma-separated built-in or --issuer names")
    ap.add_argument("--issuer", action="append", default=[], metavar="NAME=COMMAND",
                    help="a third-party issuer adapter; added to --issuers")
    ap.add_argument("--verifiers", default="python,node")
    ap.add_argument("--save", metavar="DIR")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    names = [n for n in a.issuers.split(",") if n]
    for spec in a.issuer:
        nm, _, cmd = spec.partition("=")
        if not nm or not cmd:
            sys.exit(f"--issuer wants NAME=COMMAND, got {spec!r}")
        ISSUERS[nm] = shlex.split(cmd)
        if nm not in names:
            names.append(nm)
    vnames = [v for v in a.verifiers.split(",") if v]

    def finish(summary, code):
        print(json.dumps(summary) if a.json else
              f"seed {a.seed}: {summary.get('status')} {summary.get('why', '')}")
        return code

    if a.n < MIN_N:
        return finish({"seed": a.seed, "generated": 0, "requested": a.n, "round_trips": 0, "disagreements": 0,
                       "property_violations": 0, "refusals_never_hit": I.ALL_REFUSALS, "status": "VOID",
                       "why": f"--n {a.n} is below the floor of {MIN_N}"}, 2)

    cases, applied = generate(a.seed, a.n)
    by_id = {c["id"]: c for c in cases}
    results = {n: run_issuer(n, cases) for n in names}
    ref = results[names[0]]
    disagreements = [cid for cid in by_id if len({key_of(results[n][cid]) for n in names}) > 1]

    violations = []
    issued = {}                       # (issuer, cid) -> payload, for Q3/Q4
    for n in names:
        for cid, res in results[n].items():
            if not res.get("issued"):
                if res.get("reason") not in I.ALL_REFUSALS:
                    violations.append(("Q1", n, cid, f"answer {res.get('reason')!r}"))
                continue
            payload = res.get("payload")
            if not A.in_domain(payload) or A.validate_payload(payload) is not None:
                violations.append(("Q2", n, cid, f"issued payload is out of grammar: "
                                                 f"{A.validate_payload(payload) if isinstance(payload, dict) else payload!r}"))
                continue
            if _rfc8785 is not None:
                for p in copies_sources(by_id[cid]["exchange"], payload):
                    violations.append(("Q5", n, cid, p))
            # sign each distinct payload once
            if n == names[0] or key_of(res) != key_of(ref[cid]):
                issued[(n, cid)] = payload

    # Q3: sign with issuer.sign() and verify through every verifier, in the exchange's context
    vcases, want = [], {}
    if issued:
        urls = {p["resourceUrl"] for p in issued.values()}
        registry = I.key_fixture_for(urls)
        authorized = I.issuer_authorization(urls)
        _, keys = A._registry()
        rng = random.Random(a.seed)
        for (n, cid), payload in issued.items():
            alg, kid = rng.choice(I.SIGNERS)
            ex = by_id[cid]["exchange"]
            try:
                jws = I.sign(payload, alg=alg, kid=kid, private_key=keys[alg], authorized=authorized)
            except I.SigningError as e:
                if "65536" in str(e) or "exceeds" in str(e):
                    continue            # too large to sign: §3's bound, not a §6.2 refusal
                violations.append(("Q3", n, cid, f"sign() refused: {e}"))
                continue
            vid = f"{n}|{cid}"
            vcases.append({"id": vid, "receipt": {"format": "jws", "signature": jws}, "context": I.context_json(ex)})
            want[vid] = I.expected_checks(ex)
        for vn in vnames:
            out = run_verifier(vn, vcases, registry) if vcases else {}
            for c in vcases:
                verdict, reason, report = out[c["id"]]
                n, cid = c["id"].split("|", 1)
                if verdict != A.PASS:
                    violations.append(("Q3", n, cid, f"{vn} verifier: {verdict}/{reason}"))
                elif report["checks"] != want[c["id"]]:
                    violations.append(("Q3", n, cid, f"{vn} verifier report {report['checks']} != §6.3 {want[c['id']]}"))

    # Q4: a twin with another receiptId, through every issuer
    twins = []
    for cid, res in ref.items():
        if res.get("issued") and isinstance(by_id[cid]["exchange"].get("statement"), dict):
            twin = copy.deepcopy(by_id[cid]["exchange"])
            twin["statement"]["receiptId"] = A.RECEIPT_ID_2 if res["payload"]["receiptId"] != A.RECEIPT_ID_2 else A.RECEIPT_ID
            twins.append({"id": cid + "#twin", "exchange": twin})
    if twins:
        for n in names:
            tw = run_issuer(n, twins)
            for t in twins:
                parent = results[n][t["id"][:-5]]
                res = tw[t["id"]]
                if not parent.get("issued"):
                    continue
                if not res.get("issued"):
                    violations.append(("Q4", n, t["id"], f"twin refused: {res.get('reason')}"))
                    continue
                pp = parent["payload"]
                diff = [k for k in pp if pp[k] != res["payload"].get(k)]
                same_ref = hashlib.sha256(A.jcs(pp)).digest() == hashlib.sha256(A.jcs(res["payload"])).digest()
                if diff != ["receiptId"] or same_ref:
                    violations.append(("Q4", n, t["id"], f"twin differs in {diff}, same receiptRef: {same_ref}"))

    kinds = Counter("issued" if r.get("issued") else r.get("reason") for r in (ref[c["id"]] for c in cases))
    never = sorted(set(I.ALL_REFUSALS) - set(kinds))
    ops_never = sorted({op.__name__[2:] for op, _ in OPERATORS} - set(applied))
    problems = []
    if len(cases) < a.n:
        problems.append(f"generated {len(cases)} of {a.n}")
    if not vcases:
        problems.append("no receipt was round-tripped")
    if never:
        problems.append(f"refusal reasons never hit: {never}")
    if ops_never:
        problems.append(f"operators never applied: {ops_never}")
    if _rfc8785 is None:
        problems.append("rfc8785 not installed: Q5 did not run")
    summary = {"seed": a.seed, "generated": len(cases), "requested": a.n, "issuers": names, "verifiers": vnames,
               "issued": kinds.get("issued", 0), "round_trips": len(vcases) * len(vnames),
               "refusals_hit": len(set(kinds) & set(I.ALL_REFUSALS)), "refusals_never_hit": never,
               "operators_never_applied": ops_never, "disagreements": len(disagreements),
               "property_violations": len(violations),
               "status": "FAIL" if (disagreements or violations or problems) else "PASS",
               "problems": problems}
    if a.json:
        print(json.dumps(summary))
    else:
        print(f"seed {a.seed}: {len(cases)} exchanges through issuers {', '.join(names)}")
        print(f"  outcomes ({names[0]}): {dict(kinds.most_common())}")
        print(f"  round trips through verifiers {', '.join(vnames) or '(none)'}: {summary['round_trips']}")
        for p in problems:
            print("  PROBLEM:", p)
        print(f"  disagreements: {len(disagreements)}   property violations: {len(violations)}")
        if disagreements:
            groups = defaultdict(list)
            for cid in disagreements:
                groups[" | ".join(f"{n}={key_of(results[n][cid])[:44]}" for n in names)].append(cid)
            print("\nDISAGREEMENTS by result pair:")
            for key, ids in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:25]:
                ops = Counter(o for i in ids for o in i.split(":", 2)[2].split("+"))
                print(f"  {len(ids):5d}  {key}\n         operators: {dict(ops.most_common(3))}   e.g. {ids[0]}")
        if violations:
            print("\nPROPERTY VIOLATIONS:")
            for v in violations[:20]:
                print("  ", *v)
    if a.save and (disagreements or violations):
        d = pathlib.Path(a.save)
        d.mkdir(parents=True, exist_ok=True)
        keep = list(dict.fromkeys(disagreements + [v[2].split("#")[0] for v in violations]))
        with open(d / f"issuer-seed{a.seed}.jsonl", "w") as f:
            for cid in keep:
                f.write(json.dumps({"case": by_id[cid], "results": {n: results[n][cid] for n in names}}) + "\n")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
