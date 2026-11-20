#!/usr/bin/env python3
"""
fuzz_issuer.py — differential and end-to-end fuzzing of action-receipt issuers.

Generates exchanges by mutating a valid one, runs each through every issuer
adapter (ISSUER ADAPTER PROTOCOL in CONFORMANCE.md), and reports:

  * DISAGREEMENTS  two issuers differ on whether to issue, on the refusal
                   reason, or on the payload bytes.
  * PROPERTY VIOLATIONS
        Q1  the issuer never faults, and every refusal is a declared reason
        Q2  an issued payload is in the receipt grammar (spec §4.6)
        Q3  an issued receipt, signed and verified in the context of its own
            exchange by EVERY verifier adapter, passes with the resource, the
            requirements and payTo all compared
        Q4  the same exchange with a different receiptId yields a different
            receiptRef and no other change

    python3 conformance/fuzz_issuer.py --seed 1 --n 2000

Exit 0 iff there are no disagreements and no property violations.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import random
import subprocess
import sys
from collections import Counter, defaultdict

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "conformance"))
import action_receipt as A  # noqa: E402
import issuer as I  # noqa: E402
import fuzz as V  # noqa: E402  (verifier adapters, signing, value pools)

ISSUERS = {
    "python": [sys.executable, "-B", str(ROOT / "issuer.py"), "--batch"],
    "node": ["node", str(ROOT / "issuer.mjs")],
}

JUNK = [None, True, False, 0, 1, -1, 1.5, "", "x", [], {}, [1], {"a": 1}]
SOL = (I.SOL_NET, I.SOL_PAYER, I.SOL_PAYTO, I.SOL_TX)


def at(obj, *path):
    for k in path:
        obj = obj[k]
    return obj


# --- operators: each edits an exchange dict in place --------------------------

def x_none(r, x): pass


def x_success(r, x): x["settlementResponse"]["success"] = r.choice([False, None, "true", 1, 0])


def x_transaction(r, x):
    x["settlementResponse"]["transaction"] = r.choice(V.TXS + [None, 1, "0x1234", "0X" + "Ab" * 32])


def x_reference(r, x):
    x["settlementReference"] = r.choice([A.BATCH_REF, "", None, 1, "batch:other", " "])


def x_no_tx_with_ref(r, x):
    x["settlementResponse"]["transaction"] = ""
    x["settlementReference"] = r.choice([A.BATCH_REF, A.BATCH_REF, ""])


def x_resp_network(r, x): x["settlementResponse"]["network"] = r.choice(V.NETWORKS + [None, 1])
def x_resp_payer(r, x): x["settlementResponse"]["payer"] = r.choice(V.ADDRS + [None, "", 1])


def x_resp_delete(r, x):
    d = x["settlementResponse"]
    d.pop(r.choice(sorted(d)), None)


def x_resp_shape(r, x): x["settlementResponse"] = r.choice(JUNK)


def x_auth_from(r, x):
    p = x["paymentPayload"]
    c = r.randrange(4)
    if c == 0:
        p["payload"]["authorization"]["from"] = r.choice(V.ADDRS + [None, "", 1])
    elif c == 1:
        del p["payload"]["authorization"]
    elif c == 2:
        p["payload"] = r.choice(JUNK)
    else:
        x["settlementResponse"].pop("payer", None)


def x_accepted_shape(r, x): x["paymentPayload"]["accepted"] = r.choice(JUNK)
def x_accepted_network(r, x): x["paymentPayload"]["accepted"]["network"] = r.choice(V.NETWORKS + [None, 1])


def x_accepted_payto(r, x):
    x["paymentPayload"]["accepted"]["payTo"] = r.choice(V.ADDRS + ["merchant", None, "", 1])


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


def x_non_evm(r, x):
    net, payer, pay_to, tx = SOL
    x["paymentPayload"]["accepted"].update(network=net, payTo=r.choice([pay_to, pay_to.upper(), ""]))
    x["settlementResponse"].update(network=r.choice([net, net, "solana"]), payer=r.choice([payer, None]),
                                   transaction=r.choice([tx, tx.upper(), ""]))
    x["paymentPayload"]["payload"]["authorization"]["from"] = payer


def x_resource(r, x):
    c = r.randrange(4)
    if c == 0:
        x["paymentRequired"]["resource"]["url"] = r.choice(
            ["", None, 1, A.RESOURCE + "/", "https://other.example/x", A.RESOURCE.upper()])
    elif c == 1:
        x["paymentRequired"]["resource"] = r.choice(JUNK)
    elif c == 2:
        x["paymentRequired"] = r.choice(JUNK)
    else:
        del x["paymentRequired"]["resource"]["url"]


def x_statement_ids(r, x):
    st = x["statement"]
    c = r.randrange(4)
    if c == 0:
        st["receiptId"] = r.choice(V.RECEIPT_IDS + [None, 1])
    elif c == 1:
        st["issuedAt"] = r.choice([0, -1, 2**53 - 1, 2**53, float(A.ISSUED_AT), 1.5, "1", None,
                                   True, A.ISSUED_AT + 7])
    elif c == 2:
        st["supersedes"] = r.choice(V.DIGESTS + [None, 1])
    else:
        st["reversalTransaction"] = r.choice(["0x" + "ef" * 32, "", None, "has space", "café",
                                              1, "x" * 1025, "x" * 1024])


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
        st["action"]["outcome"] = r.choice(sorted(A.OUTCOMES) + ["Delivered", "failed"])
        st["action"]["extra"] = 1


def x_statement_unicode(r, x):
    """Strings a statement may carry: non-ASCII, NFC/NFD, astral, and unpaired surrogates."""
    x["statement"]["action"][r.choice(["agent", "actionType", "scope"])] = r.choice(V.STRINGS)


def x_statement_shape(r, x):
    x["statement"] = r.choice(JUNK) if r.random() < 0.5 else x["statement"]
    if isinstance(x["statement"], dict) and r.random() < 0.5:
        x["statement"].pop(r.choice(sorted(x["statement"])), None)


def x_bindings(r, x):
    c = r.randrange(6)
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
        n = r.choice([14, 15, 16, 17])
        x["statement"]["bindings"] = [{"type": f"n:{i:02d}", "value": "1"} for i in range(n)]
    elif c == 4:
        x["statement"]["bindings"] = [{"type": r.choice([A.BT_ADVERTISED, A.BT_REVERSAL_TX]),
                                       "value": "sha256:" + "00" * 32}]
    else:
        x["statement"]["bindings"] = [{"type": "a:one", "value": "1", "note": "x"}]


def x_advertise(r, x):
    info = copy.deepcopy(A.ADVERTISED_INFO)
    c = r.randrange(9)
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
    ext = {"info": info, "schema": {"type": "object"}}
    if c == 7:
        ext = r.choice([None, [], "x", {}, {"schema": {}}])
    if c == 8:
        x["paymentRequired"]["extensions"] = r.choice([None, [], "x"])
        return
    x["paymentRequired"]["extensions"] = {"action-receipt": ext}
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
    (x_resp_network, 4), (x_resp_payer, 4), (x_resp_delete, 2), (x_resp_shape, 1),
    (x_auth_from, 3), (x_accepted_shape, 1), (x_accepted_network, 3), (x_accepted_payto, 4),
    (x_accepted_member, 5), (x_non_evm, 2), (x_resource, 3), (x_statement_ids, 6),
    (x_statement_action, 6), (x_statement_shape, 2), (x_bindings, 6), (x_advertise, 6), (x_top, 1),
    (x_statement_unicode, 3),
]


def generate(seed: int, n: int):
    rng = random.Random(seed)
    ops, weights = zip(*OPERATORS)
    cases = []
    for i in range(n):
        x = I.base_exchange()
        names = []
        for op in rng.choices(ops, weights, k=rng.choice([1, 1, 2, 2, 3])):
            try:
                op(rng, x)
                names.append(op.__name__[2:])
            except (KeyError, TypeError, AttributeError, IndexError, ValueError):
                names.append(op.__name__[2:] + "!skipped")
        whole = rng.choice([None, [], "x"]) if rng.random() < 0.005 else x
        try:
            json.dumps(whole, allow_nan=False)
        except ValueError:
            continue
        cases.append({"id": f"{seed}:{i}:{'+'.join(names)}", "exchange": whole})
    return cases


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


def key_of(result) -> str:
    """Comparable form: refusal reason, or the canonical bytes of the payload."""
    if not result.get("issued"):
        return "refuse:" + str(result.get("reason"))
    try:
        return "issue:" + V.loose(result.get("payload"))
    except TypeError:
        return "issue:<unserializable>"


def verifier_case(cid, exchange, payload):
    _, keys = A._registry()
    raw = A.jcs(payload)
    h = A.b64url(V.to_bytes(V.loose({"alg": "ES256", "kid": A.KID_ES256, "typ": A.TYP})))
    p = A.b64url(raw)
    sig = V.sign("ES256", keys["ES256"], f"{h}.{p}".encode())
    resp = exchange["settlementResponse"]
    ext = exchange["paymentRequired"].get("extensions")
    ext = ext.get("action-receipt") if isinstance(ext, dict) else None
    ctx = {"paidResourceUrl": exchange["paymentRequired"]["resource"]["url"],
           "success": resp.get("success"), "transaction": resp.get("transaction"),
           "settlementRef": exchange.get("settlementReference"), "network": resp.get("network"),
           "payer": resp.get("payer"), "accepted": exchange["paymentPayload"]["accepted"],
           "advertisedInfo": ext.get("info") if isinstance(ext, dict) else None,
           # the adapter contract requires an integer clock: stay in the safe range
           "now": min(payload["issuedAt"] + 1, A.SAFE_INT_MAX), "maxAgeSeconds": 3600,
           "mode": "session"}
    return {"id": cid, "receipt": {"format": "jws", "signature": f"{h}.{p}.{A.b64url(sig)}"},
            "context": ctx}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--issuers", default="python,node")
    ap.add_argument("--verifiers", default="python,node")
    ap.add_argument("--save", metavar="DIR")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    names = a.issuers.split(",")
    vnames = [v for v in a.verifiers.split(",") if v]

    cases = generate(a.seed, a.n)
    by_id = {c["id"]: c for c in cases}
    results = {n: run_issuer(n, cases) for n in names}
    ref = results[names[0]]
    disagreements = [cid for cid in by_id if len({key_of(results[n][cid]) for n in names}) > 1]

    violations, vcases, twins = [], [], []
    for cid, res in ref.items():
        if not res.get("issued"):
            if res.get("reason") not in I.ALL_REFUSALS:
                violations.append(("Q1", cid, f"refusal {res.get('reason')!r}"))
            continue
        payload = res["payload"]
        if A.validate_payload(payload) is not None or not A.in_domain(payload):
            violations.append(("Q2", cid, f"issued payload is out of grammar: {A.validate_payload(payload)}"))
            continue
        ex = by_id[cid]["exchange"]
        if payload["resourceUrl"] == A.RESOURCE:       # the key fixture authorizes this resource only
            vcases.append(verifier_case(cid, ex, payload))
        twin = copy.deepcopy(ex)
        twin["statement"]["receiptId"] = A.RECEIPT_ID_2 if payload["receiptId"] != A.RECEIPT_ID_2 else A.RECEIPT_ID
        twins.append({"id": cid + "#twin", "exchange": twin})
    if vcases:
        for vn in vnames:
            out = V.run_adapter(vn, vcases)
            for c in vcases:
                verdict, reason, report = out[c["id"]]
                if verdict != A.PASS:
                    violations.append(("Q3", c["id"], f"{vn} verifier: {verdict}/{reason}"))
                    continue
                ch = report["checks"]
                if not (ch.get("resourceUrl") == "compared" and ch.get("requirements") == "matched"
                        and ch.get("payTo") == "compared"):
                    violations.append(("Q3", c["id"], f"{vn} verifier left a check open: {ch}"))
                for b in report["bindings"]:
                    if b["type"] == A.BT_ADVERTISED and b["status"] != "matched":
                        violations.append(("Q3", c["id"], f"{vn}: advertised-info {b['status']}"))
    if twins:
        tw = run_issuer(names[0], twins)
        for t in twins:
            parent = ref[t["id"][:-5]]["payload"]
            res = tw[t["id"]]
            if not res.get("issued"):
                violations.append(("Q4", t["id"], f"twin refused: {res.get('reason')}"))
                continue
            diff = [k for k in parent if parent[k] != res["payload"].get(k)]
            same_ref = hashlib.sha256(A.jcs(parent)).digest() == hashlib.sha256(A.jcs(res["payload"])).digest()
            if diff != ["receiptId"] or same_ref:
                violations.append(("Q4", t["id"], f"twin differs in {diff}, same receiptRef: {same_ref}"))

    kinds = Counter("issued" if r.get("issued") else r.get("reason") for r in (ref[c["id"]] for c in cases))
    never = sorted(set(I.ALL_REFUSALS) - set(kinds))
    summary = {"seed": a.seed, "generated": len(cases), "issuers": names, "verifiers": vnames,
               "issued": kinds.get("issued", 0), "round_trips": len(vcases) * len(vnames),
               "refusals_hit": len(set(kinds) & set(I.ALL_REFUSALS)), "refusals_never_hit": never,
               "disagreements": len(disagreements), "property_violations": len(violations)}
    if a.json:
        print(json.dumps(summary))
    else:
        print(f"seed {a.seed}: {len(cases)} exchanges through issuers {', '.join(names)}")
        print(f"  outcomes ({names[0]}): {dict(kinds.most_common())}")
        print(f"  round trips through verifiers {', '.join(vnames) or '(none)'}: {summary['round_trips']}")
        if never:
            print(f"  refusal reasons never hit: {never}")
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
        keep = list(dict.fromkeys(disagreements + [v[1].split("#")[0] for v in violations]))
        with open(d / f"issuer-seed{a.seed}.jsonl", "w") as f:
            for cid in keep:
                f.write(json.dumps({"case": by_id[cid],
                                    "results": {n: results[n][cid] for n in names}}) + "\n")
    return 0 if not disagreements and not violations else 1


if __name__ == "__main__":
    sys.exit(main())
