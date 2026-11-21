#!/usr/bin/env python3
"""
run_exchanges.py — run an issuer adapter against exchanges/MANIFEST.json.

    python3 conformance/run_exchanges.py node issuer.mjs
    python3 conformance/run_exchanges.py python3 issuer.py --batch
    python3 conformance/run_exchanges.py --seed 7 --json -- node issuer.mjs

The command is an issuer adapter (ISSUER ADAPTER PROTOCOL in CONFORMANCE.md):
exchanges as JSON lines on stdin, results as JSON lines on stdout. Payloads are
compared by their RFC 8785 serialization.

The adapter never sees a fixture name: every case gets a fresh random id and the
cases are sent in a shuffled order, so an implementation cannot answer from the
manifest by name or by position (reviewer E, F9). Each exchange whose statement
is an object is also sent once more as a FOLLOW-UP with a fresh valid
`receiptId` and `issuedAt`. The expected answer follows from spec §6 without a
table: an issued payload carries the two new values and is otherwise the
manifest's; a refusal at any step other than 8 is unchanged (both new values are
well formed, so they can neither cause nor cure a refusal at another step).
Exchanges refused at step 8 get no follow-up. A lookup table keyed on the
exchange bytes has no entry for a follow-up.

Exit 0 iff every case agrees. An empty manifest, an adapter that exits non-zero
or answers the wrong set of ids, is a failure, never a pass.
"""
import argparse
import copy
import json
import pathlib
import random
import secrets
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import action_receipt as A  # noqa: E402

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def cases_for(manifest: dict, rng: random.Random):
    """[(opaque id, file, exchange, expected entry, kind)]"""
    out = []
    for e in manifest["exchanges"]:
        exchange = json.loads((ROOT / "exchanges" / e["file"]).read_text())
        out.append((secrets.token_hex(12), e["file"], exchange, e, "fixed"))
        st = exchange.get("statement") if isinstance(exchange, dict) else None
        if not isinstance(st, dict) or (not e["issued"] and e["reason"] == "invalid_statement"):
            continue
        twin = copy.deepcopy(exchange)
        rid = "".join(rng.choice(B64) for _ in range(rng.randint(22, 64)))
        at = rng.randint(0, 2**53 - 1)
        twin["statement"]["receiptId"], twin["statement"]["issuedAt"] = rid, at
        want = copy.deepcopy(e)
        if e["issued"]:
            want["payload"]["receiptId"], want["payload"]["issuedAt"] = rid, at
        out.append((secrets.token_hex(12), e["file"], twin, want, "follow-up"))
    rng.shuffle(out)
    return out


def protocol_cases(manifest: dict) -> list:
    """Adapter-protocol cases (CONFORMANCE.md, issuer adapter protocol): raw
    lines that are valid JSON a naive parser cannot read, and lines that are not
    JSON. [(opaque id, label, raw line, expected entry)]. The expected answers
    follow from spec §6 (the value of a number is its double, §4.6; a member the
    procedure does not name is ignored, §6.1) and from the protocol
    (`invalid_input` for a line that is not a JSON object)."""
    by_file = {e["file"]: e for e in manifest["exchanges"]}
    basic = by_file.get("issue_basic.json")
    if basic is None or not basic["issued"]:
        return []
    x = json.loads((ROOT / "exchanges" / "issue_basic.json").read_text())

    def line(cid, path, raw):
        y = copy.deepcopy(x)
        obj = y
        for k in path[:-1]:
            obj = obj[k]
        obj[path[-1]] = "@@RAW@@"
        return json.dumps({"id": cid, "exchange": y}).replace('"@@RAW@@"', raw)

    refuse = lambda r: {"issued": False, "reason": r}  # noqa: E731
    issued = {"issued": True, "payload": basic["payload"]}
    specs = [
        ("deep_accepted_200000", ["paymentPayload", "accepted", "extra"], "[" * 200000 + "]" * 200000,
         refuse("requirements_not_hashable")),
        ("deep_ignored_member_100000", ["statement", "note"], "[" * 100000 + "]" * 100000, issued),
        ("deep_ignored_object_5000", ["statement", "note"], '{"a":' * 5000 + "1" + "}" * 5000, issued),
        ("int_5000_digits_in_accepted", ["paymentPayload", "accepted", "extra"], '{"n":' + "9" * 5000 + "}",
         refuse("requirements_not_hashable")),
        ("int_5000_digits_issuedAt", ["statement", "issuedAt"], "1" * 5000, refuse("invalid_statement")),
        ("issuedAt_exponent_spelling", ["statement", "issuedAt"], "1.703123456e9", issued),
        ("not_json_nan", ["paymentPayload", "accepted", "maxTimeoutSeconds"], "NaN", refuse("invalid_input")),
        ("not_json_truncated", ["statement"], '{"receiptId": ', refuse("invalid_input")),
        ("not_json_deep_unclosed", ["statement", "note"], "[" * 100000, refuse("invalid_input")),
        ("not_json_deep_balanced", ["statement", "note"], "[" * 100 + "1 2" + "]" * 100, refuse("invalid_input")),
    ]
    out = []
    for label, path, raw, want in specs:
        cid = secrets.token_hex(12)
        out.append((cid, "protocol:" + label, line(cid, path, raw), want))
    # a line that begins with a UTF-8 byte-order mark is not a JSON text (RFC 8259
    # §8.1 lets a parser ignore one, so an issuer that silently strips it and one
    # that does not would disagree); the protocol answers `invalid_input`
    cid = secrets.token_hex(12)
    out.append((cid, "protocol:not_json_leading_bom", "﻿" + json.dumps({"id": cid, "exchange": x}),
                refuse("invalid_input")))
    return out


def judge(g, e) -> str | None:
    if g is None:
        return "no result"
    if e["issued"]:
        if g.get("issued") is not True:
            return f"refused with {g.get('reason')}"
        p = g.get("payload")
        try:
            same = A.in_domain(p) and A.jcs(p) == A.jcs(e["payload"])
        except Exception:  # noqa: BLE001
            same = False
        if not same:
            if not isinstance(p, dict):
                return "payload is not an object"
            diff = sorted(k for k in set(p) | set(e["payload"]) if p.get(k) != e["payload"].get(k))
            return f"payload differs in {diff}"
        return None
    if g.get("issued") is not False:
        return f"issued, expected refusal {e['reason']}"
    if g.get("reason") != e["reason"]:
        return f"refused with {g.get('reason')}, expected {e['reason']}"
    return None


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    ap = argparse.ArgumentParser(description="run an issuer adapter over the exchange manifest",
                                 add_help=False)
    ap.add_argument("--seed", type=int, default=None, help="follow-up values and order (default: random)")
    ap.add_argument("--json", action="store_true", help="also print a one-line JSON summary")
    ap.add_argument("--quiet", action="store_true")
    if "--" in argv:
        i = argv.index("--")
        opts, cmd = argv[:i], argv[i + 1:]
    else:
        k = 0
        while k < len(argv) and argv[k].startswith("--") and argv[k] in ("--seed", "--json", "--quiet"):
            k += 2 if argv[k] == "--seed" else 1
        opts, cmd = argv[:k], argv[k:]
    # `-h`/`--help`, no adapter command, or an option this runner does not know
    # where the command should be: print the usage and exit 2 (never a traceback)
    if any(o in ("-h", "--help") for o in opts) or not cmd or cmd[0].startswith("-"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        a = ap.parse_args(opts)
    except SystemExit:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    manifest = json.loads((ROOT / "exchanges" / "MANIFEST.json").read_text())
    if not manifest.get("exchanges"):
        print("SUMMARY exchanges 0/0: the manifest is empty; nothing was tested")
        return 2
    rng = random.Random(a.seed if a.seed is not None else secrets.randbits(32))
    cases = cases_for(manifest, rng)
    lines = [json.dumps({"id": cid, "exchange": x}) for cid, _, x, _, _ in cases]
    proto = protocol_cases(manifest)
    for cid, label, raw, want in proto:
        cases.append((cid, label, None, want, "protocol"))
        lines.append(raw)
    order = list(range(len(lines)))
    rng.shuffle(order)
    cases, lines = [cases[i] for i in order], [lines[i] for i in order]
    try:
        r = subprocess.run(cmd, input=("\n".join(lines) + "\n").encode(), capture_output=True, cwd=ROOT)
    except OSError as e:
        print(f"BROKEN cannot start the adapter {cmd[0]!r}: {e}")
        print(f"SUMMARY exchanges 0/{len(cases)}: the adapter did not run")
        return 1
    broken = None
    if r.returncode != 0:
        broken = f"adapter failed (exit {r.returncode}): {r.stderr.decode()[-1500:]}"
    got = {}
    for line in r.stdout.decode(errors="replace").split("\n"):
        if line.strip():
            try:
                o = json.loads(line)
            except ValueError:
                broken = broken or f"adapter wrote a line that is not JSON: {line[:200]!r}"
                continue
            if isinstance(o, dict):
                got[o.get("id")] = o
    if broken is None and set(got) != {c[0] for c in cases}:
        broken = f"adapter answered {len(got)} of {len(cases)} ids"
    bad, fixed_bad, disagreeing = 0, 0, []
    for cid, file, _, e, kind in cases:
        problem = judge(got.get(cid), e)
        if problem:
            bad += 1
            fixed_bad += kind == "fixed"
            disagreeing.append(file)
            if not a.quiet:
                print(f"DISAGREE {file} ({kind}): {problem}")
    n_fixed = sum(1 for c in cases if c[4] == "fixed")
    n_proto = sum(1 for c in cases if c[4] == "protocol")
    n_follow = len(cases) - n_fixed - n_proto
    bad_kind = {k: sum(1 for c in cases if c[4] == k and judge(got.get(c[0]), c[3]))
                for k in ("fixed", "follow-up", "protocol")}
    if a.json:
        print(json.dumps({"exchanges": n_fixed, "follow_ups": n_follow, "protocol": n_proto,
                          "disagree": bad, "broken": broken,
                          "disagreeing": sorted(set(disagreeing)),
                          "answers": {c[1] + ("#" + c[4] if c[4] != "fixed" else ""):
                                      (got.get(c[0]) or {}).get("reason", "issued" if (got.get(c[0]) or {}).get("issued") else None)
                                      for c in cases if judge(got.get(c[0]), c[3])}}))
    if broken:
        print(f"BROKEN {broken}")
    print(f"SUMMARY exchanges {n_fixed - bad_kind['fixed']}/{n_fixed} agree, follow-ups "
          f"{n_follow - bad_kind['follow-up']}/{n_follow} agree, protocol cases "
          f"{n_proto - bad_kind['protocol']}/{n_proto} agree, {bad} disagree"
          + ("; adapter BROKEN" if broken else ""))
    return 0 if bad == 0 and broken is None else 1


if __name__ == "__main__":
    sys.exit(main())
