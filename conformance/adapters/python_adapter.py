#!/usr/bin/env python3
"""Batch adapter for the Python reference verifier (see ADAPTER PROTOCOL in
CONFORMANCE.md).

    python_adapter.py KEYS.json < cases.jsonl > results.jsonl

Each input line:  {"id": ..., "receipt": <any JSON>, "context": <any JSON>}
Each output line: {"id": ..., "verdict": "PASS|REJECT|ERROR", "reason": str|null,
                   "report": {...}|null}

The context is passed through without defaults: a missing `mode` or `now`, or a
context that is not an object, is configuration outside the contract of spec §5
and the verifier answers ERROR / invalid_configuration. A missing
`maxAgeSeconds` is absent (3600); a present one, including null, is a value.
"""
import json
import pathlib
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
import action_receipt as A  # noqa: E402


def context_from_json(c):
    if not isinstance(c, dict):
        return None
    return A.Context(
        success=c.get("success"),
        transaction=c.get("transaction"),
        settlement_ref=c.get("settlementRef"),
        network=c.get("network"),
        payer=c.get("payer"),
        amount=c.get("amount"),
        extra=c.get("extra"),
        accepted=c.get("accepted"),
        advertised_info=c.get("advertisedInfo"),
        now=c.get("now", A.ABSENT),
        max_age_s=c["maxAgeSeconds"] if "maxAgeSeconds" in c else A.ABSENT,
        mode=c.get("mode", A.ABSENT),
        paid_resource_url=c.get("paidResourceUrl"),
    )


def main() -> int:
    keys = json.loads(pathlib.Path(sys.argv[1]).read_text())
    for line in sys.stdin:
        if not line.strip():
            continue
        case = json.loads(line)
        verdict, reason, report = A.verify_detailed(
            case.get("receipt"), context_from_json(case.get("context")), keys)
        sys.stdout.write(json.dumps({
            "id": case["id"], "verdict": verdict, "reason": reason,
            "report": report if verdict == A.PASS else None}) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
