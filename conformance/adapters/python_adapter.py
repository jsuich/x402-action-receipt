#!/usr/bin/env python3
"""Batch adapter for the Python reference verifier (see ADAPTER PROTOCOL in
CONFORMANCE.md).

    python_adapter.py KEYS.json < cases.jsonl > results.jsonl

Each input line:  {"id": ..., "receipt": <any JSON>, "context": {...}}
Each output line: {"id": ..., "verdict": "PASS|REJECT|ERROR", "reason": str|null,
                   "report": {...}|null}
"""
import json
import pathlib
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
import action_receipt as A  # noqa: E402


def context_from_json(c: dict) -> A.Context:
    return A.Context(
        success=c.get("success"),
        transaction=c.get("transaction"),
        settlement_ref=c.get("settlementRef"),
        network=c.get("network"),
        payer=c.get("payer"),
        accepted=c.get("accepted"),
        advertised_info=c.get("advertisedInfo"),
        now=c["now"],
        max_age_s=c.get("maxAgeSeconds", 3600),
        mode=c["mode"],
        paid_resource_url=c.get("paidResourceUrl"),
    )


def main() -> int:
    keys = json.loads(pathlib.Path(sys.argv[1]).read_text())
    for line in sys.stdin:
        if not line.strip():
            continue
        case = json.loads(line)
        verdict, reason, report = A.verify_detailed(
            case["receipt"], context_from_json(case["context"]), keys)
        sys.stdout.write(json.dumps({
            "id": case["id"], "verdict": verdict, "reason": reason,
            "report": report if verdict == A.PASS else None}) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
