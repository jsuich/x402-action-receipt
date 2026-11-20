#!/usr/bin/env python3
"""
run_exchanges.py — run an issuer adapter against exchanges/MANIFEST.json.

    python3 conformance/run_exchanges.py node issuer.mjs
    python3 conformance/run_exchanges.py python3 issuer.py --batch

The command is an issuer adapter (ISSUER ADAPTER PROTOCOL in CONFORMANCE.md):
exchanges as JSON lines on stdin, results as JSON lines on stdout. Payloads are
compared by their RFC 8785 serialization. Exit 0 iff every exchange agrees.
"""
import json
import pathlib
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import action_receipt as A  # noqa: E402


def main() -> int:
    cmd = sys.argv[1:]
    if not cmd:
        sys.exit(__doc__)
    manifest = json.loads((ROOT / "exchanges" / "MANIFEST.json").read_text())
    lines = [json.dumps({"id": e["file"], "exchange": json.loads((ROOT / "exchanges" / e["file"]).read_text())})
             for e in manifest["exchanges"]]
    r = subprocess.run(cmd, input=("\n".join(lines) + "\n").encode(), capture_output=True, cwd=ROOT)
    if r.returncode != 0:
        sys.exit(f"adapter failed (exit {r.returncode}): {r.stderr.decode()[-1500:]}")
    got = {}
    for line in r.stdout.decode().split("\n"):
        if line.strip():
            o = json.loads(line)
            got[o["id"]] = o
    bad = 0
    for e in manifest["exchanges"]:
        g = got.get(e["file"])
        problem = None
        if g is None:
            problem = "no result"
        elif e["issued"]:
            if not g.get("issued"):
                problem = f"refused with {g.get('reason')}"
            else:
                try:
                    same = A.in_domain(g["payload"]) and A.jcs(g["payload"]) == A.jcs(e["payload"])
                except Exception:  # noqa: BLE001
                    same = False
                if not same:
                    diff = sorted(k for k in set(g["payload"]) | set(e["payload"])
                                  if g["payload"].get(k) != e["payload"].get(k))
                    problem = f"payload differs in {diff}"
        elif g.get("issued"):
            problem = f"issued, expected refusal {e['reason']}"
        elif g.get("reason") != e["reason"]:
            problem = f"refused with {g.get('reason')}, expected {e['reason']}"
        bad += bool(problem)
        if problem:
            print(f"DISAGREE {e['file']}: {problem}")
    n = len(manifest["exchanges"])
    print(f"SUMMARY exchanges {n - bad}/{n} agree, {bad} disagree")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
