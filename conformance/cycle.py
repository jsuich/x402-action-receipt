#!/usr/bin/env python3
"""
cycle.py — one full test cycle, one exit code.

    python3 conformance/cycle.py                     # default: 3 fuzz seeds x 2000
    python3 conformance/cycle.py --seeds 11,12 --n 5000
    python3 conformance/cycle.py --quick             # skip the flip probe and fuzzing

Stages, in order. A stage that cannot run is reported as VOID, never as PASS:

  1 trace      every normative sentence of the spec is covered by a requirement,
               every testable requirement by a vector, every vector by a requirement
    trace-st   the trace itself reports each kind of planted defect
  2 python     reference verifier reproduces vectors/MANIFEST.json
  3 node       second verifier reproduces vectors/MANIFEST.json
  4 example    second verifier reproduces the spec's worked example from its text
  5 flips      each check of the reference verifier, disabled, turns the suite red
  6 fuzz       differential + metamorphic fuzzing across both verifiers

Exit 0 iff every stage that ran passed and no stage was VOID.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


def last(text: str) -> str:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    return lines[-1][:160] if lines else ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="one full conformance test cycle")
    ap.add_argument("--seeds", default="1,2,3")
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--save", metavar="DIR", help="where fuzz writes disagreeing cases")
    a = ap.parse_args(argv)
    py = sys.executable
    node = shutil.which("node")
    rows, t0 = [], time.time()

    def stage(name, status, detail):
        rows.append((name, status, detail))
        print(f"[{status:4s}] {name:8s} {detail}", flush=True)

    trace = ROOT / "conformance" / "trace.py"
    if trace.exists():
        r = run([py, "-B", str(trace), "--check"])
        stage("trace", "PASS" if r.returncode == 0 else "FAIL", last(r.stdout) or last(r.stderr))
        r = run([py, "-B", str(ROOT / "conformance" / "trace_selftest.py")])
        stage("trace-st", "PASS" if r.returncode == 0 else "FAIL", last(r.stdout) or last(r.stderr))
    else:
        stage("trace", "VOID", "conformance/trace.py not present")

    r = run([py, "-B", "action_receipt.py"])
    cross = "rfc8785_crosscheck=True" in r.stdout
    stage("python", "PASS" if r.returncode == 0 else "FAIL",
          last(r.stdout) + ("" if cross else "  [canonicalizer NOT cross-checked]"))
    if not cross:
        stage("xcheck", "VOID", "rfc8785 not installed: the independent canonicalizer check did not run")

    if node:
        r = run([node, "verify.mjs"])
        stage("node", "PASS" if r.returncode == 0 else "FAIL", last(r.stdout) or last(r.stderr))
        r = run([node, "verify.mjs", "--example"])
        lines = r.stdout.strip().splitlines()
        ok = sum(l.startswith("REPRODUCED") for l in lines)
        stage("example", "PASS" if r.returncode == 0 and ok == len(lines) and ok else "FAIL",
              f"{ok} of {len(lines)} steps reproduced")
    else:
        stage("node", "VOID", "node not found")
        stage("example", "VOID", "node not found")

    if a.quick:
        stage("flips", "VOID", "skipped (--quick)")
        stage("fuzz", "VOID", "skipped (--quick)")
    else:
        scratch = tempfile.mkdtemp(prefix="action-receipt-flips-")
        r = run([py, "-B", "flip_probe.py", ".", scratch])
        stage("flips", "PASS" if r.returncode == 0 else "FAIL",
              next((l for l in r.stdout.splitlines() if "flips caught" in l), last(r.stdout)))
        if not node:
            stage("fuzz", "VOID", "node not found: no second verifier to compare with")
        else:
            total = {"generated": 0, "followups": 0, "disagreements": 0, "property_violations": 0}
            never, bad = set(), False
            for seed in a.seeds.split(","):
                cmd = [py, "-B", "conformance/fuzz.py", "--seed", seed, "--n", str(a.n), "--json"]
                if a.save:
                    cmd += ["--save", a.save]
                r = run(cmd)
                try:
                    s = json.loads(r.stdout.strip().splitlines()[0])
                except (ValueError, IndexError):
                    stage("fuzz", "FAIL", f"seed {seed}: {last(r.stderr) or last(r.stdout)}")
                    bad = True
                    break
                for k in total:
                    total[k] += s[k]
                # report only what NO seed exercised
                missed = set(s["reasons_never_hit"]) | {"op:" + o for o in s["operators_never_applied"]}
                if not s["p2_independent_canonicalizer"]:
                    missed.add("P2-not-active")
                never = missed if seed == a.seeds.split(",")[0] else never & missed
            if not bad:
                ok = total["disagreements"] == 0 and total["property_violations"] == 0
                stage("fuzz", "PASS" if ok else "FAIL",
                      f"seeds {a.seeds} x {a.n}: {total['generated']} cases + {total['followups']} "
                      f"follow-ups, {total['disagreements']} disagreements, "
                      f"{total['property_violations']} property violations"
                      + (f"; not exercised: {sorted(never)}" if never else ""))

    failed = [n for n, s, _ in rows if s == "FAIL"]
    void = [n for n, s, _ in rows if s == "VOID"]
    print(f"cycle: {len(rows) - len(failed) - len(void)} passed, {len(failed)} failed, "
          f"{len(void)} void, {time.time() - t0:.0f}s"
          + (f"  FAILED: {failed}" if failed else "") + (f"  VOID: {void}" if void else ""))
    return 0 if not failed and not void else 1


if __name__ == "__main__":
    sys.exit(main())
