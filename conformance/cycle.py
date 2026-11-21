#!/usr/bin/env python3
"""
cycle.py — one full test cycle, one exit code.

    python3 conformance/cycle.py                     # default: 3 fuzz seeds x 2000
    python3 conformance/cycle.py --seeds 151,152 --n 5000   # new seeds: CYCLES.md lists the spent ones
    python3 conformance/cycle.py --quick             # skip the flip probe and fuzzing

Paths are resolved from this file, so the cycle can be started from any
directory. Stages, in order. A stage that cannot run, or ran too little to mean
anything, is reported as VOID, never as PASS:

  1 trace      every normative sentence of the spec is covered by a requirement,
               every testable requirement by a vector, every vector by a requirement;
               vectorsDigest describes the files
    trace-st   the trace itself reports each kind of planted defect
  2 python     reference verifier's own suite (hand-declared verdicts, reasons and
               reports; mutation matrix; receiptRef relations)
    python-a   the Python adapter, driven by conformance/run_vectors.py over the
               manifest, compared entry by entry (not the adapter's exit code)
  3 node       the Node adapter over the manifest, the same way
  4 example    second verifier reproduces the spec's worked example from its text
  5 flips      each check of both verifiers, disabled, turns the vectors red
  6 fuzz       differential + metamorphic fuzzing across both verifiers; FAIL if
               a seed's run exits non-zero, fewer cases ran than were asked for,
               or a reason/operator never fired on any seed
  7 issuer     reference issuer reproduces exchanges/MANIFEST.json, and every
               receipt it issues verifies in the context of its own exchange
    issuer-n   second issuer reproduces exchanges/MANIFEST.json
    issuer-fl  each step of the reference issuer, disabled, turns its suite red
    issuer-fz  the two issuers agree on generated exchanges, and every issued
               receipt verifies through both verifiers; FAIL if a seed's run exits
               non-zero or reports a status other than PASS, a problem, or an
               operator it never applied

Seeds given twice are run once (`--seeds 7,7` is one seed).

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
# A fuzz stage below this many cases per seed is VOID: it cannot have exercised
# the operators, and a green result would mean nothing (reviewer E, F4).
MIN_FUZZ_N = 500


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


def last(text: str) -> str:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    return lines[-1][:200] if lines else ""


def json_line(text: str, key: str):
    """The last line of `text` that is a JSON object with member `key`."""
    for line in reversed(text.strip().splitlines()):
        if line.startswith("{"):
            try:
                o = json.loads(line)
            except ValueError:
                continue
            if isinstance(o, dict) and key in o:
                return o
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="one full conformance test cycle")
    ap.add_argument("--seeds", default="81,82,83")
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--save", metavar="DIR", help="where fuzz writes disagreeing cases")
    a = ap.parse_args(argv)
    py = sys.executable
    node = shutil.which("node")
    seeds = list(dict.fromkeys(s.strip() for s in a.seeds.split(",") if s.strip()))
    bad_seeds = [s for s in seeds if not s.lstrip("-").isdigit()]
    if bad_seeds:
        ap.error(f"--seeds must be integers, got {bad_seeds}")
    seed_list = ",".join(seeds)
    rows, t0 = [], time.time()

    def stage(name, status, detail, t_start=None):
        took = f" ({time.time() - t_start:.0f}s)" if t_start is not None else ""
        rows.append((name, status, detail))
        print(f"[{status:4s}] {name:9s} {detail}{took}", flush=True)

    t = time.time()
    trace = ROOT / "conformance" / "trace.py"
    if trace.exists():
        r = run([py, "-B", str(trace), "--check"])
        stage("trace", "PASS" if r.returncode == 0 else "FAIL", last(r.stdout) or last(r.stderr), t)
        t = time.time()
        r = run([py, "-B", str(ROOT / "conformance" / "trace_selftest.py")])
        stage("trace-st", "PASS" if r.returncode == 0 else "FAIL", last(r.stdout) or last(r.stderr), t)
    else:
        stage("trace", "VOID", "conformance/trace.py not present")

    t = time.time()
    r = run([py, "-B", str(ROOT / "action_receipt.py")])
    cross = "rfc8785_crosscheck=True" in r.stdout
    stage("python", "PASS" if r.returncode == 0 else "FAIL",
          last(r.stdout) + ("" if cross else "  [canonicalizer NOT cross-checked]"), t)
    if not cross:
        stage("xcheck", "VOID", "rfc8785 not installed: the independent canonicalizer check did not run")

    def adapter_stage(name, cmd):
        t1 = time.time()
        r = run([py, "-B", str(ROOT / "conformance" / "run_vectors.py"), "--quiet", "--json",
                 "--seed", seeds[0] if seeds else "0", "--"] + cmd)
        s = json_line(r.stdout, "agree")
        if s is None:
            stage(name, "FAIL", f"runner produced no summary: {last(r.stderr) or last(r.stdout)}", t1)
        elif s["vectors"] == 0:
            stage(name, "VOID", "manifest has no vectors", t1)
        else:
            ok = r.returncode == 0 and s["ok"] and s["agree"] == s["vectors"]
            stage(name, "PASS" if ok else "FAIL", last(r.stdout), t1)

    adapter_stage("python-a", [py, "-B", str(ROOT / "conformance" / "adapters" / "python_adapter.py")])
    if node:
        adapter_stage("node", [node, str(ROOT / "conformance" / "adapters" / "node_adapter.mjs")])
        t = time.time()
        r = run([node, str(ROOT / "verify.mjs"), "--example"])
        lines = r.stdout.strip().splitlines()
        ok = sum(l.startswith("REPRODUCED") for l in lines)
        stage("example", "PASS" if r.returncode == 0 and ok == len(lines) and ok else "FAIL",
              f"{ok} of {len(lines)} steps reproduced", t)
    else:
        stage("node", "VOID", "node not found")
        stage("example", "VOID", "node not found")

    if a.quick:
        stage("flips", "VOID", "skipped (--quick)")
        stage("fuzz", "VOID", "skipped (--quick)")
    else:
        t = time.time()
        scratch = tempfile.mkdtemp(prefix="action-receipt-flips-")
        r = run([py, "-B", str(ROOT / "flip_probe.py"), str(ROOT), scratch])
        summary = json_line(r.stdout, "flips")
        if summary is None:
            stage("flips", "FAIL", f"flip probe produced no summary: {last(r.stderr) or last(r.stdout)}", t)
        else:
            ok = r.returncode == 0 and summary["caught"] == summary["flips"] > 0 and summary["control_ok"]
            stage("flips", "PASS" if ok else "FAIL",
                  next((l for l in r.stdout.splitlines() if "flips caught" in l), last(r.stdout)), t)
        if not node:
            stage("fuzz", "VOID", "node not found: no second verifier to compare with")
        elif a.n < MIN_FUZZ_N or not seeds:
            stage("fuzz", "VOID", f"--n {a.n} per seed over {len(seeds)} seed(s) is below the floor of "
                                  f"{MIN_FUZZ_N}: nothing meaningful was fuzzed")
        else:
            t = time.time()
            total = {"generated": 0, "requested": 0, "followups": 0, "disagreements": 0,
                     "property_violations": 0}
            never, bad, failed_seeds = None, False, []
            for seed in seeds:
                cmd = [py, "-B", str(ROOT / "conformance" / "fuzz.py"), "--seed", seed, "--n", str(a.n), "--json"]
                if a.save:
                    cmd += ["--save", a.save]
                r = run(cmd)
                s = json_line(r.stdout, "generated")
                if s is None:
                    stage("fuzz", "FAIL", f"seed {seed}: {last(r.stderr) or last(r.stdout)}", t)
                    bad = True
                    break
                if r.returncode != 0:
                    failed_seeds.append(f"{seed} (exit {r.returncode})")
                for k in total:
                    total[k] += s[k]
                # report only what NO seed exercised
                missed = set(s["reasons_never_hit"]) | {"op:" + o for o in s["operators_never_applied"]}
                if not s["p2_independent_canonicalizer"]:
                    missed.add("P2-not-active")
                missed |= {"error:" + e for e in s.get("errors_never_hit", [])}
                never = missed if never is None else never & missed
            if not bad:
                detail = (f"seeds {seed_list} x {a.n}: {total['generated']} of {total['requested']} cases + "
                          f"{total['followups']} follow-ups, {total['disagreements']} disagreements, "
                          f"{total['property_violations']} property violations")
                if total["generated"] == 0:
                    stage("fuzz", "VOID", detail + "; no case was generated", t)
                else:
                    short = total["generated"] < total["requested"]
                    ok = (total["disagreements"] == 0 and total["property_violations"] == 0
                          and not short and not never and not failed_seeds)
                    stage("fuzz", "PASS" if ok else "FAIL",
                          detail + (f"; fewer cases than requested" if short else "")
                          + (f"; not exercised: {sorted(never)}" if never else "")
                          + (f"; fuzz.py failed for seed {', '.join(failed_seeds)}" if failed_seeds else ""), t)

    t = time.time()
    r = run([py, "-B", str(ROOT / "issuer.py")])
    stage("issuer", "PASS" if r.returncode == 0 else "FAIL", last(r.stdout) or last(r.stderr), t)
    if node:
        t = time.time()
        r = run([py, "-B", str(ROOT / "conformance" / "run_exchanges.py"), node, "issuer.mjs"])
        stage("issuer-n", "PASS" if r.returncode == 0 else "FAIL", last(r.stdout) or last(r.stderr), t)
    else:
        stage("issuer-n", "VOID", "node not found")
    if a.quick:
        stage("issuer-fl", "VOID", "skipped (--quick)")
        stage("issuer-fz", "VOID", "skipped (--quick)")
    else:
        t = time.time()
        r = run([py, "-B", str(ROOT / "conformance" / "flip_issuer.py")])
        summary = json_line(r.stdout, "flips")
        ok = r.returncode == 0 and summary is not None and summary["flips"] > 0 and summary["control_ok"]
        stage("issuer-fl", "PASS" if ok else "FAIL",
              next((l for l in r.stdout.splitlines() if "flips caught" in l), last(r.stdout) or last(r.stderr)), t)
        if not node:
            stage("issuer-fz", "VOID", "node not found: no second issuer or verifier")
        elif a.n < MIN_FUZZ_N or not seeds:
            stage("issuer-fz", "VOID", f"--n {a.n} is below the floor of {MIN_FUZZ_N}")
        else:
            t = time.time()
            tot = {"generated": 0, "round_trips": 0, "disagreements": 0, "property_violations": 0}
            never, bad, reported = None, False, []
            for seed in seeds:
                cmd = [py, "-B", str(ROOT / "conformance" / "fuzz_issuer.py"), "--seed", seed, "--n", str(a.n), "--json"]
                if a.save:
                    cmd += ["--save", a.save]
                r = run(cmd)
                s = json_line(r.stdout, "generated")
                if s is None:
                    stage("issuer-fz", "FAIL", f"seed {seed}: {last(r.stderr) or last(r.stdout)}", t)
                    bad = True
                    break
                for k in tot:
                    tot[k] += s[k]
                miss = set(s["refusals_never_hit"])
                never = miss if never is None else never & miss
                # the fuzzer's own verdict counts: any problem it reports fails the stage
                why = list(s.get("problems") or [])
                if s.get("operators_never_applied"):
                    why.append(f"operators never applied: {s['operators_never_applied']}")
                if s.get("status") != "PASS":
                    why.append(f"status {s.get('status')}")
                if r.returncode != 0:
                    why.append(f"exit {r.returncode}")
                if why:
                    reported.append(f"seed {seed}: " + "; ".join(dict.fromkeys(why)))
            if not bad:
                requested = a.n * len(seeds)
                detail = (f"seeds {seed_list} x {a.n}: {tot['generated']} of {requested} exchanges, "
                          f"{tot['round_trips']} round trips, {tot['disagreements']} disagreements, "
                          f"{tot['property_violations']} property violations")
                if tot["generated"] == 0 or tot["round_trips"] == 0:
                    stage("issuer-fz", "VOID", detail + "; nothing was generated or round-tripped", t)
                else:
                    short = tot["generated"] < requested
                    ok = (tot["disagreements"] == 0 and tot["property_violations"] == 0
                          and not short and not never and not reported)
                    stage("issuer-fz", "PASS" if ok else "FAIL",
                          detail + ("; fewer exchanges than requested" if short else "")
                          + (f"; not exercised: {sorted(never)}" if never else "")
                          + (f"; fuzz_issuer.py reported: {' | '.join(reported)}" if reported else ""), t)

    failed = [n for n, s, _ in rows if s == "FAIL"]
    void = [n for n, s, _ in rows if s == "VOID"]
    print(f"cycle: {len(rows) - len(failed) - len(void)} passed, {len(failed)} failed, "
          f"{len(void)} void, {time.time() - t0:.0f}s"
          + (f"  FAILED: {failed}" if failed else "") + (f"  VOID: {void}" if void else ""))
    return 0 if not failed and not void else 1


if __name__ == "__main__":
    sys.exit(main())
