#!/usr/bin/env python3
"""
run_vectors.py — drive ANY verifier adapter over vectors/MANIFEST.json.

    python3 conformance/run_vectors.py -- <adapter command ...>
    python3 conformance/run_vectors.py --json -- node conformance/adapters/node_adapter.mjs
    python3 conformance/run_vectors.py --manifest DIR/MANIFEST.json -- python3 my_adapter.py

The adapter speaks the ADAPTER PROTOCOL of CONFORMANCE.md §3: it is started with
the key fixture's path appended as its last argument, reads one JSON case per
line on stdin and writes one JSON result per line on stdout.

For every manifest entry the runner compares the adapter's verdict, its reason
(on REJECT and ERROR) and its full report (on PASS) with the manifest. It does
not trust the adapter's exit code or its own account of success:

  * every case must come back exactly once, under the id it was sent with;
  * case ids are opaque and change with --seed, so an adapter cannot answer
    from a table keyed by vector name;
  * an empty manifest, an adapter that exits non-zero, writes nothing, or
    writes a line that is not a result object, is a FAIL;
  * metamorphic follow-ups whose answer follows from the spec and not from the
    manifest: each positive with one payload bit flipped (never PASS), and each
    vector with an unknown member added to the receipt object (same result,
    spec §3 "Any other member of the receipt object is ignored").

Exit 0 iff every entry and every follow-up agreed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def bitflip(receipt, salt: str):
    """The receipt with one bit of its payload segment flipped, or None."""
    try:
        h, p, s = receipt["signature"].split(".")
        raw = bytearray(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except (KeyError, ValueError, TypeError, AttributeError):
        return None
    if not raw:
        return None
    k = int(hashlib.sha256(salt.encode()).hexdigest(), 16)
    raw[k % len(raw)] ^= 1 << ((k // len(raw)) % 8)
    return dict(receipt, signature=f"{h}.{b64url(bytes(raw))}.{s}")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--" not in argv:
        print("usage: run_vectors.py [--manifest M] [--keys K] [--seed S] [--json] -- <adapter command>",
              file=sys.stderr)
        return 2
    i = argv.index("--")
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=str(ROOT / "vectors" / "MANIFEST.json"))
    ap.add_argument("--keys", default=None, help="key fixture (default: keys.json beside the manifest)")
    ap.add_argument("--seed", default="0", help="salt for the opaque case ids")
    ap.add_argument("--json", action="store_true", help="print the summary as one JSON object first")
    ap.add_argument("--quiet", action="store_true", help="print only disagreements and the summary")
    a = ap.parse_args(argv[:i])
    adapter = argv[i + 1:]
    if not adapter:
        print("no adapter command given", file=sys.stderr)
        return 2
    mpath = pathlib.Path(a.manifest)
    vdir = mpath.parent
    keys = pathlib.Path(a.keys) if a.keys else vdir / "keys.json"
    manifest = json.loads(mpath.read_text())
    entries = manifest.get("vectors", [])

    def opaque(tag: str) -> str:
        return hashlib.sha256(f"{a.seed}|{tag}".encode()).hexdigest()[:16]

    cases, expect = [], {}
    for v in entries:
        receipt = json.loads((vdir / v["file"]).read_text())
        context = manifest["contexts"][v["context"]]
        cid = opaque(v["file"])
        cases.append({"id": cid, "receipt": receipt, "context": context})
        expect[cid] = ("vector", v["file"], v["expect"], v.get("reason"), v.get("report"))
        flipped = bitflip(receipt, cid) if v["expect"] == "PASS" else None
        if flipped is not None:
            fid = opaque(v["file"] + "#bitflip")
            cases.append({"id": fid, "receipt": flipped, "context": context})
            expect[fid] = ("bitflip", v["file"], None, None, None)
        if isinstance(receipt, dict):
            xid = opaque(v["file"] + "#envelope")
            cases.append({"id": xid, "receipt": dict(receipt, x402ExtraMember={"ignored": True}),
                          "context": context})
            expect[xid] = ("envelope", v["file"], v["expect"], v.get("reason"), v.get("report"))

    problems, results = [], {}
    if not entries:
        problems.append("EMPTY MANIFEST: nothing to check")
    else:
        data = "".join(json.dumps(c) + "\n" for c in cases).encode()
        try:
            r = subprocess.run(adapter + [str(keys)], input=data, capture_output=True, timeout=600)
        except (OSError, subprocess.TimeoutExpired) as e:
            problems.append(f"adapter could not run: {e}")
            r = None
        if r is not None:
            if r.returncode != 0:
                problems.append(f"adapter exited {r.returncode}: {r.stderr.decode(errors='replace')[-300:]}")
            for line in r.stdout.decode(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    o = json.loads(line)
                    cid = o["id"]
                    res = (o["verdict"], o.get("reason"), o.get("report"))
                except (ValueError, KeyError, TypeError):
                    problems.append(f"adapter wrote a line that is not a result: {line[:80]!r}")
                    continue
                if cid in results:
                    problems.append(f"adapter answered case {cid} twice")
                results[cid] = res
            missing = [c for c in expect if c not in results]
            extra = [c for c in results if c not in expect]
            if missing:
                problems.append(f"adapter returned no result for {len(missing)} of {len(expect)} cases")
            if extra:
                problems.append(f"adapter returned {len(extra)} results for cases it was not sent")

    agree = disagree = 0
    follow_ok = follow_bad = 0
    bad_files = []
    for cid, (kind, fname, want, reason, report) in expect.items():
        if cid not in results:
            continue
        verdict, got_reason, got_report = results[cid]
        why = []
        if kind == "bitflip":
            if verdict == "PASS":
                why.append("a positive with one payload bit flipped PASSED")
            elif verdict == "ERROR":
                why.append(f"ERROR on a receipt-only change ({got_reason})")
        else:
            if verdict != want:
                why.append(f"verdict {verdict}, want {want}")
            elif want != "PASS" and got_reason != reason:
                why.append(f"reason {got_reason}, want {reason}")
            elif want == "PASS" and got_report != report:
                why.append(f"report {json.dumps(got_report, sort_keys=True)} != "
                           f"{json.dumps(report, sort_keys=True)}")
        label = fname + ("" if kind == "vector" else f" [{kind}]")
        if kind == "vector":
            agree += not why
            disagree += bool(why)
        else:
            follow_ok += not why
            follow_bad += bool(why)
        if why:
            bad_files.append(label)
            print(f"DISAGREE {label}: {'; '.join(why)}")
        elif not a.quiet:
            print(f"ok       {label}")
    ok = not problems and disagree == 0 and follow_bad == 0 and agree == len(entries) and agree > 0
    summary = {"adapter": " ".join(adapter), "manifest": str(mpath), "vectors": len(entries),
               "agree": agree, "disagree": disagree, "followups": follow_ok + follow_bad,
               "followups_failed": follow_bad, "problems": problems, "ok": ok}
    for p in problems:
        print(f"PROBLEM  {p}")
    line = (f"SUMMARY vectors {agree}/{len(entries)} agree, {disagree} disagree; "
            f"follow-ups {follow_ok}/{follow_ok + follow_bad} hold; "
            f"{len(problems)} harness problem(s)")
    if a.json:
        print(json.dumps(summary))
    print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
