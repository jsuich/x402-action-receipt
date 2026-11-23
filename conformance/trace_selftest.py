#!/usr/bin/env python3
"""
trace_selftest.py — show that conformance/trace.py can report each kind of defect.

Copies the spec, the catalogue, the manifest and CONFORMANCE.md to a scratch
directory, plants one defect at a time, and requires `trace.py --check` to fail
with the matching check id. Ends with a control on the untouched copy, which
must pass.

    python3 conformance/trace_selftest.py

Exit 0 iff every planted defect was reported under the expected check and the
control passed.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = ["action-receipt.md", "CONFORMANCE.md", "conformance/requirements.json",
         "conformance/trace.py", "exchanges/MANIFEST.json"]


def fresh() -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp(prefix="action-receipt-trace-"))
    for f in FILES:
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / f, d / f)
    shutil.copytree(ROOT / "vectors", d / "vectors")      # T8-T10 read the files
    return d


def edit_manifest(d, fn):
    p = d / "vectors/MANIFEST.json"
    doc = json.loads(p.read_text())
    fn(doc)
    p.write_text(json.dumps(doc, indent=2) + "\n")


def overwrite_vector(d, target, source):
    """Reviewer E's X6b: a vector overwritten with a copy of another of the
    same context. The manifest's digest is updated too, so only T9 can see it."""
    (d / "vectors" / target).write_text((d / "vectors" / source).read_text())
    import importlib.util
    spec = importlib.util.spec_from_file_location("trace_under_test", d / "conformance/trace.py")
    t = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(t)
    edit_manifest(d, lambda m: m.update(vectorsDigest=t.vectors_digest(d / "vectors")))


def check(d: pathlib.Path):
    r = subprocess.run([sys.executable, "-B", str(d / "conformance/trace.py"), "--check"],
                       capture_output=True, text=True)
    return r.returncode, r.stdout


def edit_reqs(d, fn):
    p = d / "conformance/requirements.json"
    doc = json.loads(p.read_text())
    fn(doc["requirements"])
    p.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


def by_id(reqs, rid):
    return next(r for r in reqs if r["id"] == rid)


def drop(reqs, rid):
    reqs[:] = [r for r in reqs if r["id"] != rid]


PLANTS = [
    ("T1", "an anchor that is no longer in the spec",
     lambda d: edit_reqs(d, lambda rs: by_id(rs, "V-ENV-4").update(anchor="Reject with a code that was renamed"))),
    ("T2", "a normative sentence no requirement covers",
     lambda d: edit_reqs(d, lambda rs: drop(rs, "C-5"))),
    ("T2", "a new MUST added to the spec without a requirement",
     lambda d: (d / "action-receipt.md").write_text(
         (d / "action-receipt.md").read_text().replace(
             "## 6. Issuing (normative)",
             "A verifier MUST also refuse receipts issued on a Tuesday.\n\n## 6. Issuing (normative)"))),
    ("T3", "a requirement naming a vector that does not exist",
     lambda d: edit_reqs(d, lambda rs: by_id(rs, "V-SIG-2")["vectors"].append("neg_does_not_exist.json"))),
    ("T4", "a vector that no requirement names",
     lambda d: edit_reqs(d, lambda rs: by_id(rs, "V-SIG-3").update(vectors=["neg_sig_wrong_curve.json"]))),
    ("T4", "an exchange that no requirement names",
     lambda d: edit_reqs(d, lambda rs: by_id(rs, "I-STP-1").update(exchanges=["refuse_settlement_failed.json"]))),
    ("T3", "a requirement naming an exchange that does not exist",
     lambda d: edit_reqs(d, lambda rs: by_id(rs, "I-STP-2")["exchanges"].append("refuse_nothing.json"))),
    ("T5", "an untested requirement with no listed reason",
     lambda d: edit_reqs(d, lambda rs: by_id(rs, "V-AUT-3").update(tested_by="later"))),
    ("T7", "a stale CONFORMANCE.md",
     lambda d: (d / "CONFORMANCE.md").write_text((d / "CONFORMANCE.md").read_text() + "\nedited by hand\n")),
    ("T8", "a vector file edited after the manifest was written (digest no longer describes it)",
     lambda d: (d / "vectors/neg_canon_whitespace.json").write_text(
         (d / "vectors/neg_canon_whitespace.json").read_text() + " ")),
    ("T9", "a vector overwritten with a copy of another in the same context (reviewer E X6b)",
     lambda d: overwrite_vector(d, "neg_canon_whitespace.json", "neg_canon_member_order.json")),
    ("T10", "the manifest naming a vector file that is not in vectors/",
     lambda d: (d / "vectors/neg_canon_whitespace.json").unlink()),
    ("T3", "a requirement marked tested by the suite that cites a vector that does not exist",
     lambda d: edit_reqs(d, lambda rs: by_id(rs, "V-ORD-1").update(vectors=["neg_order_nothing.json"]))),
]


def main() -> int:
    failed = 0
    # A plant counts only if it adds a line with its code that the untouched
    # copy does not already report; otherwise a red control would make every
    # plant look caught.
    rc, out = check(fresh())
    control_lines = set(out.splitlines())
    for code, what, plant in PLANTS:
        d = fresh()
        plant(d)
        prc, pout = check(d)
        hit = prc != 0 and any(line.startswith(code + " ") and line not in control_lines
                               for line in pout.splitlines())
        failed += not hit
        print(f"[{'caught' if hit else 'MISSED'}] {code}: {what}")
    print(f"control (untouched): rc={rc}  {out.strip().splitlines()[-1][:110]}")
    if rc != 0:
        print("control errors: " + "; ".join(l[:60] for l in out.splitlines() if l[:2] in ("T0", "T1", "T2", "T3", "T4", "T5", "T7", "T8", "T9")))
    ok = failed == 0 and rc == 0
    print(f"trace self-test: {len(PLANTS) - failed} of {len(PLANTS)} planted defects caught; "
          f"control {'passed' if rc == 0 else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
