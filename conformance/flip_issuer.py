#!/usr/bin/env python3
"""
flip_issuer.py — show that each step of the reference issuer can fail the
exchange suite.

Copies the issuer, the verifier, the spec and exchanges/ to a scratch directory,
disables or weakens ONE issuer step at a time, and requires `issuer.py` to exit
non-zero. Ends with a control run of the unpatched issuer, which must exit 0.

    python3 conformance/flip_issuer.py
    python3 conformance/flip_issuer.py --fuzz 3000

With --fuzz N each flipped issuer is also put in front of the issuer fuzzer
(conformance/fuzz_issuer.py, N exchanges, against the unpatched second issuer and
both verifiers). That measures the FUZZER; its misses are reported and do not
fail the run.

Exit 0 iff every flip was caught by the exchange suite, every patch applied to
exactly one place, and the control passed.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
code = (ROOT / "issuer.py").read_text()

FLIPS = [
    ("1 settlement success",   'if resp.get("success") is not True:', 'if False:'),
    ("2 settlement identifier", 'if not (transaction or reference):', 'if False:'),
    ("3 requirements hashable", '    if digest is None:\n        return None, X_REQUIREMENTS', '    pass'),
    ("4 network grammar",      'if not (isinstance(network, str) and A.RE_CAIP2.fullmatch(network)):', 'if not isinstance(network, str):'),
    ("4 network conflict",     'and resp_net != network:', 'and False:'),
    ("5 resource",             'if not _had(resource):', 'if False:'),
    ("6 payer from scheme payload", '        payer = _obj(_obj(pay.get("payload")).get("authorization")).get("from")', '        payer = None'),
    ("6 payer required",       '    if not _had(payer):\n        return None, X_PAYER', '    if False:\n        return None, X_PAYER'),
    ("7 payTo required",       'if not _had(pay_to):', 'if False:'),
    ("7 lowercasing",          'payer, pay_to, transaction = _lower_evm(payer), _lower_evm(pay_to), _lower_evm(transaction)', 'pass'),
    ("7 address grammar",      'if not (A.RE_EVM_ADDRESS.fullmatch(payer) and A.RE_EVM_ADDRESS.fullmatch(pay_to)):', 'if False:'),
    ("7 transaction grammar",  'if transaction and not A.RE_EVM_TX.fullmatch(transaction):', 'if False:'),
    ("8 statement",            '    if not ok:\n        return None, X_STATEMENT', '    pass'),
    ("8 integer by value",     '    if isinstance(v, float) and v.is_integer():\n        return int(v)', '    pass'),
    ("9 advertisement conflict", 'and info[member] != action[member]:', 'and False:'),
    ("10 advertisement committed", '    if advertised:\n        if not A.in_domain(info):', '    if False:\n        if not A.in_domain(info):'),
    ("10 advertised info hashable", '        if not A.in_domain(info):\n            return None, X_BINDINGS', '        pass'),
    ("10 reversal binding",    'if _had(st.get("reversalTransaction")):', 'if False:'),
    ("10 reserved binding types", 'and b["type"].startswith("action-receipt:") for b in bindings):', 'and False for b in bindings):'),
    ("8 well-formed strings",   ' and A.in_domain(action["scope"])', ''),
    ("10 binding count",       'if len(bindings) > A.MAX_BINDINGS:', 'if False:'),
    ("10 binding uniqueness",  ' or b["type"] in seen:', ':'),
    ("10 binding grammar",     'and A.RE_BINDING_TYPE.fullmatch(b["type"])', 'and True'),
    ("10 binding order",       '                      key=lambda b: b["type"])', '                      key=lambda b: 0)'),
    ("10 bindings must be an array", '    if not isinstance(extra, list):\n        return None, X_BINDINGS', '    if not isinstance(extra, list):\n        extra = []'),
]


FUZZ_N = int(sys.argv[sys.argv.index("--fuzz") + 1]) if "--fuzz" in sys.argv else 0


def run(text: str):
    """Return (exchange-suite exit code, fuzz detections or None)."""
    d = pathlib.Path(tempfile.mkdtemp(prefix="action-receipt-issuer-flip-")) / "t"
    shutil.copytree(ROOT, d, ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv", "out"))
    (d / "issuer.py").write_text(text)
    rc = subprocess.run([sys.executable, "-B", "issuer.py"], cwd=d, capture_output=True).returncode
    found = None
    if FUZZ_N:
        f = subprocess.run([sys.executable, "-B", "conformance/fuzz_issuer.py", "--seed", "1",
                            "--n", str(FUZZ_N), "--json"], cwd=d, capture_output=True, text=True)
        try:
            summary = json.loads(f.stdout.strip().splitlines()[0])
            found = summary["disagreements"] + summary["property_violations"]
        except (ValueError, IndexError):
            found = -1
    return rc, found


def main() -> int:
    missed, fuzz_missed = [], []
    for label, old, new in FLIPS:
        if code.count(old) != 1:
            print(f"[SETUP ERROR] {label}: source text found {code.count(old)} times")
            missed.append(label)
            continue
        rc, found = run(code.replace(old, new))
        if rc == 0:
            missed.append(label)
        fz = ""
        if FUZZ_N:
            fz = f"  fuzz={'caught(' + str(found) + ')' if found else 'MISSED'}"
            if not found:
                fuzz_missed.append(label)
        print(f"[{'caught' if rc else 'MISSED'}] {label}{fz}")
    control, control_found = run(code)
    print(f"{len(FLIPS) - len(missed)} of {len(FLIPS)} issuer flips caught; control (unpatched) rc={control}")
    print("MISSED:", missed)
    if FUZZ_N:
        print(f"issuer fuzzer ({FUZZ_N} exchanges): {len(FLIPS) - len(fuzz_missed)} of {len(FLIPS)} "
              f"flips detected; control found {control_found}")
        print("FUZZ MISSED:", fuzz_missed)
    return 0 if not missed and control == 0 and not (FUZZ_N and control_found) else 1


if __name__ == "__main__":
    sys.exit(main())
