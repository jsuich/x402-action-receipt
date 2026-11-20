#!/usr/bin/env python3
"""
flip_probe.py — show that each check in the reference verifier can fail.

A green conformance run says nothing unless the suite could have gone red. This
script copies the verifier and the vectors to a scratch directory, disables or
weakens ONE check at a time, and requires the suite to exit non-zero each time.
It ends with a control run of the unpatched verifier, which must exit 0.

    python3 flip_probe.py <repo dir> <scratch dir>
    python3 flip_probe.py <repo dir> <scratch dir> --fuzz 1500

With --fuzz N the same flips are also put in front of the differential fuzzer
(conformance/fuzz.py, N cases, against the unpatched second verifier). That
measures the FUZZER: a flip the vectors catch and the fuzzer misses is a hole in
the generator. Fuzz misses are reported and do not fail the run; a flip that
neither detector catches does.

Exit 0 iff every flip was caught by the vectors, every patch applied to exactly
one place in the source, and the control passed. The scratch directory must
exist; nothing in it is deleted.
"""
import json, sys, shutil, subprocess, pathlib, tempfile
src = pathlib.Path(sys.argv[1]).resolve(); work = pathlib.Path(sys.argv[2])
FUZZ_N = int(sys.argv[sys.argv.index('--fuzz') + 1]) if '--fuzz' in sys.argv else 0
code = (src/"action_receipt.py").read_text()
# (label, exact source text, replacement) — each disables or weakens ONE check
flips = [
 ("base64url one spelling", 'if b64url(data) != s:', 'if False:'),
 ("unusable key code",     '    if pub is None:\n        return REJECT, R_KEY_UNRESOLVED, {}', '    if pub is None:\n        return REJECT, R_SIG_INVALID, {}'),
 ("has = non-empty string",  '    return isinstance(value, str) and value != ""', '    return value is not None'),
 ("integer-valued float",     '        return v.is_integer() and -SAFE_INT_MAX <= v <= SAFE_INT_MAX', '        return False'),
 ("strict header decoding", 'header = json.loads(b64url_decode(h_b64).decode("utf-8"))', 'header = json.loads(b64url_decode(h_b64))'),
 ("null payload sentinel",  '    if payload is NOT_CANONICAL:', '    if payload is NOT_CANONICAL or payload is None:'),
 ("typ check",            'if header.get("typ") != TYP:', 'if False:'),
 ("alg allow-list",       'if header.get("alg") not in SUPPORTED_ALGS:', 'if False:'),
 ("header closed set",    'if set(header.keys()) != HEADER_KEYS or not isinstance(header.get("kid"), str):', 'if not isinstance(header.get("kid"), str):'),
 ("canonical bytes",      '    if jcs(value) != data:\n        return NOT_CANONICAL', '    pass'),
 ("value domain",         '    if not in_domain(value):\n        return NOT_CANONICAL', '    pass'),
 ("closed top-level set", 'if not isinstance(payload, dict) or set(payload.keys()) != TOP_KEYS:', 'if not isinstance(payload, dict) or not TOP_KEYS <= set(payload.keys()):'),
 ("receiptId grammar",    'if not RE_RECEIPT_ID.fullmatch(payload["receiptId"]):', 'if False:'),
 ("EVM address case",     'if not (RE_EVM_ADDRESS.fullmatch(payload["payer"])', 'if not (True'),
 ("EVM tx grammar",       'if payload["transaction"] and not RE_EVM_TX.fullmatch(payload["transaction"]):', 'if False:'),
 ("digest grammar",       'if not RE_DIGEST.fullmatch(payload["requirementsDigest"]):', 'if False:'),
 ("binding order",        'if previous is not None and not previous < t:', 'if False:'),
 ("binding count",        'if len(bindings) > MAX_BINDINGS:', 'if False:'),
 ("signer authorization", 'if kid not in service_kids and kid not in payto_kids:', 'if False:'),
 ("low-s",                'if s > CURVE_ORDER[ALG_CURVE[alg]] // 2:', 'if False:'),
 ("curve bound to alg",   'if pub.curve.name != ALG_CURVE[alg]:', 'if False:'),
 ("settlement success",   'if ctx.success is not True or not (_has(ctx.transaction) or _has(ctx.settlement_ref)):', 'if False:'),
 ("tx binding",           '        if payload["transaction"] != _norm_unsigned(network, ctx.transaction):', '        if False:'),
 ("uncorroborated tx",    '    elif payload["transaction"]:', '    elif False:'),
 ("ref binding",          '        if payload["settlementRef"] != ctx.settlement_ref:', '        if False:'),
 ("network binding",      '        if network != ctx.network:', '        if False:'),
 ("payer binding",        'if payload["payer"] != _norm_unsigned(network, ctx.payer):', 'if False:'),
 ("response case-fold",   '        return value.lower()', '        return value'),
 ("requirements digest",  'if payload["requirementsDigest"] != digest:', 'if False:'),
 ("requirements network", '        if ctx.accepted.get("network") != network:', '        if False:'),
 ("requirements payTo",   'if _norm_unsigned(network, ctx.accepted.get("payTo")) != payload["payTo"]:', 'if False:'),
 ("future-dated",         '    if age < -60:', '    if False:'),
 ("session max age",      '        if age > ctx.max_age_s:', '        if False:'),
 ("archival mode",        '    if ctx.mode == "session":', '    if True:'),
 ("advertised binding",   'ok = b["value"] == sha256_tag(jcs(info))', 'ok = True'),
 ("advertised scope rule",  'if isinstance(info.get(member), str) and info[member] != payload["action"][member]:', 'if False:'),
 ("payer not_compared label", 'checks["payer"] = "not_compared"', 'checks["payer"] = "compared"'),
 ("requirements not_evaluated label", 'checks["requirements"] = "not_evaluated"', 'checks["requirements"] = "matched"'),
 ("receiptRef = payload hash", '"receiptRef": sha256_tag(payload_bytes),', '"receiptRef": sha256_tag(b"x"),'),
]
def run(text):
    """Return (suite exit code, fuzz detections or None, first failing lines)."""
    d = pathlib.Path(tempfile.mkdtemp(dir=work))
    shutil.copytree(src/"vectors", d/"vectors")
    (d/"action_receipt.py").write_text(text)
    r = subprocess.run([sys.executable, "-B", "action_receipt.py"], cwd=d, capture_output=True, text=True)
    bad = [l.split()[2] if l.startswith("[FAIL]") else l[:100] for l in r.stdout.splitlines()
           if l.startswith("[FAIL]") or l.startswith("SUITE INVALID")]
    found = None
    if FUZZ_N:
        shutil.copytree(src/"conformance", d/"conformance")
        shutil.copy(src/"verify.mjs", d/"verify.mjs")
        f = subprocess.run([sys.executable, "-B", "conformance/fuzz.py", "--seed", "1", "--n", str(FUZZ_N), "--json"],
                           cwd=d, capture_output=True, text=True)
        try:
            summary = json.loads(f.stdout.strip().splitlines()[0])
            found = summary["disagreements"] + summary["property_violations"]
        except (ValueError, IndexError):
            found = -1     # the fuzzer itself broke on this flip
    return r.returncode, found, bad

missed, fuzz_missed = [], []
for label, old, new in flips:
    if code.count(old) != 1:
        print(f"[SETUP ERROR] {label}: source text found {code.count(old)} times"); missed.append(label); continue
    rc, found, bad = run(code.replace(old, new))
    if rc == 0: missed.append(label)
    fz = ""
    if FUZZ_N:
        fz = f" fuzz={'caught(' + str(found) + ')' if found else 'MISSED'}"
        if not found: fuzz_missed.append(label)
    print(f"[{'caught' if rc else 'MISSED'}] {label:28s} rc={rc}{fz} {bad[:2] if not FUZZ_N else ''}")
control_rc, control_found, _ = run(code)
print(f"\n{len(flips) - len(missed)} of {len(flips)} flips caught; control (unpatched) rc={control_rc}")
print("MISSED:", missed)
if FUZZ_N:
    print(f"fuzzer ({FUZZ_N} cases): {len(flips) - len(fuzz_missed)} of {len(flips)} flips detected; "
          f"control found {control_found}")
    print("FUZZ MISSED:", fuzz_missed)
both = [m for m in missed if m in fuzz_missed] if FUZZ_N else missed
sys.exit(0 if not missed and control_rc == 0 and not (FUZZ_N and control_found) else 1)
