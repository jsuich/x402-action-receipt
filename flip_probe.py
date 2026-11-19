#!/usr/bin/env python3
"""
flip_probe.py — show that each check in the reference verifier can fail.

A green conformance run says nothing unless the suite could have gone red. This
script copies the verifier and the vectors to a scratch directory, disables or
weakens ONE check at a time, and requires the suite to exit non-zero each time.
It ends with a control run of the unpatched verifier, which must exit 0.

    python3 flip_probe.py <repo dir> <scratch dir>

Exit 0 iff every flip was caught, every patch applied to exactly one place in the
source, and the control passed. The scratch directory must exist; nothing in it
is deleted.
"""
import sys, shutil, subprocess, pathlib, tempfile
src = pathlib.Path(sys.argv[1]); work = pathlib.Path(sys.argv[2])
code = (src/"action_receipt.py").read_text()
# (label, exact source text, replacement) — each disables or weakens ONE check
flips = [
 ("typ check",            'if header.get("typ") != TYP:', 'if False:'),
 ("alg allow-list",       'if header.get("alg") not in SUPPORTED_ALGS:', 'if False:'),
 ("header closed set",    'if set(header.keys()) != HEADER_KEYS or not isinstance(header.get("kid"), str):', 'if not isinstance(header.get("kid"), str):'),
 ("canonical bytes",      '    if jcs(value) != data:\n        return None', '    pass'),
 ("value domain",         '    if not in_domain(value):\n        return None', '    pass'),
 ("closed top-level set", 'if not isinstance(payload, dict) or set(payload.keys()) != TOP_KEYS:', 'if not isinstance(payload, dict) or not TOP_KEYS <= set(payload.keys()):'),
 ("receiptId grammar",    'if not RE_RECEIPT_ID.fullmatch(payload["receiptId"]):', 'if False:'),
 ("EVM address case",     'if not (RE_EVM_ADDRESS.fullmatch(payload["payer"])', 'if not (True'),
 ("EVM tx grammar",       'if payload["transaction"] and not RE_EVM_TX.fullmatch(payload["transaction"]):', 'if False:'),
 ("digest grammar",       'if not RE_DIGEST.fullmatch(payload["requirementsDigest"]):', 'if False:'),
 ("binding order",        'if previous is not None and not previous < t:', 'if False:'),
 ("binding count",        'if len(bindings) > MAX_BINDINGS:', 'if False:'),
 ("signer authorization", 'if kid not in service_kids and kid not in payto_kids:', 'if False:'),
 ("key unresolved code",  'return REJECT, R_KEY_UNRESOLVED, {}', 'return REJECT, R_SIG_INVALID, {}'),
 ("low-s",                'if s > CURVE_ORDER[ALG_CURVE[alg]] // 2:', 'if False:'),
 ("curve bound to alg",   'if pub.curve.name != ALG_CURVE[alg]:', 'if False:'),
 ("settlement success",   'if ctx.success is not True or not (ctx.transaction or ctx.settlement_ref):', 'if False:'),
 ("tx binding",           '        if payload["transaction"] != resp_tx:', '        if False:'),
 ("uncorroborated tx",    '    elif payload["transaction"]:', '    elif False:'),
 ("ref binding",          '        if payload["settlementRef"] != ctx.settlement_ref:', '        if False:'),
 ("network binding",      '        if network != ctx.network:', '        if False:'),
 ("payer binding",        'if payload["payer"] != _norm_unsigned(network, ctx.payer):', 'if False:'),
 ("response case-fold",   '        return value.lower()', '        return value'),
 ("requirements digest",  'if payload["requirementsDigest"] != digest:', 'if False:'),
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
    d = pathlib.Path(tempfile.mkdtemp(dir=work))
    shutil.copytree(src/"vectors", d/"vectors")
    (d/"action_receipt.py").write_text(text)
    return subprocess.run([sys.executable, "-B", "action_receipt.py"], cwd=d, capture_output=True, text=True)
missed = []
for label, old, new in flips:
    if code.count(old) != 1:
        print(f"[SETUP ERROR] {label}: source text found {code.count(old)} times"); missed.append(label); continue
    r = run(code.replace(old, new))
    bad = [l.split()[2] if l.startswith("[FAIL]") else l[:100] for l in r.stdout.splitlines() if l.startswith("[FAIL]") or l.startswith("SUITE INVALID")]
    if r.returncode == 0: missed.append(label)
    print(f"[{'caught' if r.returncode else 'MISSED'}] {label:26s} rc={r.returncode} {bad[:2]}")
control = run(code).returncode
print(f"\n{len(flips) - len(missed)} of {len(flips)} flips caught; control (unpatched) rc={control}")
print("MISSED:", missed)
sys.exit(0 if not missed and control == 0 else 1)
