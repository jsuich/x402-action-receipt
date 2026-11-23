#!/usr/bin/env python3
"""
flip_probe.py — show that each check in BOTH verifiers can fail.

A green conformance run says nothing unless the vectors could have gone red.
This script copies the verifiers, the adapters and the vectors to a scratch
directory, disables or weakens ONE check at a time (in action_receipt.py or in
verify.mjs), drives the flipped verifier's adapter over the manifest with
conformance/run_vectors.py, and requires at least one VECTOR to disagree. It
prints the vectors that caught each flip. It ends with a control run of each
unpatched verifier, which must agree with every entry.

    python3 flip_probe.py <repo dir> <scratch dir>
    python3 flip_probe.py <repo dir> <scratch dir> --fuzz 1500

A flip counts as caught only when run_vectors names a disagreeing vector. A
flip that makes the adapter crash, or a patch that does not apply to exactly
one place in the source, is reported as BROKEN and fails the run: it shows
nothing about the vectors (reviewer E F12).

With --fuzz N the same flips are also put in front of the differential fuzzer
(N cases, flipped verifier against the other, unflipped one). That measures the
FUZZER; fuzz misses are reported and do not fail the run.

The last line of output is a JSON summary: {"flips", "caught", "broken",
"missed", "control_ok"}. Exit 0 iff every flip was caught and both controls
passed. The scratch directory must exist; nothing in it is deleted.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

src = pathlib.Path(sys.argv[1]).resolve()
work = pathlib.Path(sys.argv[2])
FUZZ_N = int(sys.argv[sys.argv.index('--fuzz') + 1]) if '--fuzz' in sys.argv else 0
NODE = shutil.which("node") or "node"

# (label, exact source text, replacement) — each disables or weakens ONE check.
# Labels that end in a reviewer id name the defect the flip re-creates.
PY_FLIPS = [
    ("base64url one spelling", 'if b64url(data) != s:', 'if False:'),
    ("size bound off by one", 'len(compact) > MAX_COMPACT', 'len(compact) > MAX_COMPACT + 1'),
    ("header canonical form (B-1, D-08)", '    header = parse_canonical(header_bytes)\n',
     '    try:\n        header = json.loads(header_bytes.decode("utf-8"))\n'
     '    except (ValueError, RecursionError):\n        header = NOT_CANONICAL\n'),
    ("header encoding sniffing", '    header = parse_canonical(header_bytes)\n',
     '    try:\n        header = json.loads(header_bytes)\n'
     '    except (ValueError, RecursionError):\n        header = NOT_CANONICAL\n'),
    ("typ check", 'if header.get("typ") != TYP:', 'if False:'),
    ("alg allow-list", 'if not isinstance(alg, str) or alg not in SUPPORTED_ALGS:', 'if False:'),
    ("alg of any type is a reject (B-2)", 'if not isinstance(alg, str) or alg not in SUPPORTED_ALGS:',
     'if alg not in SUPPORTED_ALGS:'),
    ("header closed set", 'if set(header.keys()) != HEADER_KEYS or not isinstance(header.get("kid"), str):',
     'if not isinstance(header.get("kid"), str):'),
    ("kid is a string", 'if set(header.keys()) != HEADER_KEYS or not isinstance(header.get("kid"), str):',
     'if set(header.keys()) != HEADER_KEYS:'),
    ("null payload sentinel", '    if payload is NOT_CANONICAL:\n        return REJECT, R_NONCANONICAL',
     '    if payload is NOT_CANONICAL or payload is None:\n        return REJECT, R_NONCANONICAL'),
    ("canonical bytes", '    if jcs(value) != data:\n        return NOT_CANONICAL', '    pass'),
    ("value domain", '    if not in_domain(value):\n        return NOT_CANONICAL', '    pass'),
    ("integer-valued float", '        return v.is_integer() and -SAFE_INT_MAX <= v <= SAFE_INT_MAX', '        return False'),
    ("version before member set (A-M8)",
     '    if payload["version"] != PROFILE_VERSION:\n        return R_UNSUPPORTED_VERSION\n'
     '    # 3. the closed member set, types and grammar\n    if set(payload.keys()) != TOP_KEYS:\n        return R_MALFORMED\n',
     '    if set(payload.keys()) != TOP_KEYS:\n        return R_MALFORMED\n'
     '    if payload["version"] != PROFILE_VERSION:\n        return R_UNSUPPORTED_VERSION\n'),
    ("version is an integer", 'or "version" not in payload or not _is_int(payload["version"]):',
     'or "version" not in payload:'),
    ("closed top-level set", 'if set(payload.keys()) != TOP_KEYS:', 'if not TOP_KEYS <= set(payload.keys()):'),
    ("closed action object (V46)", 'if not isinstance(action, dict) or set(action.keys()) != ACTION_KEYS:',
     'if not isinstance(action, dict) or not ACTION_KEYS <= set(action.keys()):'),
    ("action members are strings (V50)", 'if not all(isinstance(action[f], str) for f in ACTION_KEYS):', 'if False:'),
    ("receiptId grammar", 'if not RE_RECEIPT_ID.fullmatch(payload["receiptId"]):', 'if False:'),
    ("receiptId upper bound (PAIR2)", 'RE_RECEIPT_ID = re.compile(r"[A-Za-z0-9_-]{22,64}")',
     'RE_RECEIPT_ID = re.compile(r"[A-Za-z0-9_-]{22,65}")'),
    ("network grammar", 'if not RE_NETWORK.fullmatch(network):', 'if False:'),
    ("network namespace lower bound (PAIR1)", 'RE_NETWORK = re.compile(r"[-a-z0-9]{3,32}:',
     'RE_NETWORK = re.compile(r"[-a-z0-9]{2,32}:'),
    ("network namespace upper bound", 'RE_NETWORK = re.compile(r"[-a-z0-9]{3,32}:',
     'RE_NETWORK = re.compile(r"[-a-z0-9]{3,33}:'),
    ("network reference upper bound", ':[-_a-zA-Z0-9]{1,32}")\nRE_CAIP2', ':[-_a-zA-Z0-9]{1,33}")\nRE_CAIP2'),
    ("non-empty agent (V10)", 'and action["agent"] and action["actionType"]):', 'and action["actionType"]):'),
    ("non-empty resourceUrl", 'if not (payload["resourceUrl"] and payload["payTo"]', 'if not (payload["payTo"]'),
    ("payTo grammar (V09)", 'if not RE_EVM_ADDRESS.fullmatch(payload["payTo"]):', 'if False:'),
    ("payer may be empty", 'if payload["payer"] and not RE_EVM_ADDRESS.fullmatch(payload["payer"]):',
     'if not RE_EVM_ADDRESS.fullmatch(payload["payer"]):'),
    ("EVM payer grammar", 'if payload["payer"] and not RE_EVM_ADDRESS.fullmatch(payload["payer"]):', 'if False:'),
    ("EVM tx grammar", 'if payload["transaction"] and not RE_EVM_TX.fullmatch(payload["transaction"]):', 'if False:'),
    ("eip155 prefix incl. colon (V41)", 'network.startswith("eip155:")', 'network.startswith("eip155")'),
    ("not both identifiers empty", '    if not (payload["transaction"] or payload["settlementRef"]):\n        return R_MALFORMED',
     '    if False:\n        return R_MALFORMED'),
    ("digest grammar", 'if not RE_DIGEST.fullmatch(payload["requirementsDigest"]):', 'if False:'),
    ("supersedes grammar", 'if payload["supersedes"] and not RE_DIGEST.fullmatch(payload["supersedes"]):', 'if False:'),
    ("outcome before status (V11)",
     '    if action["outcome"] not in OUTCOMES:\n        return R_INVALID_OUTCOME\n'
     '    if payload["settlementStatus"] not in SETTLEMENT_STATUSES:\n        return R_INVALID_STATUS\n',
     '    if payload["settlementStatus"] not in SETTLEMENT_STATUSES:\n        return R_INVALID_STATUS\n'
     '    if action["outcome"] not in OUTCOMES:\n        return R_INVALID_OUTCOME\n'),
    ("bindings is an array (V52)", '    if not isinstance(bindings, list):\n        return R_MALFORMED',
     '    if not isinstance(bindings, list):\n        return R_BINDING'),
    ("binding order", 'if previous is not None and not previous < t:', 'if False:'),
    ("binding count (V15)", 'if len(bindings) > MAX_BINDINGS:', 'if len(bindings) >= MAX_BINDINGS:'),
    ("binding prefix bound", 'RE_BINDING_TYPE = re.compile(r"[a-z][a-z0-9+.-]{0,63}:',
     'RE_BINDING_TYPE = re.compile(r"[a-z][a-z0-9+.-]{0,64}:'),
    ("binding name bound", ':[\\x21-\\x7e]{1,191}")', ':[\\x21-\\x7e]{1,192}")'),
    ("binding value bound", 'RE_BINDING_VALUE = re.compile(r"[\\x21-\\x7e]{1,1024}")',
     'RE_BINDING_VALUE = re.compile(r"[\\x21-\\x7e]{1,1025}")'),
    ("closed binding namespace (D-07)", '            else:\n                return R_BINDING\n        if previous',
     '            else:\n                pass\n        if previous'),
    ("advertised-info value form", '                if not RE_DIGEST.fullmatch(v):\n                    return R_BINDING',
     '                pass'),
    ("reversal value form on eip155", 'if _is_evm(network) and not RE_EVM_TX.fullmatch(v):', 'if False:'),
    ("resource paid for", '        if payload["resourceUrl"] != paid_url:', '        if False:'),
    ("paid URL '' is a URL", '    if paid_url is not None:\n        if payload["resourceUrl"]',
     '    if paid_url:\n        if payload["resourceUrl"]'),
    ("signer authorization", '    if answer != AUTHORIZED:\n        return REJECT, R_SIGNER_UNAUTH, {}', '    pass'),
    ("no answer is key_unresolved (A-B2)", '    if answer == NO_ANSWER:\n        return REJECT, R_KEY_UNRESOLVED, {}',
     '    if answer == NO_ANSWER:\n        return REJECT, R_SIGNER_UNAUTH, {}'),
    ("unavailable marker is exactly true", 'if key_registry.get("__unavailable__:" + resource_url) is True:',
     'if key_registry.get("__unavailable__:" + resource_url):'),
    ("anchor is an array of strings (M-2)",
     '    if isinstance(v, list) and all(isinstance(k, str) for k in v):\n        return v',
     '    if v:\n        return v'),
    ("payTo anchor", '    if kid in _anchor_kids(key_registry, "__payTo__:" + pay_to + "|" + resource_url):\n        return AUTHORIZED',
     '    pass'),
    ("unusable key code", '    pub = _load_key(key_registry.get(kid))\n    if pub is None:\n        return REJECT, R_KEY_UNRESOLVED, {}',
     '    pub = _load_key(key_registry.get(kid))\n    if pub is None:\n        return REJECT, R_SIG_INVALID, {}'),
    ("PEM armour, nothing around it (B-4)", '    m = _PEM_RE.fullmatch(pem)', '    m = _PEM_RE.search(pem)'),
    ("usable key kind (B-6)", '    if not _usable_kind(pub):\n        return None', '    pass'),
    ("EC key type (V27)", '            if not isinstance(pub, ec.EllipticCurvePublicKey):\n                return False\n', ''),
    ("Ed25519 key type (V54)", '            if not isinstance(pub, ed25519.Ed25519PublicKey):\n                return False\n', ''),
    ("curve bound to alg", 'if pub.curve.name != ALG_CURVE[alg]:', 'if False:'),
    ("ECDSA 64 bytes (V53)", '            if len(raw_sig) != 64:\n                return False\n', ''),
    ("low-s", 'if s > CURVE_ORDER[ALG_CURVE[alg]] // 2:', 'if False:'),
    ("settlement success", 'if ctx.success is not True or not (_has(ctx.transaction) or _has(ctx.settlement_ref)):',
     'if not (_has(ctx.transaction) or _has(ctx.settlement_ref)):'),
    ("settlement identifier half (V17)", 'if ctx.success is not True or not (_has(ctx.transaction) or _has(ctx.settlement_ref)):',
     'if ctx.success is not True:'),
    ("present = non-empty string", '    return isinstance(value, str) and value != "" and in_domain(value)', '    return value is not None'),
    ("present = well-formed Unicode", '    return isinstance(value, str) and value != "" and in_domain(value)',
     '    return isinstance(value, str) and value != ""'),
    ("tx binding", '        if payload["transaction"] != _norm_unsigned(network, ctx.transaction):', '        if False:'),
    ("uncorroborated tx", '    elif payload["transaction"]:', '    elif False:'),
    ("ref binding", '        if payload["settlementRef"] != ctx.settlement_ref:', '        if False:'),
    ("uncorroborated ref", '    elif payload["settlementRef"]:', '    elif False:'),
    ("nothing else is normalized (V61b)", '        if payload["settlementRef"] != ctx.settlement_ref:',
     '        if payload["settlementRef"] != _norm_unsigned(network, ctx.settlement_ref):'),
    ("network binding", '        if network != ctx.network:', '        if False:'),
    ("response network must be an identifier", 'if isinstance(ctx.network, str) and RE_NETWORK.fullmatch(ctx.network):',
     'if isinstance(ctx.network, str):'),
    ("payer binding", 'if payload["payer"] != _norm_unsigned(network, ctx.payer):', 'if False:'),
    ("response case-fold", '        return re.sub(r"[A-Z]", lambda m: m.group(0).lower(), value)   # ASCII only', '        return value'),
    ("requirements digest", 'if payload["requirementsDigest"] != digest:', 'if False:'),
    ("requirements network", '        if ctx.accepted.get("network") != network:', '        if False:'),
    ("requirements payTo", 'if _norm_unsigned(network, ctx.accepted.get("payTo")) != payload["payTo"]:', 'if False:'),
    ("future-dated", '    if age < -60:', '    if False:'),
    ("future-dated bound", '    if age < -60:', '    if age < -61:'),
    ("session max age", '        if age > max_age:', '        if False:'),
    ("session max age bound", '        if age > max_age:', '        if age >= max_age:'),
    ("default max age 3600 (J01)", 'DEFAULT_MAX_AGE = 3600 ', 'DEFAULT_MAX_AGE = 36000 '),
    ("archival mode", '    if mode == "session":', '    if True:'),
    ("configuration: mode (B-3)", '    if not (isinstance(mode, str) and mode in ("session", "archival")):\n        return None',
     '    pass'),
    ("configuration: clock (B-5)", '    now = _config_int(ctx.now)\n    if now is None:\n        return None',
     '    now = ctx.now'),
    ("configuration: maximum age (B-5)", '        if max_age is None or max_age < 0:\n            return None', '        pass'),
    ("configuration: paid URL (m-4)", '    if paid is not None and not isinstance(paid, str):\n        return None', '    pass'),
    ("advertised binding digest", 'ok = b["value"] == sha256_tag(jcs(info))', 'ok = True'),
    ("advertised scope/actionType rule", 'if member in info and info[member] != payload["action"][member]:', 'if False:'),
    ("advertised actionType half (PAIR3)", 'for member in ("scope", "actionType"):', 'for member in ("scope",):'),
    ("advertised info in the value domain", 'info_held = isinstance(info, dict) and in_domain(info)',
     'info_held = isinstance(info, dict)'),
    ("checks.advertisement absent", '    advertisement = "absent" if info_held else "not_evaluated"',
     '    advertisement = "not_evaluated"'),
    # the reviewer's M05b: `absent` only when the receipt has no bindings at all
    ("checks.advertisement absent beside other bindings", '    checks["advertisement"] = advertisement\n',
     '    if advertisement == "absent" and payload["bindings"]:\n        advertisement = "not_evaluated"\n'
     '    checks["advertisement"] = advertisement\n'),
    ("network reference: no dot", 'RE_NETWORK = re.compile(r"[-a-z0-9]{3,32}:[-_a-zA-Z0-9]{1,32}")',
     'RE_NETWORK = re.compile(r"[-a-z0-9]{3,32}:[-_.a-zA-Z0-9]{1,32}")'),
    ("network namespace: no dot", 'RE_NETWORK = re.compile(r"[-a-z0-9]{3,32}:[-_a-zA-Z0-9]{1,32}")',
     'RE_NETWORK = re.compile(r"[-.a-z0-9]{3,32}:[-_a-zA-Z0-9]{1,32}")'),
    ("network reference lower bound 1", 'RE_NETWORK = re.compile(r"[-a-z0-9]{3,32}:[-_a-zA-Z0-9]{1,32}")',
     'RE_NETWORK = re.compile(r"[-a-z0-9]{3,32}:[-_a-zA-Z0-9]{0,32}")'),
    # the reviewer's M12 and M12b: the clock's range is symmetric (spec §5)
    ("configuration: clock may be negative", '    now = _config_int(ctx.now)\n    if now is None:',
     '    now = _config_int(ctx.now)\n    if now is None or now < 0:'),
    ("configuration: maximum age 0 is valid", '        if max_age is None or max_age < 0:',
     '        if max_age is None or max_age <= 0:'),
    ("binding value lower bound 1", r'RE_BINDING_VALUE = re.compile(r"[\x21-\x7e]{1,1024}")',
     r'RE_BINDING_VALUE = re.compile(r"[\x21-\x7e]{0,1024}")'),
    ("binding value starts at 0x21", r'RE_BINDING_VALUE = re.compile(r"[\x21-\x7e]{1,1024}")',
     r'RE_BINDING_VALUE = re.compile(r"[\x20-\x7e]{1,1024}")'),
    ("binding value ends at 0x7e", r'RE_BINDING_VALUE = re.compile(r"[\x21-\x7e]{1,1024}")',
     r'RE_BINDING_VALUE = re.compile(r"[\x21-\x7f]{1,1024}")'),
    ("payer not_compared label", 'checks["payer"] = "not_compared"', 'checks["payer"] = "compared"'),
    ("requirements not_evaluated label", 'checks["requirements"] = "not_evaluated"', 'checks["requirements"] = "matched"'),
    ("receiptRef = payload hash", '"receiptRef": sha256_tag(payload_bytes),', '"receiptRef": sha256_tag(b"x"),'),
    # chargedAmount (spec §4.3, §4.6, §5.8)
    ("chargedAmount grammar",
     'if payload["chargedAmount"] and not RE_CHARGED_AMOUNT.fullmatch(payload["chargedAmount"]):', 'if False:'),
    ("chargedAmount at most 78 digits", 'RE_CHARGED_AMOUNT = re.compile(r"0|[1-9][0-9]{0,77}")',
     'RE_CHARGED_AMOUNT = re.compile(r"0|[1-9][0-9]{0,78}")'),
    ("chargedAmount no leading zero", 'RE_CHARGED_AMOUNT = re.compile(r"0|[1-9][0-9]{0,77}")',
     'RE_CHARGED_AMOUNT = re.compile(r"[0-9]{1,78}")'),
    ("chargedAmount is a string",
     '                     "settlementRef", "chargedAmount", "settlementStatus", "requirementsDigest",\n',
     '                     "settlementRef", "settlementStatus", "requirementsDigest",\n'),
    ("charged amount binding", '        if payload["chargedAmount"] != charged:', '        if False:'),
    ("uncorroborated charged amount", '    elif payload["chargedAmount"]:', '    elif False:'),
    ("charged amount not normalized", '        if payload["chargedAmount"] != charged:',
     '        if payload["chargedAmount"].lstrip("0") != charged.lstrip("0"):'),
    # the per-scheme location of the charged amount (spec §4.3 table, §5.8)
    ("exact reads amount", 'CHARGED_AMOUNT_ROWS = {"exact": "amount",', 'CHARGED_AMOUNT_ROWS = {"exact": "extra",'),
    ("upto reads amount", '"upto": "amount", "batch-settlement"', '"upto": "extra", "batch-settlement"'),
    ("upto has a row", '"upto": "amount", "batch-settlement"', '"batch-settlement"'),
    ("batch-settlement reads extra.chargedAmount", '"batch-settlement": "extra"}', '"batch-settlement": "amount"}'),
    ("batch-settlement never falls back to amount",
     '        value = None\n    return value if _has(value) else ""',
     '        value = None\n    if row == "extra" and not _has(value):\n        value = amount\n'
     '    return value if _has(value) else ""'),
    ("a scheme with no row has none", '    else:\n        value = None\n', '    else:\n        value = amount\n'),
    ("scheme compared exactly", 'row = CHARGED_AMOUNT_ROWS.get(accepted["scheme"])',
     'row = CHARGED_AMOUNT_ROWS.get(accepted["scheme"].lower())'),
    ("charged amount present (4.6)", '        value = None\n    return value if _has(value) else ""',
     '        value = None\n    return value if isinstance(value, str) and value else ""'),
    ("not compared without accepted",
     'isinstance(accepted.get("scheme"), str)):\n        return None\n',
     'isinstance(accepted.get("scheme"), str)):\n        accepted = {"scheme": "exact"}\n'),
    ("accepted in the value domain", 'isinstance(accepted, dict) and in_domain(accepted) and isinstance(',
     'isinstance(accepted, dict) and isinstance('),
    ("scheme is a string",
     'if not (isinstance(accepted, dict) and in_domain(accepted) and isinstance(accepted.get("scheme"), str)):',
     'if not (isinstance(accepted, dict) and in_domain(accepted)):'),
    ("checks.chargedAmount not_compared label", 'checks["chargedAmount"] = "not_compared"',
     'checks["chargedAmount"] = "compared"'),
    ("checks.chargedAmount compared label", 'checks["chargedAmount"] = "compared"',
     'checks["chargedAmount"] = "not_compared"'),
    ("checks.chargedAmount in the report", '"chargedAmount", "advertisement", "freshness")',
     '"advertisement", "freshness")'),
]

JS_FLIPS = [
    ("js base64url one spelling", "if (buf.toString('base64url') !== s) return null;", ''),
    ("js size bound", 'compact.length > MAX_COMPACT', 'compact.length > MAX_COMPACT + 1'),
    ("js header canonical form", "  const hp = parseCanonical(dec[0]);\n",
     "  let hp; try { hp = { ok: true, value: JSON.parse(utf8Strict(dec[0])) }; } catch { hp = { ok: false }; }\n"),
    ("js typ check", "if (own(header, 'typ') !== TYP) return reject('invalid_actionreceipt_typ');", ''),
    ("js alg allow-list", "if (!isStr(alg) || !ALGS.includes(alg)) return reject('invalid_actionreceipt_alg');", ''),
    ("js header closed set", "if (!hasExactly(header, ['alg', 'kid', 'typ']) || !isStr(header.kid)) {",
     "if (!isStr(header.kid)) {"),
    ("js canonical bytes", "  if (!jcs(v).equals(buf)) return { ok: false };\n", ''),
    ("js value domain", "  if (!inDomain(v)) return { ok: false };\n", ''),
    ("js version before member set", "  if (p.version !== 1) return reject('invalid_actionreceipt_version');\n  // 3\n  if (!hasExactly(p, PAYLOAD_MEMBERS)) return reject('invalid_payload');\n",
     "  if (!hasExactly(p, PAYLOAD_MEMBERS)) return reject('invalid_payload');\n  if (p.version !== 1) return reject('invalid_actionreceipt_version');\n"),
    ("js closed action object", "if (!isObj(a) || !hasExactly(a, ACTION_MEMBERS)) return reject('invalid_payload');",
     "if (!isObj(a)) return reject('invalid_payload');"),
    ("js receiptId upper bound (PAIR2)", 'receiptId: /^[A-Za-z0-9_-]{22,64}$/', 'receiptId: /^[A-Za-z0-9_-]{22,65}$/'),
    ("js network namespace lower bound (PAIR1)", 'network: /^[-a-z0-9]{3,32}:', 'network: /^[-a-z0-9]{2,32}:'),
    ("js network namespace upper bound", 'network: /^[-a-z0-9]{3,32}:', 'network: /^[-a-z0-9]{3,33}:'),
    ("js payer may be empty", "(!evm || p.payer === '' || RE.evmAddr.test(p.payer))", "(!evm || RE.evmAddr.test(p.payer))"),
    ("js payTo grammar", "(!evm || RE.evmAddr.test(p.payTo)) &&", ''),
    ("js eip155 prefix incl. colon", "const evm = p.network.startsWith('eip155:');\n    const ok =",
     "const evm = p.network.startsWith('eip155');\n    const ok ="),
    ("js non-empty agent", "a.agent !== '' && a.actionType !== ''", "a.actionType !== ''"),
    ("js outcome before status",
     "  if (!OUTCOMES.includes(p.action.outcome)) return reject('invalid_actionreceipt_outcome');\n  if (!STATUSES.includes(p.settlementStatus)) return reject('invalid_actionreceipt_status');\n",
     "  if (!STATUSES.includes(p.settlementStatus)) return reject('invalid_actionreceipt_status');\n  if (!OUTCOMES.includes(p.action.outcome)) return reject('invalid_actionreceipt_outcome');\n"),
    ("js binding count", 'if (bs.length > 16)', 'if (bs.length > 17)'),
    ("js closed binding namespace", "        } else {\n          return reject('invalid_actionreceipt_binding');\n        }\n",
     "        }\n"),
    ("js advertised-info value form", "if (!RE.digest.test(b.value)) return reject('invalid_actionreceipt_binding');", ''),
    ("js resource paid for", "if (p.resourceUrl !== cfg.paid) return reject('invalid_actionreceipt_resource_mismatch');", ''),
    ("js no answer is key_unresolved", "if (answer === 'no_answer') return reject('invalid_actionreceipt_key_unresolved');", ''),
    ("js anchor is an array of strings", 'return Array.isArray(v) && v.every(isStr) ? v : [];',
     "return Array.isArray(v) ? v : (isStr(v) ? [v] : []);"),
    ("js key is SPKI only (B-4)", "export function parsePublicKey(pem) {\n  if (!isStr(pem)) return null;\n",
     "export function parsePublicKey(pem) {\n  if (!isStr(pem)) return null;\n"
     "  try { return createPublicKey(pem); } catch { return null; }\n"),
    ("js usable key kind", '  if (!usableKind(key)) return null;\n', ''),
    # node:crypto refuses a 65-byte ieee-p1363 signature by itself, so dropping
    # the length test alone is an equivalent mutant; the real defect (V53) reads
    # r and s from the two ends of a longer signature
    ("js ECDSA 64 bytes (V53)",
     "      if (curveOk && sig.length === 64) {\n        const s = BigInt('0x' + sig.subarray(32).toString('hex'));",
     "      if (curveOk) {\n        sig = Buffer.concat([sig.subarray(0, 32), sig.subarray(sig.length - 32)]);"
     "\n        const s = BigInt('0x' + sig.subarray(32).toString('hex'));"),
    ("js low-s", 'if (s <= ORDER[alg] / 2n) {', 'if (true) {'),
    ("js curve bound to alg", "&& key.asymmetricKeyDetails?.namedCurve === CURVE[alg];", ';'),
    ("js present = well-formed", "const present = (v) => isStr(v) && v !== '' && v.isWellFormed();",
     "const present = (v) => isStr(v) && v !== '';"),
    ("js settlement identifier half", "if (own(sr, 'success') !== true || !(hasTx || hasRef))", "if (own(sr, 'success') !== true)"),
    ("js nothing else is normalized", 'const refOk = hasRef ? p.settlementRef === srRef', 'const refOk = hasRef ? p.settlementRef === norm(srRef)'),
    ("js uncorroborated ref", ": p.settlementRef === '';", ': true;'),
    ("js response case-fold", 'const norm = (v) => (evm ? asciiLower(v) : v);', 'const norm = (v) => v;'),
    ("js requirements payTo", 'accPayTo !== p.payTo', 'false'),
    ("js future-dated bound", "if (age < -60) return reject", "if (age < -61) return reject"),
    ("js session max age bound", "age > cfg.maxAge) return reject", "age >= cfg.maxAge) return reject"),
    ("js default max age 3600 (J01)", 'const DEFAULT_MAX_AGE = 3600;', 'const DEFAULT_MAX_AGE = 36000;'),
    ("js configuration: mode", "if (mode !== 'session' && mode !== 'archival') return null;", ''),
    ("js configuration: clock", '  if (!Number.isSafeInteger(now)) return null;\n', ''),
    ("js configuration: maximum age", '    if (!Number.isSafeInteger(m) || m < 0) return null;\n', ''),
    ("js configuration: paid URL", '  else if (!isStr(paid)) return null;\n', ''),
    ("js advertised actionType half (PAIR3)", "for (const n of ['scope', 'actionType']) {", "for (const n of ['scope']) {"),
    ("js checks.advertisement absent", "let advertisement = infoHeld ? 'absent' : 'not_evaluated';",
     "let advertisement = 'not_evaluated';"),
    ("js checks.advertisement absent beside other bindings",
     "let advertisement = infoHeld ? 'absent' : 'not_evaluated';",
     "let advertisement = infoHeld && p.bindings.length === 0 ? 'absent' : 'not_evaluated';"),
    ("js network reference: no dot", 'network: /^[-a-z0-9]{3,32}:[-_a-zA-Z0-9]{1,32}$/',
     'network: /^[-a-z0-9]{3,32}:[-_.a-zA-Z0-9]{1,32}$/'),
    ("js network reference lower bound 1", 'network: /^[-a-z0-9]{3,32}:[-_a-zA-Z0-9]{1,32}$/',
     'network: /^[-a-z0-9]{3,32}:[-_a-zA-Z0-9]{0,32}$/'),
    ("js configuration: clock may be negative", '  if (!Number.isSafeInteger(now)) return null;\n',
     '  if (!Number.isSafeInteger(now) || now < 0) return null;\n'),
    ("js configuration: maximum age 0 is valid", '    if (!Number.isSafeInteger(m) || m < 0) return null;\n',
     '    if (!Number.isSafeInteger(m) || m <= 0) return null;\n'),
    ("js binding value lower bound 1", r'bindingValue: /^[\x21-\x7e]{1,1024}$/', r'bindingValue: /^[\x21-\x7e]{0,1024}$/'),
    ("js receiptRef = payload hash", "receiptRef: 'sha256:' + sha256hex(B),", "receiptRef: 'sha256:' + sha256hex(dec[0]),"),
    # chargedAmount (spec 4.3, 4.6, 5.8)
    ("js chargedAmount grammar", "      (p.chargedAmount === '' || RE.chargedAmount.test(p.chargedAmount)) &&\n", ''),
    ("js chargedAmount at most 78 digits", 'chargedAmount: /^(?:0|[1-9][0-9]{0,77})$/',
     'chargedAmount: /^(?:0|[1-9][0-9]{0,78})$/'),
    ("js chargedAmount no leading zero", 'chargedAmount: /^(?:0|[1-9][0-9]{0,77})$/', 'chargedAmount: /^[0-9]{1,78}$/'),
    ("js chargedAmount is a string", 'p.settlementRef, p.chargedAmount, p.settlementStatus',
     'p.settlementRef, p.settlementStatus'),
    ("js charged amount binding", "? p.chargedAmount === srCharged : p.chargedAmount === '';",
     "? true : p.chargedAmount === '';"),
    ("js uncorroborated charged amount", "? p.chargedAmount === srCharged : p.chargedAmount === '';",
     "? p.chargedAmount === srCharged : true;"),
    # the per-scheme location of the charged amount (spec 4.3 table, 5.8)
    ("js exact reads amount", "if (acc.scheme === 'exact' || acc.scheme === 'upto') v",
     "if (acc.scheme === 'upto') v"),
    ("js upto reads amount", "if (acc.scheme === 'exact' || acc.scheme === 'upto') v",
     "if (acc.scheme === 'exact') v"),
    ("js batch-settlement reads extra.chargedAmount",
     "else if (acc.scheme === 'batch-settlement') v = own(own(sr, 'extra'), 'chargedAmount');",
     "else if (acc.scheme === 'batch-settlement') v = own(sr, 'amount');"),
    ("js batch-settlement never falls back to amount", "srCharged = present(v) ? v : '';",
     "srCharged = present(v) ? v : (present(own(sr, 'amount')) ? own(sr, 'amount') : '');"),
    ("js a scheme with no row has none",
     "else if (acc.scheme === 'batch-settlement') v = own(own(sr, 'extra'), 'chargedAmount');",
     "else if (acc.scheme === 'batch-settlement') v = own(own(sr, 'extra'), 'chargedAmount');\n"
     "      else v = own(sr, 'amount');"),
    ("js scheme compared exactly (exact)", "if (acc.scheme === 'exact' ||",
     "if (acc.scheme.toLowerCase() === 'exact' ||"),
    ("js scheme compared exactly (batch)", "else if (acc.scheme === 'batch-settlement')",
     "else if (acc.scheme.toLowerCase() === 'batch-settlement')"),
    ("js charged amount present (4.6)", "srCharged = present(v) ? v : '';",
     "srCharged = isStr(v) && v !== '' ? v : '';"),
    ("js not compared without accepted", "  let srCharged = null;\n",
     "  let srCharged = present(own(sr, 'amount')) ? own(sr, 'amount') : '';\n"),
    ("js accepted in the value domain", "if (isObj(acc) && inDomain(acc) && isStr(own(acc, 'scheme'))) {",
     "if (isObj(acc) && isStr(own(acc, 'scheme'))) {"),
    ("js scheme is a string", "if (isObj(acc) && inDomain(acc) && isStr(own(acc, 'scheme'))) {",
     "if (isObj(acc) && inDomain(acc)) {"),
    ("js checks.chargedAmount not_compared label", "checks.chargedAmount = 'not_compared';",
     "checks.chargedAmount = 'compared';"),
    ("js checks.chargedAmount compared label", "checks.chargedAmount = 'compared';",
     "checks.chargedAmount = 'not_compared';"),
    ("js checks.chargedAmount in the report", "        chargedAmount: checks.chargedAmount,\n", ''),
]


def make_copy() -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp(dir=work))
    for f in ("action_receipt.py", "verify.mjs", "action-receipt.md"):
        shutil.copy(src / f, d / f)
    shutil.copytree(src / "vectors", d / "vectors")
    (d / "conformance").mkdir()
    shutil.copytree(src / "conformance" / "adapters", d / "conformance" / "adapters")
    for f in ("run_vectors.py", "fuzz.py"):
        shutil.copy(src / "conformance" / f, d / "conformance" / f)
    return d


def adapter_cmd(d: pathlib.Path, lang: str):
    if lang == "py":
        return [sys.executable, "-B", str(d / "conformance" / "adapters" / "python_adapter.py")]
    return [NODE, str(d / "conformance" / "adapters" / "node_adapter.mjs")]


def run(lang: str, filename: str, text: str):
    """Return (status, catching vectors, detail, fuzz detections or None)."""
    d = make_copy()
    (d / filename).write_text(text)
    r = subprocess.run([sys.executable, "-B", str(d / "conformance" / "run_vectors.py"), "--quiet", "--"]
                       + adapter_cmd(d, lang), cwd=d, capture_output=True, text=True)
    caught = list(dict.fromkeys(l.split()[1].rstrip(":") for l in r.stdout.splitlines()
                                if l.startswith("DISAGREE ")))
    problems = [l for l in r.stdout.splitlines() if l.startswith("PROBLEM ")]
    status = "caught" if caught and not problems else ("BROKEN" if problems else
                                                       ("MISSED" if r.returncode == 0 else "BROKEN"))
    found = None
    if FUZZ_N:
        f = subprocess.run([sys.executable, "-B", str(d / "conformance" / "fuzz.py"), "--seed", "1",
                            "--n", str(FUZZ_N), "--json"], cwd=d, capture_output=True, text=True)
        try:
            summary = json.loads(f.stdout.strip().splitlines()[0])
            found = summary["disagreements"] + summary["property_violations"]
        except (ValueError, IndexError):
            found = -1     # the fuzzer itself broke on this flip
    return status, caught, (problems[0] if problems else ""), found


def main() -> int:
    results = []
    sources = {"py": (src / "action_receipt.py").read_text(), "js": (src / "verify.mjs").read_text()}
    files = {"py": "action_receipt.py", "js": "verify.mjs"}
    for lang, flips in (("py", PY_FLIPS), ("js", JS_FLIPS)):
        code = sources[lang]
        for label, old, new in flips:
            n = code.count(old)
            if n != 1:
                print(f"[BROKEN] {label}: source text found {n} times in {files[lang]}")
                results.append((label, "BROKEN", [], None))
                continue
            status, caught, detail, found = run(lang, files[lang], code.replace(old, new))
            fz = ""
            if FUZZ_N:
                fz = f" fuzz={'caught(' + str(found) + ')' if found else 'MISSED'}"
            names = ", ".join(caught[:3]) + (f" (+{len(caught) - 3})" if len(caught) > 3 else "")
            print(f"[{status}] {label:44s}{fz} {names or detail}")
            results.append((label, status, caught, found))
    controls = {}
    for lang in ("py", "js"):
        status, caught, detail, found = run(lang, files[lang], sources[lang])
        controls[lang] = status == "MISSED" and not caught and (not FUZZ_N or found == 0)
        print(f"control ({files[lang]} unpatched): {'agrees with every vector' if controls[lang] else 'FAILED ' + detail}")
    n = len(results)
    caught = sum(1 for _, s, _, _ in results if s == "caught")
    broken = [l for l, s, _, _ in results if s == "BROKEN"]
    missed = [l for l, s, _, _ in results if s == "MISSED"]
    print(f"\n{caught} of {n} flips caught by a named vector "
          f"({len(PY_FLIPS)} in action_receipt.py, {len(JS_FLIPS)} in verify.mjs); "
          f"broken {len(broken)}, missed {len(missed)}")
    print("MISSED:", missed)
    print("BROKEN:", broken)
    fuzz_missed = [l for l, _, _, f in results if FUZZ_N and not f]
    if FUZZ_N:
        print(f"fuzzer ({FUZZ_N} cases): {n - len(fuzz_missed)} of {n} flips detected")
        print("FUZZ MISSED:", fuzz_missed)
    # an empty flip list (or one side's) shows nothing can fail: that is a failure
    ok = n > 0 and bool(PY_FLIPS) and bool(JS_FLIPS) and caught == n and all(controls.values())
    if not (PY_FLIPS and JS_FLIPS):
        print("NO FLIPS: a flip list is empty, so nothing was shown to be able to fail")
    print(json.dumps({"flips": n, "caught": caught, "broken": broken, "missed": missed,
                      "control_ok": all(controls.values()),
                      "fuzz_missed": fuzz_missed if FUZZ_N else None}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
