#!/usr/bin/env python3
"""
flip_issuer.py — show that each sub-check of BOTH issuers can fail the
exchange suite, and say which exchange catches it.

For each flip: copy the repository to a scratch directory, weaken ONE sub-check
of `issuer.py` or `issuer.mjs`, and drive the patched issuer through
`conformance/run_exchanges.py` (opaque ids, follow-ups, protocol cases). A flip
of `issuer.py`'s self-check or signing is driven through `issuer.py`'s own
suite instead, whose named checks cover them. Each flip is:

  caught   at least one NAMED exchange (or named suite check) disagrees, and at
           least one disagreement is a real answer, not `issuer_fault`
  MISSED   nothing disagrees
  BROKEN   the adapter crashed, answered the wrong ids, or every disagreement
           is an `issuer_fault` / missing answer: the patch broke the program
           rather than changed what it decides, so it shows nothing

Ends with a control run of both unpatched issuers, which must agree on every
case. Exit 0 iff every flip applied to exactly one place and was caught, and the
control passed.

    python3 conformance/flip_issuer.py
    python3 conformance/flip_issuer.py --only node --jobs 4
    python3 conformance/flip_issuer.py --fuzz 3000      # also measure the fuzzer
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PY = sys.executable
NODE = shutil.which("node") or "node"
ADAPTER = {"issuer.py": [PY, "-B", "issuer.py", "--batch"], "issuer.mjs": [NODE, "issuer.mjs"]}

P, J = "issuer.py", "issuer.mjs"
X, S = "exchanges", "suite"

FLIPS = [
    # ---- issuer.py --------------------------------------------------------------
    (P, "1 success is exactly true", 'if resp.get("success") is not True:', 'if not resp.get("success"):', X),
    (P, "2 identifier required", 'if not (transaction or reference):', 'if False:', X),
    (P, "2 transaction present (well-formed)",
     'transaction = resp.get("transaction") if _present(resp.get("transaction")) else ""',
     'transaction = resp.get("transaction") if isinstance(resp.get("transaction"), str) else ""', X),
    (P, "2 reference present (well-formed)", '            return value if _present(value) else ""',
     '            return value if isinstance(value, str) else ""', X),
    (P, "2 reference: the row's scheme", 'if scheme == row_scheme and network.startswith(namespace + ":"):',
     'if network.startswith(namespace + ":"):', X),
    (P, "2 reference: the row's network", 'if scheme == row_scheme and network.startswith(namespace + ":"):',
     'if scheme == row_scheme:', X),
    (P, "2 reference: namespace exact, not a prefix", 'network.startswith(namespace + ":")',
     'network.startswith(namespace)', X),
    (P, "2 reference: from the table only, never out of band",
     '    reference = settlement_reference(pay.get("accepted"), resp)\n',
     '    reference = settlement_reference(pay.get("accepted"), resp) or (x.get("settlementReference") or "")\n', X),
    (P, "3 requirements in the value domain", '    digest = A.requirements_digest(accepted)\n',
     '    digest = A.requirements_digest(accepted) or (A.sha256_tag(b"x") if isinstance(accepted, dict) else None)\n', X),
    (P, "4 accepts must be an array", '    if not isinstance(accepts, list):\n        return None, X_OFFERED',
     '    if not isinstance(accepts, list):\n        accepts = [accepted]', X),
    (P, "4 every member compared (asset)",
     "    if not any(A.in_domain(entry) and A.jcs(entry) == accepted_bytes for entry in accepts):",
     "    _strip = lambda o: A.jcs({k: v for k, v in o.items() if k != 'asset'}) if isinstance(o, dict) else b''\n"
     "    if not any(A.in_domain(entry) and _strip(entry) == _strip(accepted) for entry in accepts):", X),
    (P, "4 accepted must be offered", 'if not any(A.in_domain(entry) and A.jcs(entry) == accepted_bytes for entry in accepts):',
     'if not accepts:', X),
    (P, "4 offered compared by JCS bytes, not by network+payTo",
     'A.in_domain(entry) and A.jcs(entry) == accepted_bytes for entry in accepts',
     'isinstance(entry, dict) and entry.get("payTo") == accepted.get("payTo") for entry in accepts', X),
    (P, "5 network grammar", 'if not (isinstance(network, str) and A.RE_NETWORK.fullmatch(network)):',
     'if not isinstance(network, str):', X),
    (P, "5 network namespace bound 3..32", 'if not (isinstance(network, str) and A.RE_NETWORK.fullmatch(network)):',
     'if not (isinstance(network, str) and re.fullmatch(r"[-a-z0-9]{2,40}:[-_a-zA-Z0-9]{1,32}", network)):', X),
    (P, "5 network conflict", 'and resp_net != network:', 'and False:', X),
    (P, "6 resource required", '    if not _present(resource):\n        return None, X_RESOURCE',
     '    if resource is None:\n        return None, X_RESOURCE', X),
    (P, "6 resource well-formed", '    if not _present(resource):\n        return None, X_RESOURCE',
     '    if not (isinstance(resource, str) and resource):\n        return None, X_RESOURCE', X),
    (P, "7 authorization.from on any network",
     '        payer = _obj(_obj(pay.get("payload")).get("authorization")).get("from")',
     '        payer = _obj(_obj(pay.get("payload")).get("authorization")).get("from") if network.startswith("eip155:") else None', X),
    (P, "7 response payer wins over authorization", '    payer = resp.get("payer")\n    if not _present(payer):',
     '    payer = _obj(_obj(pay.get("payload")).get("authorization")).get("from") or resp.get("payer")\n    if not _present(payer):', X),
    (P, "7 payer falls back to authorization.from",
     '        payer = _obj(_obj(pay.get("payload")).get("authorization")).get("from")\n', '        payer = None\n', X),
    (P, "7 no payer is \"\", not a refusal", '            payer = ""', '            return None, X_GRAMMAR', X),
    (P, "7 payTo required", '    if not _present(pay_to):\n        return None, X_GRAMMAR',
     '    if pay_to is None:\n        return None, X_GRAMMAR', X),
    (P, "7 lowercase payer", 'payer, pay_to, transaction = _lower_evm(payer), ', 'payer, pay_to, transaction = payer, ', X),
    (P, "7 lowercase payTo", '_lower_evm(pay_to), _lower_evm(transaction)', 'pay_to, _lower_evm(transaction)', X),
    (P, "7 lowercase transaction", ', _lower_evm(pay_to), _lower_evm(transaction)\n', ', _lower_evm(pay_to), transaction\n', X),
    (P, "7 eip155 payTo grammar", 'if not A.RE_EVM_ADDRESS.fullmatch(pay_to):', 'if False:', X),
    (P, "7 eip155 payer grammar", 'if payer and not A.RE_EVM_ADDRESS.fullmatch(payer):', 'if False:', X),
    (P, "7 eip155 transaction grammar", 'if transaction and not A.RE_EVM_TX.fullmatch(transaction):', 'if False:', X),
    (P, "7 charged amount grammar", 'if charged and not RE_CHARGED_AMOUNT.fullmatch(charged):', 'if False:', X),
    (P, "7 charged amount at most 78 digits", 'RE_CHARGED_AMOUNT = re.compile(r"0|[1-9][0-9]{0,77}")',
     'RE_CHARGED_AMOUNT = re.compile(r"0|[1-9][0-9]{0,78}")', X),
    (P, "7 charged amount no leading zero", 'RE_CHARGED_AMOUNT = re.compile(r"0|[1-9][0-9]{0,77}")',
     'RE_CHARGED_AMOUNT = re.compile(r"[0-9]{1,78}")', X),
    (P, "7 charged amount verbatim, never normalized", '    charged = charged_amount(resp)\n',
     '    charged = charged_amount(resp)\n    charged = str(int(charged)) if charged.isdigit() else charged\n', X),
    (P, "4.3 extra.chargedAmount before amount",
     '    if _present(value):\n        return value\n    amount = _obj(resp).get("amount")\n'
     '    return amount if _present(amount) else ""',
     '    amount = _obj(resp).get("amount")\n    if _present(amount):\n        return amount\n'
     '    return value if _present(value) else ""', X),
    (P, "4.3 extra.chargedAmount is read", '    if _present(value):\n        return value\n', '', X),
    (P, "4.3 extra.chargedAmount present (4.6)", '    if _present(value):\n        return value\n',
     '    if value is not None:\n        return value\n', X),
    (P, "4.3 amount present (4.6)", 'return amount if _present(amount) else ""',
     'return amount if amount is not None else ""', X),
    (P, "4.3 charged amount never computed from accepted.amount", '    charged = charged_amount(resp)\n',
     '    charged = charged_amount(resp) or str(accepted.get("amount") or "")\n', X),
    (P, "6.3 chargedAmount copied", '"chargedAmount": charged,', '"chargedAmount": "",', X),
    (P, "8 agent present", '    if not _present(agent):\n        return None, X_STATEMENT',
     '    if not isinstance(agent, str):\n        return None, X_STATEMENT', X),
    (P, "8 agent well-formed", '    if not _present(agent):\n        return None, X_STATEMENT',
     '    if not (isinstance(agent, str) and agent):\n        return None, X_STATEMENT', X),
    (P, "8 actionType present", '    if not _present(action_type):\n        return None, X_STATEMENT',
     '    if not isinstance(action_type, str):\n        return None, X_STATEMENT', X),
    (P, "8 scope a string", 'if not (isinstance(scope, str) and A.in_domain(scope)):', 'if not A.in_domain(scope):', X),
    (P, "8 scope well-formed", 'if not (isinstance(scope, str) and A.in_domain(scope)):', 'if not isinstance(scope, str):', X),
    (P, "8 outcome listed", 'if not (isinstance(outcome, str) and outcome in A.OUTCOMES):', 'if not isinstance(outcome, str):', X),
    (P, "8 outcome partial accepted", 'if not (isinstance(outcome, str) and outcome in A.OUTCOMES):',
     'if not (isinstance(outcome, str) and outcome in {"delivered", "failed"}):', X),
    (P, "8 status listed", 'if not (isinstance(status, str) and status in A.SETTLEMENT_STATUSES):',
     'if not isinstance(status, str):', X),
    (P, "8 status capturePending/reversed accepted", 'if not (isinstance(status, str) and status in A.SETTLEMENT_STATUSES):',
     'if not (isinstance(status, str) and status in {"settled", "refunded"}):', X),
    (P, "8 receiptId upper bound 64", 'A.RE_RECEIPT_ID.fullmatch(receipt_id)', 're.fullmatch(r"[A-Za-z0-9_-]{22,}", receipt_id)', X),
    (P, "8 receiptId lower bound 22", 'A.RE_RECEIPT_ID.fullmatch(receipt_id)', 're.fullmatch(r"[A-Za-z0-9_-]{1,64}", receipt_id)', X),
    (P, "8 receiptId alphabet", 'A.RE_RECEIPT_ID.fullmatch(receipt_id)', 're.fullmatch(r"[A-Za-z0-9_+=-]{22,64}", receipt_id)', X),
    (P, "8 issuedAt integer value", '    if isinstance(v, float) and v.is_integer():\n        return int(v)',
     '    if isinstance(v, float):\n        return int(v)', X),
    (P, "8 issuedAt not a boolean", '    if isinstance(v, bool):\n        return None', '    if False:\n        return None', X),
    (P, "8 issuedAt not a string", '    if isinstance(v, int):\n        return v',
     '    if isinstance(v, int):\n        return v\n    if isinstance(v, str) and v.isdigit():\n        return int(v)', X),
    (P, "8 issuedAt lower bound 0", 'if not 0 <= issued_at <= A.SAFE_INT_MAX:', 'if not issued_at <= A.SAFE_INT_MAX:', X),
    (P, "8 issuedAt upper bound 2^53-1", 'if not 0 <= issued_at <= A.SAFE_INT_MAX:', 'if not 0 <= issued_at:', X),
    (P, "8 supersedes grammar", '(supersedes == "" or A.RE_DIGEST.fullmatch(supersedes))', 'True', X),
    (P, "8 supersedes given must be a string", '    if supersedes is _NOT_GIVEN:\n        supersedes = ""',
     '    if not isinstance(supersedes, str):\n        supersedes = ""', X),
    (P, "8 reversal given must be a string",
     '    if reversal is not _NOT_GIVEN and not isinstance(reversal, str):\n        return None, X_STATEMENT',
     '    if reversal is not _NOT_GIVEN and not isinstance(reversal, str):\n        reversal = _NOT_GIVEN', X),
    (P, "8 further bindings given must be an array",
     '    if further is not _NOT_GIVEN and not isinstance(further, list):\n        return None, X_STATEMENT',
     '    if further is not _NOT_GIVEN and not isinstance(further, list):\n        return None, X_BINDINGS', X),
    (P, "8 null means not given", 'return _NOT_GIVEN if v is None else v', 'return _NOT_GIVEN if key not in st else v', X),
    (P, "9 advertised actionType compared", 'for member in ("actionType", "scope"):', 'for member in ("scope",):', X),
    (P, "9 advertised scope compared", 'for member in ("actionType", "scope"):', 'for member in ("actionType",):', X),
    (P, "9 advertised null member is a member", 'if member in info and not',
     'if info.get(member) is not None and not', X),
    (P, "9 advertised is any info object", 'advertised = isinstance(info, dict)',
     'advertised = isinstance(info, dict) and info.get("willIssueReceipt") is True', X),
    (P, "10 supplied action-receipt: types refused",
     'b["type"].startswith(A.BT_NAMESPACE):\n            return None, X_BINDINGS',
     'b["type"].startswith("action-receipt:x"):\n            return None, X_BINDINGS', X),
    (P, "10 advertisement committed", '    if advertised:\n        if not A.in_domain(info):',
     '    if False:\n        if not A.in_domain(info):', X),
    (P, "10 advertised info hashable", '        if not A.in_domain(info):\n            return None, X_BINDINGS', '        pass', X),
    (P, "10 reversal binding added", '    if reversal is not _NOT_GIVEN:\n        bindings.append',
     '    if False:\n        bindings.append', X),
    (P, "10 reversal lowercased on eip155", '_lower_evm(reversal) if evm else reversal', 'reversal', X),
    (P, "10 at most 16 bindings", 'if len(bindings) > A.MAX_BINDINGS:', 'if len(bindings) > 17:', X),
    (P, "10 exactly two members", 'set(b.keys()) == A.BINDING_KEYS', 'A.BINDING_KEYS <= set(b.keys())', X),
    (P, "10 type grammar", 'if not (A.RE_BINDING_TYPE.fullmatch(t) and A.RE_BINDING_VALUE.fullmatch(v)):',
     'if not A.RE_BINDING_VALUE.fullmatch(v):', X),
    (P, "10 value grammar", 'if not (A.RE_BINDING_TYPE.fullmatch(t) and A.RE_BINDING_VALUE.fullmatch(v)):',
     'if not A.RE_BINDING_TYPE.fullmatch(t):', X),
    (P, "10 reversal value form on eip155", 'if evm and not A.RE_EVM_TX.fullmatch(v):', 'if False:', X),
    (P, "10 sorted by type", '                      key=lambda b: b["type"])', '                      key=lambda b: 0)', X),
    (P, "10 unique types", 'if bindings[i - 1]["type"] == bindings[i]["type"]:', 'if False:', X),
    (P, "batch: any nesting depth", 'if text.count("[") + text.count("{") > MAX_LINE_DEPTH:', 'if False:', X),
    (P, "batch: huge integers", 'return int(s) if len(s) <= 4000 else float(s)', 'return int(s)', X),
    (P, "batch: deep line must be JSON", '            if not _json_valid(text):\n                raise ValueError("not JSON")',
     '            pass', X),
    (P, "batch: NaN is not JSON", 'parse_constant=_no_constants, ', '', X),
    (P, "6.3 self-check runs 5.3", '    return A.validate_payload(payload) is None', '    return True', S),
    (P, "6.3 self-check checks the value domain", '    if not A.in_domain(payload):\n        return False',
     '    if not A.in_domain(payload) and False:\n        return False', S),
    (P, "6.3 sign: low s", 'if _low_s and s > n // 2:', 'if False:', S),
    (P, "6.3 sign: kid listed for resourceUrl", 'if not (isinstance(kids, list) and kid in kids):', 'if False:', S),
    (P, "6.3 sign: EC curve matches alg", 'and private_key.curve.name == ALG_KEY[alg]):', '):', S),
    (P, "6.3 sign: Ed25519 key for EdDSA", '    elif not isinstance(private_key, ed25519.Ed25519PrivateKey):',
     '    elif False:', S),
    (P, "6.3 sign: compact bound", 'if len(compact) > A.MAX_COMPACT:', 'if False:', S),
    (P, "6.3 sign: header is JCS", 'header = A.jcs({"alg": alg, "kid": kid, "typ": A.TYP})',
     'header = json.dumps({"alg": alg, "kid": kid, "typ": A.TYP}).encode()', S),
    # ---- issuer.mjs ---------------------------------------------------------------
    (J, "1 success is exactly true", "if (get(sr, 'success') !== true)", "if (!get(sr, 'success'))", X),
    (J, "2 identifier required", "if (transaction === '' && settlementRef === '') return", "if (false) return", X),
    (J, "4.6 present means well-formed", "const present = (v) => typeof v === 'string' && v.length > 0 && wf(v);",
     "const present = (v) => typeof v === 'string' && v.length > 0;", X),
    (J, "2 reference: the row's scheme", "if (scheme !== 'batch-settlement' || typeof network", "if (typeof network", X),
    (J, "2 reference: the row's network", " || !network.startsWith('solana:')) return '';", ") return '';", X),
    (J, "2 reference: namespace exact, not a prefix", "!network.startsWith('solana:')", "!network.startsWith('solana')", X),
    (J, "2 reference present (well-formed)", "return present(v) ? v : '';", "return typeof v === 'string' ? v : '';", X),
    (J, "3 requirements in the value domain", "if (!isObj(accepted) || !inDomain(accepted)) return",
     "if (!isObj(accepted)) return", X),
    (J, "4 accepts must be an array", "const accepts = get(pr, 'accepts');",
     "const accepts = Array.isArray(get(pr, 'accepts')) ? get(pr, 'accepts') : [accepted];", X),
    (J, "4 accepted must be offered", "if (!accepts.some((e) => inDomain(e) && jcs(e) === acceptedJcs)) return",
     "if (false) return", X),
    (J, "5 network namespace bound 3..32", "const RE_NETWORK = /^[-a-z0-9]{3,32}:", "const RE_NETWORK = /^[-a-z0-9]{3,8}:", X),
    (J, "5 network reference grammar", "const RE_NETWORK = /^[-a-z0-9]{3,32}:[-_a-zA-Z0-9]{1,32}$/;",
     "const RE_NETWORK = /^[-a-z0-9]{3,32}:[-_.a-zA-Z0-9]{1,32}$/;", X),
    (J, "4 every member compared (maxTimeoutSeconds)",
     "  if (!accepts.some((e) => inDomain(e) && jcs(e) === acceptedJcs)) return refuse('requirements_not_offered');",
     "  const _s = (o) => (isObj(o) ? jcs(Object.fromEntries(Object.entries(o).filter(([k]) => k !== 'maxTimeoutSeconds'))) : '');\n"
     "  if (!accepts.some((e) => inDomain(e) && _s(e) === _s(accepted))) return refuse('requirements_not_offered');", X),
    (J, "5 network conflict", "&& srNet !== network) return", "&& false) return", X),
    (J, "6 resource required", "if (!present(url)) return refuse('resource_unavailable');",
     "if (url === undefined) return refuse('resource_unavailable');", X),
    (J, "7 response payer wins", "  let payer = get(sr, 'payer');\n  if (!present(payer)) {",
     "  let payer = get(get(get(pp, 'payload'), 'authorization'), 'from') || get(sr, 'payer');\n  if (!present(payer)) {", X),
    (J, "7 payer falls back to authorization.from",
     "    payer = get(get(get(pp, 'payload'), 'authorization'), 'from');", "    payer = undefined;", X),
    (J, "7 no payer is \"\", not a refusal", "if (!present(payer)) payer = '';",
     "if (!present(payer)) return refuse('identifier_out_of_grammar');", X),
    (J, "7 payTo required", "if (!present(payTo)) return refuse('identifier_out_of_grammar');",
     "if (payTo === undefined) return refuse('identifier_out_of_grammar');", X),
    (J, "7 lowercase payer", "    payer = evmLower(payer);\n", "", X),
    (J, "7 lowercase payTo", "    payTo = evmLower(payTo);\n", "", X),
    (J, "7 lowercase transaction", "    transaction = evmLower(transaction);\n", "", X),
    (J, "7 eip155 payer grammar", "if (payer !== '' && !RE_ADDR.test(payer)) return", "if (false) return", X),
    (J, "7 eip155 transaction grammar", "if (transaction !== '' && !RE_TX.test(transaction)) return", "if (false) return", X),
    (J, "7 charged amount grammar",
     "  if (chargedAmount !== '' && !RE_CHARGED.test(chargedAmount)) return refuse('identifier_out_of_grammar');\n",
     "", X),
    (J, "7 charged amount at most 78 digits", "const RE_CHARGED = /^(?:0|[1-9][0-9]{0,77})$/;",
     "const RE_CHARGED = /^(?:0|[1-9][0-9]{0,78})$/;", X),
    (J, "7 charged amount no leading zero", "const RE_CHARGED = /^(?:0|[1-9][0-9]{0,77})$/;",
     "const RE_CHARGED = /^[0-9]{1,78}$/;", X),
    (J, "4.3 extra.chargedAmount before amount",
     "  if (present(fromExtra)) return fromExtra;\n  const amount = get(sr, 'amount');\n"
     "  return present(amount) ? amount : '';",
     "  const amount = get(sr, 'amount');\n  if (present(amount)) return amount;\n"
     "  return present(fromExtra) ? fromExtra : '';", X),
    (J, "4.3 extra.chargedAmount present (4.6)", "if (present(fromExtra)) return fromExtra;",
     "if (fromExtra !== undefined) return fromExtra;", X),
    (J, "4.3 amount present (4.6)", "return present(amount) ? amount : '';", "return amount !== undefined ? amount : '';", X),
    (J, "4.3 charged amount never computed from accepted.amount", "  const chargedAmount = chargedAmountOf(sr);",
     "  const chargedAmount = chargedAmountOf(sr) || String(get(accepted, 'amount') ?? '');", X),
    (J, "6.3 chargedAmount copied", "    chargedAmount,\n    settlementStatus,", "    chargedAmount: '',\n    settlementStatus,", X),
    (J, "8 agent present", "if (!present(agent)) return refuse('invalid_statement');",
     "if (typeof agent !== 'string') return refuse('invalid_statement');", X),
    (J, "8 actionType present", "if (!present(actionType)) return refuse('invalid_statement');",
     "if (typeof actionType !== 'string') return refuse('invalid_statement');", X),
    (J, "8 scope well-formed", "if (typeof scope !== 'string' || !wf(scope)) return",
     "if (typeof scope !== 'string') return", X),
    (J, "8 outcome listed", "if (typeof outcome !== 'string' || !OUTCOMES.includes(outcome)) return",
     "if (typeof outcome !== 'string') return", X),
    (J, "8 status listed", "if (typeof settlementStatus !== 'string' || !STATUSES.includes(settlementStatus)) return",
     "if (typeof settlementStatus !== 'string') return", X),
    (J, "8 receiptId grammar 22..64", "const RE_RID = /^[A-Za-z0-9_-]{22,64}$/;", "const RE_RID = /^[A-Za-z0-9_-]{22,65}$/;", X),
    (J, "8 issuedAt safe integer", "if (typeof issuedAt !== 'number' || !Number.isSafeInteger(issuedAt)) return",
     "if (typeof issuedAt !== 'number') return", X),
    (J, "8 issuedAt lower bound 0", "  if (issuedAt < 0) return refuse('invalid_statement');\n", "", X),
    (J, "8 supersedes grammar", "!(supersedes === '' || RE_REF.test(supersedes))) return", "false) return", X),
    (J, "8 supersedes given must be a string", "const supersedes = supersedesIn === NOT_GIVEN ? '' : supersedesIn;",
     "const supersedes = typeof supersedesIn === 'string' ? supersedesIn : '';", X),
    (J, "8 reversal given must be a string", "const reversal = given(st, 'reversalTransaction');",
     "const reversal = typeof get(st, 'reversalTransaction') === 'string' ? get(st, 'reversalTransaction') : NOT_GIVEN;", X),
    (J, "8 further bindings given must be an array", "if (further !== NOT_GIVEN && !Array.isArray(further)) return refuse('invalid_statement');",
     "if (further !== NOT_GIVEN && !Array.isArray(further)) return refuse('invalid_bindings');", X),
    (J, "9 advertised actionType compared", "if (own(info, 'actionType') && !(typeof info.actionType === 'string' && info.actionType === actionType)) {",
     "if (false) {", X),
    (J, "9 advertised scope compared", "if (own(info, 'scope') && !(typeof info.scope === 'string' && info.scope === scope)) {",
     "if (false) {", X),
    (J, "9 advertised null member is a member", "if (own(info, 'scope') && !(",
     "if (own(info, 'scope') && info.scope !== null && !(", X),
    (J, "10 supplied action-receipt: types refused", "e.type.startsWith(RESERVED)) return refuse('invalid_bindings');",
     "e.type === ADVERTISED + 'x') return refuse('invalid_bindings');", X),
    (J, "10 supplied reversal binding refused", "e.type.startsWith(RESERVED)) return refuse('invalid_bindings');",
     "e.type.startsWith(RESERVED) && e.type !== REVERSAL) return refuse('invalid_bindings');", X),
    (J, "10 advertisement committed", "    entries.push({ type: ADVERTISED, value: digest(info) });\n", "", X),
    (J, "10 advertised info hashable", "    if (!inDomain(info)) return refuse('invalid_bindings');\n", "", X),
    (J, "10 reversal binding added", "if (reversal !== NOT_GIVEN) entries.push(", "if (false) entries.push(", X),
    (J, "10 reversal lowercased on eip155", "value: evm ? evmLower(reversal) : reversal", "value: reversal", X),
    (J, "10 at most 16 bindings", "if (entries.length > 16) return refuse('invalid_bindings');", "", X),
    (J, "10 exactly two members", "if (keys.length !== 2 || !own(e, 'type')", "if (!own(e, 'type')", X),
    (J, "10 value grammar", "if (typeof e.value !== 'string' || !RE_BVALUE.test(e.value)) return",
     "if (typeof e.value !== 'string') return", X),
    (J, "10 type grammar", "if (typeof e.type !== 'string' || !RE_BTYPE.test(e.type)) return",
     "if (typeof e.type !== 'string') return", X),
    (J, "10 reversal value form on eip155", "if (evm && !RE_TX.test(e.value)) return refuse('invalid_bindings');", "", X),
    (J, "10 sorted by type", "bindings.sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));", "", X),
    (J, "10 unique types", "if (bindings[i - 1].type === bindings[i].type) return refuse('invalid_bindings');", "", X),
    (J, "adapter: a non-JSON line is invalid_input", "    return { id, ...refuse('invalid_input') };\n  }\n  if (!isObj(msg))",
     "    return { id, ...refuse('settlement_not_successful') };\n  }\n  if (!isObj(msg))", X),
    (J, "adapter: a leading byte-order mark is not stripped", "{ fatal: true, ignoreBOM: true }",
     "{ fatal: true, ignoreBOM: false }", X),
]

# A flip that changes one place of the source in a way no conforming input
# can observe is not listed, and so not counted: the self-check CALL SITE in
# either issuer (with every step intact the self-check never fails; the
# self-check FUNCTION is flipped above and caught by issuer.py's self-check
# suite), the advertised-info value-form check of step 10 (the issuer adds that
# binding itself, always in form), and the "unknown action-receipt: type"
# branch of step 10 (supplied action-receipt: types are refused earlier).


def copy_repo(scratch_root: pathlib.Path) -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp(prefix="flip-", dir=scratch_root)) / "t"
    shutil.copytree(ROOT, d, ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv", "out"))
    return d


def drive(d: pathlib.Path, target: str, via: str, seed: int) -> dict:
    """Run the patched copy. Returns {caught: [names], faults_only: bool, broken: str|None}."""
    names, real, broken = set(), False, None
    if via == X:
        r = subprocess.run([PY, "-B", "conformance/run_exchanges.py", "--seed", str(seed), "--json", "--quiet",
                            "--"] + ADAPTER[target], cwd=d, capture_output=True, text=True)
        s = None
        for line in r.stdout.splitlines():
            if line.startswith("{"):
                try:
                    s = json.loads(line)
                except ValueError:
                    pass
        if s is None:
            return {"caught": [], "faults_only": False, "broken": f"runner produced no summary: {r.stderr[-300:]}"}
        broken = s["broken"]
        for name, answer in s["answers"].items():
            names.add(name)
            real = real or answer not in ("issuer_fault", None)
    else:
        r = subprocess.run([PY, "-B", "issuer.py"], cwd=d, capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if line.startswith("[FAIL]"):
                name = line.split()[1].rstrip(":")
                names.add(name)
                real = real or "issuer_fault" not in line
        if r.returncode != 0 and not names:
            broken = f"suite exited {r.returncode} with no named failure: {(r.stderr or r.stdout)[-300:]}"
    return {"caught": sorted(names), "faults_only": bool(names) and not real, "broken": broken}


def run_one(flip, scratch_root, seed, fuzz_n):
    target, label, old, new, via = flip
    src = (ROOT / target).read_text()
    if src.count(old) != 1:
        return flip, {"setup": f"source text found {src.count(old)} times"}, None
    d = copy_repo(scratch_root)
    (d / target).write_text(src.replace(old, new))
    res = drive(d, target, via, seed)
    fz = None
    if fuzz_n:
        f = subprocess.run([PY, "-B", "conformance/fuzz_issuer.py", "--seed", "1", "--n", str(fuzz_n), "--json"],
                           cwd=d, capture_output=True, text=True)
        try:
            summary = json.loads([l for l in f.stdout.splitlines() if l.startswith("{")][-1])
            fz = summary["disagreements"] + summary["property_violations"]
        except (ValueError, IndexError, KeyError):
            fz = -1
    shutil.rmtree(d.parent, ignore_errors=True)
    return flip, res, fz


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="flip each issuer sub-check; the suite must go red")
    ap.add_argument("--only", choices=["python", "node"], default=None)
    ap.add_argument("--jobs", type=int, default=max(2, min(8, (os.cpu_count() or 2))))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--fuzz", type=int, default=0, metavar="N")
    ap.add_argument("--scratch", default=None, help="directory for the patched copies")
    a = ap.parse_args(argv)
    flips = [f for f in FLIPS if a.only is None or f[0] == (P if a.only == "python" else J)]
    scratch_root = pathlib.Path(a.scratch or tempfile.mkdtemp(prefix="action-receipt-issuer-flips-"))
    scratch_root.mkdir(parents=True, exist_ok=True)
    results = {}
    with cf.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        for flip, res, fz in ex.map(lambda f: run_one(f, scratch_root, a.seed, a.fuzz), flips):
            results[(flip[0], flip[1])] = (res, fz)
    caught = missed = broken = setup = 0
    fuzz_missed = []
    for target, label, _, _, via in flips:
        res, fz = results[(target, label)]
        if "setup" in res:
            status, detail = "SETUP", res["setup"]
            setup += 1
        elif res["broken"] or res["faults_only"]:
            status, detail = "BROKEN", res["broken"] or "only issuer_fault answers: " + ", ".join(res["caught"][:3])
            broken += 1
        elif res["caught"]:
            status, detail = "caught", "by " + ", ".join(res["caught"][:4]) + (
                f" (+{len(res['caught']) - 4})" if len(res["caught"]) > 4 else "")
            caught += 1
        else:
            status, detail = "MISSED", ""
            missed += 1
        fzs = ""
        if a.fuzz:
            fzs = f"  fuzz={'caught(' + str(fz) + ')' if fz else 'MISSED'}"
            if not fz:
                fuzz_missed.append(f"{target}: {label}")
        print(f"[{status:6s}] {target:10s} {label:52s} {detail}{fzs}")
    # control: both unpatched issuers, the same way
    ctl_ok = True
    for target in ([P, J] if a.only is None else [P if a.only == "python" else J]):
        d = copy_repo(scratch_root)
        res = drive(d, target, X, a.seed)
        ok = not res["caught"] and not res["broken"]
        if target == P:
            r = subprocess.run([PY, "-B", "issuer.py"], cwd=d, capture_output=True, text=True)
            ok = ok and r.returncode == 0
        shutil.rmtree(d.parent, ignore_errors=True)
        print(f"[{'ok' if ok else 'FAIL':6s}] control    {target} unpatched: "
              + ("agrees on every case" if ok else f"disagrees: {res}"))
        ctl_ok = ctl_ok and ok
    n = len(flips)
    if n == 0:
        print("NO FLIPS: the flip list is empty, so nothing was shown to be able to fail")
    print(f"{caught} of {n} issuer flips caught by a named exchange or suite check "
          f"({sum(1 for f in flips if f[0] == P)} issuer.py, {sum(1 for f in flips if f[0] == J)} issuer.mjs); "
          f"{missed} missed, {broken} broken, {setup} setup errors; control {'ok' if ctl_ok else 'FAILED'}")
    if a.fuzz:
        print(f"issuer fuzzer ({a.fuzz} exchanges): {n - len(fuzz_missed)} of {n} flips detected")
        print("FUZZ MISSED:", fuzz_missed)
    print(json.dumps({"flips": n, "caught": caught, "missed": missed, "broken": broken, "setup": setup,
                      "control_ok": ctl_ok}))
    shutil.rmtree(scratch_root, ignore_errors=True) if a.scratch is None else None
    return 0 if n > 0 and caught == n and ctl_ok else 1


if __name__ == "__main__":
    sys.exit(main())
