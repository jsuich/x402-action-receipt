// Second issuer for the `action-receipt` extension, spec section 6 (draft 0.4).
// Written from the spec text; brought to 0.4 from the 0.4 text of section 6.
// Adapter protocol: JSON lines in on stdin, JSON lines out on stdout
// (CONFORMANCE.md, issuer adapter protocol). Besides a payload or a section 6.2
// refusal, an answer may be `invalid_input` (the line is not a JSON object),
// `issuer_fault` (this program failed) or `self_check_failed` (the payload it
// built failed its own 5.2/5.3 check, section 6.3). None of the three is a
// refusal, and a conforming issuer gives none of them for a JSON exchange.
import { createHash } from 'node:crypto';

// ---------- helpers ----------
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
// own-property read that never walks the prototype chain and never throws
const get = (o, k) => (isObj(o) && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined);
const own = (o, k) => isObj(o) && Object.prototype.hasOwnProperty.call(o, k);
const wf = (s) => s.isWellFormed();
// "present" (section 4.6): a non-empty string of well-formed Unicode.
const present = (v) => typeof v === 'string' && v.length > 0 && wf(v);
// an optional statement member is not given when missing or null (section 6.1)
const NOT_GIVEN = Symbol('not given');
const given = (o, k) => { const v = get(o, k); return v === undefined || v === null ? NOT_GIVEN : v; };

// Value domain of section 4.6. Outermost object/array is level 1; max 8.
function inDomain(v, level = 1) {
  if (v === null || v === true || v === false) return true;
  if (typeof v === 'number') return Number.isSafeInteger(v);
  if (typeof v === 'string') return wf(v);
  if (typeof v !== 'object') return false;
  if (level > 8) return false;
  if (Array.isArray(v)) {
    for (const e of v) if (!inDomain(e, level + 1)) return false;
    return true;
  }
  for (const k of Object.keys(v)) {
    if (!wf(k)) return false;
    if (!inDomain(v[k], level + 1)) return false;
  }
  return true;
}

// RFC 8785 over the value domain (caller guarantees inDomain).
function jcs(v) {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') return v === 0 ? '0' : String(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)); // UTF-16 code units
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}
const digest = (v) => 'sha256:' + createHash('sha256').update(Buffer.from(jcs(v), 'utf8')).digest('hex');

// network identifier (section 4.6): CAIP-2 shape, namespace 3..32
const RE_NETWORK = /^[-a-z0-9]{3,32}:[-_a-zA-Z0-9]{1,32}$/;
const RE_ADDR = /^0x[0-9a-f]{40}$/;
const RE_TX = /^0x[0-9a-f]{64}$/;
const RE_RID = /^[A-Za-z0-9_-]{22,64}$/;
const RE_REF = /^sha256:[0-9a-f]{64}$/;
const RE_BTYPE = /^[a-z][a-z0-9+.-]{0,63}:[\x21-\x7e]{1,191}$/;
const RE_BVALUE = /^[\x21-\x7e]{1,1024}$/;
const OUTCOMES = ['delivered', 'partial', 'failed'];
const STATUSES = ['settled', 'capturePending', 'reversed', 'refunded'];
const MAX_SAFE = 2 ** 53 - 1;
const ADVERTISED = 'action-receipt:advertised-info';
const REVERSAL = 'action-receipt:reversal-transaction';
const RESERVED = 'action-receipt:';

// ASCII A-Z -> a-z, the rule a verifier applies in section 5.8. Nothing else.
const evmLower = (s) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

const refuse = (reason) => ({ issued: false, reason });

// The settlement reference of the exchange (section 4.3): found by the table from
// accepted.scheme and accepted.network and nothing else. The one row:
// `batch-settlement` on `solana:*` -> SettlementResponse.extra.commitmentId.
// The `*` matches whatever follows `solana:`; step 5 judges its grammar.
function referenceOf(accepted, sr) {
  const scheme = get(accepted, 'scheme');
  const network = get(accepted, 'network');
  if (scheme !== 'batch-settlement' || typeof network !== 'string' || !network.startsWith('solana:')) return '';
  const v = get(get(sr, 'extra'), 'commitmentId');
  return present(v) ? v : '';
}

function issue(ex) {
  const pr = get(ex, 'paymentRequired');
  const pp = get(ex, 'paymentPayload');
  const sr = get(ex, 'settlementResponse');
  const st = get(ex, 'statement');

  // 1
  if (get(sr, 'success') !== true) return refuse('settlement_not_successful');

  // 2
  const srTx = get(sr, 'transaction');
  let transaction = present(srTx) ? srTx : '';
  const settlementRef = referenceOf(get(pp, 'accepted'), sr);
  if (transaction === '' && settlementRef === '') return refuse('no_settlement_identifier');

  // 3
  const accepted = get(pp, 'accepted');
  if (!isObj(accepted) || !inDomain(accepted)) return refuse('requirements_not_hashable');

  // 4: accepted equals an offered entry by JCS bytes
  const accepts = get(pr, 'accepts');
  if (!Array.isArray(accepts)) return refuse('requirements_not_offered');
  const acceptedJcs = jcs(accepted);
  if (!accepts.some((e) => inDomain(e) && jcs(e) === acceptedJcs)) return refuse('requirements_not_offered');

  // 5
  const network = get(accepted, 'network');
  if (typeof network !== 'string' || !RE_NETWORK.test(network)) return refuse('network_unusable');
  const srNet = get(sr, 'network');
  if (typeof srNet === 'string' && RE_NETWORK.test(srNet) && srNet !== network) return refuse('network_unusable');

  // 6
  const url = get(get(pr, 'resource'), 'url');
  if (!present(url)) return refuse('resource_unavailable');

  // 7
  let payer = get(sr, 'payer');
  if (!present(payer)) {
    payer = get(get(get(pp, 'payload'), 'authorization'), 'from');
    if (!present(payer)) payer = '';
  }
  let payTo = get(accepted, 'payTo');
  if (!present(payTo)) return refuse('identifier_out_of_grammar');
  const evm = network.startsWith('eip155:');
  if (evm) {
    payer = evmLower(payer);
    payTo = evmLower(payTo);
    transaction = evmLower(transaction);
    if (!RE_ADDR.test(payTo)) return refuse('identifier_out_of_grammar');
    if (payer !== '' && !RE_ADDR.test(payer)) return refuse('identifier_out_of_grammar');
    if (transaction !== '' && !RE_TX.test(transaction)) return refuse('identifier_out_of_grammar');
  }

  // 8
  const action = get(st, 'action');
  const agent = get(action, 'agent');
  const actionType = get(action, 'actionType');
  const scope = get(action, 'scope');
  const outcome = get(action, 'outcome');
  const settlementStatus = get(st, 'settlementStatus');
  const receiptId = get(st, 'receiptId');
  const issuedAt = get(st, 'issuedAt');
  const supersedesIn = given(st, 'supersedes');
  const reversal = given(st, 'reversalTransaction');
  const further = given(st, 'bindings');
  if (!present(agent)) return refuse('invalid_statement');
  if (!present(actionType)) return refuse('invalid_statement');
  if (typeof scope !== 'string' || !wf(scope)) return refuse('invalid_statement');
  if (typeof outcome !== 'string' || !OUTCOMES.includes(outcome)) return refuse('invalid_statement');
  if (typeof settlementStatus !== 'string' || !STATUSES.includes(settlementStatus)) return refuse('invalid_statement');
  if (typeof receiptId !== 'string' || !RE_RID.test(receiptId)) return refuse('invalid_statement');
  if (typeof issuedAt !== 'number' || !Number.isSafeInteger(issuedAt)) return refuse('invalid_statement');
  if (issuedAt < 0) return refuse('invalid_statement');
  const supersedes = supersedesIn === NOT_GIVEN ? '' : supersedesIn;
  if (typeof supersedes !== 'string' || !(supersedes === '' || RE_REF.test(supersedes))) return refuse('invalid_statement');
  if (reversal !== NOT_GIVEN && typeof reversal !== 'string') return refuse('invalid_statement');
  if (further !== NOT_GIVEN && !Array.isArray(further)) return refuse('invalid_statement');

  // 9: the advertised info is read strictly; a member whose value is null is a member
  const ext = get(get(pr, 'extensions'), 'action-receipt');
  const info = get(ext, 'info');
  const advertised = isObj(ext) && isObj(info);
  if (advertised) {
    if (own(info, 'actionType') && !(typeof info.actionType === 'string' && info.actionType === actionType)) {
      return refuse('advertisement_conflict');
    }
    if (own(info, 'scope') && !(typeof info.scope === 'string' && info.scope === scope)) {
      return refuse('advertisement_conflict');
    }
  }

  // 10
  const entries = further === NOT_GIVEN ? [] : further.slice();
  for (const e of entries) {
    if (isObj(e) && typeof get(e, 'type') === 'string' && e.type.startsWith(RESERVED)) return refuse('invalid_bindings');
  }
  if (advertised) {
    if (!inDomain(info)) return refuse('invalid_bindings');
    entries.push({ type: ADVERTISED, value: digest(info) });
  }
  if (reversal !== NOT_GIVEN) entries.push({ type: REVERSAL, value: evm ? evmLower(reversal) : reversal });
  if (entries.length > 16) return refuse('invalid_bindings');
  const bindings = [];
  for (const e of entries) {
    if (!isObj(e)) return refuse('invalid_bindings');
    const keys = Object.keys(e);
    if (keys.length !== 2 || !own(e, 'type') || !own(e, 'value')) return refuse('invalid_bindings');
    if (typeof e.type !== 'string' || !RE_BTYPE.test(e.type)) return refuse('invalid_bindings');
    if (typeof e.value !== 'string' || !RE_BVALUE.test(e.value)) return refuse('invalid_bindings');
    if (e.type.startsWith(RESERVED)) {
      if (e.type === ADVERTISED) {
        if (!RE_REF.test(e.value)) return refuse('invalid_bindings');
      } else if (e.type === REVERSAL) {
        if (evm && !RE_TX.test(e.value)) return refuse('invalid_bindings');
      } else {
        return refuse('invalid_bindings');
      }
    }
    bindings.push({ type: e.type, value: e.value });
  }
  bindings.sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));
  for (let i = 1; i < bindings.length; i++) {
    if (bindings[i - 1].type === bindings[i].type) return refuse('invalid_bindings');
  }

  // 6.3
  const payload = {
    version: 1,
    receiptId,
    issuedAt: issuedAt === 0 ? 0 : issuedAt,
    network,
    resourceUrl: url,
    payer,
    payTo,
    transaction,
    settlementRef,
    settlementStatus,
    requirementsDigest: digest(accepted),
    supersedes,
    action: { agent, actionType, scope, outcome },
    bindings,
  };
  if (!selfCheck(payload)) return refuse('self_check_failed');
  return { issued: true, payload };
}

// ---------- section 6.3 self-check: sections 5.2 and 5.3 on the built payload ----------
const TOP = ['version', 'receiptId', 'issuedAt', 'network', 'resourceUrl', 'payer', 'payTo', 'transaction',
  'settlementRef', 'settlementStatus', 'requirementsDigest', 'supersedes', 'action', 'bindings'];
const ACTION = ['agent', 'actionType', 'scope', 'outcome'];
const STRINGS = ['receiptId', 'network', 'resourceUrl', 'payer', 'payTo', 'transaction', 'settlementRef',
  'settlementStatus', 'requirementsDigest', 'supersedes'];
const sameSet = (keys, want) => keys.length === want.length && want.every((k) => keys.includes(k));

function selfCheck(p) {
  // 5.2: in the value domain, and the JCS bytes parse back to the same bytes
  if (!inDomain(p)) return false;
  const text = jcs(p);
  let back;
  try { back = JSON.parse(text); } catch { return false; }
  if (!inDomain(back) || jcs(back) !== text) return false;
  // 5.3
  if (!isObj(p) || !Number.isSafeInteger(p.version) || p.version !== 1) return false;
  if (!sameSet(Object.keys(p), TOP)) return false;
  if (!isObj(p.action) || !sameSet(Object.keys(p.action), ACTION)) return false;
  if (!STRINGS.every((k) => typeof p[k] === 'string')) return false;
  if (!ACTION.every((k) => typeof p.action[k] === 'string')) return false;
  if (!Number.isSafeInteger(p.issuedAt) || p.issuedAt < 0 || p.issuedAt > MAX_SAFE) return false;
  if (!RE_RID.test(p.receiptId) || !RE_NETWORK.test(p.network)) return false;
  if (!p.resourceUrl || !p.payTo || !p.action.agent || !p.action.actionType) return false;
  if (!p.transaction && !p.settlementRef) return false;
  const evm = p.network.startsWith('eip155:');
  if (evm) {
    if (!RE_ADDR.test(p.payTo)) return false;
    if (p.payer && !RE_ADDR.test(p.payer)) return false;
    if (p.transaction && !RE_TX.test(p.transaction)) return false;
  }
  if (!RE_REF.test(p.requirementsDigest)) return false;
  if (p.supersedes && !RE_REF.test(p.supersedes)) return false;
  if (!OUTCOMES.includes(p.action.outcome) || !STATUSES.includes(p.settlementStatus)) return false;
  if (!Array.isArray(p.bindings) || p.bindings.length > 16) return false;
  let prev = null;
  for (const b of p.bindings) {
    if (!isObj(b) || !sameSet(Object.keys(b), ['type', 'value'])) return false;
    if (typeof b.type !== 'string' || typeof b.value !== 'string') return false;
    if (!RE_BTYPE.test(b.type) || !RE_BVALUE.test(b.value)) return false;
    if (b.type.startsWith(RESERVED)) {
      if (b.type === ADVERTISED) { if (!RE_REF.test(b.value)) return false; }
      else if (b.type === REVERSAL) { if (evm && !RE_TX.test(b.value)) return false; }
      else return false;
    }
    if (prev !== null && !(prev < b.type)) return false;
    prev = b.type;
  }
  return true;
}

// ---------- adapter ----------
// ignoreBOM keeps a leading U+FEFF in the text, so JSON.parse rejects the line
// (a byte-order mark is not JSON whitespace, RFC 8259 section 8.1): invalid_input.
const fatalUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function handle(bytes) {
  let line;
  try { line = fatalUtf8.decode(bytes); } catch { return { id: null, ...refuse('invalid_input') }; }
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    let id = null;
    const m = /"id"\s*:\s*("(?:[^"\\]|\\.)*")/.exec(line);
    if (m) { try { id = JSON.parse(m[1]); } catch { /* keep null */ } }
    return { id, ...refuse('invalid_input') };
  }
  if (!isObj(msg)) return { id: null, ...refuse('invalid_input') };
  const rawId = get(msg, 'id');
  const id = rawId === undefined ? null : rawId;
  let res;
  try {
    res = issue(get(msg, 'exchange'));
  } catch {
    res = refuse('issuer_fault');
  }
  return { id, ...res };
}

const chunks = [];
process.stdin.on('data', (c) => chunks.push(c));
process.stdin.on('end', () => {
  const all = Buffer.concat(chunks);
  const out = [];
  let start = 0;
  while (start <= all.length) {
    let end = all.indexOf(0x0a, start);
    if (end === -1) end = all.length;
    const bytes = all.subarray(start, end);
    start = end + 1;
    if (/^[ \t\r]*$/.test(bytes.toString('latin1'))) continue;
    let s;
    try { s = JSON.stringify(handle(bytes)); } catch { s = JSON.stringify({ id: null, issued: false, reason: 'issuer_fault' }); }
    out.push(s);
  }
  process.stdout.write(out.length ? out.join('\n') + '\n' : '');
});
