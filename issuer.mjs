// Second issuer for the `action-receipt` extension, spec section 6.
// Written from the spec text alone; later changed in five places where the spec
// settled a reading it had left open (conformance/CYCLES.md, issuer cycle 2).
// Adapter protocol: JSON lines in on stdin, JSON lines out on stdout.
import { createHash } from 'node:crypto';

// ---------- helpers ----------
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
// own-property read that never walks the prototype chain and never throws
const get = (o, k) => (isObj(o) && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined);
const wf = (s) => s.isWellFormed();
// "had": a non-empty string of well-formed Unicode (section 6.1).
const had = (v) => typeof v === 'string' && v.length > 0 && wf(v);
// an optional member that is absent and one that is null are the same (section 6.1)
const opt = (o, k) => { const v = get(o, k); return v === null ? undefined : v; };

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

const RE_CAIP2 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
const RE_ADDR = /^0x[0-9a-f]{40}$/;
const RE_TX = /^0x[0-9a-f]{64}$/;
const RE_RID = /^[A-Za-z0-9_-]{22,64}$/;
const RE_REF = /^sha256:[0-9a-f]{64}$/;
const RE_BTYPE = /^[a-z][a-z0-9+.-]{0,63}:[\x21-\x7e]{1,191}$/;
const RE_BVALUE = /^[\x21-\x7e]{1,1024}$/;
const OUTCOMES = ['delivered', 'partial', 'failed'];
const STATUSES = ['settled', 'capturePending', 'reversed', 'refunded'];

// ASCII A-Z -> a-z, the rule a verifier applies in section 5.8. Nothing else.
const evmLower = (s) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

const refuse = (reason) => ({ issued: false, reason });

function issue(ex) {
  const pr = get(ex, 'paymentRequired');
  const pp = get(ex, 'paymentPayload');
  const sr = get(ex, 'settlementResponse');
  const sref = get(ex, 'settlementReference');
  const st = get(ex, 'statement');

  // 1
  if (get(sr, 'success') !== true) return refuse('settlement_not_successful');

  // 2
  const srTx = get(sr, 'transaction');
  const hasTx = had(srTx);
  const hasRef = had(sref);
  if (!hasTx && !hasRef) return refuse('no_settlement_identifier');

  // 3
  const accepted = get(pp, 'accepted');
  if (!isObj(accepted) || !inDomain(accepted)) return refuse('requirements_not_hashable');

  // 4
  const network = get(accepted, 'network');
  if (typeof network !== 'string' || !RE_CAIP2.test(network)) return refuse('network_unusable');
  const srNet = get(sr, 'network');
  if (typeof srNet === 'string' && RE_CAIP2.test(srNet) && srNet !== network) return refuse('network_unusable');

  // 5
  const url = get(get(pr, 'resource'), 'url');
  if (!had(url) || !wf(url)) return refuse('resource_unavailable');

  // 6
  let payer = get(sr, 'payer');
  if (!had(payer)) payer = get(get(get(pp, 'payload'), 'authorization'), 'from');
  if (!had(payer)) return refuse('payer_unavailable');

  // 7
  let payTo = get(accepted, 'payTo');
  if (!had(payTo)) return refuse('identifier_out_of_grammar');
  let transaction = hasTx ? srTx : '';
  const settlementRef = hasRef ? sref : '';
  const evm = network.startsWith('eip155:');
  if (evm) {
    payer = evmLower(payer);
    payTo = evmLower(payTo);
    transaction = evmLower(transaction);
  }
  if (evm) {
    if (!RE_ADDR.test(payer) || !RE_ADDR.test(payTo)) return refuse('identifier_out_of_grammar');
    if (transaction !== '' && !RE_TX.test(transaction)) return refuse('identifier_out_of_grammar');
  }

  // 8
  if (!isObj(st)) return refuse('invalid_statement');
  const action = get(st, 'action');
  const agent = get(action, 'agent');
  const actionType = get(action, 'actionType');
  const scope = get(action, 'scope');
  const outcome = get(action, 'outcome');
  const settlementStatus = get(st, 'settlementStatus');
  const receiptId = get(st, 'receiptId');
  const issuedAt = get(st, 'issuedAt');
  const supersedesIn = opt(st, 'supersedes');
  if (!had(agent) || !wf(agent)) return refuse('invalid_statement');
  if (!had(actionType) || !wf(actionType)) return refuse('invalid_statement');
  if (typeof scope !== 'string' || !wf(scope)) return refuse('invalid_statement');
  if (typeof outcome !== 'string' || !OUTCOMES.includes(outcome)) return refuse('invalid_statement');
  if (typeof settlementStatus !== 'string' || !STATUSES.includes(settlementStatus)) return refuse('invalid_statement');
  if (typeof receiptId !== 'string' || !RE_RID.test(receiptId)) return refuse('invalid_statement');
  if (typeof issuedAt !== 'number' || !Number.isSafeInteger(issuedAt) || issuedAt < 0) return refuse('invalid_statement');
  if (!(supersedesIn === undefined || supersedesIn === '' || (typeof supersedesIn === 'string' && RE_REF.test(supersedesIn)))) {
    return refuse('invalid_statement');
  }

  // 9
  const ext = get(get(pr, 'extensions'), 'action-receipt');
  const info = get(ext, 'info');
  // advertised iff the extension entry is an object whose info is a JSON object
  const advertised = isObj(ext) && isObj(info);
  if (advertised) {
    // each of actionType and scope PRESENT in info must be a string equal to the statement's
    const own = (k) => Object.prototype.hasOwnProperty.call(info, k);
    if (own('actionType') && info.actionType !== actionType) return refuse('advertisement_conflict');
    if (own('scope') && info.scope !== scope) return refuse('advertisement_conflict');
  }

  // 10
  const further = opt(st, 'bindings');
  let entries = [];
  if (further !== undefined) {
    if (!Array.isArray(further)) return refuse('invalid_bindings');
    entries = further.slice();
    // types this specification defines are added below, never supplied
    for (const e of entries) {
      if (isObj(e) && typeof get(e, 'type') === 'string' && e.type.startsWith('action-receipt:')) {
        return refuse('invalid_bindings');
      }
    }
  }
  if (advertised) {
    if (!inDomain(info)) return refuse('invalid_bindings');
    entries.push({ type: 'action-receipt:advertised-info', value: digest(info) });
  }
  const reversal = get(st, 'reversalTransaction');
  if (had(reversal)) entries.push({ type: 'action-receipt:reversal-transaction', value: reversal });
  if (entries.length > 16) return refuse('invalid_bindings');
  const bindings = [];
  for (const e of entries) {
    if (!isObj(e)) return refuse('invalid_bindings');
    const keys = Object.keys(e);
    if (keys.length !== 2 || !keys.includes('type') || !keys.includes('value')) return refuse('invalid_bindings');
    if (typeof e.type !== 'string' || !RE_BTYPE.test(e.type)) return refuse('invalid_bindings');
    if (typeof e.value !== 'string' || !RE_BVALUE.test(e.value)) return refuse('invalid_bindings');
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
    supersedes: typeof supersedesIn === 'string' ? supersedesIn : '',
    action: { agent, actionType, scope, outcome },
    bindings,
  };
  return { issued: true, payload };
}

function handle(line) {
  let id = null;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    const m = /"id"\s*:\s*("(?:[^"\\]|\\.)*")/.exec(line);
    if (m) { try { id = JSON.parse(m[1]); } catch { /* keep null */ } }
    return { id, ...refuse('settlement_not_successful') };
  }
  const rawId = get(msg, 'id');
  if (rawId !== undefined) id = rawId;
  let res;
  try {
    res = issue(get(msg, 'exchange'));
  } catch {
    res = refuse('settlement_not_successful'); // defensive; not expected to be reachable
  }
  return { id, ...res };
}

const chunks = [];
process.stdin.on('data', (c) => chunks.push(c));
process.stdin.on('end', () => {
  const text = Buffer.concat(chunks).toString('utf8');
  const out = [];
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue;
    let s;
    try { s = JSON.stringify(handle(line)); } catch { s = JSON.stringify({ id: null, issued: false, reason: 'settlement_not_successful' }); }
    out.push(s);
  }
  process.stdout.write(out.length ? out.join('\n') + '\n' : '');
});
