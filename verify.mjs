// Clean-room verifier for the x402 `action-receipt` extension, draft 0.3.
// Written from action-receipt.md alone. Node built-ins only.
//
//   node verify.mjs            run every vector in vectors/MANIFEST.json
//   node verify.mjs --example  check the worked example of spec section 4.7
//
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------- helpers

const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex');

function hasExactly(o, names) {
  const k = Object.keys(o);
  if (k.length !== names.length) return false;
  for (const n of names) if (!Object.hasOwn(o, n)) return false;
  return true;
}

// ASCII-only lowercasing (spec 5.8: "lowercases"); avoids Unicode case mapping.
const asciiLower = (s) => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));

// Strict unpadded base64url (spec 3, 5.1 step 1). Returns Buffer or null.
function b64urlDecode(s) {
  if (!isStr(s)) return null;
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  if (s.length % 4 === 1) return null;
  const buf = Buffer.from(s, 'base64url');
  if (buf.toString('base64url') !== s) return null; // non-zero trailing bits
  return buf;
}

function utf8Strict(buf) {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buf);
  } catch {
    return null;
  }
}

// ------------------------------------------------- value domain (spec 4.6)

const MAX_DEPTH = 8;

// A scalar has depth 0; a container is one level deeper than its deepest child.
function inDomain(v, level = 0) {
  if (v === null || v === true || v === false) return true;
  if (typeof v === 'number') return Number.isSafeInteger(v);
  if (typeof v === 'string') return v.isWellFormed();
  if (Array.isArray(v)) {
    if (level + 1 > MAX_DEPTH) return false;
    for (const x of v) if (!inDomain(x, level + 1)) return false;
    return true;
  }
  if (isObj(v)) {
    if (level + 1 > MAX_DEPTH) return false;
    for (const k of Object.keys(v)) {
      if (!k.isWellFormed()) return false;
      if (!inDomain(v[k], level + 1)) return false;
    }
    return true;
  }
  return false;
}

// ---------------------------------- RFC 8785 over the domain of spec 4.6

function jcsString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0d) out += '\\r';
    else if (c === 0x09) out += '\\t';
    else if (c < 0x20) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += s[i];
  }
  return out + '"';
}

function jcsText(v) {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new Error('number outside domain');
    return Object.is(v, -0) ? '0' : String(v);
  }
  if (typeof v === 'string') return jcsString(v);
  if (Array.isArray(v)) return '[' + v.map(jcsText).join(',') + ']';
  if (isObj(v)) {
    // Array.prototype.sort without a comparator orders by UTF-16 code units.
    const keys = Object.keys(v).sort();
    return '{' + keys.map((k) => jcsString(k) + ':' + jcsText(v[k])).join(',') + '}';
  }
  throw new Error('value outside domain');
}

export const jcs = (v) => Buffer.from(jcsText(v), 'utf8');

// ------------------------------------------------------ grammar (spec 4.6)

const RE = {
  receiptId: /^[A-Za-z0-9_-]{22,64}$/,
  caip2: /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/,
  evmAddr: /^0x[0-9a-f]{40}$/,
  evmTx: /^0x[0-9a-f]{64}$/,
  digest: /^sha256:[0-9a-f]{64}$/,
  bindingType: /^[a-z][a-z0-9+.-]{0,63}:[\x21-\x7e]{1,191}$/,
  bindingValue: /^[\x21-\x7e]{1,1024}$/,
};

const PAYLOAD_MEMBERS = [
  'version', 'receiptId', 'issuedAt', 'network', 'resourceUrl', 'payer', 'payTo',
  'transaction', 'settlementRef', 'settlementStatus', 'requirementsDigest',
  'supersedes', 'action', 'bindings',
];
const ACTION_MEMBERS = ['agent', 'actionType', 'scope', 'outcome'];
const OUTCOMES = ['delivered', 'partial', 'refused', 'disputed'];
const STATUSES = ['settled', 'capturePending', 'reversed', 'refunded'];
const ALGS = ['ES256', 'ES256K', 'EdDSA'];
const TYP = 'x402-action-receipt+jws';

// Curve orders, for the low-s rule (spec 3, 5.6).
const ORDER = {
  ES256: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
  ES256K: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
};
const CURVE = { ES256: 'prime256v1', ES256K: 'secp256k1' };

// --------------------------------------------- fixture resolver (spec 7)

export function fixtureResolver(keys) {
  const list = (name) => (Object.hasOwn(keys, name) && Array.isArray(keys[name]) ? keys[name] : []);
  return {
    // spec 5.4 (a) and (b)
    isAuthorized(kid, resourceUrl, payTo) {
      return list(`__service__:${resourceUrl}`).includes(kid)
        || list(`__payTo__:${payTo}|${resourceUrl}`).includes(kid);
    },
    // spec 5.5: returns a KeyObject or null
    resolveKey(kid) {
      if (!Object.hasOwn(keys, kid) || !isStr(keys[kid])) return null;
      try {
        return createPublicKey(keys[kid]);
      } catch {
        return null;
      }
    },
  };
}

// ------------------------------------------------- verification (spec 5)

const reject = (reason) => ({ verdict: 'REJECT', reason });

export function verify(receipt, ctx, resolver) {
  try {
    return verifyInner(receipt, ctx, resolver);
  } catch (e) {
    return { verdict: 'ERROR', error: String(e && e.message ? e.message : e) };
  }
}

function verifyInner(receipt, ctx, resolver) {
  // ---- 5.1 envelope and header
  if (!isObj(receipt) || receipt.format !== 'jws' || !isStr(receipt.signature)) {
    return reject('invalid_payload');
  }
  const segs = receipt.signature.split('.');
  if (segs.length !== 3) return reject('invalid_payload');
  const dec = segs.map(b64urlDecode);
  if (dec.some((d) => d === null)) return reject('invalid_payload');
  let header;
  {
    const t = utf8Strict(dec[0]);
    if (t === null) return reject('invalid_payload');
    try {
      header = JSON.parse(t);
    } catch {
      return reject('invalid_payload');
    }
    if (!isObj(header)) return reject('invalid_payload');
  }
  const h = (n) => (Object.hasOwn(header, n) ? header[n] : undefined);
  if (h('typ') !== TYP) return reject('invalid_actionreceipt_typ');
  if (!ALGS.includes(h('alg'))) return reject('invalid_actionreceipt_alg');
  if (!hasExactly(header, ['alg', 'kid', 'typ']) || !isStr(header.kid)) {
    return reject('invalid_payload');
  }
  const alg = header.alg;
  const kid = header.kid;

  // ---- 5.2 canonical bytes
  const B = dec[1];
  let p;
  {
    const t = utf8Strict(B);
    if (t === null) return reject('invalid_actionreceipt_canonicalization');
    try {
      p = JSON.parse(t);
    } catch {
      return reject('invalid_actionreceipt_canonicalization');
    }
    if (!inDomain(p)) return reject('invalid_actionreceipt_canonicalization');
    if (!jcs(p).equals(B)) return reject('invalid_actionreceipt_canonicalization');
  }

  // ---- 5.3 closed schema and field grammar
  // 1
  if (!isObj(p) || !hasExactly(p, PAYLOAD_MEMBERS) || !Number.isSafeInteger(p.version)) {
    return reject('invalid_payload');
  }
  // 2
  if (p.version !== 1) return reject('invalid_actionreceipt_version');
  // 3
  {
    const a = p.action;
    if (!isObj(a) || !hasExactly(a, ACTION_MEMBERS)) return reject('invalid_payload');
    const strs = [p.receiptId, p.network, p.resourceUrl, p.payer, p.payTo, p.transaction,
      p.settlementRef, p.settlementStatus, p.requirementsDigest, p.supersedes,
      a.agent, a.actionType, a.scope, a.outcome];
    if (!strs.every(isStr)) return reject('invalid_payload');
    const evm = p.network.startsWith('eip155:');
    const ok =
      Number.isSafeInteger(p.issuedAt) && p.issuedAt >= 0 &&
      RE.receiptId.test(p.receiptId) &&
      RE.caip2.test(p.network) &&
      p.resourceUrl !== '' && p.payer !== '' && p.payTo !== '' &&
      (!evm || (RE.evmAddr.test(p.payer) && RE.evmAddr.test(p.payTo))) &&
      (!evm || p.transaction === '' || RE.evmTx.test(p.transaction)) &&
      !(p.transaction === '' && p.settlementRef === '') &&
      RE.digest.test(p.requirementsDigest) &&
      (p.supersedes === '' || RE.digest.test(p.supersedes)) &&
      a.agent !== '' && a.actionType !== '';
    if (!ok) return reject('invalid_payload');
  }
  // 4, 5
  if (!OUTCOMES.includes(p.action.outcome)) return reject('invalid_actionreceipt_outcome');
  if (!STATUSES.includes(p.settlementStatus)) return reject('invalid_actionreceipt_status');
  // 6
  if (!Array.isArray(p.bindings)) return reject('invalid_payload');
  // 7
  {
    const bs = p.bindings;
    if (bs.length > 16) return reject('invalid_actionreceipt_binding');
    let prev = null;
    for (const b of bs) {
      if (!isObj(b) || !hasExactly(b, ['type', 'value']) || !isStr(b.type) || !isStr(b.value)
        || !RE.bindingType.test(b.type) || !RE.bindingValue.test(b.value)) {
        return reject('invalid_actionreceipt_binding');
      }
      if (prev !== null && !(prev < b.type)) return reject('invalid_actionreceipt_binding');
      prev = b.type;
    }
  }

  // ---- 5.4 a verifier that paid compares the URL it paid for
  let resourceCheck = 'not_compared';
  const paid = isObj(ctx) ? ctx.paidResourceUrl : undefined;
  if (isStr(paid) && paid !== '') {
    if (p.resourceUrl !== paid) return reject('invalid_actionreceipt_resource_mismatch');
    resourceCheck = 'compared';
  }
  // ---- 5.4 signer authorization
  if (!resolver.isAuthorized(kid, p.resourceUrl, p.payTo)) {
    return reject('invalid_actionreceipt_signer');
  }

  // ---- 5.5 key resolution
  const key = resolver.resolveKey(kid);
  if (key === null) return reject('invalid_actionreceipt_key_unresolved');

  // ---- 5.6 signature
  {
    const sig = dec[2];
    const input = Buffer.from(`${segs[0]}.${segs[1]}`, 'ascii');
    let good = false;
    if (alg === 'EdDSA') {
      if (key.asymmetricKeyType === 'ed25519') {
        try { good = cryptoVerify(null, input, key, sig); } catch { good = false; }
      }
    } else {
      const curveOk = key.asymmetricKeyType === 'ec'
        && key.asymmetricKeyDetails?.namedCurve === CURVE[alg];
      if (curveOk && sig.length === 64) {
        const s = BigInt('0x' + sig.subarray(32).toString('hex'));
        if (s <= ORDER[alg] / 2n) {
          try {
            good = cryptoVerify('sha256', input, { key, dsaEncoding: 'ieee-p1363' }, sig);
          } catch { good = false; }
        }
      }
    }
    if (!good) return reject('invalid_actionreceipt_signature');
  }

  // ---- 5.7 settlement success
  const sr = isObj(ctx) ? ctx : {};
  const present = (v) => isStr(v) && v !== '';
  const evm = p.network.startsWith('eip155:');
  const hasTx = present(sr.transaction);
  const hasRef = present(sr.settlementRef);
  if (sr.success !== true || !(hasTx || hasRef)) return reject('invalid_transaction_state');

  // ---- 5.8 settlement binding
  const checks = { resourceUrl: resourceCheck };
  {
    const norm = (v) => (evm ? asciiLower(v) : v);
    const txOk = hasTx ? p.transaction === norm(sr.transaction) : p.transaction === '';
    const refOk = hasRef ? p.settlementRef === sr.settlementRef : p.settlementRef === '';
    let netOk = true;
    if (isStr(sr.network) && RE.caip2.test(sr.network)) {
      checks.network = 'compared';
      netOk = p.network === sr.network;
    } else {
      checks.network = 'not_compared';
    }
    let payerOk = true;
    if (present(sr.payer)) {
      checks.payer = 'compared';
      payerOk = p.payer === norm(sr.payer);
    } else {
      checks.payer = 'not_compared';
    }
    if (!(txOk && refOk && netOk && payerOk)) {
      return reject('invalid_actionreceipt_settlement_mismatch');
    }
  }

  // ---- 5.9 payment requirements
  {
    const acc = sr.accepted;
    if (isObj(acc) && inDomain(acc)) {
      const digest = 'sha256:' + sha256hex(jcs(acc));
      const accPayTo = isObj(acc) && isStr(acc.payTo) ? (evm ? asciiLower(acc.payTo) : acc.payTo) : null;
      const accNet = isObj(acc) ? acc.network : undefined;
      if (p.requirementsDigest !== digest || accNet !== p.network || accPayTo !== p.payTo) {
        return reject('invalid_actionreceipt_requirements_mismatch');
      }
      checks.requirements = 'matched';
      checks.payTo = 'compared';
    } else {
      checks.requirements = 'not_evaluated';
      checks.payTo = 'not_compared';
    }
  }

  // ---- 5.10 freshness
  const mode = sr.mode;
  if (mode !== 'session' && mode !== 'archival') throw new Error('verifier mode not set');
  if (!Number.isSafeInteger(sr.now)) throw new Error('verifier clock not set');
  const age = sr.now - p.issuedAt;
  {
    const maxAge = Number.isFinite(sr.maxAgeSeconds) ? sr.maxAgeSeconds : 3600;
    if (age < -60) return reject('invalid_actionreceipt_freshness');
    if (mode === 'session' && age > maxAge) return reject('invalid_actionreceipt_freshness');
    checks.freshness = mode === 'session' ? 'enforced' : 'reported';
  }

  // ---- 5.11 bindings
  const info = sr.advertisedInfo;
  const bindings = p.bindings.map((b) => {
    let status = 'not_evaluated';
    if (b.type === 'action-receipt:advertised-info' && isObj(info) && inDomain(info)) {
      let m = b.value === 'sha256:' + sha256hex(jcs(info));
      for (const n of ['scope', 'actionType']) {
        if (Object.hasOwn(info, n) && info[n] !== p.action[n]) m = false;
      }
      status = m ? 'matched' : 'mismatched';
    }
    return { type: b.type, status };
  });

  // ---- 5.12 report
  return {
    verdict: 'PASS',
    report: {
      receiptRef: 'sha256:' + sha256hex(B),
      outcome: p.action.outcome,
      settlementStatus: p.settlementStatus,
      ageSeconds: age,
      checks: {
        resourceUrl: checks.resourceUrl,
        network: checks.network,
        payer: checks.payer,
        payTo: checks.payTo,
        requirements: checks.requirements,
        freshness: checks.freshness,
      },
      supersedes: p.supersedes,
      bindings,
    },
  };
}

// receiptRef of a receipt file regardless of verdict (for the relations).
function receiptRefOf(receipt) {
  if (!isObj(receipt) || !isStr(receipt.signature)) return null;
  const segs = receipt.signature.split('.');
  if (segs.length !== 3) return null;
  const B = b64urlDecode(segs[1]);
  return B === null ? null : 'sha256:' + sha256hex(B);
}

// ------------------------------------------------------------------ runner

function loadJson(path) {
  try {
    return { ok: true, value: JSON.parse(readFileSync(path, 'utf8')) };
  } catch (e) {
    return { ok: false, error: String(e.message) };
  }
}

function runVectors() {
  const vdir = join(HERE, 'vectors');
  const manifest = JSON.parse(readFileSync(join(vdir, 'MANIFEST.json'), 'utf8'));
  const keys = JSON.parse(readFileSync(join(vdir, 'keys.json'), 'utf8'));
  const resolver = fixtureResolver(keys);
  let agree = 0;
  const bad = [];
  const results = new Map();
  for (const v of manifest.vectors) {
    const loaded = loadJson(join(vdir, v.file));
    const receipt = loaded.ok ? loaded.value : undefined;
    const ctx = manifest.contexts[v.context];
    const r = verify(receipt, ctx, resolver);
    results.set(v.file, { r, receipt });
    const problems = [];
    if (r.verdict !== v.expect) problems.push(`verdict ${r.verdict} != ${v.expect}`);
    if (v.expect === 'REJECT' && r.verdict === 'REJECT' && r.reason !== v.reason) {
      problems.push(`reason ${r.reason} != ${v.reason}`);
    }
    if (v.expect === 'REJECT' && r.verdict !== 'REJECT') problems.push(`expected reason ${v.reason}`);
    if (v.expect === 'PASS' && r.verdict === 'REJECT') problems.push(`got reason ${r.reason}`);
    if (r.verdict === 'ERROR') problems.push(`error ${r.error}`);
    if (v.expect === 'PASS' && r.verdict === 'PASS' && !isDeepStrictEqual(r.report, v.report)) {
      problems.push(`report ${JSON.stringify(r.report)} != ${JSON.stringify(v.report)}`);
    }
    const tag = problems.length ? 'DISAGREE' : 'ok      ';
    const got = r.verdict === 'REJECT' ? `REJECT ${r.reason}` : r.verdict;
    console.log(`${tag} ${v.file} [${v.context}] ${got}${problems.length ? '  <- ' + problems.join('; ') : ''}`);
    if (problems.length) bad.push(v.file); else agree++;
  }
  let relOk = 0;
  let relBad = 0;
  const ref = (f) => {
    const x = results.get(f);
    const rec = x ? x.receipt : loadJson(join(vdir, f)).value;
    return receiptRefOf(rec);
  };
  for (const d of manifest.distinctReceiptRef ?? []) {
    const a = ref(d.a);
    const b = ref(d.b);
    const ok = a !== null && b !== null && a !== b;
    console.log(`${ok ? 'ok      ' : 'DISAGREE'} distinctReceiptRef ${d.a} / ${d.b}`);
    ok ? relOk++ : relBad++;
  }
  for (const s of manifest.sameReceiptRef ?? []) {
    const refs = s.files.map(ref);
    const ok = refs.every((x) => x !== null && x === refs[0]);
    console.log(`${ok ? 'ok      ' : 'DISAGREE'} sameReceiptRef ${s.files.length} files -> ${refs[0]}`);
    ok ? relOk++ : relBad++;
  }
  const total = manifest.vectors.length;
  console.log(`SUMMARY vectors ${agree}/${total} agree, ${bad.length} disagree; relations ${relOk}/${relOk + relBad} hold`);
  if (bad.length) console.log('DISAGREEMENTS: ' + bad.join(', '));
  return bad.length === 0 && relBad === 0 ? 0 : 1;
}

// ------------------------------------------- worked example (spec 4.7)

function runExample() {
  const spec = readFileSync(join(HERE, 'action-receipt.md'), 'utf8');
  const start = spec.indexOf('**Worked example (normative).**');
  const end = spec.indexOf('## 5. Verification');
  const sect = spec.slice(start, end);
  const blocks = [...sect.matchAll(/```\n([\s\S]*?)\n```/g)].map((m) => m[1]);
  const [accText, reqDigest, headerText, payloadText, receiptRef, compact] = blocks;
  const spki = sect.match(/public key is\s+`([^`]+)`/)[1];
  let fail = 0;
  const say = (name, ok, extra = '') => {
    console.log(`${ok ? 'REPRODUCED    ' : 'NOT REPRODUCED'} ${name}${extra ? '  ' + extra : ''}`);
    if (!ok) fail++;
  };
  const accBytes = Buffer.from(accText, 'utf8');
  say('accepted requirements are 230 bytes', accBytes.length === 230, `(${accBytes.length})`);
  say('printed accepted requirements are in JCS form (my canonicalizer round-trips them)',
    jcs(JSON.parse(accText)).equals(accBytes));
  const d = 'sha256:' + sha256hex(accBytes);
  say('requirementsDigest from printed bytes', d === reqDigest, d);
  const payBytes = Buffer.from(payloadText, 'utf8');
  say('payload is 638 bytes', payBytes.length === 638, `(${payBytes.length})`);
  say('printed payload is in JCS form', jcs(JSON.parse(payloadText)).equals(payBytes));
  say('payload.requirementsDigest equals the printed digest',
    JSON.parse(payloadText).requirementsDigest === reqDigest);
  const r = 'sha256:' + sha256hex(payBytes);
  say('receiptRef from printed payload', r === receiptRef, r);
  const segs = compact.split('.');
  say('compact segment 1 decodes to the printed header',
    b64urlDecode(segs[0])?.toString('utf8') === headerText);
  say('compact segment 2 decodes to the printed payload', b64urlDecode(segs[1])?.equals(payBytes) === true);
  const key = createPublicKey({ key: Buffer.from(spki, 'base64'), format: 'der', type: 'spki' });
  const sigOk = key.asymmetricKeyType === 'ed25519'
    && cryptoVerify(null, Buffer.from(`${segs[0]}.${segs[1]}`, 'ascii'), key, b64urlDecode(segs[2]));
  say('Ed25519 compact JWS verifies under the printed public key', sigOk);
  // Full section 5 procedure on the example, with the printed key and the printed requirements.
  const resolver = {
    isAuthorized: (kid, url) => kid === 'did:web:api.example.com#ed25519' && url === 'https://api.example.com/v1/complete',
    resolveKey: () => key,
  };
  const ctx = {
    success: true,
    transaction: '0xabababababababababababababababababababababababababababababababab',
    network: 'eip155:8453',
    payer: '0x857b06519E91e3A54538791bDbb0E22373e36b66',
    accepted: JSON.parse(accText),
    advertisedInfo: null,
    now: 1703123500,
    mode: 'session',
  };
  const res = verify({ format: 'jws', signature: compact }, ctx, resolver);
  say('full section-5 verification of the example (section-8 SettlementResponse, checksum-case payer)',
    res.verdict === 'PASS' && res.report.receiptRef === receiptRef, JSON.stringify(res));
  return fail === 0 ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = process.argv.includes('--example') ? runExample() : runVectors();
}
