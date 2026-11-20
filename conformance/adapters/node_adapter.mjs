// Batch adapter for the JavaScript verifier (see ADAPTER PROTOCOL in
// CONFORMANCE.md). It imports verify.mjs unmodified.
//
//   node node_adapter.mjs KEYS.json < cases.jsonl > results.jsonl
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { verify, fixtureResolver } from '../../verify.mjs';

const keys = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const resolver = fixtureResolver(keys);
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
const out = [];
for await (const line of rl) {
  if (!line.trim()) continue;
  const c = JSON.parse(line);
  const r = verify(c.receipt, c.context, resolver);
  out.push(JSON.stringify({
    id: c.id,
    verdict: r.verdict,
    reason: r.verdict === 'REJECT' ? r.reason : (r.verdict === 'ERROR' ? 'verifier_fault' : null),
    report: r.verdict === 'PASS' ? r.report : null,
  }));
}
process.stdout.write(out.join('\n') + (out.length ? '\n' : ''));
