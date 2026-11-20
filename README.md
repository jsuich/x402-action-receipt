# x402 `action-receipt` — draft extension and conformance suite

A draft x402 extension: after a payment settles, the resource server returns a
signed statement of what was done, within what scope and with what outcome, bound
to the settlement, to the payment requirements the client accepted, and (through
signed binding slots) to evidence defined by other extensions.

**Status:** draft 0.3, proposed for discussion in
[x402-foundation/x402#2906][2906]. Draft 0.3 is a breaking revision of the 0.2.1
draft that this repository previously held; see the spec's version history.

[2906]: https://github.com/x402-foundation/x402/issues/2906

## Files

| File | What |
|---|---|
| `action-receipt.md` | The specification. It governs where it and the code disagree |
| `action_receipt.py` | Reference verifier, conformance suite and vector generator |
| `vectors/` | Committed test vectors (inputs, not run-time outputs) |
| `vectors/MANIFEST.json` | Language-neutral manifest: context, expected verdict, reason code and report per vector |
| `VECTORS.md` | Vector index, generated from the same tables the suite runs |
| `flip_probe.py` | Disables each verifier check in turn and requires the suite to go red |
| `issuer.py` | Reference issuer (spec §6) and the issuer conformance suite |
| `issuer.mjs` | Second issuer, JavaScript, written from the spec text and the exchange inputs alone |
| `exchanges/` | Issuer conformance: what a server holds when it issues, and the payload or refusal expected |
| `verify.mjs` | Second verifier, JavaScript (Node built-ins only), written from the spec text and the vectors without sight of `action_receipt.py` |
| `CONFORMANCE.md` | What conformance means: classes, the adapter protocol, and every requirement with the vectors that test it. Generated |
| `conformance/requirements.json` | The requirements catalogue `CONFORMANCE.md` is rendered from |
| `conformance/trace.py` | Checks the catalogue against the spec and the suite; `trace_selftest.py` checks the checker |
| `conformance/fuzz.py` | Differential and metamorphic fuzzer across verifiers |
| `conformance/fuzz_issuer.py` | Differential fuzzer across issuers; every issued receipt must verify through every verifier |
| `conformance/flip_issuer.py` | Disables each issuer step in turn and requires the exchange suite to go red |
| `conformance/run_exchanges.py` | Runs any issuer adapter against the exchange manifest |
| `conformance/adapters/` | Batch adapters that put a verifier behind the adapter protocol |
| `conformance/cycle.py` | One full test cycle, one exit code |
| `conformance/CYCLES.md` | What each test cycle found and what changed |
| `requirements.txt` | Dependencies |
| `LICENSE` | Apache-2.0 |

## Run

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python action_receipt.py                 # verify the committed vectors
.venv/bin/python action_receipt.py --verify vectors/pos_es256_valid.json
.venv/bin/python action_receipt.py --worked        # print the spec's worked example
.venv/bin/python action_receipt.py --regenerate    # rebuild vectors, MANIFEST.json, VECTORS.md
.venv/bin/python flip_probe.py . /tmp/flip-scratch # show that each check can fail
```

The suite exits 0 only if every vector gives its expected verdict, reason and
report; both verdicts were observed; every reason code was exercised; the
mutation matrix and the identifier relations hold; and the reason codes in the
spec match the code.

## Test process

```bash
.venv/bin/python conformance/cycle.py                       # full cycle, about a minute
.venv/bin/python conformance/cycle.py --seeds 21,22 --n 5000 --save out/
.venv/bin/python flip_probe.py . /tmp/flip-scratch --fuzz 3000   # also measure the fuzzer
```

A cycle runs eleven stages and returns one exit code. A stage that cannot run is
reported as VOID and fails the cycle; it is never counted as a pass.

| Stage | Establishes |
|---|---|
| trace | every normative sentence of the spec is covered by a requirement, every vector by a requirement, and `CONFORMANCE.md` is current |
| trace-st | the trace reports each kind of planted defect |
| python | the reference verifier reproduces the manifest, cross-checked against an independent RFC 8785 library |
| node | the second verifier reproduces the manifest |
| example | the second verifier reproduces the spec's worked example from the spec text |
| flips | each check of the reference verifier, disabled, turns the suite red |
| fuzz | the two verifiers agree on generated cases, and six oracle-free properties hold |
| issuer | the reference issuer reproduces the exchange manifest, and every receipt it issues verifies in the context of its own exchange |
| issuer-n | the second issuer reproduces the exchange manifest |
| issuer-fl | each step of the reference issuer, disabled, turns its suite red |
| issuer-fz | the two issuers agree on generated exchanges, and every issued receipt verifies through both verifiers |

Each instrument has a control: the flip probe ends with an unpatched run that
must pass, the trace has a self-test, and `flip_probe.py --fuzz` measures how
many disabled checks the fuzzer detects.

When the fuzzer finds a disagreement, it is triaged as an implementation bug, a
spec gap or a harness bug, fixed at the right place, and pinned with a vector.
`conformance/CYCLES.md` has the rule and the history: nineteen findings so far,
among them defects in the reference verifier, in the reference issuer, in the
spec text and in the harness itself.

To test another verifier, put it behind the adapter protocol in `CONFORMANCE.md`
section 3, add it to `ADAPTERS` in `conformance/fuzz.py`, and run
`conformance/fuzz.py --adapters python,<yours>`.

### Dependencies

- `cryptography` is required. A verifier that cannot check signatures must not
  return PASS, so there is no signature-free mode.
- `rfc8785` is used when present: every canonicalization is then cross-checked
  byte for byte against that independent RFC 8785 implementation. The first line
  of the suite's output says whether the cross-check ran. A disagreement is
  reported as a verifier fault (`ERROR`), never as a rejected receipt.

## What changed in draft 0.3

The changes came from review of the 0.2.1 draft and from the discussion in the
x402 repository around post-settlement evidence.

- **`actionRef` is gone; `receiptRef` replaces it.** The 0.2.1 `actionRef` hashed
  thirteen fields and was described as a join key and a replay key. It was
  neither: it could not be computed before the receipt existed, and it was unique
  per statement, not per payment. `receiptRef` is the SHA-256 of the signed
  payload bytes, derived and not carried, and the spec says what it is and is not
  for. It is not the four-field `action_ref` of issue #2332 and is not
  interchangeable with it.
- **`receiptId`.** Two payments under one batch settlement in the same second
  produced byte-identical 0.2.1 receipts. Each receipt now carries a unique id.
- **`requirementsDigest`** commits the accepted payment requirements: amount,
  asset, recipient, scheme, network.
- **`bindings`** carries values defined by other extensions under this receipt's
  signature. A new binding type needs no change to this schema.
- **`supersedes`** links a later lifecycle receipt (capture, reversal, refund) to
  the one it replaces.
- **Field grammar.** EVM addresses and hashes are lowercase in the receipt;
  values from the unsigned settlement response are lowercased before comparison.
  The 0.2.1 verifier rejected a correct receipt when a facilitator returned a
  different hex case.
- **Check order.** The canonical-bytes check now runs before schema typing, so
  parser differences between languages land on one reason code.
- **A report, not just a verdict.** The verifier says which bindings it compared
  and which it could not. An unresolvable key has its own indeterminate code and
  is no longer reported as a forged signature.
- **Session and archival freshness.** An auditor holding a months-old receipt is
  no longer rejected for its age.
- **Stated limits.** The receipt is the paid counterparty's statement; the
  settlement checks compare against an unsigned response; neither proves funds
  moved.

## Design notes

- **Issuer conformance is about the payload.** `exchanges/MANIFEST.json` states,
  for each exchange, the exact payload or the refusal reason. The expected
  payloads were declared by hand as differences from the payload printed in the
  spec; none was produced by running an issuer.
- **JWS only** (ES256, ES256K, EdDSA). An EIP-712 format is an open question.
- **Vectors are inputs.** Keys derive from fixed seeds, so payloads and every
  `receiptRef` regenerate identically. EdDSA signatures regenerate byte for byte.
  ES256 and ES256K signatures use fresh randomness, so their bytes differ between
  regenerations; every verdict and every `receiptRef` is unaffected.
- **All settlement identifiers in the vectors are synthetic.** The suite tests
  the receipt procedure, not any chain.
- **Not a new primitive.** JCS, JWS and SHA-256, composed. No novelty is claimed.

## Cross-implementation conformance

`vectors/MANIFEST.json` is language-neutral. An implementation conforms if it
reproduces every entry: verdict, reason on REJECT, report on PASS, and the
`receiptRef` relations. Cite the manifest's `vectorsDigest` when reporting a
result. Results from independent implementations are welcome here or on [#2906].

`verify.mjs` is a second implementation with its own RFC 8785 canonicalizer:

```bash
node verify.mjs            # every vector in the manifest, plus the receiptRef relations
node verify.mjs --example  # reproduce the spec's worked example from the printed text
```

What it is and is not evidence of. It was written by a separate AI agent session
that was given only `action-receipt.md` and `vectors/`, was told not to read the
Python, and wrote the whole verifier before looking at any expected result. Run
unedited, it agreed with the manifest on its first run, and it agreed again on
two vectors added afterwards. The choices it had to make where the text was
unclear were then written into the spec. It has since been changed once, in one
line, when fuzzing exposed a case the spec had not decided
(`conformance/CYCLES.md`, cycle 1). It is not a third-party implementation:
the same author commissioned both, and the agent saw the vector file names, which
hint at each negative's category. An implementation by someone else is still the
result that matters.

## License and contributor

Apache-2.0. Contributed openly by Holological LLC (`jsuich`). Prepared with AI
assistance.
