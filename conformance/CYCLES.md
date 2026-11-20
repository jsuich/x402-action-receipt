# Test cycles

A record of each test cycle run against draft 0.3: what ran, what it found, and
what changed as a result. Add an entry whenever a cycle finds something or the
harness changes. A cycle that finds nothing is recorded in one line.

How to run one: `python3 conformance/cycle.py --seeds <new seeds> --n 5000 --save <dir>`.
Use seeds that have not been used before; seeds 1 to 8 and 11 to 18 are spent.

Triage rule for a fuzz disagreement. Decide which it is, and record it:

- **A, implementation bug.** The spec is clear; one implementation is wrong. Fix
  it, add a vector that pins the case, add a flip for the fixed check.
- **B, spec ambiguity or gap.** The text admits both readings or says nothing.
  Decide, state it in the spec, add a requirement and a vector.
- **C, harness bug.** The generator produced an input outside the adapter
  contract, or the comparison is wrong. Fix the harness.

Never resolve a disagreement by changing one implementation to match the other
without deciding which of the three it was.

## Cycle 1 — 2026-11-19

Harness: differential fuzzer (`conformance/fuzz.py`), two adapters, six
properties. Seed 1, 3,000 cases, 1,458 follow-ups.

18 disagreements, 0 property violations, in three groups:

| # | Finding | Class | Resolution |
|---|---|---|---|
| 1 | What the verifier holds as accepted requirements is not a JSON object (`1`, `[]`, `"x"`). Python reported "not evaluated"; JavaScript rejected with a requirements mismatch | B | Spec §5.9: not a JSON object means not evaluated. JavaScript changed. Vector `pos_requirements_not_object` |
| 2 | Accepted requirements spelling an integer as `60.0`. Python kept a float and skipped the check; JavaScript saw the integer 60 and matched | B | Spec §4.6: the value domain is defined on values, not spellings. Python changed. Vector `pos_requirements_float_spelling` |
| 3 | Response `payer` is the empty string. Python compared it and rejected; JavaScript treated it as absent | A (Python) | Spec §5.8 already said a value is "had" only when it is a non-empty string. Python changed. Vector `pos_payer_empty_string` |

## Cycle 2 — 2026-11-19

Seeds 1 to 3, 3,000 cases each. Flip probe red on two patterns that the cycle 1
edits had invalidated (the probe reports a pattern that no longer matches as a
failure, which is the intended behaviour).

28 disagreements, 0 property violations, in two groups:

| # | Finding | Class | Resolution |
|---|---|---|---|
| 4 | JWS header prefixed with a UTF-8 byte-order mark. Python accepted it: `json.loads` given bytes detects the encoding, so it would also accept UTF-16 and UTF-32 headers. JavaScript rejected | A (Python) | Header decoded strictly as UTF-8 before parsing. Spec §5.1 now says so. Vectors `neg_header_bom`, `neg_header_utf16` |
| 5 | Payload that is the JSON value `null`. Python returned the canonicalization code because its canonical-parse function used `None` as its failure signal; JavaScript returned `invalid_payload` | A (Python) | Distinct sentinel. Spec §5.2 now says any canonical JSON value passes that step. Vector `neg_schema_null` |

## Cycle 3 — 2026-11-19

Seeds 1 to 6, 4,000 cases each: 24,000 cases, 12,222 follow-ups. 0 disagreements,
0 property violations.

Fuzzer power measured for the first time (`flip_probe.py --fuzz 3000`): the
fuzzer detected 34 of 38 disabled checks. Two misses were rare cases; two were
generator gaps:

| Gap | Fix |
|---|---|
| Nothing swapped the header's algorithm for another supported one under an unchanged key, so the curve-to-`alg` binding was never exercised | operator `alg_swap` |
| The advertisement binding's digest never matched when the scope differed, so the scope rule was masked | `binding_advertised` now usually commits to the info actually held |
| Byte-order marks and other encodings on the header were one choice in nine of one operator | operator `header_encoding` |
| Scalar payloads were one choice in ten of one operator | operator `payload_scalar` |
| Well-formed bindings in the wrong order were rare | operator `bindings_wellformed` |
| Integer-valued floats in held requirements were rare | operator `ctx_number_spelling` |

After the fixes the fuzzer detects 38 of 38 from one 3,000-case seed.

## Cycle 4 — 2026-11-19

Seeds 1 to 8, 5,000 cases each, strengthened generator: 40,000 cases, 20,945
follow-ups. 0 disagreements, 0 property violations.

## Cycle 5 — 2026-11-20

Requirements trace added (`conformance/trace.py`, `conformance/requirements.json`,
rendered to `CONFORMANCE.md`), with its own self-test.

| # | Finding | Class | Resolution |
|---|---|---|---|
| 6 | Writing the catalogue showed one verifier rule with no vector: "`accepted.network` equals the receipt's `network`" (§5.9). An earlier step always caught a network mismatch first | suite gap | Vector `neg_requirements_network_mismatch`, in a context whose response network is not in CAIP-2 form. Flip added |
| 7 | The verification procedure said the verifier "performs the steps in order" with no MUST | B | §5 now uses MUST for both the order and stopping at the first failure |

Seeds 11 to 18, 5,000 cases each: 40,000 cases, 20,237 follow-ups. 0
disagreements, 0 property violations. Flip probe 39 of 39.

## Cycle 6 — 2026-11-20

Run on an export of the committed tree. Seeds 21 to 24, 5,000 cases each: 20,000
cases, 10,483 follow-ups. 0 disagreements, 0 property violations. All seven
stages passed.

Fuzzer power: 38 of 39. The miss was the flip added in cycle 5 (requirements
network): no operator produced a receipt that commits to the held requirements
while those requirements name another network. Operator
`ctx_requirements_network` added; power is 39 of 39 from one 3,000-case seed.

Seeds 21 to 24 are spent.

## Known limits of this process

- Both verifiers were written in one working session, one of them from the spec
  text alone. Agreement between them is weaker evidence than agreement with an
  implementation by someone else.
- The fuzzer compares the two implementations with each other. A reading that
  both share and that is wrong is invisible to it; only the properties (P1 to P6)
  and the hand-declared vector expectations stand against that.
- The properties are few and all concern a passing receipt.
- 30 of 80 requirements are not tested, 9 of them verifier requirements. They are
  listed with reasons in `CONFORMANCE.md`. There is no issuer conformance class.
- Every settlement identifier is synthetic. Nothing here touches a payment rail,
  a DID document or DNS.
- The flip probe patches source text. A refactor that changes a patched line
  makes that flip a setup error, which fails the run until the pattern is updated.
