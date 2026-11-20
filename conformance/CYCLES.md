# Test cycles

A record of each test cycle run against draft 0.3: what ran, what it found, and
what changed as a result. Add an entry whenever a cycle finds something or the
harness changes. A cycle that finds nothing is recorded in one line.

How to run one: `python3 conformance/cycle.py --seeds <new seeds> --n 5000 --save <dir>`.
Use seeds that have not been used before. Spent: 1 to 8, 11 to 18, 21 to 24,
31 to 33, 41 to 43, 51 to 53.

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

## Cycle 7 — 2026-11-20 (verifier)

| # | Finding | Class | Resolution |
|---|---|---|---|
| 8 | The catalogue listed a verifier MUST with no step and no reason code: a requesting verifier "MUST additionally check that `resourceUrl` is the URL it paid for" | B | Now the first part of §5.4, with `invalid_actionreceipt_resource_mismatch`, a report entry, two vectors, a flip and a fuzz operator |

Adding the report entry broke agreement with the second verifier on every
positive vector until it was updated, which is the cycle working as intended.
Seeds 41 to 43, 5,000 cases each: 0 disagreements.

## Issuer cycle 1 — 2026-11-20

Spec §6 rewritten as a ten-step procedure with named refusal reasons. Reference
issuer (`issuer.py`), 34 exchanges with expectations declared by hand as
differences from the payload printed in spec §4.7, issuer flip probe, issuer
fuzzer with four properties. Reference issuer alone, seed 1, 4,000 exchanges,
round trips through both verifiers: 82 property violations in two groups.

| # | Finding | Class | Resolution |
|---|---|---|---|
| 9 | A statement could supply a binding in the `action-receipt:` namespace. With nothing advertised, the issuer produced a receipt carrying an advertisement commitment no verifier could evaluate | B | §6.2: the types this specification defines are added by the issuer and never supplied. Exchange `refuse_binding_reserved_type` |
| 10 | An unpaired surrogate in a statement string produced a payload that cannot be serialized | A + B | §6.1: a value is "had" only if it is well-formed Unicode; step 8 requires well-formed strings. Exchange `refuse_scope_unpaired_surrogate` |
| 11 | The issuer flip probe showed the network-grammar rule was tested only where a second rule gave the same reason; later the same for binding uniqueness | suite gap | Exchanges `refuse_network_not_caip2_either_side`, `refuse_binding_duplicate_type` |

## Issuer cycle 2 — 2026-11-20

A second issuer (`issuer.mjs`) was written by a separate agent session from the
spec text and the 34 exchange inputs only. The exchanges were given opaque names
and no expected outputs existed in its directory. Run unedited, it reproduced
the spec's worked example byte for byte and agreed on all 34 exchanges. Its
report listed 56 places where the text made it choose; these were real:

| # | Finding | Class | Resolution |
|---|---|---|---|
| 12 | §5.8 said a verifier lowercases "ASCII `A-F`", while both verifiers lowercase all ASCII letters, and §6.2 added "a leading `0X` to `0x`". As written, a response spelling an address `0X...` would issue a receipt that then fails verification | B (text wrong) | One rule in both places: ASCII `A-Z` to `a-z`. The reference verifier now lowercases ASCII only |
| 13 | `null` versus absent for `supersedes` and `bindings` was undecided; the two issuers split | B | §6.1: an absent optional member and a `null` one are the same. Exchange `issue_null_means_absent` |
| 14 | "If the issuer advertised this extension" had no testable definition; the issuers split on an `info` that is not an object | B | §6.1 defines it: the extension entry is an object whose `info` is a JSON object. Exchange `issue_advertisement_info_not_object` |
| 15 | Step 9 compared only string-valued advertised members while §4.5.2 requires equality for every member present. An `info` with `scope: 5` was issued and verified as `mismatched` by one verifier and `matched` by the other | B | Step 9 and §4.5.2 both say "present". Both issuers and the reference verifier changed. Exchange `refuse_advertised_scope_not_string`, vector `pos_binding_advertised_scope_not_string` |
| 16 | The closing claim of §6.3, "passes with every check compared", was false for `network`, `payer` and `resourceUrl` in ordinary exchanges | B (text wrong) | Reworded to what holds |
| 17 | Extra members of the statement's `action`, and a `transaction` of the wrong type, were unspecified | B | §6.1 conventions. Exchanges `issue_action_extra_member_ignored`, `issue_transaction_wrong_type_with_reference` |
| 18 | The harness split adapter output with `str.splitlines()`, which also splits on U+2028; Node emits that character unescaped inside a JSON string | C | Split on LF only, in three places |
| 19 | The fuzzer derived a verifier clock of 2^53 from the largest `issuedAt` | C | Clock capped to the safe range |

The second issuer was then changed in five places to the settled text. Seed 1,
5,000 exchanges: 0 disagreements, 0 violations. Issuer fuzzer power: 24 of 25,
then 25 of 25 after operator `statement_unicode`.

## Cycle 8 — 2026-11-20 (all eleven stages)

Seeds 51 to 53, 5,000 each. Verifiers: 15,000 cases, 7,981 follow-ups, 0
disagreements. Issuers: 15,000 exchanges, 10,064 round trips through both
verifiers, 0 disagreements, 0 property violations. 94 vectors, 46 exchanges, 40
verifier flips, 25 issuer flips, 101 requirements (77 tested).

## Known limits of this process

- Both verifiers were written in one working session, one of them from the spec
  text alone. Agreement between them is weaker evidence than agreement with an
  implementation by someone else.
- The fuzzer compares the two implementations with each other. A reading that
  both share and that is wrong is invisible to it; only the properties (P1 to P6)
  and the hand-declared vector expectations stand against that.
- The properties are few and all concern a passing receipt.
- 24 of 101 requirements are not tested, 9 of them verifier requirements. They
  are listed with reasons in `CONFORMANCE.md`.
- Issuer conformance covers the payload an issuer builds and its refusals. It
  does not cover signing, the randomness of `receiptId`, or key retention.
- The scheme-payload payer is defined for one field,
  `payload.authorization.from`; other schemes are untested.
- Every settlement identifier is synthetic. Nothing here touches a payment rail,
  a DID document or DNS.
- The flip probe patches source text. A refactor that changes a patched line
  makes that flip a setup error, which fails the run until the pattern is updated.
