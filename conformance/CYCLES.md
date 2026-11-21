# Test cycles

A record of each test cycle run against drafts 0.3 and 0.4: what ran, what it
found, and what changed as a result. Add an entry whenever a cycle finds
something or the harness changes. A cycle that finds nothing is recorded in one
line.

How to run one: `python3 conformance/cycle.py --seeds <new seeds> --n 5000 --save <dir>`.
Use seeds that have not been used before. Spent: 1 to 8, 11 to 18, 21 to 24,
31 to 33, 41 to 43, 51 to 53, 61 to 64, 71 to 73, 81 to 83, 91 and 92, 101 to
103 (the CI workflow's fixed seeds, run on every push), 111 to 113, 121 to 123,
131 and 132, 141, 151 to 153, 161 and 162, 171 and 172, 181 to 183, 191 and 192,
201 to 203, 211 and 212, 9001.

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

## Cycle 9 — 2026-11-20 (outcome values)

| # | Finding | Class | Resolution |
|---|---|---|---|
| 20 | `outcome` allowed `refused` and `disputed`. A survey of the x402 threads found no proposal or implementation that uses either as an outcome value, while the delivery-receipt proposal (#2833) implements exactly `delivered`, `failed`, `partial`, and five authors use `failed` | B | `outcome` is `delivered`, `partial` or `failed`. The retired values are pinned as rejections: vectors `neg_outcome_retired_refused`, `neg_outcome_retired_disputed`, exchange `refuse_outcome_retired_value` |

Seeds 61 to 64 ran on an export of the committed tree before this change; seeds
71 to 73 after it: 15,000 cases and 15,000 exchanges, 0 disagreements, all eleven
stages passed. 95 vectors, 47 exchanges.

## Cycle 10 — 2026-11-20 (draft 0.4: review, pre-publication review)

**Six-reviewer review of 0.3.** Its findings, dispositions and how each code
disposition was verified are in `conformance/REVIEW-0.4.md`; draft 0.4 is the
result. The 0.4 work ran seeds 81 to 83, 91 and 92, 111 to 113, 121 to 123,
131 and 132, and 141.

**Pre-publication review of 0.4.** A further reviewer read the 0.4 text and
code, ran 21 hand-written mutants of the four implementations through the full
cycle (seeds 131 and 132, 2,000 each) and cross-checked both verifiers on
generated receipts. It found:

| # | Finding | Class | Resolution |
|---|---|---|---|
| 21 | The issuer exchanges handed the settlement reference in as a top-level `settlementReference`, outside the x402 objects. Five EVM `exact` exchanges (`issue_batch`, `issue_settlement_ref_upper_case_evm`, `issue_transaction_wrong_type_with_reference`, `issue_surrogate_response_transaction`, `issue_both_identifiers`) expected a `settlementRef` that the settlement result never carried, which §4.3 forbids; an issuer that found the reference by the table was red on all five | B + C | §4.3 now says the reference of an exchange is found by the table from `accepted.scheme` and `accepted.network` and nothing else. Both issuers do that; the input is gone from the exchanges and the adapter protocol. The five, and `issue_surrogate_settlement_reference`, are Solana `batch-settlement` exchanges testing the same rules (`issue_settlement_ref_upper_case_evm` is now `issue_settlement_ref_upper_case_verbatim`). New exchanges: `commitmentId` under `exact` or off `solana` is no reference; empty, non-string or missing `commitmentId` gives none; scheme and namespace match exactly; a top-level `settlementReference` is ignored. Requirements I-SET-1, I-SET-2 now cite them; I-SET-3 added |
| 22 | Four mutants survived the whole cycle: the second issuer's network regex admitting `.` (M16), the reference verifier admitting `.` in the network reference (M10b), `checks.advertisement` reported `not_evaluated` instead of `absent` beside other bindings (M05b), a negative clock treated as a configuration error (M12b) | suite gap | Fixed cases for each: `refuse_network_reference_dot`, `neg_schema_network_reference_dot`, `pos_advertisement_absent_other_bindings`, `pos_clock_negative_archival`; and both sides of every configuration bound (clock ±(2^53 - 1) valid, ±2^53 `ERROR`; `maxAgeSeconds` 0 and 2^53 - 1 valid, 2^53 `ERROR`, a receipt one second old stale under 0). Sweeping the other bounds of §3, §4.5, §4.6 and §5 added: `issuedAt` at -(2^53 - 1) and -(2^53), payload nesting 8, held requirements and advertised `info` at 2^53 - 1 / 2^53 and 8 / 9 levels, binding prefix, name and value of length 0, characters 0x20 and 0x7F. Each new rule has a flip |
| 23 | Rules caught only by a fuzzer, never by a named case: step 4 comparing `asset` and `maxTimeoutSeconds`, a supplied `action-receipt:reversal-transaction` binding, `authorization.from` off `eip155` (M06, M17, M07, M14 were killed by the fuzzers and by flip-probe setup errors, not by an exchange) | suite gap | Exchanges `refuse_offered_asset_changed`, `refuse_offered_max_timeout_changed`, `refuse_offered_scheme_changed`, `refuse_offered_network_changed`, `refuse_binding_reserved_reversal_type`, `issue_payer_from_authorization_non_evm`; issuer flips for each |
| 24 | The text claimed the JavaScript implementations were independent of the Python ones; for 0.4 each side was revised by one implementer, and both verifiers use OpenSSL | B (text wrong) | §7 and the README now say so, and say some defects are caught only by the fuzzers |
| 25 | §5.8's new consumer sentence had no requirement | suite gap | C-13 (consumer, untested) |
| 26 | A line beginning with a UTF-8 byte-order mark: the Node issuer stripped it and issued, the Python issuer answered `invalid_input` | A (Node) | Both answer `invalid_input`; protocol case `not_json_leading_bom`; flip |
| 27 | `cycle.py` ignored the fuzzers' exit codes and `fuzz_issuer.py`'s `status`, `problems` and `operators_never_applied`; `--seeds 7,7` ran a seed twice; `flip_issuer.py` and `flip_probe.py` passed with an empty flip list; `run_exchanges.py --help` raised a traceback; the CI comment named a local cycle's seeds and said CI explores | C | Each fixed; a fuzzer that reports a problem fails its stage |

**This cycle.** Seeds 151 to 153, 3,000 each: 9,000 cases and 3,328 follow-ups
through both verifiers, 9,000 exchanges and 5,462 round trips through both
issuers and both verifiers; 0 disagreements, 0 property violations, all twelve
stages passed. 256 vectors, 178 exchanges, 153 verifier flips, 133 issuer
flips, 156 requirements (124 tested). Seeds 161 and 162 ran one fuzzer each
while the fixes were made.

The reviewer's 21 mutants were re-run against the result: with the fixed-case
stages alone (`cycle.py --quick`) all 21 are killed, each by a named vector or
exchange. Through the full cycle (seeds 171 and 172, 3,000 each) all 21 are
killed as well; none survives. A flip-probe stage that fails only with "broken"
or "setup errors" is an artifact of the mutant editing the line a flip patches,
not a detection, so it is not counted as a kill above. The mutant labelled M15
by the reviewer (find the reference by the table) is now the correct
behaviour; it was re-run reversed (the old out-of-band read) and is killed by
eight exchanges.

## Cycle 11 — 2026-11-21 (chargedAmount)

Spec 0.4 added the member `chargedAmount` (§4.1, §4.3, §4.6, §5.8, §6.2 step 7,
§6.3). All four implementations carry it; the worked example of §4.7 was
recomputed with `action_receipt.py --worked` (662 bytes, new `receiptRef` and
compact JWS). Every existing expectation was kept; existing payloads gained the
member, with each exchange's value decided from its own response (EVM `exact`
`10000` from `amount`; Solana batch `10000` from `extra.chargedAmount`, `""`
where the exchange replaces `extra`; SVM `exact` and Cloudflare `""`).

Nine hand-written mutants of the new rule were run in scratch copies, first
through the full cycle (seeds 211 and 212, 3,000 each), then through the fixed
stages alone:

| # | Mutant | Killed by, before the fix | Fixed cases added |
|---|---|---|---|
| M01 | verifier reads `extra.chargedAmount` only on `solana:` | the issuer round trip and both fuzzers; no vector | `pos_charged_amount_from_extra_any_scheme`, `pos_charged_amount_from_extra_cloudflare` |
| M02 | issuer strips leading zeros | `refuse_charged_amount_leading_zero`, `refuse_charged_amount_extra_out_of_grammar` | — |
| M03 | Node issuer treats an `extra.chargedAmount` of `0` as missing | the issuer fuzzer only | `issue_charged_amount_extra_zero_overrides_amount`, `pos_charged_amount_extra_zero` |
| M04 | Node verifier bound 77 digits | `pos_charged_amount_78_digits`, `issue_charged_amount_78_digits` | — |
| M05 | Node verifier skips the comparison when the receipt's is `""` | `neg_settlement_charged_amount_dropped` | — |
| M06 | issuer takes `accepted.amount` under `exact` when the response has none | `issue_charged_amount_empty_no_amount`, `issue_svm_exact` and six more | — |
| M07 | verifier checks the grammar only on `eip155` | the verifier fuzzer only | `neg_schema_charged_amount_leading_zero_non_evm`, `refuse_charged_amount_leading_zero_svm` |
| M08 | Node issuer checks the amount after step 8 | `refuse_order_charged_amount_before_statement` | — |
| M09 | Node verifier compares amounts as integers | `neg_settlement_charged_amount_not_normalized` | — |

None survived the full cycle. Three (M01, M03, M07) were caught by no named
case; after the fixed cases above, all nine are killed by a named vector or
exchange in the fixed stages (`cycle.py --quick`).

Seeds 201 to 203, 3,000 each: all twelve stages passed. 280 vectors, 197
exchanges, 173 verifier flips, 151 issuer flips, 165 requirements (133 tested).
Seed 9001 ran each fuzzer once while the operators were written.

## Known limits of this process

- Both verifiers were written in one working session, one of them from the spec
  text alone; for draft 0.4 one implementer revised both. Agreement between them
  is weaker evidence than agreement with an implementation by someone else.
- The fuzzer compares the two implementations with each other. A reading that
  both share and that is wrong is invisible to it; only the properties (P1 to P6)
  and the hand-declared vector expectations stand against that.
- The properties are few and all concern a passing receipt.
- 32 of 156 requirements are not tested, 8 of them verifier requirements (draft
  0.4, cycle 10). They are listed with reasons in `CONFORMANCE.md`.
- Issuer conformance covers the payload an issuer builds and its refusals. It
  does not cover signing, the randomness of `receiptId`, or key retention.
- The scheme-payload payer is defined for one field,
  `payload.authorization.from`; other schemes are untested.
- Every settlement identifier is synthetic. Nothing here touches a payment rail,
  a DID document or DNS.
- The flip probe patches source text. A refactor that changes a patched line
  makes that flip a setup error, which fails the run until the pattern is updated.
