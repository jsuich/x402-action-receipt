# Independent review of draft 0.3, and what draft 0.4 did about it

2026-11-20. Six reviewers read draft 0.3 (commit `e8c72ad`) in parallel. Each had
one question, worked on its own copy, and was not given the author's view of the
draft or the other reviewers' findings. Reviewers B to E had to reproduce a
claim about the code with a script before it counted.

| Reviewer | Question | Findings (blocker / major / minor) |
|---|---|---|
| A | Is the spec, read alone, a coherent model? (No code read.) | 5 / 12 / 7 |
| B | Do the two verifiers do what the spec says? | 6 / 2 / 5 |
| C | Do the two issuers do what the spec says, and can a faithful issuer emit what a faithful verifier rejects? | 3 / 5 / 5 |
| D | What does a verified receipt prove, against which adversary? | 1 / 5 / 9 |
| E | When the conformance process is green, what has been established? | 4 / 6 / 6 |
| F | Does the draft's picture of x402 match upstream (`9271066d`)? | 3 / 9 / 7 |

Severity is each reviewer's own, on the rubric it was given; a "blocker" from B
includes any disagreement between the two verifiers, including ones that need a
wrong value in the verifier's own configuration.

## What the review showed about the design

Four reviewers arrived separately at the same faults. That agreement is the
strongest evidence in the review.

1. **The payload was specified tightly and everything around it loosely.** The
   JWS header had no canonical form (A, B, D). The verifier's own configuration
   had no contract, so wrong values fell through to defaults (B, D). The key
   fixture accepted private keys and certificates in one implementation (B, D).
   0.4 gives each of these a rule.
2. **The model was EVM `exact` with wider claims.** The network grammar rejected
   a network upstream ships; `payer` was mandatory where one binding forbids it;
   `settlementRef` had no source on the schemes it was motivated by (F; A found
   the last from the text alone). 0.4 loosens the grammar and `payer`, names the
   one settlement reference upstream defines, and states which schemes are not
   covered.
3. **The receipt claimed more than a verifier can establish.** Nothing ties the
   signer to the party paid (D). Archival verification has no trust root a third
   party can check (A, D). The digest covered client-written requirements (C, D).
   There is no identifier for a payment, and the mandated counting key was wrong
   in the spec's own batch example (A, D). 0.4 adds an issuer step for the
   requirements and narrows the other claims in §1.2, §1.3, §5.14 and §9.
4. **The lifecycle promised delivery it does not have.** Superseding receipts
   had no channel and no rules (A, C, D, F). 0.4 gives consumers rules for
   honouring a supersession and removes the promise. Whether the lifecycle
   should stay at all is open question 6.
5. **The issuer and verifier used different definitions of a present value**
   (A predicted it; C reproduced it: a to-the-letter issuer emitted receipts
   both verifiers rejected). 0.4 has one definition, in §4.6.
6. **Green did not mean conforming.** The cycle passed with zero fuzz cases; 14
   mutants survived it, three of which accept what the spec rejects; a rule
   marked tested was removed from all four implementations with no effect; a
   lookup table reproduced the manifest (E). 14 of 15 issuer mutants passed all
   exchanges (C).

## Findings and dispositions

Disposition codes: **text** (spec changed), **code** (implementation changed,
with a case that fails if it regresses), **claim** (the spec now says less),
**open** (recorded, not resolved), **declined** (with the reason).

### Model (reviewer A)

| Id | Finding | Disposition |
|---|---|---|
| A-B1 | Counting key gives the wrong count in the batch case; no payment identifier | claim: §4.7, §1.3; open question 8 |
| A-B2 | Unreachable authorization source rejected as `signer`; §9 promised `key_unresolved` | text + code: §5.4 three answers |
| A-B3 | Non-requesting verifier forbidden to use the only URL it has | text: §5.4 rule is now about `kid`, not `resourceUrl` |
| A-B4 | "Resource URL it paid for" undefined | text: §5 inputs pin it to `PaymentRequired.resource.url` |
| A-B5 | §6.3 round-trip guarantee false | text + code: one "present" definition; guarantee restated with its preconditions |
| A-M1 | `settlementRef` has no source | text: §4.3 table |
| A-M2 | `failed` and `capturePending` definitions mix payment and delivery | text: §4.2, §4.3 |
| A-M3, A-M4 | Superseding receipts: no channel, no transition rules, forks | text: §4.3 consumer rules; open question 6 |
| A-M5 | Authorization "scoped to the resource" over host-scoped mechanisms | text: §5.4 says what the base mechanisms can express |
| A-M6 | A server can omit the advertisement binding unseen | text + code: `checks.advertisement: absent` |
| A-M7 | Binding ownership and criticality | text: §4.5.1; closed `action-receipt:` namespace in code |
| A-M8 | `version` code unreachable behind the member-set check | text + code: §5.3 order |
| A-M9 | §1.2 and Summary overclaim | claim |
| A-M10 | Statement has no derivation; `agent`, `scope` undefined | text: stated as opaque and as the issuer's own |
| A-M11 | §2.4 equality conflicts with lowercase rule | text |
| A-M12 | Header has no canonical form | text + code |

### Verifier (reviewer B)

| Id | Finding | Disposition |
|---|---|---|
| B-1 | Python accepts a non-JSON header | code (header canonical form) |
| B-2 | Python returns ERROR on a non-string `alg` | code |
| B-3 | Python treats any unknown mode as archival | code (configuration contract) |
| B-4 | JavaScript accepts a private key or certificate as the key | code |
| B-5 | Wrong-typed clock and maximum age give three verdicts | code (configuration contract) |
| B-6 | Python returns ERROR for an unknown key algorithm | code |
| B-M1 | Header with huge integer or deep nesting: different reasons | code (header in the value domain) |
| B-M2 | Fixture authorization entry of the wrong type | code |
| B-m1 | Fixture key for anchor (b) is ambiguous off EVM | open: fixture only |
| B-m2 | `verify.mjs` silent exit 0 through a symlink; cycle scored it as pass | code |
| B-m3 | Duplicate header members accepted | code (header canonical form) |
| B-m4, B-m5 | Wrong-typed context values | code (configuration contract) |
| B-T1..T10 | Trace gaps | code: requirements added |

### Issuer (reviewer C)

| Id | Finding | Disposition |
|---|---|---|
| C-F1 | To-the-letter issuer emits what verifiers reject | text + code: one "present" definition |
| C-F2 | `issuer.py --batch` crashes on valid JSON | code |
| C-F3 | Two answers for advertised `scope: null` | text: the advertised `info` is never read leniently; case pinned |
| C-F4 | Conventions applied unevenly; malformed reversal transaction dropped | text + code: statement read strictly |
| C-F5 | 14 of 15 issuer mutants pass the exchanges | code: exchanges per sub-check; issuer self-check |
| C-F6 | Issuer signs client-written requirements | text + code: step 4 `requirements_not_offered` |
| C-F7 | Superseding receipts | as A-M3 |
| C-F8 | Signing outside §6; no low-`s` duty | text: §6.3 signing |
| C-F9 | `issuer.mjs` reports its own faults as a refusal | code |
| C-F10 | Reversal transaction not lowercased or checked | text + code |
| C-F11 | Number value is the IEEE double | text: §4.6 |
| C-F12 | `willIssueReceipt` never read | text: §2.3 says the advertisement obliges nothing |

### Security (reviewer D)

| Id | Finding | Disposition |
|---|---|---|
| D-01 | As B-1 | code |
| D-02 | Signer need not be the paid party | claim: §1.3, §5.14, §9 |
| D-03 | Archival verification has no third-party trust root; backdating; rebinding | claim: Summary, §5.4, §9 |
| D-04 | An action receipt may verify as a base receipt | claim: §2.4, §9 (not in this extension's hands) |
| D-05 | As C-F6 | text + code |
| D-06 | `supersedes` unconstrained | text: §4.3 consumer rules |
| D-07 | Unknown `action-receipt:*` bindings pass | code: closed namespace |
| D-08 | Duplicate-member headers | code |
| D-09 | One receipt passes for two payments under one reference | claim: §4.7 |
| D-10 | Anchor (b): who vouches | text: §5.4 |
| D-11 | As B-4 | code |
| D-12 | No size bound | text + code: 65536 |
| D-13 | Control and bidi characters; no URL grammar | claim: §4.6, §9 |
| D-14 | As A-B4 | text |
| D-15 | Context-validation differentials | code |

### Fit to x402 (reviewer F)

| Id | Finding | Disposition |
|---|---|---|
| F-B1 | Network grammar rejects `cloudflare:402` | text + code |
| F-B2 | `payer` mandatory; Lightning forbids one | text + code: `payer` may be `""` |
| F-B3 | `settlementRef` has no source | text: §4.3 table; uncovered schemes stated |
| F-M1 | Payer fallback exists only for EIP-3009 | text: §4.3; else `""` |
| F-M2 | Amount charged not stated | claim: §1.3; open question 5 |
| F-M3 | `settled` asserted where nothing moved | text: definitions; vector corrected |
| F-M4, F-M5 | Supersession channel; lifecycle gaps | text: §4.3; open question 6 |
| F-M6 | `failed` unreachable in the default flow | text: §4.2 |
| F-M7 | Zero-amount `upto` has no identifier | claim: §1.3 |
| F-M8 | §2.4 equality the base implementation will not produce | text |
| F-M9 | Fixtures are relabelled EVM `exact` | partly: fixtures corrected; §7 states the limit |

### Test process (reviewer E)

| Id | Finding | Disposition |
|---|---|---|
| E-F1 | Reference verifier violates the spec, cycle green | code (as B-1, B-2, B-M1); fuzzer now mutates headers |
| E-F2, E-F3 | 10 single and 4 common-mode mutants survive | code: fixed cases for each; boundary cases for every constant |
| E-F4 | Cycle passes with zero fuzz cases | code |
| E-F5 | Trace sees only RFC 2119 sentences | open: requirements added by hand for the statements named; the trace still cannot see a rule written without a keyword |
| E-F6 | "Tested" means a file exists; `vectorsDigest` unverified | code |
| E-F7 | Flip probe overstates; no JavaScript flips | code |
| E-F8 | Independence: shared code, self-written reports, one crypto library | partly: properties evaluated on both; the rest stated in §7 |
| E-F9 | Lookup-table implementations pass | partly: adapter runner and fuzz accept a third-party adapter; a fixed manifest alone cannot defeat a lookup table |
| E-F10 | §5.4 reduced to a fixture lookup | open: `did:web` host rule and "as of `issuedAt`" are not implemented anywhere |

## How the code dispositions were verified

Two implementers, each in its own clone, brought the verifier side and then the
issuer side to the 0.4 text without editing it; their questions were answered
in the spec (commit `d920250`). Then the author re-ran everything on seeds
neither implementer had used:

| Check | Result |
|---|---|
| `cycle.py --seeds 121,122,123 --n 3000` | 12 of 12 stages pass, 0 void |
| Verifier vectors | 229 (60 positive, 152 negative, 17 configuration), every report declared by hand; both verifiers agree on all of them through the adapter runner |
| Issuer exchanges | 158 (60 issued, 98 refused); every issued payload, signed, passes both verifiers with the §6.3 report |
| Verifier flips | 138 of 138 caught by a named vector (93 Python, 45 JavaScript) |
| Issuer flips | 119 of 119 caught by a named case (73 Python, 46 JavaScript) |
| Fuzzing | 9000 verifier cases and 9000 exchanges, 0 disagreements, 0 property violations |
| Reviewer E's 14 surviving mutants | all killed by fixed cases |
| New mutants by the implementers | verifier 19 of 20 killed by fixed vectors (survivor argued equivalent); issuer 18 of 18 after six witnesses were added (12 of 18 before) |
| Mutants by the author | three (freshness skew `<=`, binding count 17, offered requirements compared by amount only): all killed by fixed cases |
| Signing | 1200 signatures (400 per algorithm, 800 of them ECDSA with a stock randomized signer, low-`s` normalized), all pass both verifiers; without normalization 45 to 58 of 100 ECDSA signatures are rejected |
| 0.3 implementations against the 0.4 suite | every B and D defect shows as a red vector |

One defect introduced during the fix: commit `d920250` added a paragraph to
§5.13 that the verifier suite's reason-code drift check read as a new reason
code, and the author ran only the trace after that edit, not the cycle. The
issuer implementer found it, and `af226c9` makes the check read only the table.

Remaining limits, as stated in §7: every implementation came from one working
session; `did:web` and authorization "as of `issuedAt`" are implemented nowhere;
the trace sees only sentences with an RFC 2119 keyword; a fixed manifest cannot
defeat an implementation that looks receipts up by their signature string.

## What was found sound

- Every worked and wire example reproduces from the printed text (A).
- The verification step order holds for 20 single faults and all 187 compatible
  pairs, in both verifiers (B).
- Signature handling, base64url strictness, payload canonicalization, ASCII-only
  normalization, and linear behaviour on hostile sizes (B, D).
- The two issuers agree on 145 hand-built exchanges apart from adapter crashes,
  and no issued payload differed (C).
- The differential fuzzer killed 40 of the 50 mutants the fixed suites missed
  (E).

## Limits of this review

All six reviewers and both implementers are the same model family, working from
one session. They were isolated from each other and from the author's view, and
they disagreed with the draft freely, but that is not the same as an outside
implementer. Reviewer F read twelve per-network `exact` specifications by search
only, and the pull requests §11 cites were not in the upstream tree at the commit
read.
