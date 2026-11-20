# Extension: `action-receipt`

Draft 0.3 (2026-11-19). Proposal for discussion; see the version history for what
changed against the 0.2.1 draft. Where this file and the reference suite
disagree, this file governs.

## Summary

`action-receipt` is an optional x402 extension. After a payment settles, the
resource server returns a signed statement of **what was done, within what scope,
with what outcome**, bound to:

- the settlement (a transaction hash or a scheme's settlement reference),
- the payment requirements the client accepted (amount, asset, recipient, scheme),
- and, through signed **binding slots**, evidence defined by other extensions
  (a response hash, an authorization commitment, a refund transaction).

A third party holding the receipt can check, without calling the server, that the
statement is authentic, unmodified, signed by a key authorized for the resource,
and consistent with the settlement and payment terms the verifier holds.

The receipt is a JWS (RFC 7515) over an RFC 8785 (JCS) payload, hashed with
SHA-256. It introduces no new cryptographic primitive. It reuses the object shape,
JWS conventions and signer-authorization model of the Offer and Receipt extension
(`specs/extensions/extension-offer-and-receipt.md`, "the base extension" below;
section references to it are written "base §n", and to the core v2 specification
"core §n").

## 1. Scope and limits

### 1.1 What the base receipt does not carry

The base receipt states that a payment for a resource occurred. It does not say
what the server did for the payment, what happened when the server did not
deliver, which payment terms were accepted, or what later became of the payment
(captured, reversed, refunded). Its settlement reference is optional. Those are
the facts a dispute, an audit or an accounting system needs after settlement.

### 1.2 What a valid receipt establishes

A receipt that passes §5 establishes exactly this:

- a key authorized for `resourceUrl` signed this statement, and it is unmodified;
- the statement names the settlement and payment terms that the verifier holds.

### 1.3 What it does not establish (non-goals)

- **It is the signer's statement, and the signer is a party.** The resource
  server is the paid counterparty. `action.outcome`, `action.scope`,
  `action.agent`, `settlementStatus` and `issuedAt` are asserted by it. A receipt
  is evidence of what the server said, not an independent finding. Section 7's
  mutation matrix lists which members nothing the verifier holds can constrain.
- **It does not prove funds moved.** The checks in §5.7 and §5.8 compare the
  receipt with a `SettlementResponse`, which is unsigned. Establishing that the
  settlement exists requires resolving the settlement identifier on the payment
  rail (§5.14).
- **It does not prove the work was correct**, or say what was returned. Binding
  the response content is delegated to other extensions through §4.5.
- **Absence proves nothing.** A server can decline to issue a receipt for a
  delivery that went badly. A missing receipt is "no attestation available", not
  a payment failure and not a protocol error.
- **It is not unlinkable.** See §10.

## 2. Roles and placement

### 2.1 Who signs

The resource server signs and emits the receipt after it has the settlement
result. The facilitator does not sign it: the facilitator never sees the request
or the response, so it cannot state an outcome.

### 2.2 Placement

On success the receipt is returned under its own extension key:

```
SettlementResponse.extensions["action-receipt"].info.receipt
```

Per core §5.1.2 the extension object carries `info` and `schema` (§8). The
receipt is not a facilitator extension and does not appear in `/supported`.

### 2.3 Advertisement

A resource server that will issue receipts SHOULD advertise the extension in
`PaymentRequired.extensions["action-receipt"]`. The advertised `info` is a static
object:

| Member | Type | Required | Meaning |
|---|---|---|---|
| `willIssueReceipt` | boolean | Yes | `true` |
| `actionType` | string | No | The `action.actionType` the receipt will carry |
| `scope` | string | No | The `action.scope` the receipt will carry |

The client echoes `info` in `PaymentPayload.extensions` as core §5.1.2 requires.
When the server advertised `actionType` or `scope`, the receipt it later issues
MUST carry the same values, and the server SHOULD commit the advertisement with
the `action-receipt:advertised-info` binding (§4.5.2). That is what lets a client
show the scope it paid for was fixed before it paid. This is an issuer
requirement: no step of §5 rejects on it. A verifier sees a violation as a
`mismatched` binding, and only when the server included the binding.

### 2.4 Relationship to the base receipt

A server MAY emit both a base receipt and an action receipt. When it does, the
members the two have in common (`network`, `resourceUrl`, `payer`, `issuedAt`,
and `transaction` when the base receipt carries one) MUST be equal.

This is a separate extension, not a new payload version of the base receipt,
because it makes a different statement. A base receipt is issued "only on success,
confirming that payment was received and service was delivered" (base §5) and is
privacy-minimal by default (base §5.2, §11). An action receipt can state that the
service was refused or that the payment was reversed, and it is deliberately not
minimal. A verifier MUST NOT verify an action receipt as a base receipt or the
reverse; the `typ` header (§3) makes the two distinguishable under the signature.

## 3. Envelope and JWS header

The receipt object has the base extension's JWS shape (base §3.1, §3.1.1):

```json
{ "format": "jws", "signature": "<JWS Compact Serialization>" }
```

`payload` is omitted; the compact string carries it. Any other member of the
receipt object is ignored and is not covered by the signature.

All base64url in this specification is unpadded (RFC 7515 §2) and has one
spelling per byte string: only the characters `A-Z a-z 0-9 - _`, and re-encoding
the decoded bytes MUST reproduce the string. (A final character with non-zero
padding bits decodes to the same bytes in a lenient decoder; it is rejected, so
that one receipt does not have several compact strings.)

The JWS protected header contains exactly three members:

| Member | Value |
|---|---|
| `alg` | `ES256` (P-256), `ES256K` (secp256k1) or `EdDSA` (Ed25519) |
| `kid` | string; the key identifier, normally a DID URL (base §3.3) |
| `typ` | `x402-action-receipt+jws` |

ECDSA signatures are the 64-byte `r || s` form of RFC 7518 §3.4 and MUST be
low-`s` (`s <= floor(n/2)`). `ES256K` is ECDSA over secp256k1 with SHA-256
(RFC 8812). The header is parsed as JSON and checked as a parsed object; no
canonical form is required of it.

## 4. Receipt payload

### 4.1 Members

The JWS payload is a JSON object with **exactly** the members below. The set is
closed: a payload with any other member, or missing one, is rejected. Every
member is always present; "none" is the empty string or the empty array, so the
shape never varies.

The Source column is normative for the issuer: it says where each value comes
from, so that two implementations build the same payload from the same exchange.

| Member | Type | Source (issuer) | Meaning |
|---|---|---|---|
| `version` | integer | constant | `1` |
| `receiptId` | string | issuer-generated | Unique per receipt (§4.3) |
| `issuedAt` | integer | issuer clock | Unix seconds at signing |
| `network` | string | `PaymentPayload.accepted.network` | CAIP-2 network identifier |
| `resourceUrl` | string | `PaymentRequired.resource.url`, verbatim | The paid resource |
| `payer` | string | `SettlementResponse.payer`; if absent, the payer address in the scheme's payment payload | Who paid |
| `payTo` | string | `PaymentPayload.accepted.payTo` | Who was paid |
| `transaction` | string | `SettlementResponse.transaction` | Settlement transaction, or `""` |
| `settlementRef` | string | the scheme's non-transaction settlement identifier | Or `""` (§4.3) |
| `settlementStatus` | string | issuer | Payment lifecycle (§4.3) |
| `requirementsDigest` | string | computed (§4.4) | Digest of the accepted payment requirements |
| `supersedes` | string | `receiptRef` of an earlier receipt | Or `""` (§4.3) |
| `action` | object | issuer (§4.2) | What was done |
| `bindings` | array | issuer (§4.5) | Evidence defined by other extensions |

Values copied from another x402 object are copied verbatim, with one exception:
on `eip155` networks `payer`, `payTo` and `transaction` are written in lowercase
hex (§4.6).

### 4.2 The `action` object

Exactly four string members:

| Member | Meaning |
|---|---|
| `agent` | Identifier of the party the server acted for or as (for example a DID). Non-empty. Asserted by the server; this extension does not authenticate it |
| `actionType` | What was done, for example `inference.completion`. Non-empty |
| `scope` | The authorization scope the action fell within. May be empty |
| `outcome` | One of the values below |

`outcome` describes service delivery. It is independent of whether the payment
settled, which is `settlementStatus`.

| `outcome` | Meaning |
|---|---|
| `delivered` | The service was performed and the result returned |
| `partial` | Part of the service was performed |
| `refused` | The payment settled and the server did not perform the service |
| `disputed` | The server records that the payer contests delivery |

`refused` here means "paid, not delivered". A payment the server declined to
accept is a different event and is out of scope (§11).

### 4.3 Identity, settlement and lifecycle

**`receiptId`** is 22 to 64 characters from the base64url alphabet. The issuer
MUST generate at least 128 bits of it from a cryptographically secure source and
MUST NOT reuse a value. It exists so that two payments which share every other
member are still two receipts. That case is ordinary: two payments by one payer
for one resource in the same second under one batch settlement.

**Settlement identifiers.** At least one of `transaction` and `settlementRef` is
non-empty. `settlementRef` is this extension's name for a scheme's settlement
identifier that is not a transaction hash, for example the commitment identifier
of a batch-settlement scheme or an authorization identifier under auth-capture.
Core defines no such field in `SettlementResponse`; the verifier obtains the value
from the scheme-specific settlement result. A receipt MUST NOT carry an identifier
the server did not receive from settlement.

**`settlementStatus`** is the payment lifecycle as the server observed it at
`issuedAt`:

| Value | Meaning |
|---|---|
| `settled` | Funds captured |
| `capturePending` | Service delivered under an authorization; capture not yet landed |
| `reversed` | The authorization was voided |
| `refunded` | Funds were captured and then returned |

A verifier or consumer MUST NOT read a passing receipt as "paid": it MUST read
`settlementStatus`. It MUST NOT read `settlementStatus` as evidence about
delivery, or `outcome` as evidence about payment.

**`supersedes`.** When the lifecycle moves on, the server issues a new receipt
with a new `receiptId` and sets `supersedes` to the `receiptRef` (§4.7) of the
receipt it replaces. Otherwise `supersedes` is `""`. A holder of an older receipt
cannot learn from that receipt that it was superseded; a consumer that needs the
current state MUST obtain the latest receipt or resolve the settlement on the
rail. When the reversal or refund has its own transaction, the server SHOULD
carry it in the `action-receipt:reversal-transaction` binding (§4.5.2).

### 4.4 `requirementsDigest`

```
requirementsDigest = "sha256:" || lowercase-hex( SHA-256( JCS( accepted ) ) )
```

`accepted` is the `PaymentRequirements` object the client selected, exactly as it
appears in `PaymentPayload.accepted` (core §5.2). The parsed object is
canonicalized as it stands: no member is added, removed, renamed or case-folded.

This commits the receipt to the terms agreed before payment: `scheme`, `network`,
`amount`, `asset`, `payTo`, `maxTimeoutSeconds` and `extra`. A verifier that
holds the `PaymentPayload` recomputes it (§5.9).

`accepted` MUST lie in the value domain of §4.6. If it does not (for example a
scheme whose `extra` contains a non-integer number), the server cannot compute
the digest and MUST NOT issue a receipt for that payment.

### 4.5 `bindings`: signed slots for other extensions

`bindings` lets a receipt carry evidence that another specification defines,
under this receipt's signature, **without a change to this schema**. Each entry
is an object with exactly two string members:

| Member | Constraint |
|---|---|
| `type` | `prefix ":" name`. `prefix` is 1 to 64 characters, lowercase letter first, then lowercase letters, digits, `+`, `.` or `-`. `name` is 1 to 191 printable ASCII characters (0x21 to 0x7E) |
| `value` | 1 to 1024 printable ASCII characters (0x21 to 0x7E) |

The array holds at most 16 entries, in strictly ascending order of `type`
(compared as ASCII strings), so a `type` appears at most once and a set of
bindings has one serialization.

#### 4.5.1 Carriage rules

- **Who defines a type.** If `prefix` is an x402 extension key, the type is
  defined by that extension's specification. Otherwise `type` is a URI and is
  defined by whoever controls that URI. This specification defines only the types
  in §4.5.2.
- **Verbatim values.** `value` is the string exactly as the owning specification
  writes it. This extension does not re-encode, re-hash or interpret it.
- **Unknown types are not errors.** A verifier MUST NOT reject a receipt because
  it does not recognize a binding type. It reports the entry as `not_evaluated`
  (§5.11).
- **Bindings never change the verdict.** Each entry is reported with its own
  status. A consumer MUST NOT treat a `not_evaluated` or `mismatched` binding as
  verified.
- **No overriding.** A binding MUST NOT restate or contradict a member of §4.1.

What the signature gives a binding is carriage: the server committed to that
value, in this receipt, for this settlement. Whether the value is true is decided
by the owning specification's own procedure.

A new binding type needs no new version of this extension. A new top-level
member, a new enumeration value or a changed grammar does.

#### 4.5.2 Types defined by this specification

| `type` | `value` | Evaluated when |
|---|---|---|
| `action-receipt:advertised-info` | `"sha256:"` + hex of SHA-256 over the JCS form of the `info` object the server advertised (§2.3) | The verifier holds that `info` object. `matched` iff the digest is equal and, for each of `scope` and `actionType` present in `info`, the receipt's `action` member is equal. Otherwise `mismatched` |
| `action-receipt:reversal-transaction` | The rail's identifier of the transaction that reversed or refunded the payment | Never offline. A verifier that resolves it on the rail reports the result itself |

#### 4.5.3 Types owned by other proposals (informative)

These show how neighbouring work composes. Both specifications were open pull
requests when this draft was written, so the names may change; they are examples,
not dependencies.

| `type` | Carries | Defined by |
|---|---|---|
| `response-provenance:responseHash`, `response-provenance:fixedPointVersion` | What the response contained | `response-provenance` (x402 PR #3304) |
| `offer-receipt:authorizationMethod`, `offer-receipt:authorizationCommitment` | A salted commitment to the payment authorization | base receipt payload v2 (x402 PR #3827) |

A deployment that also computes an identifier defined outside x402 carries it the
same way, under a URI type.

### 4.6 Value domain and field grammar (normative)

**Value domain.** The payload bytes, and any object this extension hashes, are
the RFC 8785 serialization of a JSON value in which:

- every number is an integer in `[-(2^53 - 1), 2^53 - 1]`. The test is on the
  number's value, not its spelling: an object received as JSON text that spells
  a member `60.0` holds the integer 60, is in the domain, and serializes as `60`;
- every string and member name is well-formed Unicode (no unpaired surrogate);
- objects and arrays nest at most 8 levels deep, counting the outermost object
  or array as level 1; scalars do not count.

`true`, `false` and `null` are in the domain. The receipt payload uses none of
them, but an object hashed under §4.4 or §4.5.2 may.

Over this domain RFC 8785 reduces to: members sorted by UTF-16 code units, no
insignificant whitespace, strings escaped minimally (`\"`, `\\`, `\b`, `\f`,
`\n`, `\r`, `\t`, and `\u00XX` in lowercase hex for other code points below
0x20), integers in shortest decimal form.

**Agreement semantics.** Strings are compared as exact sequences of code points.
No Unicode normalization, case folding, percent-decoding or URL normalization is
applied to any signed member. Two receipts whose `agent` differ only in NFC
versus NFD form are different receipts.

**Field grammar.** A signed member that does not match its grammar is rejected;
it is never repaired.

| Member | Grammar |
|---|---|
| `version` | integer `1` |
| `issuedAt` | integer in `[0, 2^53 - 1]` |
| `receiptId` | `[A-Za-z0-9_-]{22,64}` |
| `network` | CAIP-2: `[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}` |
| `resourceUrl`, `payer`, `payTo` | non-empty string |
| `payer`, `payTo` when `network` begins `eip155:` | `0x[0-9a-f]{40}` |
| `transaction` | any string; when `network` begins `eip155:` and it is non-empty, `0x[0-9a-f]{64}` |
| `settlementRef` | any string |
| `transaction`, `settlementRef` | not both empty |
| `requirementsDigest` | `sha256:[0-9a-f]{64}` |
| `supersedes` | `""` or `sha256:[0-9a-f]{64}` |
| `action.agent`, `action.actionType` | non-empty string |
| `action.scope` | any string |
| `action.outcome`, `settlementStatus` | one of the values in §4.2, §4.3 |
| `bindings` | §4.5 |

EVM identifiers are lowercase because EIP-55 checksum casing gives one address
many spellings, and the receipt needs one. Values a verifier takes from
**unsigned** inputs are normalized before comparison (§5.8, §5.9); signed values
are not.

### 4.7 `receiptRef`

```
receiptRef = "sha256:" || lowercase-hex( SHA-256( JWS payload bytes ) )
```

The JWS payload bytes are the base64url-decoding of the second segment of the
compact string. `receiptRef` is derived; it is not a member of the payload.

It identifies the **signed statement**. It does not cover the JWS header or the
signature, so the same statement signed under two keys has one `receiptRef`. It
is the value `supersedes` carries, and the value a dispute record or an anchor
should reference. As 32 bytes of hex it can be used directly as a `bytes32`.

It is **not** a count of payments or of actions. A server can issue several
receipts for one settlement (§4.3 requires it when the lifecycle moves). A
consumer that counts payments MUST key on `(network, transaction)` or
`(network, settlementRef)`, never on `receiptRef` or `receiptId`.

**Worked example (normative).** Accepted payment requirements, in JCS form (230
bytes):

```
{"amount":"10000","asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","extra":{"name":"USD Coin","version":"2"},"maxTimeoutSeconds":60,"network":"eip155:8453","payTo":"0x209693Bc6afc0C5328bA36FaF03C514EF312287C","scheme":"exact"}
```

`requirementsDigest`:

```
sha256:928ef8ee5f5df7a325dc5a5e2dbd9a3cdf89ab71fe28dec7c713e6efdd36aabc
```

JWS protected header:

```
{"alg":"EdDSA","kid":"did:web:api.example.com#ed25519","typ":"x402-action-receipt+jws"}
```

JWS payload (638 bytes):

```
{"action":{"actionType":"inference.completion","agent":"did:web:agent.example","outcome":"delivered","scope":"read:model-x"},"bindings":[],"issuedAt":1703123456,"network":"eip155:8453","payTo":"0x209693bc6afc0c5328ba36faf03c514ef312287c","payer":"0x857b06519e91e3a54538791bdbb0e22373e36b66","receiptId":"Zm9yLXRlc3Rpbmctb25seS0wMQ","requirementsDigest":"sha256:928ef8ee5f5df7a325dc5a5e2dbd9a3cdf89ab71fe28dec7c713e6efdd36aabc","resourceUrl":"https://api.example.com/v1/complete","settlementRef":"","settlementStatus":"settled","supersedes":"","transaction":"0xabababababababababababababababababababababababababababababababab","version":1}
```

`receiptRef`:

```
sha256:5ea130c2d5c3750da8e54ea640cdbf653056202c08a2af4c43677947becda7c2
```

Signed with the Ed25519 key whose public key is
`MCowBQYDK2VwAyEA7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=` (SubjectPublicKeyInfo,
base64). Ed25519 signatures are deterministic, so the compact string reproduces
exactly:

```
eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YXBpLmV4YW1wbGUuY29tI2VkMjU1MTkiLCJ0eXAiOiJ4NDAyLWFjdGlvbi1yZWNlaXB0K2p3cyJ9.eyJhY3Rpb24iOnsiYWN0aW9uVHlwZSI6ImluZmVyZW5jZS5jb21wbGV0aW9uIiwiYWdlbnQiOiJkaWQ6d2ViOmFnZW50LmV4YW1wbGUiLCJvdXRjb21lIjoiZGVsaXZlcmVkIiwic2NvcGUiOiJyZWFkOm1vZGVsLXgifSwiYmluZGluZ3MiOltdLCJpc3N1ZWRBdCI6MTcwMzEyMzQ1NiwibmV0d29yayI6ImVpcDE1NTo4NDUzIiwicGF5VG8iOiIweDIwOTY5M2JjNmFmYzBjNTMyOGJhMzZmYWYwM2M1MTRlZjMxMjI4N2MiLCJwYXllciI6IjB4ODU3YjA2NTE5ZTkxZTNhNTQ1Mzg3OTFiZGJiMGUyMjM3M2UzNmI2NiIsInJlY2VpcHRJZCI6IlptOXlMWFJsYzNScGJtY3RiMjVzZVMwd01RIiwicmVxdWlyZW1lbnRzRGlnZXN0Ijoic2hhMjU2OjkyOGVmOGVlNWY1ZGY3YTMyNWRjNWE1ZTJkYmQ5YTNjZGY4OWFiNzFmZTI4ZGVjN2M3MTNlNmVmZGQzNmFhYmMiLCJyZXNvdXJjZVVybCI6Imh0dHBzOi8vYXBpLmV4YW1wbGUuY29tL3YxL2NvbXBsZXRlIiwic2V0dGxlbWVudFJlZiI6IiIsInNldHRsZW1lbnRTdGF0dXMiOiJzZXR0bGVkIiwic3VwZXJzZWRlcyI6IiIsInRyYW5zYWN0aW9uIjoiMHhhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiIiwidmVyc2lvbiI6MX0.3Cim_I_UfWkIMPo3NC9yevQbR0Gk4NmYsnz4sxT52FFR_zX40mQjDA22UEdmAV_KNRz2EgzE33WOPdRxY5GOBQ
```

The settlement transaction in this example is a placeholder, not a real
transaction.

## 5. Verification (normative)

**Inputs.** The verifier holds the receipt and:

- the `SettlementResponse` (core §5.3): `success`, `transaction`, `network`,
  optionally `payer`, and where the scheme has one, its non-transaction
  settlement identifier;
- optionally the `PaymentRequirements` the client accepted;
- optionally the `info` object the server advertised (§2.3);
- if the verifier made the payment itself, the resource URL it paid for;
- a clock, a maximum age, and a mode: `session` or `archival`;
- a way to learn which keys are authorized for a resource (§5.4).

**Outcomes.** Verification yields one of:

- `PASS`, with a report (§5.12);
- `REJECT`, with exactly one reason code (§5.13);
- `ERROR`, when the verifier itself failed (for example its canonicalizer
  disagreed with a second implementation). `ERROR` says nothing about the
  receipt and MUST NOT be reported as a rejection.

The verifier MUST perform the steps below **in order** and MUST stop at the first
failure. It MUST NOT raise on malformed input.

### 5.1 Envelope and header

1. Reject with `invalid_payload` unless the receipt is an object with
   `format == "jws"`; `signature` is a string of exactly three `.`-separated
   segments; each segment is unpadded base64url; and the first decodes to UTF-8
   text (no byte-order mark, no other encoding) that parses as a JSON object. A
   parser that detects encodings from the bytes MUST NOT be given the bytes.
2. Reject with `invalid_actionreceipt_typ` unless the header's `typ` is
   `x402-action-receipt+jws`.
3. Reject with `invalid_actionreceipt_alg` unless `alg` is `ES256`, `ES256K` or
   `EdDSA`.
4. Reject with `invalid_payload` unless the header has exactly the members
   `alg`, `kid`, `typ` and `kid` is a string.

### 5.2 Canonical bytes

Let `B` be the decoded payload segment. Reject with
`invalid_actionreceipt_canonicalization` unless all of these hold:

- `B` is valid UTF-8 and parses as JSON (RFC 8259). Any JSON value can pass
  this step: a payload of `null`, `[]` or `1` is canonical and is rejected by
  §5.3, not here;
- the parsed value lies in the value domain of §4.6;
- `JCS(parsed value) == B`, byte for byte.

This step comes **before** any typing so that parser differences between
languages all land on one reason code. Implementation notes:

- A payload that writes an integer as `1.0` or `1E0`, writes `-0`, repeats a
  member name, escapes a character that needs no escape, or contains whitespace
  fails the byte comparison in every language.
- Whether a number is an integer in range must be tested on the parsed value
  (in JavaScript, `Number.isSafeInteger`).
- An unpaired surrogate must be tested explicitly (in JavaScript,
  `String.prototype.isWellFormed`): some serializers reproduce the escape and
  the byte comparison alone would pass.

### 5.3 Closed schema and field grammar

Reject with the code shown, checking in this order:

1. `invalid_payload` unless the value is an object with exactly the members of
   §4.1, and `version` is an integer.
2. `invalid_actionreceipt_version` unless `version == 1`.
3. `invalid_payload` unless `action` is an object with exactly the members of
   §4.2; every string-typed member, including `action.outcome` and
   `settlementStatus`, is a string; and every member except `action.outcome`,
   `settlementStatus` and `bindings` satisfies every row of the grammar table in
   §4.6 that names it, including "not both empty".
4. `invalid_actionreceipt_outcome` unless `action.outcome` is a listed value.
5. `invalid_actionreceipt_status` unless `settlementStatus` is a listed value.
6. `invalid_payload` unless `bindings` is an array.
7. `invalid_actionreceipt_binding` unless `bindings` satisfies §4.5: at most 16
   entries, each an object with exactly `type` and `value`, both strings matching
   their grammar, in strictly ascending order of `type`.

### 5.4 Resource and signer authorization

A verifier that made the payment itself first rejects with
`invalid_actionreceipt_resource_mismatch` unless the receipt's `resourceUrl`
equals, as an exact string, the resource URL it paid for. A verifier that did not
make the payment has nothing to compare, and the report records
`resourceUrl: not_compared`.

Reject with `invalid_actionreceipt_signer` unless `kid` is authorized for the
receipt's `resourceUrl` by at least one of:

- (a) **the service**: a binding from the resource to the key identifier;
- (b) **the recipient**: a binding from the pair `(payTo, resourceUrl)` to the
  key identifier.

Both anchors are scoped to the resource. A key that is authorized for a
recipient address is not thereby authorized for every URL. Anchor (b) is looked
up with the receipt's own `payTo`, which is not yet bounded at this step (§5.9
bounds it); that is safe only because the anchor is itself tied to
`resourceUrl`.

Authorization uses the mechanisms of base §4.5.1 (`did:web` at the resource's
host, DNS TXT `_controllers.<host>`, or a registry the verifier trusts). Two
rules are specific to this extension:

- **Authorization precedes any fetch.** The verifier locates authorization data
  from context it already holds: the host of the `resourceUrl` it paid or is
  auditing, or its configured registry. It MUST NOT dereference a location that
  only the receipt names. A `did:web` `kid` whose host is not the host of
  `resourceUrl` is not authorized under (a) unless a registry the verifier
  trusts says so.
- **As of `issuedAt`.** In `archival` mode the question is whether the key was
  authorized when the receipt was issued (base §5.5). Removal of a key from a
  mutable source is prospective: it does not show the key was unauthorized at
  `issuedAt`.

### 5.5 Key resolution

If `kid` is authorized but the verifier cannot obtain a usable key (the document
is unreachable, the key has been rotated out and no record of it is held, or
what was obtained does not parse as a public key), reject with
`invalid_actionreceipt_key_unresolved`.

This code is **indeterminate**. It means the verifier could not check, not that
the receipt is forged. A consumer MUST NOT treat it as a finding against the
signer.

### 5.6 Signature

Reject with `invalid_actionreceipt_signature` unless the signature verifies over
`ASCII(segment1 || "." || segment2)` under the resolved key (RFC 7515), and:

- the key's type and curve match `alg`;
- for `ES256` and `ES256K`, the signature is 64 bytes and `s <= n/2`.

### 5.7 Settlement success

Reject with `invalid_transaction_state` unless the `SettlementResponse` has
`success == true` and provides at least one settlement identifier (a non-empty
`transaction`, or a settlement reference).

### 5.8 Settlement binding

Values from the `SettlementResponse` are unsigned. Before comparing, the verifier
normalizes them: when the **receipt's** `network` begins `eip155:` it lowercases
the response's `transaction` and `payer` (ASCII `A-F` to `a-f`). Nothing else is
normalized. Throughout §5.7 and §5.8 the response "has" a transaction, a
settlement reference or a payer when the value is a non-empty string; an absent
member, `null` and `""` all mean it has none. Reject with
`invalid_actionreceipt_settlement_mismatch` if any of these fails:

- If the response has a `transaction`, the receipt's `transaction` equals it.
  If the response has none, the receipt's `transaction` is `""`.
- If the response has a settlement reference, the receipt's `settlementRef`
  equals it. If it has none, the receipt's `settlementRef` is `""`.
- If the response's `network` is in CAIP-2 form, the receipt's `network` equals
  it. Otherwise the report records `network: not_compared`.
- If the response has a `payer`, the receipt's `payer` equals it. Otherwise the
  report records `payer: not_compared`.

The second half of the first two rules means a receipt cannot carry an identifier
the response does not corroborate, and cannot silently drop one the response has.

### 5.9 Payment requirements

If the verifier holds the accepted `PaymentRequirements`, as a JSON object in the
value domain of §4.6, reject with `invalid_actionreceipt_requirements_mismatch`
unless:

- `requirementsDigest` equals the digest computed per §4.4;
- `accepted.network` equals the receipt's `network`;
- `accepted.payTo`, lowercased on `eip155` networks, equals the receipt's
  `payTo`.

If the verifier does not hold them, or what it holds is not a JSON object or lies
outside the value domain (which no conforming issuer would have issued a receipt
for, §4.4), the report
records `requirements: not_evaluated` and `payTo: not_compared`. In that case
nothing bounds the receipt's `payTo` or the amount.

### 5.10 Freshness

Let `age = now - issuedAt`.

- In both modes, reject with `invalid_actionreceipt_freshness` if `age < -60`.
- In `session` mode, also reject if `age > maxAge`. The default `maxAge` is 3600
  seconds.
- In `archival` mode age is not a reason to reject. The report carries it.

`session` mode is for a client checking the receipt it was just handed.
`archival` mode is for an auditor or a dispute, where a receipt may be months
old and still accurate. `issuedAt` is asserted by the signer in either mode.

### 5.11 Bindings

For each entry of `bindings` the verifier records a status:

- `matched` or `mismatched`, for a type the verifier implements and holds the
  inputs for (§4.5.2);
- `not_evaluated` otherwise.

No binding status changes the verdict.

### 5.12 The report

`PASS` is returned with a report. A verifier MUST make at least this available:

| Member | Content |
|---|---|
| `receiptRef` | §4.7 |
| `outcome`, `settlementStatus` | Copied from the receipt |
| `ageSeconds` | `now - issuedAt` |
| `checks.resourceUrl`, `checks.network`, `checks.payer`, `checks.payTo` | `compared` or `not_compared` |
| `checks.requirements` | `matched` or `not_evaluated` |
| `checks.freshness` | `enforced` or `reported` |
| `supersedes` | Copied from the receipt |
| `bindings` | One `{type, status}` per entry |

`checks.freshness` is `enforced` in `session` mode and `reported` in `archival`
mode. `bindings` lists the entries in receipt order. In the conformance manifest
the report has exactly this shape:

```json
{
  "receiptRef": "sha256:5ea130c2d5c3750da8e54ea640cdbf653056202c08a2af4c43677947becda7c2",
  "outcome": "delivered",
  "settlementStatus": "settled",
  "ageSeconds": 44,
  "checks": {
    "resourceUrl": "not_compared",
    "network": "compared",
    "payer": "compared",
    "requirements": "matched",
    "payTo": "compared",
    "freshness": "enforced"
  },
  "supersedes": "",
  "bindings": []
}
```

A consumer MUST NOT read `PASS` as covering anything the report marks
`not_compared` or `not_evaluated`.

### 5.13 Reason codes

Codes follow core §9 and the `invalid_<extension>_<check>` convention.

| Step | Reason code |
|---|---|
| §5.1, §5.3 structure and grammar | `invalid_payload` |
| §5.1 `typ` | `invalid_actionreceipt_typ` |
| §5.1 `alg` | `invalid_actionreceipt_alg` |
| §5.2 | `invalid_actionreceipt_canonicalization` |
| §5.3 `version` | `invalid_actionreceipt_version` |
| §5.3 `outcome` | `invalid_actionreceipt_outcome` |
| §5.3 `settlementStatus` | `invalid_actionreceipt_status` |
| §5.3 `bindings` | `invalid_actionreceipt_binding` |
| §5.4 resource | `invalid_actionreceipt_resource_mismatch` |
| §5.4 signer | `invalid_actionreceipt_signer` |
| §5.5 (indeterminate) | `invalid_actionreceipt_key_unresolved` |
| §5.6 | `invalid_actionreceipt_signature` |
| §5.7 | `invalid_transaction_state` |
| §5.8 | `invalid_actionreceipt_settlement_mismatch` |
| §5.9 | `invalid_actionreceipt_requirements_mismatch` |
| §5.10 | `invalid_actionreceipt_freshness` |

Every code issued before §5.6 describes bytes that are not yet authenticated. A
canonicalization rejection has three possible causes: the issuer, an intermediary
that re-serialized the receipt, or the verifier's own canonicalizer. A verifier
SHOULD pass the conformance suite (§7) before reporting one against an issuer.

### 5.14 Verifier roles and grounding on the rail

A **requesting verifier** made the payment. It holds the request, the
`PaymentPayload` and the `SettlementResponse` first-hand, and MUST supply the URL
it paid for, so that §5.4 compares it with `resourceUrl`.

A **non-requesting verifier** (an auditor, an arbiter) holds recorded copies. It
MUST say so when it reports a result: everything it compared in §5.7 to §5.9
came from the party presenting the receipt or from the signer.

Either can go further by resolving the settlement identifier on the payment rail.
A verifier that does so SHOULD confirm that the node serves the chain named by
`network`, that the transaction succeeded, and that it transferred the asset and
amount of the accepted requirements from `payer` to `payTo`. It SHOULD NOT assume
the transaction's submitter is the payee: under x402 the facilitator usually
submits. This extension does not specify rail resolution further.

## 6. Issuer requirements

1. Sign only after settlement returns, and only with identifiers settlement
   returned.
2. Build each member from the source named in §4.1.
3. Generate `receiptId` per §4.3.
4. Keep every key that has signed a receipt resolvable for as long as receipts
   signed by it may need to be verified, and never rebind a `kid` to a different
   key. A dedicated signing key separate from the `payTo` key is RECOMMENDED
   (base §4.5.1).
5. When the lifecycle changes, issue a superseding receipt (§4.3).
6. When both receipts are emitted, keep them consistent (§2.4).

## 7. Conformance

The reference suite is at <https://github.com/jsuich/x402-action-receipt>: a
verifier, the vectors under `vectors/`, and `vectors/MANIFEST.json`, which states
for every vector the context to verify it in, the expected verdict, the reason
code on `REJECT` and the report on `PASS`. A conformance claim cites the
`vectorsDigest` in that manifest.

An implementation conforms if it reproduces every entry of the manifest.
`CONFORMANCE.md` in that repository lists every requirement of this document
with the vectors that test it, names the requirements the suite does not test,
and defines the adapter protocol a verifier is driven through.

Properties of the suite:

- **Two-sided.** It asserts that both verdicts were observed and that every
  reason code of §5.13 was exercised.
- **One fault per negative.** Each negative is a single mutation of a canonical
  positive, so its reason code does not depend on anything but the order of §5.
- **Mutation matrix.** Each signed member of a positive is changed once and
  re-signed. The suite records whether the result still passes. The members that
  still pass are the issuer-asserted ones (§1.3): `receiptId`, `issuedAt`,
  `settlementStatus`, `supersedes`, all four `action` members and `bindings`.
- **Identifier relations.** It asserts that two payments under one batch root in
  the same second have different `receiptRef` values, and that one statement
  signed under different keys has one.
- **No drift.** The reason codes in §5.13 are compared with the verifier's, and
  the vector index is generated from the tables the suite runs.
- **Each check can fail.** `flip_probe.py` disables each check of the verifier
  in turn and requires the suite to go red.
- **Implementable from this text.** A second verifier was written in JavaScript
  from this file and the vectors alone, without sight of the reference code, and
  reproduced the manifest. The places where that implementer had to choose
  between readings were then closed in this text.

`vectors/keys.json` is a test fixture. It stands in for the authorization and key
resolution of §5.4 and §5.5: `"__service__:<resourceUrl>"` and
`"__payTo__:<payTo>|<resourceUrl>"` list authorized key identifiers, and each key
identifier maps to a PEM public key. A key identifier that is authorized but has
no entry, or whose entry does not parse, exercises §5.5. It is not a wire format.

All settlement identifiers in the vectors are synthetic.

## 8. Wire examples

`PaymentRequired` advertisement:

```json
{
  "extensions": {
    "action-receipt": {
      "info": {
        "willIssueReceipt": true,
        "actionType": "inference.completion",
        "scope": "read:model-x"
      },
      "schema": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
          "willIssueReceipt": { "type": "boolean" },
          "actionType": { "type": "string" },
          "scope": { "type": "string" }
        },
        "required": ["willIssueReceipt"]
      }
    }
  }
}
```

`SettlementResponse` with a receipt (`signature` abbreviated; §4.7 has a complete
one):

```json
{
  "success": true,
  "transaction": "0xabababababababababababababababababababababababababababababababab",
  "network": "eip155:8453",
  "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
  "extensions": {
    "action-receipt": {
      "info": { "receipt": { "format": "jws", "signature": "eyJ...header.eyJ...payload.sig" } },
      "schema": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
          "receipt": {
            "type": "object",
            "properties": {
              "format": { "type": "string", "const": "jws" },
              "signature": { "type": "string" }
            },
            "required": ["format", "signature"]
          }
        },
        "required": ["receipt"]
      }
    }
  }
}
```

Here the response's `payer` is in checksum case and the receipt's is lowercase;
§5.8 compares them after lowercasing the response value.

A `bindings` array carrying an advertisement commitment and a response hash:

```json
[
  { "type": "action-receipt:advertised-info",
    "value": "sha256:33df93fe0564655d6fa711a9b0b6a390396132ca577f0b7cfac2f6cd3dbffd76" },
  { "type": "response-provenance:responseHash",
    "value": "sha256:81ea1f2227fd9df5b868954e6d26d091810352f148dade483b260844788ede03" }
]
```

## 9. Security considerations

- **A statement by a party** (§1.3). Trust in `outcome` rests on who signed, not
  on the signature's validity.
- **Unsigned settlement input.** §5.7 and §5.8 test consistency with a
  `SettlementResponse` that the signer relayed. They do not establish that funds
  moved. See §5.14.
- **Re-presentation.** A receipt is a bearer artifact. A verifier that must
  detect the same receipt shown twice keeps a set keyed by `receiptRef`. That
  detects re-presentation only; it does not count payments (§4.7).
- **Many receipts, one settlement.** A signer can issue any number of receipts
  for one settlement. A holder can present the one that reads best. `supersedes`
  lets an honest signer order them; it cannot stop a holder withholding the
  later one.
- **Key lifetime.** If the signer's origin disappears, or a key is rotated out
  with no record kept, old receipts become unverifiable
  (`invalid_actionreceipt_key_unresolved`), not invalid. Verifiers that retain
  receipts SHOULD retain the key and the authorization evidence they relied on,
  with the time they resolved it.
- **Algorithm and type confusion.** The key's type and curve are bound to `alg`
  (§5.6; RFC 8725 §3.1), and `typ` is required, so a receipt cannot be replayed
  as a different JWS-based artifact.
- **Client-chosen identifiers.** An identifier the client chooses (for example a
  `payment-identifier` id) MUST NOT be used as the sole link between a receipt
  and a settlement: an unrelated payment can reuse it.
- **Transport.** HTTPS remains essential (base §10). Where the integrity of the
  whole response matters, the `http-message-signatures` extension signs it; this
  extension signs only the receipt.

## 10. Privacy considerations

The receipt is not privacy-minimal. It carries the settlement identifier, the
payer, the recipient, the resource and a description of what was done. Use the
base receipt where that is not wanted.

`agent` and `scope` SHOULD be pseudonymous where the use case allows.

`receiptRef` and `requirementsDigest` are unsalted hashes of data that is largely
public or guessable. Anyone who can guess the inputs can confirm a guess.
Publishing a `receiptRef` (for example anchoring it) therefore links the anchor
to the payment for an observer who knows or can enumerate the payer's activity.
A deployment that needs to publish a commitment without that link should publish
a salted commitment and keep the salt with the receipt.

## 11. Relationship to other work

- **Base receipt** (`extension-offer-and-receipt.md`): reused for object shape,
  JWS conventions and signer authorization; see §2.4 for why this is a separate
  extension.
- **Issue #2332 and `action_ref`.** That proposal, and the individual draft that
  followed it, define `action_ref`: a digest over a four-field tuple (agent,
  action type, scope, timestamp) intended as a join key that any party can
  compute. `receiptRef` is a different thing: it identifies a signed statement
  and cannot be computed before the receipt exists. The two are not
  interchangeable, and this extension defines no four-field digest. A deployment
  that computes `action_ref` can carry it in a binding (§4.5).
- **Issue #2648** recommended RFC 8785 over a structured object in place of raw
  concatenation. This extension follows that and makes byte equality with the
  JCS form a tested check (§5.2).
- **`response-provenance`** (issue #3234, PR #3304) attests what was returned.
  Its text says the hash is tamper-evident only when carried in a signed receipt;
  §4.5.3 is that carriage.
- **Delivery receipt** (issue #2833) binds request and response digests and the
  payment requirements. `requirementsDigest` is the same idea for the
  requirements; this extension leaves content digests to it and to
  `response-provenance`.
- **Base receipt payload v2** (PR #3827) commits the payment authorization in
  salted form. §4.5.3 carries it; this extension does not define a second
  construction.
- **Rejection receipt** (PR #4215) covers a payment the server declined to
  accept. This extension starts after a successful settlement (§5.7) and does
  not cover that case.
- **Core settlement and refusal identity** (PR #3776) concerns the identity of a
  payment attempt derived at ingress. `receiptRef` is not that identity: it
  includes values that did not exist at ingress.

## 12. Open questions

1. Should `outcome` gain `failed` (the service was attempted and did not achieve
   its result), distinct from `refused`? Should `disputed` remain, given that the
   signer is the paid counterparty?
2. Should the payload carry a per-signer sequence number, so that a gap in a
   server's receipts is detectable?
3. An EIP-712 format. It would need its own domain name or primary type, so that
   it cannot be confused with the base receipt's typed data.
4. Whether this belongs under `specs/extensions/` as its own extension or as an
   optional profile of the base extension.

## Version history

| Version | Date | Changes | Author |
|---|---|---|---|
| 0.1 – 0.2.1 | 2026-07-19 | Initial drafts: JWS profile, settlement binding by transaction or settlement reference, payment lifecycle, reason codes, `actionRef` over a 13-field tuple. | Josh Suich |
| 0.3 | 2026-11-19 | Breaking. `actionRef` removed from the payload; `receiptRef` is the hash of the signed payload bytes, in `sha256:` hex form. Added `receiptId`, `requirementsDigest`, `supersedes`, `bindings`. Required `typ` header and a closed header. Canonical-bytes check moved ahead of schema typing. EVM identifiers lowercase; comparison semantics stated. Authorization before key resolution; unresolved keys reported separately. Session and archival freshness. Verification report. Non-goals stated. Circularity code removed (covered by the closed schema). | Josh Suich |

Payload `version` remains `1`: no earlier draft was adopted, and a 0.2.x receipt
fails §5.1 (no `typ`) under this text, so the two cannot be confused.

Prepared with AI assistance; the reference verifier and vectors were run and
cross-checked as described in §7.

## References

RFC 7515 (JWS) · RFC 7518 (JWA) · RFC 8259 (JSON) · RFC 8725 (JWT BCP) ·
RFC 8785 (JCS) · RFC 8812 (ES256K) · CAIP-2 · x402 core specification v2 §5.1, §5.2, §5.3, §9 ·
`specs/extensions/extension-offer-and-receipt.md` §3, §4.5.1, §5, §10, §11 ·
x402 issues #2332, #2648, #2833, #3234 · x402 pull requests #3304, #3776, #3827,
#4215.
