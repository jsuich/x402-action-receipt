# Extension: `action-receipt`

Draft 0.4 (2026-11-20). Proposal for discussion; see the version history for what
changed against earlier drafts. Where this file and the reference suite
disagree, this file governs.

## Summary

`action-receipt` is an optional x402 extension. After a payment settles, the
resource server returns a signed statement of **what was done, within what scope,
with what outcome**, bound to:

- the settlement (a transaction hash or a scheme's settlement reference),
- the payment requirements the client accepted (amount, asset, recipient, scheme),
- and, through signed **binding slots**, evidence defined by other extensions
  (a response hash, an authorization commitment, a refund transaction).

A party holding the receipt can check that the statement is unmodified, was
signed by a key authorized for the resource the receipt names, and is consistent
with the settlement and payment terms that party holds. Checking the signature
and the consistency needs no call to anyone. Learning which keys are authorized
does: it uses the signer's own origin or a registry (§5.4), and for an old
receipt it depends on evidence of authorization that someone kept (§9).

**Coverage.** The payload is scheme-neutral, but its sources are not. This draft
defines them for schemes whose `SettlementResponse` carries a transaction
identifier, and names the settlement reference for one deferred scheme (§4.3).
Where a scheme's settlement result carries neither, no receipt can be issued
under this draft (§1.3).

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

A receipt that passes §5 establishes this, and no more:

- a key that the verifier's authorization source lists for the receipt's
  `resourceUrl` signed this statement, and it is unmodified;
- the statement is consistent with each input the report (§5.12) marks
  `compared` or `matched`. An input the verifier did not hold constrains
  nothing, and the report says which those were.

What that is worth depends on who the verifier is (§5.14). A verifier that made
the payment knows the resource it paid and compares it. A verifier that did not
learns only that the origin the receipt names signed it.

### 1.3 What it does not establish (non-goals)

- **It is the signer's statement, and the signer is a party.** `action.outcome`,
  `action.scope`, `action.agent`, `settlementStatus` and `issuedAt` are asserted
  by it. A receipt is evidence of what the server said, not an independent
  finding. Section 7's mutation matrix lists which members nothing the verifier
  holds can constrain.
- **It does not prove the signer was the party paid.** Authorization ties the
  key to `resourceUrl`. Nothing in the receipt ties that resource to `payTo`,
  except under anchor (b) of §5.4. An origin can sign a well-formed receipt over
  a settlement that paid someone else for something else, and a verifier that
  did not make the payment cannot tell from the receipt. Such a verifier
  establishes the link another way: from the `PaymentRequired` the payer kept,
  from anchor (b), or from its own knowledge of who operates the resource.
- **It does not state the amount charged.** `requirementsDigest` commits the
  accepted requirements. Under `exact` that is the amount paid. Under `upto`, a
  batch scheme, or any settlement with fees or splits, it is a ceiling or a
  term, and the amount that moved is in the scheme's settlement result, which
  this receipt does not carry (§12).
- **It does not identify a payment.** It carries the settlement's identifiers.
  Where one settlement identifier covers several payments, the receipt
  distinguishes the statements (`receiptId`) and not the payments (§4.7).
- **It does not cover every scheme.** A settlement result with an empty
  `transaction` and no settlement reference this draft names (§4.3) gives the
  issuer nothing to bind to, and step 2 of §6.2 refuses. At the time of writing
  that includes voucher-only responses of the EVM and Cloudflare
  `batch-settlement` bindings and a zero-amount `upto` settlement.
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
MUST carry the same values, and the server commits the advertisement with the
`action-receipt:advertised-info` binding (§4.5.2, §6.2). That is what lets a client
show the scope it paid for was fixed before it paid. This is an issuer
requirement: no step of §5 rejects on it. A verifier that holds the advertised
`info` reports `checks.advertisement` (§5.11): `matched`, `mismatched`, or
`absent` when the server advertised and the receipt carries no such binding.

The advertisement is a statement of intent, not an obligation another party can
enforce: a server that advertised and then issues nothing has broken no rule a
verifier can detect (§1.3, "Absence proves nothing").

### 2.4 Relationship to the base receipt

A server MAY emit both a base receipt and an action receipt for one settlement.
When it does, `network` and `resourceUrl` MUST be equal in the two, and `payer`
and `transaction` (when the base receipt carries one) MUST name the same account
and transaction. On `eip155` networks this receipt writes them in lowercase
(§4.6) and the base receipt may not, so they are compared after lowercasing the
base receipt's values. `issuedAt` need not be equal: each receipt is stamped
when it is signed.

This is a separate extension, not a new payload version of the base receipt,
because it makes a different statement. A base receipt is issued "only on success,
confirming that payment was received and service was delivered" (base §5) and is
privacy-minimal by default (base §5.2, §11). An action receipt can state that the
service failed or that the payment was reversed, and it is deliberately not
minimal. A verifier MUST NOT verify an action receipt as a base receipt or the
reverse; the `typ` header (§3) makes the two distinguishable under the signature.
That protects this side only: §5.1 rejects a base receipt. The base extension
does not require a `typ`, so whether a base verifier rejects an action receipt
presented to it depends on that verifier (§9).

## 3. Envelope and JWS header

The receipt object has the base extension's JWS shape (base §3.1, §3.1.1):

```json
{ "format": "jws", "signature": "<JWS Compact Serialization>" }
```

`payload` is omitted; the compact string carries it. Any other member of the
receipt object is ignored and is not covered by the signature.

The compact string is at most 65536 characters. A payload at the limits of §4
fits several times over; the bound exists so that a verifier, which must parse
before it can authenticate, parses a bounded input.

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

The header bytes are the RFC 8785 serialization of that object, so a header has
one spelling: `{"alg":…,"kid":…,"typ":…}` with no whitespace. A header that
repeats a member, reorders members or escapes a character needlessly is
rejected (§5.1). Without this, a signer could produce one receipt that two
parsers read differently.

ECDSA signatures are the 64-byte `r || s` form of RFC 7518 §3.4 and MUST be
low-`s` (`s <= floor(n/2)`). `ES256K` is ECDSA over secp256k1 with SHA-256
(RFC 8812). Most ECDSA libraries produce a high-`s` signature about half the
time, so a signer normalizes `s` after signing (§6.3).

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
| `network` | string | `PaymentPayload.accepted.network` | Network identifier, as x402 writes it |
| `resourceUrl` | string | `PaymentRequired.resource.url`, verbatim | The paid resource |
| `payer` | string | `SettlementResponse.payer`; failing that the scheme payload's payer (§4.3) | Who paid, or `""` when neither source has one |
| `payTo` | string | `PaymentPayload.accepted.payTo` | The recipient the accepted requirements name |
| `transaction` | string | `SettlementResponse.transaction` | Settlement transaction, or `""` |
| `settlementRef` | string | the scheme's settlement reference (§4.3) | Or `""` |
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

`agent`, `actionType` and `scope` are opaque strings. This extension gives them
no grammar and no registry; their vocabulary belongs to the deployment or to
another specification, and a verifier compares them only where §4.5.2 says so.

`outcome` describes service delivery and nothing else. Whether and how the
payment settled is `settlementStatus`. Every pairing of the two is a valid
receipt.

| `outcome` | Meaning |
|---|---|
| `delivered` | The service was performed and the result returned |
| `partial` | Part of the service was performed |
| `failed` | The service was not performed, whether the server could not or would not |

These are the three states the delivery-receipt proposal uses (§11), so the two
receipts for one call cannot disagree in vocabulary. Two things are deliberately
not outcomes. A payment the server declined to accept is a different event and is
out of scope (§11). A dispute is not something the paid party can declare about
its own delivery; it belongs to whoever adjudicates (§11).

`failed` needs a settlement to exist (§5.7). In the default x402 flow the server
settles only after its handler succeeds, so a failed handler produces no
settlement and no receipt. `failed` arises where settlement does not wait for
the handler: a flow that settles first, or a deferred scheme whose commitment was
accepted before the work was attempted.

### 4.3 Identity, settlement and lifecycle

**`receiptId`** is 22 to 64 characters from the base64url alphabet. The issuer
MUST generate at least 128 bits of it from a cryptographically secure source and
MUST NOT reuse a value. It exists so that two statements which share every other
member are still two receipts. That case is ordinary: two payments by one payer
for one resource in the same second under one batch settlement. (The worked
example in §4.7 uses a fixed, readable `receiptId` so that it reproduces; it is
not a model for generating one.)

**Settlement identifiers.** At least one of `transaction` and `settlementRef` is
non-empty.

`transaction` is `SettlementResponse.transaction`.

`settlementRef` is the scheme's **settlement reference**: a value that the
scheme's own specification places in its settlement result to identify what was
settled when there is no transaction to name. Core defines no such field. The
references this draft recognizes are:

| Scheme and network | Settlement reference |
|---|---|
| `batch-settlement` on `solana:*` | `SettlementResponse.extra.commitmentId` |

A scheme that later defines such a field adds a row; that needs no change to the
payload. An issuer MUST NOT use as `settlementRef` a value the settlement result
did not carry, and MUST NOT compute one. A scheme whose result has an empty
`transaction` and no row here is not covered (§1.3).

**`payer`.** The payer is `SettlementResponse.payer`. When the response has
none, it is the payer the scheme's payment payload names: for the EVM `exact`
scheme with an EIP-3009 authorization, `PaymentPayload.payload.authorization.from`.
A scheme that names its payer elsewhere defines that source in its own
specification. When neither source has one, `payer` is `""`. That is expected on
a rail that reveals no stable payer (the Lightning binding of `exact` requires
`SettlementResponse.payer` to be omitted), and it means the receipt says nothing
about who paid.

**`settlementStatus`** is the state of the payment as the server observed it at
`issuedAt`. It describes the payment and nothing else:

| Value | Meaning |
|---|---|
| `settled` | The settlement the identifiers name completed: the transfer was made |
| `capturePending` | The payment was authorized or committed (an authorization, a voucher) and the transfer has not yet been made |
| `reversed` | The authorization or commitment was released without a transfer |
| `refunded` | The transfer was made and then returned |

A verifier or consumer MUST NOT read a passing receipt as "paid": it MUST read
`settlementStatus`. It MUST NOT read `settlementStatus` as evidence about
delivery, or `outcome` as evidence about payment.

These four values do not describe every event a rail has: a partial capture or
refund, a claim that settles many payments in one transaction, or a reclaim the
payer makes without the server. A receipt states the nearest value; the amounts
and the detail are in the scheme's own records.

**`supersedes`.** A server MAY issue a later receipt for the same settlement
when the payment's state changes or it corrects an earlier statement. The later
receipt has a new `receiptId` and sets `supersedes` to the `receiptRef` (§4.7)
of the receipt it replaces. Otherwise `supersedes` is `""`. When a reversal or
refund has its own transaction, the server SHOULD carry it in the
`action-receipt:reversal-transaction` binding (§4.5.2, §6.2).

`supersedes` is the signer's claim, and a hash anyone can compute. A consumer
holding receipts `A` and `B` MUST treat `B` as superseding `A` only if all of
these hold, and otherwise MUST treat the two as unrelated:

- both pass §5 under authorization for the same `resourceUrl`;
- `B.supersedes` equals the `receiptRef` of `A`;
- `network`, `resourceUrl`, `payTo`, `payer`, `transaction`, `settlementRef` and
  `requirementsDigest` are equal in the two;
- the pair (`A.settlementStatus`, `B.settlementStatus`) is one of:
  the same value twice; `capturePending` then `settled`; `capturePending` then
  `reversed`; `settled` then `refunded`.

Two receipts that each validly supersede the same receipt show that the signer
issued inconsistent statements; a consumer MUST NOT pick one.

This draft defines no channel for delivering a later receipt. The settlement
response reaches the client once, and a reversal or refund usually happens with
no request in flight. A holder of a receipt therefore cannot learn from it, or
from this extension, that a later one exists. A consumer that needs the current
state of a payment MUST NOT rely on a receipt for it and resolves the settlement
on the rail (§5.14).

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

`PaymentPayload` is written by the client. The digest is worth something only if
`accepted` is what the server offered, so the issuer checks that before it signs
(§6.2 step 4).

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
  in §4.5.2, and that set is closed: a binding whose `type` begins
  `action-receipt:` and is not listed there is rejected (§5.3), so that a later
  draft of this document cannot give a new meaning to a receipt already issued.
  The meaning of any other type is whatever its owner's specification said when
  the receipt was issued; this extension does not pin it.
- **Verbatim values.** `value` is the string exactly as the owning specification
  writes it. This extension does not re-encode, re-hash or interpret it.
- **Unknown types are not errors.** A verifier MUST NOT reject a receipt because
  it does not recognize a binding type. It reports the entry as `not_evaluated`
  (§5.11).
- **Bindings never change the verdict.** Each entry is reported with its own
  status. A consumer MUST NOT treat a `not_evaluated` or `mismatched` binding as
  verified.
- **No overriding.** The members of §4.1 govern. An issuer SHOULD NOT carry a
  binding that restates or contradicts one, and a consumer MUST NOT let a
  binding change how it reads a member of §4.1.
- **Nothing here is critical.** A binding cannot be marked "must understand". A
  value that every verifier has to understand for the receipt to be read
  correctly does not belong in a binding; it needs a member, and so a new
  payload version.

What the signature gives a binding is carriage: the server committed to that
value, in this receipt, for this settlement. Whether the value is true is decided
by the owning specification's own procedure.

A new binding type needs no new version of this extension. A new top-level
member, a new enumeration value or a changed grammar does.

#### 4.5.2 Types defined by this specification

| `type` | `value` | Evaluated when |
|---|---|---|
| `action-receipt:advertised-info` | `"sha256:"` + hex of SHA-256 over the JCS form of the `info` object the server advertised (§2.3) | The verifier holds that `info` object, as a JSON object in the value domain of §4.6. `matched` iff the digest is equal and, for each of `scope` and `actionType` that is a member of `info`, its value is a string equal to the receipt's `action` member. Otherwise `mismatched` |
| `action-receipt:reversal-transaction` | The rail's identifier of the transaction that reversed or refunded the payment. On `eip155` networks, `0x[0-9a-f]{64}` | Never offline. A verifier that resolves it on the rail reports the result itself |

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
  a member `60.0` holds the integer 60, is in the domain, and serializes as `60`.
  The value of a number is the IEEE 754 double nearest its JSON text (RFC 8785
  §3.2.2.3; RFC 7493). An implementation whose parser keeps more precision
  converts before testing, so that all implementations agree on texts such as
  `9007199254740991.4`;
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
| `network` | `[-a-z0-9]{3,32}:[-_a-zA-Z0-9]{1,32}` (below) |
| `resourceUrl`, `payTo` | non-empty string |
| `payer` | any string |
| `payTo` when `network` begins `eip155:` | `0x[0-9a-f]{40}` |
| `payer` when `network` begins `eip155:` and it is non-empty | `0x[0-9a-f]{40}` |
| `transaction` | any string; when `network` begins `eip155:` and it is non-empty, `0x[0-9a-f]{64}` |
| `settlementRef` | any string |
| `transaction`, `settlementRef` | not both empty |
| `requirementsDigest` | `sha256:[0-9a-f]{64}` |
| `supersedes` | `""` or `sha256:[0-9a-f]{64}` |
| `action.agent`, `action.actionType` | non-empty string |
| `action.scope` | any string |
| `action.outcome`, `settlementStatus` | one of the values in §4.2, §4.3 |
| `bindings` | §4.5 |

The `network` grammar is the CAIP-2 shape with a longer namespace. CAIP-2 limits
the namespace to 8 characters; x402 network identifiers are not all CAIP-2 (the
Cloudflare `batch-settlement` binding uses `cloudflare:402`), and this receipt
has to be able to name any network x402 does. This document calls a string that
matches the grammar a **network identifier**.

`resourceUrl` has no URL grammar here: it is compared as a string (§5.4) and
never parsed by this extension. A signed string can contain any Unicode,
including control and bidirectional-formatting characters, so software that
shows a receipt to a person escapes what it displays (§9).

EVM identifiers are lowercase because EIP-55 checksum casing gives one address
many spellings, and the receipt needs one. Values a verifier takes from
**unsigned** inputs are normalized before comparison (§5.8, §5.9); signed values
are not.

**Present and absent (both procedures).** Where §5 or §6 reads a string from an
unsigned x402 object or from the issuer's statement, the value is **present**
when it is a non-empty string of well-formed Unicode. Anything else is absent:
a missing member, `null`, `""`, a value of another type, and a string with an
unpaired surrogate (which cannot be serialized, so it can never equal a signed
value). The issuer and the verifier use this one definition, so they cannot
disagree about whether a response carried a value.

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

It is **not** a count of payments or of actions, and neither is `receiptId`. A
server can issue several receipts for one settlement (§4.3). A consumer MUST NOT
count payments by `receiptRef` or `receiptId`.

Nothing in the receipt identifies a payment as such. `(network, transaction)`
and `(network, settlementRef)` identify a **settlement**. They count payments
only under a scheme that settles each payment with its own identifier, as
`exact` does. Where one settlement identifier covers several payments, two
receipts that share it may be two payments or two statements about one, and the
receipt cannot say which; the scheme's own records can.

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
  optionally `payer`, and the scheme's settlement reference where §4.3 names
  one;
- optionally the `PaymentRequirements` the client accepted;
- optionally the `info` object the server advertised (§2.3);
- if the verifier made the payment itself, **the resource URL it paid for**:
  the `resource.url` of the `PaymentRequired` it answered, verbatim. That is the
  value the issuer signs (§4.1), so the comparison in §5.4 is between two copies
  of one string. It is not the URL the client typed or was redirected from;
- a clock, a maximum age, and a mode;
- a way to learn which keys are authorized for a resource (§5.4).

The receipt and the x402 objects come from other parties, and no value in them
makes the verifier fail: every malformed case has a step below that rejects it
or treats it as absent. The remaining inputs are the verifier's own
configuration and have a contract:

| Input | Contract |
|---|---|
| mode | exactly `session` or `archival` |
| clock (`now`) | an integer number of Unix seconds |
| maximum age | absent, meaning 3600, or an integer `>= 0` |
| resource URL paid for | absent, or a string |
| authorized key | a public key (for example a SubjectPublicKeyInfo PEM). A private key or a certificate is not one |

A verifier given configuration outside this contract returns `ERROR`. It MUST
NOT substitute a default or the nearest valid value: a mode it does not
recognize is not `archival`, and a maximum age it cannot read is not 3600.

**Outcomes.** Verification yields one of:

- `PASS`, with a report (§5.12);
- `REJECT`, with exactly one reason code (§5.13);
- `ERROR`, when the verifier itself failed: its configuration was outside the
  contract above, or it faulted internally (for example its canonicalizer
  disagreed with a second implementation). `ERROR` says nothing about the
  receipt and MUST NOT be reported as a rejection.

The verifier MUST perform the steps below **in order** and MUST stop at the first
failure. It MUST NOT raise, and MUST NOT return `ERROR`, because of anything in
the receipt or in the x402 objects.

### 5.1 Envelope and header

1. Reject with `invalid_payload` unless the receipt is an object with
   `format == "jws"`; `signature` is a string of at most 65536 characters and
   exactly three `.`-separated segments; each segment is unpadded base64url
   (§3); and the first decodes to bytes `H` that pass the test of §5.2 (valid
   UTF-8, parses as JSON, in the value domain, and `JCS(parsed) == H`) and
   parse to a JSON object. A header with a byte-order mark, in another
   encoding, with a repeated member, with `NaN`, or with members out of order
   fails here.
2. Reject with `invalid_actionreceipt_typ` unless the header's `typ` is the
   string `x402-action-receipt+jws`.
3. Reject with `invalid_actionreceipt_alg` unless `alg` is one of the strings
   `ES256`, `ES256K` or `EdDSA`. A value of any other type is rejected here.
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

1. `invalid_payload` unless the value is an object that has a `version` member
   whose value is an integer.
2. `invalid_actionreceipt_version` unless `version == 1`. This comes before the
   member set is checked, so that a receipt of a later version, which may have
   other members, is reported as a version this verifier does not implement
   and not as a malformed payload.
3. `invalid_payload` unless the object has exactly the members of §4.1;
   `action` is an object with exactly the members of §4.2; every string-typed
   member, including `action.outcome` and `settlementStatus`, is a string; and
   every member except `action.outcome`, `settlementStatus` and `bindings`
   satisfies every row of the grammar table in §4.6 that names it, including
   "not both empty".
4. `invalid_actionreceipt_outcome` unless `action.outcome` is a listed value.
5. `invalid_actionreceipt_status` unless `settlementStatus` is a listed value.
6. `invalid_payload` unless `bindings` is an array.
7. `invalid_actionreceipt_binding` unless `bindings` satisfies §4.5: at most 16
   entries, each an object with exactly `type` and `value`, both strings matching
   their grammar, in strictly ascending order of `type`; and every entry whose
   `type` begins `action-receipt:` is one of the two types of §4.5.2 with a
   `value` of that type's form (`sha256:[0-9a-f]{64}` for `advertised-info`;
   for `reversal-transaction`, `0x[0-9a-f]{64}` when `network` begins `eip155:`).

### 5.4 Resource and signer authorization

A verifier that made the payment itself first rejects with
`invalid_actionreceipt_resource_mismatch` unless the receipt's `resourceUrl`
equals, as an exact string, the resource URL it paid for. A verifier that did not
make the payment has nothing to compare, and the report records
`resourceUrl: not_compared`.

The verifier then asks its authorization source whether `kid` is authorized for
the receipt's `resourceUrl`. `kid` is authorized when the source gives at least
one of:

- (a) **the service**: a binding from the resource to the key identifier;
- (b) **the recipient**: a binding from the pair `(payTo, resourceUrl)` to the
  key identifier, made by whoever controls `payTo`.

The question has three answers, and they lead to different results:

- **Authorized.** Continue with §5.5.
- **Not authorized**: the source answered, and `kid` is not among the keys it
  lists for the resource. Reject with `invalid_actionreceipt_signer`.
- **No answer**: the source could not be consulted (the host is unreachable, the
  origin no longer exists) or, in `archival` mode, the verifier has no evidence
  either way of what was authorized at `issuedAt`. Reject with
  `invalid_actionreceipt_key_unresolved` (§5.5). The verifier MUST NOT report
  this as `invalid_actionreceipt_signer`: failing to reach a source is not a
  finding against the signer.

Both anchors are scoped to the resource. A key that is authorized for a
recipient address is not thereby authorized for every URL. Anchor (b) is looked
up with the receipt's own `payTo`, which is not yet bounded at this step (§5.9
bounds it); that is safe only because the anchor is itself tied to
`resourceUrl`. Anchor (a) says the origin that serves the resource signed. Only
anchor (b) also says the recipient vouches for that origin (§1.3).

Authorization uses the mechanisms of base §4.5.1 (`did:web` at the resource's
host, DNS TXT `_controllers.<host>`, or a registry the verifier trusts). Those
mechanisms speak for a host. A verifier using them treats a key the host lists
as authorized for every resource on that host; a narrower scope needs a registry
that records one. Two rules are specific to this extension:

- **The key identifier never chooses the source.** The verifier takes the
  location of authorization data from the receipt's `resourceUrl` (its host) or
  from its configured registry. It MUST NOT take it from `kid`: a `did:web`
  `kid` whose host is not the host of `resourceUrl` is not authorized under (a)
  unless a registry the verifier trusts says so. A requesting verifier has
  already checked `resourceUrl` against what it paid. A non-requesting verifier
  has not, so for it this step shows only that the origin the receipt names
  vouches for the key (§1.3, §5.14).
- **As of `issuedAt`.** In `archival` mode the question is whether the key was
  authorized when the receipt was issued (base §5.5). Removal of a key from a
  mutable source is prospective: it does not show the key was unauthorized at
  `issuedAt`. What the source says today is evidence about today. Evidence
  about `issuedAt` is a record someone kept at the time (§9); a verifier without
  one, facing a source that no longer lists the key, has no answer.

### 5.5 Key resolution

If `kid` is authorized but the verifier cannot obtain a usable key (the document
is unreachable, the key has been rotated out and no record of it is held, or
what was obtained is not a public key of a kind the verifier can use), reject
with `invalid_actionreceipt_key_unresolved`.

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
the response's `transaction` and `payer` (ASCII `A-Z` to `a-z`). Nothing else is
normalized. Throughout §5.7 and §5.8 the response "has" a transaction, a
settlement reference or a payer when the value is present in the sense of §4.6.
Reject with `invalid_actionreceipt_settlement_mismatch` if any of these fails:

- If the response has a `transaction`, the receipt's `transaction` equals it.
  If the response has none, the receipt's `transaction` is `""`.
- If the response has a settlement reference, the receipt's `settlementRef`
  equals it. If it has none, the receipt's `settlementRef` is `""`.
- If the response's `network` is a network identifier (§4.6), the receipt's
  `network` equals it. Otherwise the report records `network: not_compared`.
- If the response has a `payer`, the receipt's `payer` equals it. Otherwise the
  report records `payer: not_compared`, and the receipt's `payer` (which may be
  `""`, or may come from the scheme payload) is not constrained here.

The second half of the first two rules means a receipt cannot carry an identifier
the response does not corroborate, and cannot silently drop one the response has.
A verifier applies the settlement-reference rule with the reference §4.3 names
for the scheme. A verifier that does not know the scheme's row has no settlement
reference to supply, and correctly rejects a receipt that carries one: it cannot
corroborate it.

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

A per-entry status cannot show an entry that is missing, so the report also
carries `checks.advertisement`:

- `not_evaluated` when the verifier does not hold the advertised `info`, or what
  it holds is not a JSON object in the value domain;
- `absent` when it holds one and the receipt has no
  `action-receipt:advertised-info` binding. A conforming issuer that advertised
  always includes it (§6.2), so `absent` means the server did not follow its
  advertisement, or the `info` the verifier holds is not one this server sent;
- otherwise the status of that binding, `matched` or `mismatched`.

### 5.12 The report

`PASS` is returned with a report. A verifier MUST make at least this available:

| Member | Content |
|---|---|
| `receiptRef` | §4.7 |
| `outcome`, `settlementStatus` | Copied from the receipt |
| `ageSeconds` | `now - issuedAt` |
| `checks.resourceUrl`, `checks.network`, `checks.payer`, `checks.payTo` | `compared` or `not_compared` |
| `checks.requirements` | `matched` or `not_evaluated` |
| `checks.advertisement` | `matched`, `mismatched`, `absent` or `not_evaluated` (§5.11) |
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
    "advertisement": "not_evaluated",
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
| §5.4 signer not authorized | `invalid_actionreceipt_signer` |
| §5.4 no answer, §5.5 (indeterminate) | `invalid_actionreceipt_key_unresolved` |
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
came from the party presenting the receipt or from the signer, and the resource
is the one the receipt names, not one the verifier chose. Its `PASS` means that
the origin of `resourceUrl` signed a statement consistent with the records
presented. Whether that origin was the party paid is a separate question
(§1.3), answered by anchor (b), by the payer's copy of the `PaymentRequired`
(which ties `resource.url` to `payTo` before payment), or by the rail.

Either can go further by resolving the settlement identifier on the payment rail.
A verifier that does so SHOULD confirm that the node serves the chain named by
`network`, that the transaction succeeded, and that it transferred the accepted
asset from `payer` to `payTo` in an amount the scheme allows for the accepted
requirements: equal under `exact`; at most the accepted amount under `upto`;
whatever the scheme defines otherwise. It SHOULD NOT assume the transaction's
submitter is the payee: under x402 the facilitator usually submits. This
extension does not specify rail resolution further.

## 6. Issuing (normative)

### 6.1 Inputs

The issuer is the resource server. To issue a receipt it holds:

- the `PaymentRequired` it sent, for `resource.url`, `accepts` and, when it
  advertised this extension, `extensions["action-receipt"].info`;
- the `PaymentPayload` it received, for `accepted` and the scheme payload;
- the `SettlementResponse`, and the scheme's settlement reference where §4.3
  names one;
- its **statement**: the four `action` members, `settlementStatus`, and
  optionally `supersedes`, a reversal transaction and further bindings;
- a fresh `receiptId` (§4.3) and its clock.

The statement is the issuer's own: this document does not say how a server
decides what it did. It says only what form the statement takes and what the
issuer must refuse to sign.

Conventions for this section:

- **x402 objects are read leniently.** A string read from the
  `PaymentRequired`, the `PaymentPayload` or the `SettlementResponse` is
  present or absent as §4.6 defines: a `transaction` of the wrong type is no
  transaction. Those objects come from other parties, and the verifier reads
  them the same way (§5.8).
- **The statement is read strictly.** It is the issuer's own input, so a wrong
  value is an error and is never dropped. An optional statement member
  (`supersedes`, the reversal transaction, the further bindings) is not given
  when it is missing or `null`. Given, it MUST be well formed (steps 8 and 10),
  and the issuer refuses if it is not.
- Members of the statement, and of its `action` object, that this section does
  not name are ignored. That applies at those two levels only: a binding entry
  has exactly two members (§4.5).
- The issuer **advertised** this extension when
  `PaymentRequired.extensions["action-receipt"]` is an object whose `info` is a
  JSON object. That `info` is "the advertised `info`". Anything else is no
  advertisement. The advertised `info` is hashed as it stands (§4.5.2), so
  nothing in it is read leniently: a member of it whose value is `null` is a
  member, not an absence.

### 6.2 Procedure

The issuer MUST perform these steps in order. At the first step that fails it
MUST NOT issue a receipt. The refusal reasons are local names, used in logs and
in conformance testing; they never appear on the wire.

| Step | Refusal reason | The issuer refuses unless |
|---|---|---|
| 1 | `settlement_not_successful` | `SettlementResponse.success` is `true` |
| 2 | `no_settlement_identifier` | the response has a `transaction`, or the issuer has a settlement reference (§4.3) |
| 3 | `requirements_not_hashable` | `PaymentPayload.accepted` is a JSON object in the value domain of §4.6 |
| 4 | `requirements_not_offered` | `PaymentRequired.accepts` is an array, and `accepted` equals one of its entries (below) |
| 5 | `network_unusable` | `accepted.network` is a network identifier (§4.6); and, when `SettlementResponse.network` is also one, the two are equal |
| 6 | `resource_unavailable` | `PaymentRequired.resource.url` is present |
| 7 | `identifier_out_of_grammar` | `accepted.payTo` is present, and after the lowercasing below `payer`, `payTo` and `transaction` satisfy §4.6 |
| 8 | `invalid_statement` | the statement is well formed (below) |
| 9 | `advertisement_conflict` | for each of `actionType` and `scope` that is a member of the advertised `info`, its value is a string equal to the statement's `action` member |
| 10 | `invalid_bindings` | the assembled `bindings` satisfy §4.5 |

**Offered requirements (step 4).** `accepted` equals an entry of `accepts` when
both are in the value domain and their JCS serializations are the same bytes.
Core already requires a server to match the client's choice against what it
offered before it settles; this step makes the receipt depend on it. Without
it, a client could have the server sign a digest over terms the server never
offered, and a verifier that holds the same `PaymentPayload` would report those
terms as matched.

**Payer and lowercasing (step 7).** `payer` is `SettlementResponse.payer` when
present; failing that the scheme payload's payer when present (§4.3; this
document and its suite read only `PaymentPayload.payload.authorization.from`);
failing that `""`. When `accepted.network` begins `eip155:` the issuer
lowercases `payer`, `payTo` and `transaction` (ASCII `A-Z` to `a-z`, the rule a
verifier applies in §5.8). On other networks they are copied verbatim. The
settlement reference is never changed.

**Well-formed statement (step 8).** `action.agent` and `action.actionType` are
present (§4.6); `action.scope` is a string of well-formed Unicode;
`action.outcome` and `settlementStatus` are listed values; `receiptId` matches
its grammar; `issuedAt` is a number with an integer value (§4.6) in
`[0, 2^53 - 1]`; `supersedes`, when given, is `""` or matches its grammar; the
reversal transaction, when given, is a string; the further bindings, when
given, are an array.

**Assembling bindings (step 10).** Start from the further bindings in the
statement. A further binding whose `type` begins `action-receipt:` fails the
step: the types this specification defines are added by the issuer below and are
never supplied. Then:

- if the issuer advertised this extension, add `action-receipt:advertised-info`
  with the digest of the advertised `info` (§4.5.2). An advertised `info` that is
  not in the value domain cannot be committed and fails the step;
- if the statement gives a reversal transaction, add
  `action-receipt:reversal-transaction` with that value, lowercased when
  `accepted.network` begins `eip155:`.

Sort the entries in ascending order of `type`. Two entries with one `type`, an
entry that breaks the grammar of §4.5 or the value form of §4.5.2, or more than
16 entries fails the step.

### 6.3 The payload

When no step refused, the payload is built from the sources of §4.1: `version`
is `1`; `network` is `accepted.network`; `resourceUrl` is
`PaymentRequired.resource.url`; `payer`, `payTo` and `transaction` are the values
of step 7 (`transaction` is `""` when the response has none);
`settlementRef` is the settlement reference or `""`; `requirementsDigest` is
computed per §4.4; `supersedes` is the statement's or `""`; `bindings` is the
array of step 10.

The steps above are sufficient: a payload built this way satisfies §5.2 and
§5.3. An implementation SHOULD nevertheless run those two checks on the payload
it built and refuse if either fails, so that a defect in the issuer shows up as
a refusal and not as a receipt nobody can verify.

**Signing.** The issuer signs the JCS serialization of the payload under a
header that is the JCS serialization of the three members of §3. It MUST:

- use a key whose `kid` its own authorization source lists for `resourceUrl`
  (§5.4), and whose type matches `alg`;
- for `ES256` and `ES256K`, emit the 64-byte `r || s` form with `s <= n/2`,
  replacing `s` by `n - s` when the library returns the high form;
- emit a compact string within the bound of §3.

**What a conforming issuer can rely on.** Take a receipt built and signed as
above, and a verifier following §5 that is given the same `SettlementResponse`
and settlement reference, the same `accepted`, the same advertised `info` if
there was one, a clock within the freshness bounds, and an authorization source
that answers for the key. That verifier returns `PASS` with requirements
`matched`, `payTo` `compared`, and, if the issuer advertised,
`checks.advertisement` `matched`. `resourceUrl` is compared when the verifier
made the payment; `network` and `payer` are compared when the
`SettlementResponse` carries them.

### 6.4 Standing requirements

1. Sign only after settlement returns.
2. Keep every key that has signed a receipt resolvable for as long as receipts
   signed by it may need to be verified, and never rebind a `kid` to a different
   key: a verifier that resolves a rebound `kid` sees a genuine receipt fail its
   signature check, which reads as forgery. A dedicated signing key separate
   from the `payTo` key is RECOMMENDED (base §4.5.1).
3. A later receipt for the same settlement follows §4.3: same settlement
   members, `supersedes` set, a permitted status pair.
4. When both receipts are emitted, keep them consistent (§2.4).

## 7. Conformance

The reference suite is at <https://github.com/jsuich/x402-action-receipt>: a
verifier, the vectors under `vectors/`, and `vectors/MANIFEST.json`, which states
for every vector the context to verify it in, the expected verdict, the reason
code on `REJECT` and the report on `PASS`. A conformance claim cites the
`vectorsDigest` in that manifest.

A verifier conforms if it reproduces every entry of the manifest. An issuer
conforms if, for every exchange under `exchanges/`, it produces exactly the
expected payload or refuses with the expected reason
(`exchanges/MANIFEST.json`).
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
`"__payTo__:<payTo>|<resourceUrl>"` each map to an array of authorized key
identifiers (a value that is not an array of strings authorizes nothing);
`"__unavailable__:<resourceUrl>"` set to `true` says the authorization source
gave no answer for that resource; and each key identifier maps to a
SubjectPublicKeyInfo PEM public key. A key identifier that is authorized but has
no entry, or whose entry is not such a key, exercises §5.5. It is not a wire
format.

What conformance does and does not show:

- Reproducing the manifests shows agreement with this text on the cases they
  contain. It does not show a verifier's authorization source is sound, that an
  issuer signs correctly (the issuer exchanges compare payloads, not
  signatures), or that `receiptId` values are unpredictable.
- Every implementation in the repository came from one working session. Their
  agreement with each other is weaker evidence than agreement with an
  implementation written elsewhere.
- The exchanges and vectors are `exact`-shaped messages. Networks other than
  `eip155` appear, but no vector was produced by another scheme's SDK.

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
- **The signer and the payee** (§1.3). Authorization shows the origin of
  `resourceUrl` signed. It does not show that origin was paid. A receipt over a
  real settlement between two other parties verifies for an auditor who takes
  the resource from the receipt.
- **Requirements the client wrote.** `accepted` comes from the client. The
  digest means what it should only because the issuer checked `accepted`
  against what it offered (§6.2 step 4). A verifier cannot see whether an
  issuer did.
- **Key lifetime and old receipts.** If the signer's origin disappears, or a
  key is rotated out with no record kept, old receipts become unverifiable
  (`invalid_actionreceipt_key_unresolved`), not invalid. Verifiers that retain
  receipts SHOULD retain the key and the authorization evidence they relied on,
  with the time they resolved it. That evidence convinces the party that kept
  it. It is not transferable: a third party shown a copy is trusting whoever
  kept it. This extension has no mechanism by which a party who was not there
  can establish what was authorized at `issuedAt`.
- **Backdating.** `issuedAt` is asserted by the signer and nothing bounds it
  from below in `archival` mode. Whoever holds a key, including a key since
  retired, can sign a receipt with any earlier `issuedAt`. Removal of a key is
  treated as prospective (§5.4), so such a receipt is judged against the time
  it claims.
- **Rebinding a key identifier.** If a `kid` is pointed at a different key, a
  genuine old receipt fails §5.6 with `invalid_actionreceipt_signature`. A
  consumer SHOULD NOT read a signature failure on an old receipt as proof the
  presenter forged it unless it knows the key it resolved is the key that was
  bound at `issuedAt`.
- **Algorithm and type confusion.** The key's type and curve are bound to `alg`
  (§5.6; RFC 8725 §3.1), the header has one spelling (§3), and `typ` is
  required, so this verifier does not accept a different JWS-based artifact.
  The reverse is not in this extension's hands: an action receipt payload
  contains every member a base receipt payload requires, and the base extension
  requires no `typ`, so a base verifier that tolerates unknown members and
  headers could accept one as a base receipt.
- **Parsing before authentication.** Every step before §5.6 runs on bytes
  nobody has authenticated. The size bound (§3), the depth bound (§4.6) and the
  binding limits (§4.5) keep that work bounded.
- **Display.** Signed strings can contain control and bidirectional-formatting
  characters, and `resourceUrl` is not checked to be a URL. Software that shows
  receipt fields to a person escapes them.
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

1. Should `outcome` distinguish a service the server declined to perform from one
   it attempted and could not complete? Draft 0.3 does not: no implementation or
   proposal reviewed for it draws that line.
2. Should the payload carry a per-signer sequence number, so that a gap in a
   server's receipts is detectable?
3. An EIP-712 format. It would need its own domain name or primary type, so that
   it cannot be confused with the base receipt's typed data.
4. Whether this belongs under `specs/extensions/` as its own extension or as an
   optional profile of the base extension.
5. Should the payload carry the amount the settlement charged
   (`SettlementResponse.amount`, or a scheme's `extra.chargedAmount`)? Without
   it the receipt commits only the accepted terms, which under `upto` and the
   batch schemes are a ceiling (§1.3). It would be a new member.
6. Should the lifecycle stay? `reversed`, `refunded` and `supersedes` describe
   events for which this draft has no delivery channel (§4.3). The alternative
   is a receipt that states only what was true when the response was sent, and
   leaves later events to the rail.
7. A settlement reference for the deferred schemes that return neither a
   transaction nor an identifier (§1.3). That is for those schemes to define.
8. A payment identifier. Core PR #3776 concerns one; if it lands, a receipt
   could carry it and §4.7's limit would go.

## Version history

| Version | Date | Changes | Author |
|---|---|---|---|
| 0.1 – 0.2.1 | 2026-07-19 | Initial drafts: JWS profile, settlement binding by transaction or settlement reference, payment lifecycle, reason codes, `actionRef` over a 13-field tuple. | Josh Suich |
| 0.3 | 2026-11-19 | Breaking. `actionRef` removed from the payload; `receiptRef` is the hash of the signed payload bytes, in `sha256:` hex form. Added `receiptId`, `requirementsDigest`, `supersedes`, `bindings`. Required `typ` header and a closed header. Canonical-bytes check moved ahead of schema typing. EVM identifiers lowercase; comparison semantics stated. Authorization before key resolution; unresolved keys reported separately. Session and archival freshness. Verification report. Non-goals stated. Circularity code removed (covered by the closed schema). `outcome` is `delivered`, `partial` or `failed`; `refused` and `disputed` are retired. §6 is a ten-step issuing procedure with refusal reasons. A verifier that paid checks the URL it paid for. | Josh Suich |

| 0.4 | 2026-11-20 | Breaking, after an independent review of 0.3 (six reviewers; `conformance/REVIEW-0.4.md`). The header has one spelling (JCS). `payer` may be `""`; the network grammar admits x402's non-CAIP-2 identifiers; `settlementRef` has a named source per scheme. The issuer refuses requirements it did not offer (`requirements_not_offered`); `payer_unavailable` is retired. One definition of a present value for issuer and verifier. `version` is checked before the member set. The `action-receipt:` binding namespace is closed and its values have a form. An authorization source that gives no answer is `key_unresolved`, not `signer`. The verifier's own inputs have a contract; outside it the result is `ERROR`. `checks.advertisement` added to the report. Supersession has consumer rules and no promised delivery. Signing requirements moved into §6.3. A 65536-character bound. Claims narrowed: what a non-requesting verifier learns, the signer is not shown to be the payee, the amount charged is not stated, a payment is not identified, schemes without an identifier are not covered. | Josh Suich |

Payload `version` remains `1`: no earlier draft was adopted, and a 0.2.x receipt
fails §5.1 (no `typ`) under this text, so the two cannot be confused. A 0.3
receipt is a valid 0.4 receipt unless it relied on something 0.4 removed (a
header that was not in JCS form, an unlisted `action-receipt:` binding).

Prepared with AI assistance; the reference verifier and vectors were run and
cross-checked as described in §7.

## References

RFC 7515 (JWS) · RFC 7518 (JWA) · RFC 8259 (JSON) · RFC 8725 (JWT BCP) ·
RFC 8785 (JCS) · RFC 8812 (ES256K) · CAIP-2 · x402 core specification v2 §5.1, §5.2, §5.3, §9 ·
`specs/extensions/extension-offer-and-receipt.md` §3, §4.5.1, §5, §10, §11 ·
x402 issues #2332, #2648, #2833, #3234 · x402 pull requests #3304, #3776, #3827,
#4215.
