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

## License and contributor

Apache-2.0. Contributed openly by Holological LLC (`jsuich`). Prepared with AI
assistance.
