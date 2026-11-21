#!/usr/bin/env python3
"""
issuer.py — reference issuer + issuer conformance suite for `action-receipt`
(spec §6, draft 0.4).

An EXCHANGE is what a resource server holds when it decides to issue: the
PaymentRequired it sent, the PaymentPayload it received, the SettlementResponse,
the scheme's settlement reference if any, and its own statement. The issuer
either builds the receipt payload or refuses with one of the ten reasons of
§6.2. `sign()` turns a payload into a compact JWS (§6.3).

    python3 issuer.py                 # run the exchange suite (exchanges/MANIFEST.json)
    python3 issuer.py --regenerate    # rewrite exchanges/ from the tables below, then run
    python3 issuer.py --batch         # adapter: exchanges as JSON lines on stdin

Batch adapter (ISSUER ADAPTER PROTOCOL in CONFORMANCE.md):
    in : {"id": ..., "exchange": {...}}
    out: {"id": ..., "issued": true,  "payload": {...}}
         {"id": ..., "issued": false, "reason": "<refusal reason>"}
         {"id": ..., "issued": false, "reason": "issuer_fault" | "self_check_failed" | "invalid_input"}
The last three are not refusals of §6.2: `invalid_input` means the line was not
a JSON object, `issuer_fault` that the issuer itself failed, `self_check_failed`
that the payload it built failed its own §5.2/§5.3 check (§6.3). A conforming
issuer never gives any of them for a JSON exchange.
"""
from __future__ import annotations

import copy
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import action_receipt as A  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils as asym_utils  # noqa: E402

EXCHANGES = HERE / "exchanges"

# refusal reasons, in step order (spec §6.2)
X_SETTLEMENT = "settlement_not_successful"
X_NO_ID = "no_settlement_identifier"
X_REQUIREMENTS = "requirements_not_hashable"
X_OFFERED = "requirements_not_offered"
X_NETWORK = "network_unusable"
X_RESOURCE = "resource_unavailable"
X_GRAMMAR = "identifier_out_of_grammar"
X_STATEMENT = "invalid_statement"
X_ADVERT = "advertisement_conflict"
X_BINDINGS = "invalid_bindings"
ALL_REFUSALS = [X_SETTLEMENT, X_NO_ID, X_REQUIREMENTS, X_OFFERED, X_NETWORK, X_RESOURCE,
                X_GRAMMAR, X_STATEMENT, X_ADVERT, X_BINDINGS]
# Answers that are not §6.2 refusals (CONFORMANCE.md, issuer adapter protocol).
SELF_CHECK = "self_check_failed"   # §6.3 SHOULD: the built payload failed §5.2 or §5.3
FAULT = "issuer_fault"             # the issuer itself failed
INVALID_INPUT = "invalid_input"    # the adapter line was not a JSON object
NOT_REFUSALS = [SELF_CHECK, FAULT, INVALID_INPUT]

_NOT_GIVEN = object()


def _obj(v):
    return v if isinstance(v, dict) else {}


# One definition of "present" for every string read from an x402 object or the
# statement (spec §4.6 "Present and absent"): the verifier's own.
_present = A._has


def _given(st: dict, key: str):
    """An optional statement member (spec §6.1): not given when missing or null."""
    v = st.get(key)
    return _NOT_GIVEN if v is None else v


def _lower_evm(v: str) -> str:
    """ASCII lowercasing of hex identifiers (spec §6.2): A-Z to a-z, nothing else."""
    return re.sub(r"[A-Z]", lambda m: m.group(0).lower(), v)


def _int_value(v):
    """The integer a JSON number holds, or None (spec §4.6: value, not spelling)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    return None


def issue(exchange) -> tuple[dict | None, str | None]:
    """Return (payload, None) or (None, reason). Never raises on junk."""
    try:
        return _issue(exchange)
    except Exception:  # noqa: BLE001
        return None, FAULT


def _issue(exchange):
    x = _obj(exchange)
    required = _obj(x.get("paymentRequired"))
    pay = _obj(x.get("paymentPayload"))
    resp = _obj(x.get("settlementResponse"))
    st = _obj(x.get("statement"))

    # 1 settlement succeeded
    if resp.get("success") is not True:
        return None, X_SETTLEMENT
    # 2 a settlement identifier
    transaction = resp.get("transaction") if _present(resp.get("transaction")) else ""
    reference = x.get("settlementReference") if _present(x.get("settlementReference")) else ""
    if not (transaction or reference):
        return None, X_NO_ID
    # 3 accepted is hashable
    accepted = pay.get("accepted")
    digest = A.requirements_digest(accepted)
    if digest is None:
        return None, X_REQUIREMENTS
    # 4 accepted is one of the offered requirements, by JCS bytes
    accepts = required.get("accepts")
    if not isinstance(accepts, list):
        return None, X_OFFERED
    accepted_bytes = A.jcs(accepted)
    if not any(A.in_domain(entry) and A.jcs(entry) == accepted_bytes for entry in accepts):
        return None, X_OFFERED
    # 5 network identifier, and no conflict with the response's
    network = accepted.get("network")
    if not (isinstance(network, str) and A.RE_NETWORK.fullmatch(network)):
        return None, X_NETWORK
    resp_net = resp.get("network")
    if isinstance(resp_net, str) and A.RE_NETWORK.fullmatch(resp_net) and resp_net != network:
        return None, X_NETWORK
    # 6 resource
    resource = _obj(required.get("resource")).get("url")
    if not _present(resource):
        return None, X_RESOURCE
    # 7 payer, payTo, transaction
    payer = resp.get("payer")
    if not _present(payer):
        payer = _obj(_obj(pay.get("payload")).get("authorization")).get("from")
        if not _present(payer):
            payer = ""
    pay_to = accepted.get("payTo")
    if not _present(pay_to):
        return None, X_GRAMMAR
    evm = network.startswith("eip155:")
    if evm:
        payer, pay_to, transaction = _lower_evm(payer), _lower_evm(pay_to), _lower_evm(transaction)
        if not A.RE_EVM_ADDRESS.fullmatch(pay_to):
            return None, X_GRAMMAR
        if payer and not A.RE_EVM_ADDRESS.fullmatch(payer):
            return None, X_GRAMMAR
        if transaction and not A.RE_EVM_TX.fullmatch(transaction):
            return None, X_GRAMMAR
    # 8 the statement is well formed
    action = _obj(st.get("action"))
    agent, action_type = action.get("agent"), action.get("actionType")
    scope, outcome = action.get("scope"), action.get("outcome")
    status = st.get("settlementStatus")
    receipt_id = st.get("receiptId")
    issued_at = _int_value(st.get("issuedAt"))
    supersedes = _given(st, "supersedes")
    reversal = _given(st, "reversalTransaction")
    further = _given(st, "bindings")
    if not _present(agent):
        return None, X_STATEMENT
    if not _present(action_type):
        return None, X_STATEMENT
    if not (isinstance(scope, str) and A.in_domain(scope)):
        return None, X_STATEMENT
    if not (isinstance(outcome, str) and outcome in A.OUTCOMES):
        return None, X_STATEMENT
    if not (isinstance(status, str) and status in A.SETTLEMENT_STATUSES):
        return None, X_STATEMENT
    if not (isinstance(receipt_id, str) and A.RE_RECEIPT_ID.fullmatch(receipt_id)):
        return None, X_STATEMENT
    if issued_at is None:
        return None, X_STATEMENT
    if not 0 <= issued_at <= A.SAFE_INT_MAX:
        return None, X_STATEMENT
    if supersedes is _NOT_GIVEN:
        supersedes = ""
    if not (isinstance(supersedes, str) and (supersedes == "" or A.RE_DIGEST.fullmatch(supersedes))):
        return None, X_STATEMENT
    if reversal is not _NOT_GIVEN and not isinstance(reversal, str):
        return None, X_STATEMENT
    if further is not _NOT_GIVEN and not isinstance(further, list):
        return None, X_STATEMENT
    # 9 the advertisement (read strictly: a member whose value is null is a member)
    ext = _obj(required.get("extensions")).get("action-receipt")
    info = ext.get("info") if isinstance(ext, dict) else None
    advertised = isinstance(info, dict)
    if advertised:
        for member in ("actionType", "scope"):
            if member in info and not (isinstance(info[member], str) and info[member] == action[member]):
                return None, X_ADVERT
    # 10 bindings
    bindings = [] if further is _NOT_GIVEN else list(further)
    # types this specification defines are added by the issuer, never supplied
    for b in bindings:
        if isinstance(b, dict) and isinstance(b.get("type"), str) and b["type"].startswith(A.BT_NAMESPACE):
            return None, X_BINDINGS
    if advertised:
        if not A.in_domain(info):
            return None, X_BINDINGS
        bindings.append({"type": A.BT_ADVERTISED, "value": A.sha256_tag(A.jcs(info))})
    if reversal is not _NOT_GIVEN:
        bindings.append({"type": A.BT_REVERSAL_TX, "value": _lower_evm(reversal) if evm else reversal})
    if len(bindings) > A.MAX_BINDINGS:
        return None, X_BINDINGS
    for b in bindings:
        if not (isinstance(b, dict) and set(b.keys()) == A.BINDING_KEYS):
            return None, X_BINDINGS
        t, v = b["type"], b["value"]
        if not (isinstance(t, str) and isinstance(v, str)):
            return None, X_BINDINGS
        if not (A.RE_BINDING_TYPE.fullmatch(t) and A.RE_BINDING_VALUE.fullmatch(v)):
            return None, X_BINDINGS
        if t.startswith(A.BT_NAMESPACE):             # value form of §4.5.2
            if t == A.BT_ADVERTISED:
                if not A.RE_DIGEST.fullmatch(v):
                    return None, X_BINDINGS
            elif t == A.BT_REVERSAL_TX:
                if evm and not A.RE_EVM_TX.fullmatch(v):
                    return None, X_BINDINGS
            else:
                return None, X_BINDINGS
    bindings = sorted(({"type": b["type"], "value": b["value"]} for b in bindings),
                      key=lambda b: b["type"])
    for i in range(1, len(bindings)):
        if bindings[i - 1]["type"] == bindings[i]["type"]:
            return None, X_BINDINGS

    # §6.3 the payload
    payload = {
        "version": A.PROFILE_VERSION, "receiptId": receipt_id, "issuedAt": issued_at,
        "network": network, "resourceUrl": resource, "payer": payer, "payTo": pay_to,
        "transaction": transaction, "settlementRef": reference,
        "settlementStatus": status, "requirementsDigest": digest,
        "supersedes": supersedes,
        "action": {"agent": agent, "actionType": action_type, "scope": scope, "outcome": outcome},
        "bindings": bindings,
    }
    if not self_check(payload):
        return None, SELF_CHECK
    return payload, None


def self_check(payload) -> bool:
    """§6.3 SHOULD: run §5.2 and §5.3 on the payload the issuer built."""
    if not A.in_domain(payload):
        return False
    raw = A.jcs(payload)
    if A.parse_canonical(raw) is A.NOT_CANONICAL:
        return False
    return A.validate_payload(payload) is None


# --- signing (spec §3, §6.3) --------------------------------------------------

class SigningError(Exception):
    """The issuer will not sign: the key is not one it may use for this payload."""


ALG_KEY = {"ES256": "secp256r1", "ES256K": "secp256k1"}


def sign(payload: dict, *, alg: str, kid: str, private_key, authorized: dict,
         _low_s: bool = True) -> str:
    """Sign an issued payload; return the compact JWS string.

    `authorized` is the issuer's OWN authorization source: resourceUrl -> list of
    kids it may sign that resource under (§6.3: a kid its own source lists for
    resourceUrl). The header is the JCS serialization of {alg, kid, typ}; ECDSA
    uses the library's ordinary (randomized) signer and then replaces a high `s`
    by n - s. `_low_s=False` exists only so the suite can show the verifiers
    reject what this function would otherwise emit."""
    if alg not in A.SUPPORTED_ALGS:
        raise SigningError(f"unknown alg {alg!r}")
    if not isinstance(kid, str):
        raise SigningError("kid is not a string")
    kids = authorized.get(payload.get("resourceUrl")) if isinstance(payload, dict) else None
    if not (isinstance(kids, list) and kid in kids):
        raise SigningError("kid is not authorized for resourceUrl by the issuer's own source")
    if alg in ALG_KEY:
        if not (isinstance(private_key, ec.EllipticCurvePrivateKey)
                and private_key.curve.name == ALG_KEY[alg]):
            raise SigningError(f"key does not match {alg}")
    elif not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise SigningError("key does not match EdDSA")
    if not self_check(payload):
        raise SigningError("payload fails its own §5.2/§5.3 check")
    header = A.jcs({"alg": alg, "kid": kid, "typ": A.TYP})
    signing_input = f"{A.b64url(header)}.{A.b64url(A.jcs(payload))}".encode()
    if alg in ALG_KEY:
        der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        n = A.CURVE_ORDER[ALG_KEY[alg]]
        if _low_s and s > n // 2:
            s = n - s
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        raw = private_key.sign(signing_input)
    compact = signing_input.decode() + "." + A.b64url(raw)
    if len(compact) > A.MAX_COMPACT:
        raise SigningError("compact string exceeds the bound of §3")
    return compact


# --- the exchange suite ------------------------------------------------------
# Expected payloads are DECLARED BY HAND as differences from the payload printed
# in spec §4.7, which the suite reads out of the spec file. Digest literals were
# computed once with hashlib over sorted-key JSON, not with this module's JCS.
# No expectation is produced by running the issuer.

ADVERT_INFO = {"willIssueReceipt": True, "actionType": "inference.completion", "scope": "read:model-x"}
ADVERT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
    "properties": {"willIssueReceipt": {"type": "boolean"}, "actionType": {"type": "string"},
                   "scope": {"type": "string"}},
    "required": ["willIssueReceipt"],
}
ADVERT_DIGEST_LITERAL = "sha256:33df93fe0564655d6fa711a9b0b6a390396132ca577f0b7cfac2f6cd3dbffd76"
INFO_EMPTY_DIGEST = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
INFO_WILL_FALSE_DIGEST = "sha256:1819870fb6c521d4f365597f37dc7372aeaae63b6d722416d09f93450ed175f0"
REFUND_SUPERSEDES = "sha256:5ea130c2d5c3750da8e54ea640cdbf653056202c08a2af4c43677947becda7c2"

SOL_NET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOL_PAYER = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
SOL_PAYTO = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
SOL_TX = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"
SOL_USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SOL_FEE_PAYER = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd"

# SVM `exact`: extra.feePayer, payload is a base64 transaction, no payer member.
ACC_SVM_EXACT = {"scheme": "exact", "network": SOL_NET, "amount": "10000", "asset": SOL_USDC,
                 "payTo": SOL_PAYTO, "maxTimeoutSeconds": 60, "extra": {"feePayer": SOL_FEE_PAYER}}
SVM_EXACT_DIGEST = "sha256:60ea5a3bab3ffeaaf42fcae332e100fdd58e49ac82139e74277763c9fff2154b"
# SVM `batch-settlement`: the one settlement reference draft 0.4 names (§4.3).
ACC_SOL_BATCH = copy.deepcopy(A.ACCEPTED_SOL)
SOL_BATCH_DIGEST = "sha256:d510811d2179b2233463632c7982e339e630ccc7a49c70a9f116938fd908ccea"
# Cloudflare `batch-settlement`: network outside CAIP-2, role-constant payTo.
ACC_CF = {"scheme": "batch-settlement", "network": "cloudflare:402", "amount": "10000",
          "asset": "USD", "payTo": "merchant", "maxTimeoutSeconds": 60, "extra": {}}
CF_DIGEST = "sha256:344600e74e80d8402de2f2aefd0c2f8c0f2c2dd3a1bf1a242ca3cd87144818e6"
ACC_NS32 = dict(A.ACCEPTED, network="a" * 32 + ":x")
NS32_DIGEST = "sha256:5a8bc57d62652789ccdff8517e1c2a27b478bf989bb5073a4c4ffaec00ac1859"
ACC_DEPTH8 = dict(A.ACCEPTED, extra={"d": [[[[[["x"]]]]]]})        # level 8 counting accepted
DEPTH8_DIGEST = "sha256:27905833e432a5548f511e46c000f19898a319c1d3d8b7396be49fd3fe886bbf"
ACC_DEPTH9 = dict(A.ACCEPTED, extra={"d": [[[[[[["x"]]]]]]]})

PAYER_OTHER = "0x" + "22" * 20
PAYER_MIXED = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"
UPPER_REF = "Batch:Voucher:9F3C1D0A-0000-4A11-B2CC-Settlement-Root-01"
REVERSAL = "0x" + "ef" * 32
SOL_REVERSAL = "4aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ1"
URL_WS = "  " + A.RESOURCE + " \t"
EXTRA_OFFER = dict(A.ACCEPTED, amount="20000", payTo="0x" + "33" * 20)


def base_exchange() -> dict:
    return {
        "paymentRequired": {
            "x402Version": 2,
            "error": "Payment required",
            "resource": {"url": A.RESOURCE, "description": "Text completion",
                         "mimeType": "application/json"},
            "accepts": [copy.deepcopy(A.ACCEPTED)],
            "extensions": {},
        },
        "paymentPayload": {
            "x402Version": 2,
            "resource": {"url": A.RESOURCE, "description": "Text completion",
                         "mimeType": "application/json"},
            "accepted": copy.deepcopy(A.ACCEPTED),
            "payload": {"signature": "0x" + "9a" * 65,
                        "authorization": {"from": A.PAYER_CHECKSUM, "to": A.PAY_TO_CHECKSUM,
                                          "value": "10000", "validAfter": "1703123000",
                                          "validBefore": "1703123600", "nonce": "0x" + "f3" * 32}},
            "extensions": {},
        },
        "settlementResponse": {"success": True, "transaction": A.SETTLEMENT_TX,
                               "network": A.NETWORK, "payer": A.PAYER_CHECKSUM},
        "settlementReference": None,
        "statement": {
            "receiptId": A.RECEIPT_ID, "issuedAt": A.ISSUED_AT,
            "action": {"agent": "did:web:agent.example", "actionType": "inference.completion",
                       "scope": "read:model-x", "outcome": "delivered"},
            "settlementStatus": "settled",
        },
    }


DELETE = object()


def E(name, expect, **edit):
    """One exchange: `edit` holds `__`-separated path assignments; `expect` is a
    dict of payload differences from the spec's worked example, or a refusal
    reason. Unless the edit sets `paymentRequired__accepts` itself, an edited
    `accepted` that is an object is also what the server offered (step 4), so
    that a case aimed at a later step has every earlier step satisfied."""
    x = base_exchange()
    for path, value in edit.items():
        obj = x
        keys = path.split("__")
        for k in keys[:-1]:
            obj = obj[k]
        if value is DELETE:
            del obj[keys[-1]]
        else:
            obj[keys[-1]] = copy.deepcopy(value)
    touched = any(p.startswith("paymentPayload__accepted") for p in edit)
    if touched and "paymentRequired__accepts" not in edit:
        acc = x["paymentPayload"]["accepted"]
        if isinstance(acc, dict):
            x["paymentRequired"]["accepts"] = [copy.deepcopy(acc)]
    return name, x, expect


def advert(info, echo=None):
    """The edits that advertise `info` and have the client echo it (core §5.1.2)."""
    return {"paymentRequired__extensions": {"action-receipt": {"info": info, "schema": ADVERT_SCHEMA}},
            "paymentPayload__extensions": {"action-receipt": {"info": info if echo is None else echo}}}


def act(**kw):
    a = {"agent": "did:web:agent.example", "actionType": "inference.completion",
         "scope": "read:model-x", "outcome": "delivered"}
    a.update(kw)
    return a


_MANY = [{"type": f"n:{i:02d}", "value": "1"} for i in range(16)]
B_ADV = {"type": "action-receipt:advertised-info", "value": ADVERT_DIGEST_LITERAL}
B_REV = {"type": "action-receipt:reversal-transaction", "value": REVERSAL}
_SOL_RESPONSE = {"success": True, "transaction": SOL_TX, "network": SOL_NET, "payer": SOL_PAYER}
_SVM_PAYLOAD = {"transaction": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDAw=="}
_PERMIT2_PAYLOAD = {"signature": "0x" + "7c" * 65,
                    "permit2Authorization": {"from": A.PAYER_CHECKSUM, "permitted": {
                        "token": A.ACCEPTED["asset"], "amount": "10000"},
                        "spender": "0x" + "44" * 20, "nonce": "1", "deadline": "1703123600",
                        "witness": {"to": A.PAY_TO_CHECKSUM, "validAfter": "1703123000"}}}
_SOL_BATCH_PAYLOAD = {"type": "voucher", "channelId": "chan-01",
                      "voucher": {"maxClaimableAmount": "10000", "nonce": "1"},
                      "signature": "3sZq" + "1" * 84}
_SOL_BATCH_RESPONSE = {"success": True, "transaction": "", "network": SOL_NET, "amount": "",
                       "extra": {"commitmentId": A.COMMITMENT_ID, "chargedAmount": "10000"}}
_SOL_BATCH_EXPECT = {"network": SOL_NET, "payer": "", "payTo": A.SOL_PAY_TO, "transaction": "",
                     "settlementRef": A.COMMITMENT_ID, "settlementStatus": "capturePending",
                     "requirementsDigest": SOL_BATCH_DIGEST}
_SOL_BATCH = dict(paymentPayload__accepted=ACC_SOL_BATCH, paymentPayload__payload=_SOL_BATCH_PAYLOAD,
                  paymentRequired__accepts=[A.ACCEPTED, ACC_SOL_BATCH],
                  settlementResponse=_SOL_BATCH_RESPONSE, settlementReference=A.COMMITMENT_ID,
                  statement__settlementStatus="capturePending")
_SVM = dict(paymentPayload__accepted=ACC_SVM_EXACT, paymentPayload__payload=_SVM_PAYLOAD,
            paymentRequired__accepts=[A.ACCEPTED, ACC_SVM_EXACT], settlementResponse=_SOL_RESPONSE)
_SVM_EXPECT = {"network": SOL_NET, "payer": SOL_PAYER, "payTo": SOL_PAYTO, "transaction": SOL_TX,
               "requirementsDigest": SVM_EXACT_DIGEST}
_CF = dict(paymentPayload__accepted=ACC_CF, paymentPayload__payload={"amount": "10000", "asset": "USD"},
           settlementResponse={"success": True, "transaction": A.CF_TX, "network": "cloudflare:402"})
_CF_EXPECT = {"network": "cloudflare:402", "payer": "", "payTo": "merchant", "transaction": A.CF_TX,
              "requirementsDigest": CF_DIGEST}
_NO_RESOURCE = {"paymentRequired__resource": {"description": "Text completion"}}

SUITE = [
    # ---- issued -------------------------------------------------------------
    E("issue_basic", {}),
    E("issue_payer_from_authorization", {}, settlementResponse__payer=DELETE),
    E("issue_payer_response_wins_over_authorization", {},
      paymentPayload__payload__authorization__from=PAYER_OTHER),
    E("issue_payer_from_authorization_lowercased", {"payer": PAYER_MIXED.lower()},
      settlementResponse__payer=DELETE, paymentPayload__payload__authorization__from=PAYER_MIXED),
    E("issue_payer_none", {"payer": ""}, settlementResponse__payer=DELETE,
      paymentPayload__payload={"signature": "0x00"}),
    E("issue_payer_permit2_from_response", {}, paymentPayload__payload=_PERMIT2_PAYLOAD),
    E("issue_payer_permit2_no_response_payer", {"payer": ""},
      paymentPayload__payload=_PERMIT2_PAYLOAD, settlementResponse__payer=DELETE),
    E("issue_payer_response_not_string", {}, settlementResponse__payer=7),
    E("issue_response_uppercase_hex", {},
      settlementResponse__transaction="0X" + "AB" * 32,
      settlementResponse__payer="0X" + A.PAYER[2:].upper()),
    E("issue_response_network_not_identifier", {}, settlementResponse__network="base"),
    E("issue_response_network_absent", {}, settlementResponse__network=DELETE),
    E("issue_requirements_float_spelling", {}, paymentPayload__accepted__maxTimeoutSeconds=60.0,
      paymentRequired__accepts=[A.ACCEPTED]),
    E("issue_offer_float_spelling", {}, paymentRequired__accepts=[dict(A.ACCEPTED, maxTimeoutSeconds=60.0)]),
    E("issue_offer_member_order_differs", {},
      paymentRequired__accepts=[dict(reversed(list(A.ACCEPTED.items())))]),
    E("issue_offer_among_several", {}, paymentRequired__accepts=[EXTRA_OFFER, A.ACCEPTED]),
    E("issue_offer_entry_out_of_domain_skipped", {},
      paymentRequired__accepts=[dict(A.ACCEPTED, amount=1.5), "junk", A.ACCEPTED]),
    E("issue_requirements_depth_8", {"requirementsDigest": DEPTH8_DIGEST},
      paymentPayload__accepted=ACC_DEPTH8),
    E("issue_batch", {"transaction": "", "settlementRef": A.BATCH_REF},
      settlementResponse__transaction="", settlementReference=A.BATCH_REF),
    E("issue_both_identifiers", {"settlementRef": A.BATCH_REF}, settlementReference=A.BATCH_REF),
    E("issue_settlement_ref_upper_case_evm", {"transaction": "", "settlementRef": UPPER_REF},
      settlementResponse__transaction="", settlementReference=UPPER_REF),
    E("issue_solana_batch_settlement", _SOL_BATCH_EXPECT, **_SOL_BATCH),
    E("issue_svm_exact", _SVM_EXPECT, **_SVM),
    E("issue_svm_exact_no_response_payer", dict(_SVM_EXPECT, payer=""),
      **dict(_SVM, settlementResponse=dict(_SOL_RESPONSE, payer=None))),
    E("issue_network_cloudflare", _CF_EXPECT, **_CF),
    E("issue_network_namespace_32",
      {"network": "a" * 32 + ":x", "payer": A.PAYER_CHECKSUM, "payTo": A.PAY_TO_CHECKSUM,
       "requirementsDigest": NS32_DIGEST},
      paymentPayload__accepted=ACC_NS32, settlementResponse__network="a" * 32 + ":x"),
    E("issue_advertised", {"bindings": [B_ADV]}, **advert(ADVERT_INFO)),
    E("issue_advertised_echo_ignored", {"bindings": [B_ADV]},
      **advert(ADVERT_INFO, echo=dict(ADVERT_INFO, scope="write:everything"))),
    E("issue_advertised_info_empty",
      {"bindings": [{"type": "action-receipt:advertised-info", "value": INFO_EMPTY_DIGEST}]},
      **advert({})),
    E("issue_advertised_will_issue_false",
      {"bindings": [{"type": "action-receipt:advertised-info", "value": INFO_WILL_FALSE_DIGEST}]},
      **advert({"willIssueReceipt": False})),
    E("issue_advertisement_info_not_object", {},
      **{"paymentRequired__extensions": {"action-receipt": {"info": "yes"}}}),
    E("issue_advertisement_entry_not_object", {},
      **{"paymentRequired__extensions": {"action-receipt": ["info"]}}),
    E("issue_refund",
      {"settlementStatus": "refunded", "receiptId": A.RECEIPT_ID_2, "supersedes": REFUND_SUPERSEDES,
       "bindings": [B_REV]},
      statement__settlementStatus="refunded", statement__receiptId=A.RECEIPT_ID_2,
      statement__supersedes=REFUND_SUPERSEDES, statement__reversalTransaction=REVERSAL),
    E("issue_reversal_lowercased_evm", {"settlementStatus": "reversed", "bindings": [B_REV]},
      statement__settlementStatus="reversed", statement__reversalTransaction="0X" + "EF" * 32),
    E("issue_reversal_non_evm_verbatim",
      dict(_SVM_EXPECT, settlementStatus="refunded",
           bindings=[{"type": "action-receipt:reversal-transaction", "value": SOL_REVERSAL}]),
      **_SVM, statement__settlementStatus="refunded", statement__reversalTransaction=SOL_REVERSAL),
    E("issue_bindings_sorted",
      {"bindings": [B_ADV, {"type": "offer-receipt:authorizationMethod", "value": "eip3009"},
                    {"type": "response-provenance:responseHash", "value": "sha256:" + "81" * 32}]},
      **advert(ADVERT_INFO),
      statement__bindings=[{"type": "response-provenance:responseHash", "value": "sha256:" + "81" * 32},
                           {"type": "offer-receipt:authorizationMethod", "value": "eip3009"}]),
    E("issue_outcome_failed", {"action": act(outcome="failed")}, statement__action__outcome="failed"),
    E("issue_outcome_partial", {"action": act(outcome="partial")}, statement__action__outcome="partial"),
    E("issue_status_capture_pending", {"settlementStatus": "capturePending"},
      statement__settlementStatus="capturePending"),
    E("issue_status_reversed", {"settlementStatus": "reversed"}, statement__settlementStatus="reversed"),
    E("issue_scope_empty", {"action": act(scope="")}, statement__action__scope=""),
    E("issue_receiptid_22", {"receiptId": "A" * 22}, statement__receiptId="A" * 22),
    E("issue_receiptid_64", {"receiptId": "a-_Z" * 16}, statement__receiptId="a-_Z" * 16),
    E("issue_issuedat_zero", {"issuedAt": 0}, statement__issuedAt=0),
    E("issue_issuedat_max", {"issuedAt": 2**53 - 1}, statement__issuedAt=2**53 - 1),
    E("issue_sixteen_bindings", {"bindings": _MANY}, statement__bindings=list(reversed(_MANY))),
    E("issue_sixteen_with_issuer_added",
      {"bindings": [B_ADV, B_REV] + _MANY[:14]},
      **advert(ADVERT_INFO), statement__reversalTransaction=REVERSAL, statement__bindings=_MANY[:14]),
    E("issue_issuedat_float_spelling", {}, statement__issuedAt=float(A.ISSUED_AT)),
    E("issue_null_means_absent", {}, statement__supersedes=None, statement__bindings=None,
      statement__reversalTransaction=None),
    E("issue_supersedes_empty_string", {}, statement__supersedes=""),
    E("issue_action_extra_member_ignored", {}, statement__action__note="ignored"),
    E("issue_statement_extra_member_ignored", {}, statement__note={"deep": [1.5]}),
    E("issue_transaction_wrong_type_with_reference", {"transaction": "", "settlementRef": A.BATCH_REF},
      settlementResponse__transaction=123, settlementReference=A.BATCH_REF),
    E("issue_resource_url_whitespace_verbatim", {"resourceUrl": URL_WS},
      paymentRequired__resource__url=URL_WS),
    # C-F1: a response string with an unpaired surrogate is absent (§4.6), and
    # the receipt built from that reading passes both verifiers.
    E("issue_surrogate_response_transaction", {"transaction": "", "settlementRef": A.BATCH_REF},
      settlementResponse__transaction="0x\ud800", settlementReference=A.BATCH_REF),
    E("issue_surrogate_response_payer", {}, settlementResponse__payer="\ud800" + A.PAYER[1:]),
    E("issue_surrogate_settlement_reference", {}, settlementReference="batch\udfff"),
    E("issue_surrogate_authorization_from", {"payer": ""}, settlementResponse__payer=DELETE,
      paymentPayload__payload__authorization__from="0x\udc00"),
    # ---- refused, step 1 ---------------------------------------------------
    E("refuse_settlement_failed", X_SETTLEMENT,
      settlementResponse={"success": False, "errorReason": "insufficient_funds", "transaction": "",
                          "network": A.NETWORK, "payer": A.PAYER_CHECKSUM}),
    E("refuse_settlement_pending", X_SETTLEMENT,
      settlementResponse={"success": False, "errorReason": "settlement_pending",
                          "transaction": A.SETTLEMENT_TX, "network": A.NETWORK}),
    E("refuse_settlement_truthy_string", X_SETTLEMENT, settlementResponse__success="true"),
    E("refuse_settlement_success_one", X_SETTLEMENT, settlementResponse__success=1),
    # ---- step 2 ------------------------------------------------------------
    E("refuse_no_identifier", X_NO_ID, settlementResponse__transaction=""),
    E("refuse_no_identifier_wrong_type", X_NO_ID, settlementResponse__transaction=123),
    E("refuse_no_identifier_surrogate", X_NO_ID, settlementResponse__transaction="0x\ud800"),
    E("refuse_cloudflare_no_identifier", X_NO_ID,
      **dict(_CF, settlementResponse={"success": True, "transaction": "", "network": "cloudflare:402",
                                      "extra": {"timestamp": 1730872968}})),
    # ---- step 3 ------------------------------------------------------------
    E("refuse_requirements_non_integer", X_REQUIREMENTS, paymentPayload__accepted__extra={"rate": 1.5}),
    E("refuse_requirements_missing", X_REQUIREMENTS, paymentPayload__accepted=None),
    E("refuse_requirements_array", X_REQUIREMENTS, paymentPayload__accepted=[A.ACCEPTED],
      paymentRequired__accepts=[[A.ACCEPTED]]),
    E("refuse_requirements_unsafe_integer", X_REQUIREMENTS, paymentPayload__accepted__maxTimeoutSeconds=2**53),
    E("refuse_requirements_depth_9", X_REQUIREMENTS, paymentPayload__accepted=ACC_DEPTH9),
    # ---- step 4 ------------------------------------------------------------
    E("refuse_offered_amount_changed", X_OFFERED, paymentPayload__accepted__amount="1",
      paymentRequired__accepts=[A.ACCEPTED]),
    E("refuse_offered_payto_changed", X_OFFERED, paymentPayload__accepted__payTo="0x" + "11" * 20,
      paymentRequired__accepts=[A.ACCEPTED]),
    E("refuse_offered_extra_changed", X_OFFERED,
      paymentPayload__accepted__extra={"name": "USD Coin", "version": "3"},
      paymentRequired__accepts=[A.ACCEPTED]),
    E("refuse_offered_member_added", X_OFFERED, paymentPayload__accepted__clientNote="anything",
      paymentRequired__accepts=[A.ACCEPTED]),
    E("refuse_offered_payto_case_differs", X_OFFERED, paymentPayload__accepted__payTo=A.PAY_TO,
      paymentRequired__accepts=[A.ACCEPTED]),
    E("refuse_offered_accepts_missing", X_OFFERED, paymentRequired__accepts=DELETE),
    E("refuse_offered_accepts_not_array", X_OFFERED, paymentRequired__accepts=A.ACCEPTED),
    E("refuse_offered_accepts_empty", X_OFFERED, paymentRequired__accepts=[]),
    E("refuse_offered_only_out_of_domain", X_OFFERED,
      paymentRequired__accepts=[dict(A.ACCEPTED, amount=1.5)]),
    # ---- step 5 ------------------------------------------------------------
    # the response's network is absent or not an identifier, so only the grammar of
    # accepted.network can refuse (the conflict rule needs both to be identifiers)
    E("refuse_network_not_identifier", X_NETWORK, paymentPayload__accepted__network="base",
      settlementResponse__network=DELETE),
    E("refuse_network_namespace_33", X_NETWORK, paymentPayload__accepted__network="a" * 33 + ":x",
      settlementResponse__network="a" * 33 + ":x"),
    E("refuse_network_namespace_2", X_NETWORK, paymentPayload__accepted__network="ab:1",
      settlementResponse__network="ab:1"),
    E("refuse_network_reference_33", X_NETWORK, paymentPayload__accepted__network="eip155:" + "1" * 33,
      settlementResponse__network=DELETE),
    E("refuse_network_not_identifier_either_side", X_NETWORK,
      paymentPayload__accepted__network="base", settlementResponse__network="base"),
    E("refuse_network_conflict", X_NETWORK, settlementResponse__network="eip155:1"),
    # ---- step 6 ------------------------------------------------------------
    E("refuse_no_resource", X_RESOURCE, **_NO_RESOURCE),
    E("refuse_resource_url_empty", X_RESOURCE, paymentRequired__resource__url=""),
    E("refuse_resource_url_not_string", X_RESOURCE, paymentRequired__resource__url=["x"]),
    E("refuse_resource_url_surrogate", X_RESOURCE, paymentRequired__resource__url=A.RESOURCE + "\ud800"),
    # ---- step 7 ------------------------------------------------------------
    E("refuse_payto_role_constant", X_GRAMMAR, paymentPayload__accepted__payTo="merchant"),
    E("refuse_payto_missing", X_GRAMMAR, paymentPayload__accepted__payTo=DELETE),
    E("refuse_payto_empty_non_evm", X_GRAMMAR, **dict(_SVM, paymentPayload__accepted=dict(ACC_SVM_EXACT, payTo=""),
                                                      paymentRequired__accepts=[dict(ACC_SVM_EXACT, payTo="")])),
    E("refuse_transaction_not_hex", X_GRAMMAR, settlementResponse__transaction="0x1234"),
    E("refuse_payer_out_of_grammar_evm", X_GRAMMAR, settlementResponse__payer="0x1234"),
    E("refuse_payer_from_authorization_out_of_grammar", X_GRAMMAR, settlementResponse__payer=DELETE,
      paymentPayload__payload__authorization__from="alice"),
    # ---- step 8, one exchange per sub-check -----------------------------------
    E("refuse_agent_empty", X_STATEMENT, statement__action__agent=""),
    E("refuse_agent_surrogate", X_STATEMENT, statement__action__agent="did:web:\udfff"),
    E("refuse_actiontype_empty", X_STATEMENT, statement__action__actionType=""),
    E("refuse_actiontype_missing", X_STATEMENT, statement__action__actionType=DELETE),
    E("refuse_scope_not_string", X_STATEMENT, statement__action__scope=5),
    E("refuse_scope_missing", X_STATEMENT, statement__action__scope=DELETE),
    E("refuse_scope_unpaired_surrogate", X_STATEMENT, statement__action__scope="read:\ud800"),
    E("refuse_outcome_unknown", X_STATEMENT, statement__action__outcome="shipped"),
    E("refuse_outcome_retired_value", X_STATEMENT, statement__action__outcome="refused"),
    E("refuse_status_unknown", X_STATEMENT, statement__settlementStatus="captured"),
    E("refuse_status_case", X_STATEMENT, statement__settlementStatus="Settled"),
    E("refuse_receiptid_21", X_STATEMENT, statement__receiptId="A" * 21),
    E("refuse_receiptid_65", X_STATEMENT, statement__receiptId="A" * 65),
    E("refuse_receiptid_alphabet", X_STATEMENT, statement__receiptId="A" * 21 + "+"),
    E("refuse_issuedat_negative", X_STATEMENT, statement__issuedAt=-1),
    E("refuse_issuedat_2_53", X_STATEMENT, statement__issuedAt=2**53),
    E("refuse_issuedat_fraction", X_STATEMENT, statement__issuedAt=1703123456.5),
    E("refuse_issuedat_boolean", X_STATEMENT, statement__issuedAt=True),
    E("refuse_issuedat_string", X_STATEMENT, statement__issuedAt="1703123456"),
    E("refuse_supersedes_grammar", X_STATEMENT, statement__supersedes="sha256:" + "AB" * 32),
    E("refuse_supersedes_not_string", X_STATEMENT, statement__supersedes=5),
    E("refuse_reversal_not_string", X_STATEMENT, statement__settlementStatus="refunded",
      statement__reversalTransaction=12345),
    E("refuse_further_bindings_not_array", X_STATEMENT,
      statement__bindings={"type": "a:b", "value": "1"}),
    E("refuse_statement_not_object", X_STATEMENT, statement=["receiptId"]),
    E("refuse_action_not_object", X_STATEMENT, statement__action="delivered"),
    # ---- step 9 ------------------------------------------------------------
    E("refuse_advertised_scope_conflict", X_ADVERT, **advert(ADVERT_INFO),
      statement__action__scope="write:model-x"),
    E("refuse_advertised_actiontype_conflict", X_ADVERT, **advert(ADVERT_INFO),
      statement__action__actionType="inference.embedding"),
    E("refuse_advertised_scope_not_string", X_ADVERT, **advert({"willIssueReceipt": True, "scope": 5})),
    E("refuse_advertised_scope_null", X_ADVERT, **advert(dict(ADVERT_INFO, scope=None))),
    E("refuse_advertised_actiontype_null", X_ADVERT, **advert(dict(ADVERT_INFO, actionType=None))),
    # ---- step 10 -----------------------------------------------------------
    E("refuse_binding_reserved_type", X_BINDINGS,
      statement__bindings=[{"type": "action-receipt:advertised-info", "value": "sha256:" + "00" * 32}]),
    E("refuse_binding_reserved_unknown_type", X_BINDINGS,
      statement__bindings=[{"type": "action-receipt:other", "value": "1"}]),
    E("refuse_binding_duplicates_advertisement", X_BINDINGS, **advert(ADVERT_INFO),
      statement__bindings=[{"type": "action-receipt:advertised-info", "value": "sha256:" + "00" * 32}]),
    E("refuse_advertised_info_not_hashable", X_BINDINGS, **advert({"willIssueReceipt": True, "weight": 1.5})),
    E("refuse_advertised_info_depth_9", X_BINDINGS,
      **advert({"willIssueReceipt": True, "d": [[[[[[[[1]]]]]]]]})),
    E("refuse_binding_duplicate_type", X_BINDINGS,
      statement__bindings=[{"type": "a:one", "value": "1"}, {"type": "a:one", "value": "2"}]),
    E("refuse_binding_grammar", X_BINDINGS, statement__bindings=[{"type": "no-colon", "value": "1"}]),
    E("refuse_binding_value_grammar", X_BINDINGS, statement__bindings=[{"type": "a:b", "value": "a b"}]),
    E("refuse_binding_value_empty", X_BINDINGS, statement__bindings=[{"type": "a:b", "value": ""}]),
    E("refuse_binding_extra_member", X_BINDINGS,
      statement__bindings=[{"type": "a:b", "value": "1", "note": "x"}]),
    E("refuse_binding_not_object", X_BINDINGS, statement__bindings=["a:b=1"]),
    E("refuse_seventeen_bindings", X_BINDINGS,
      statement__bindings=_MANY + [{"type": "n:16", "value": "1"}]),
    E("refuse_seventeen_with_issuer_added", X_BINDINGS, **advert(ADVERT_INFO),
      statement__reversalTransaction=REVERSAL, statement__bindings=_MANY[:15]),
    E("refuse_reversal_malformed_evm", X_BINDINGS, statement__settlementStatus="refunded",
      statement__reversalTransaction="0x1234"),
    E("refuse_reversal_empty_string", X_BINDINGS, statement__settlementStatus="refunded",
      statement__reversalTransaction=""),
    E("refuse_reversal_surrogate", X_BINDINGS, **_SVM, statement__settlementStatus="refunded",
      statement__reversalTransaction="4aBc\ud800"),
    # ---- order: faults in two adjacent steps, the earlier step's reason wins --
    E("refuse_order_1_before_2", X_SETTLEMENT, settlementResponse__success=False,
      settlementResponse__transaction=""),
    E("refuse_order_2_before_3", X_NO_ID, settlementResponse__transaction="",
      paymentPayload__accepted__extra={"rate": 1.5}),
    E("refuse_order_3_before_4", X_REQUIREMENTS, paymentPayload__accepted__extra={"rate": 1.5},
      paymentRequired__accepts=[A.ACCEPTED]),
    E("refuse_order_4_before_5", X_OFFERED, paymentPayload__accepted__network="base",
      paymentRequired__accepts=[A.ACCEPTED]),
    E("refuse_order_5_before_6", X_NETWORK, paymentPayload__accepted__network="base",
      settlementResponse__network="base", **_NO_RESOURCE),
    E("refuse_order_6_before_7", X_RESOURCE, paymentPayload__accepted__payTo="merchant", **_NO_RESOURCE),
    E("refuse_order_7_before_8", X_GRAMMAR, paymentPayload__accepted__payTo="merchant",
      statement__action__outcome="shipped"),
    E("refuse_order_8_before_9", X_STATEMENT, **advert(ADVERT_INFO),
      statement__action__scope="write:model-x", statement__action__outcome="shipped"),
    E("refuse_order_9_before_10", X_ADVERT, **advert(ADVERT_INFO),
      statement__action__scope="write:model-x", statement__bindings=[{"type": "no-colon", "value": "1"}]),
    E("refuse_order_settlement_before_statement", X_SETTLEMENT,
      settlementResponse__success=False, statement__receiptId="tooshort"),
]


def spec_example_payload() -> dict:
    """The payload printed in spec §4.7, read from the spec file."""
    text = (HERE / "action-receipt.md").read_text()
    m = re.search(r'^(\{"action":\{"actionType".*\})$', text, flags=re.M)
    if not m:
        raise SystemExit("cannot find the worked-example payload in action-receipt.md")
    return json.loads(m.group(1))


def expected_payload(expect: dict) -> dict:
    p = spec_example_payload()
    p.update(copy.deepcopy(expect))
    return p


# --- round trip: sign each issued payload and verify it ------------------------

SIGNERS = [("ES256", A.KID_ES256), ("ES256K", A.KID_ES256K), ("EdDSA", A.KID_ED)]


def context_json(exchange: dict) -> dict:
    """The adapter-protocol context a verifier holding this same exchange would
    verify in (spec §6.3 "What a conforming issuer can rely on"), with the clock
    set from the statement."""
    x = _obj(exchange)
    resp = _obj(x.get("settlementResponse"))
    req = _obj(x.get("paymentRequired"))
    ext = _obj(req.get("extensions")).get("action-receipt")
    issued = _int_value(_obj(x.get("statement")).get("issuedAt")) or 0
    return {"paidResourceUrl": _obj(req.get("resource")).get("url"),
            "success": resp.get("success"), "transaction": resp.get("transaction"),
            "settlementRef": x.get("settlementReference"), "network": resp.get("network"),
            "payer": resp.get("payer"), "accepted": _obj(x.get("paymentPayload")).get("accepted"),
            "advertisedInfo": ext.get("info") if isinstance(ext, dict) else None,
            "now": min(issued + 1, A.SAFE_INT_MAX), "maxAgeSeconds": 3600, "mode": "session"}


def expected_checks(exchange: dict) -> dict:
    """The report checks §6.3 promises for a receipt issued from `exchange`."""
    x = _obj(exchange)
    resp = _obj(x.get("settlementResponse"))
    ext = _obj(_obj(x.get("paymentRequired")).get("extensions")).get("action-receipt")
    advertised = isinstance(ext, dict) and isinstance(ext.get("info"), dict)
    net = resp.get("network")
    return {"resourceUrl": "compared",
            "network": "compared" if isinstance(net, str) and A.RE_NETWORK.fullmatch(net) else "not_compared",
            "payer": "compared" if _present(resp.get("payer")) else "not_compared",
            "requirements": "matched", "payTo": "compared",
            "advertisement": "matched" if advertised else "not_evaluated", "freshness": "enforced"}


def key_fixture_for(resource_urls) -> dict:
    """The verifier key fixture, extended so that the test keys are authorized
    for every resource URL an exchange issues for."""
    registry, _ = A._registry()
    for url in resource_urls:
        registry.setdefault("__service__:" + url, [kid for _, kid in SIGNERS])
    return registry


def issuer_authorization(resource_urls) -> dict:
    """The issuer's OWN authorization source (§6.3): resource -> kids."""
    return {url: [kid for _, kid in SIGNERS] for url in resource_urls}


def run_node_verifier(cases: list, registry: dict) -> dict:
    """Verify adapter-protocol cases with the Node verifier; id -> (verdict, reason, report)."""
    node = os.environ.get("NODE") or "node"
    with tempfile.TemporaryDirectory(prefix="action-receipt-issuer-") as d:
        kf = pathlib.Path(d) / "keys.json"
        kf.write_text(json.dumps(registry))
        r = subprocess.run([node, str(HERE / "conformance" / "adapters" / "node_adapter.mjs"), str(kf)],
                           input=("\n".join(json.dumps(c) for c in cases) + "\n").encode(),
                           capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"node verifier adapter failed: {r.stderr.decode()[-800:]}")
    out = {}
    for line in r.stdout.decode().split("\n"):
        if line.strip():
            o = json.loads(line)
            out[o["id"]] = (o["verdict"], o["reason"], o["report"])
    return out


def verify_both(cases: list, registry: dict) -> dict:
    """id -> {"python": (verdict, reason, report), "node": (...)}."""
    node = run_node_verifier(cases, registry)
    out = {}
    for c in cases:
        verdict, reason, report = A.verify_detailed(c["receipt"], A.context_from_json(c["context"]), registry)
        out[c["id"]] = {"python": (verdict, reason, report), "node": node.get(c["id"], ("NO-RESULT", None, None))}
    return out


def round_trips(issued: list) -> dict:
    """issued: [(name, exchange, payload)]. Sign each payload with this issuer's
    sign() under one of the three algorithms and verify it through both verifiers
    in its own exchange's context. Returns name -> list of problems."""
    urls = {p["resourceUrl"] for _, _, p in issued}
    registry = key_fixture_for(urls)
    authorized = issuer_authorization(urls)
    _, keys = A._registry()
    cases, want = [], {}
    for i, (name, exchange, payload) in enumerate(issued):
        alg, kid = SIGNERS[i % len(SIGNERS)]
        jws = sign(payload, alg=alg, kid=kid, private_key=keys[alg], authorized=authorized)
        cases.append({"id": name, "receipt": {"format": "jws", "signature": jws},
                      "context": context_json(exchange)})
        want[name] = expected_checks(exchange)
    results = verify_both(cases, registry)
    problems = {}
    for c in cases:
        name, out = c["id"], []
        for vname, (verdict, reason, report) in results[name].items():
            if verdict != A.PASS:
                out.append(f"{vname} verifier: {verdict}/{reason}")
                continue
            if report["checks"] != want[name]:
                diff = {k: report["checks"].get(k) for k in want[name] if report["checks"].get(k) != want[name][k]}
                out.append(f"{vname} verifier report differs from §6.3: {diff}")
        problems[name] = out
    return problems


def _must_refuse_to_sign(label, payload, **kw) -> list[str]:
    try:
        sign(payload, **kw)
    except SigningError:
        return []
    except Exception as e:  # noqa: BLE001
        return [f"signing with {label} raised {type(e).__name__}, not SigningError"]
    return [f"signed with {label}"]


def signing_suite(per_alg: int = 400) -> list[str]:
    """§6.3 signing, through both verifiers: for each algorithm, `per_alg`
    payloads signed with the library's ordinary randomized ECDSA signer and
    normalized to low s must all pass; the same signer WITHOUT normalization must
    be rejected at least once (so this check can fail); and the issuer must
    refuse a kid its own source does not list, or a key of the wrong type."""
    problems = []
    _, base_x, _ = SUITE[0]
    payload, reason = issue(base_x)
    if payload is None:
        return [f"base exchange refused: {reason}"]
    registry = key_fixture_for([A.RESOURCE])
    authorized = issuer_authorization([A.RESOURCE])
    _, keys = A._registry()
    ctx = context_json(base_x)
    cases, control = [], []
    for alg, kid in SIGNERS:
        for i in range(per_alg):
            p = dict(payload, receiptId=secrets.token_urlsafe(24))
            cases.append({"id": f"{alg}:{i}", "receipt": {"format": "jws", "signature":
                          sign(p, alg=alg, kid=kid, private_key=keys[alg], authorized=authorized)},
                          "context": ctx})
            if alg != "EdDSA" and i < 100:
                control.append({"id": f"control:{alg}:{i}", "receipt": {"format": "jws", "signature":
                                sign(p, alg=alg, kid=kid, private_key=keys[alg], authorized=authorized,
                                     _low_s=False)}, "context": ctx})
    results = verify_both(cases + control, registry)
    for c in cases:
        for vname, (verdict, reason, _) in results[c["id"]].items():
            if verdict != A.PASS:
                problems.append(f"signed {c['id']}: {vname} verifier {verdict}/{reason}")
    ctl = {}
    for alg in ("ES256", "ES256K"):
        rejected = {v: sum(1 for c in control if c["id"].startswith(f"control:{alg}:")
                           and results[c["id"]][v][0] == A.REJECT) for v in ("python", "node")}
        ctl[alg] = rejected["python"]
        if min(rejected.values()) == 0:
            problems.append(f"control {alg}: no un-normalized signature was rejected ({rejected}); "
                            "the low-s check cannot fail")
    for label, kw in [("unlisted kid", dict(alg="ES256", kid=A.KID_EVIL, private_key=keys["ES256"])),
                      ("ES256K key under ES256", dict(alg="ES256", kid=A.KID_ES256, private_key=keys["ES256K"])),
                      ("EC key under EdDSA", dict(alg="EdDSA", kid=A.KID_ED, private_key=keys["ES256"])),
                      ("Ed25519 key under ES256K", dict(alg="ES256K", kid=A.KID_ES256K, private_key=keys["EdDSA"]))]:
        problems += _must_refuse_to_sign(label, payload, authorized=authorized, **kw)
    other = dict(payload, resourceUrl="https://other.example/x")
    problems += _must_refuse_to_sign("a resourceUrl its own source does not list", other, alg="ES256",
                                     kid=A.KID_ES256, private_key=keys["ES256"], authorized=authorized)
    big = dict(payload, action=dict(payload["action"], scope="s" * 50000))
    problems += _must_refuse_to_sign("a compact string over 65536 characters", big, alg="EdDSA",
                                     kid=A.KID_ED, private_key=keys["EdDSA"], authorized=authorized)
    print(f"signing: {len(cases)} receipts ({per_alg} per algorithm, randomized ECDSA, low-s normalized) "
          f"through both verifiers; un-normalized controls rejected {ctl.get('ES256')}/100 ES256, "
          f"{ctl.get('ES256K')}/100 ES256K; 6 refusals to sign"
          + ("" if not problems else f"; {len(problems)} problem(s)"))
    return problems


def self_check_suite() -> list[str]:
    """The §6.3 self-check must refuse payloads that break §5.2 or §5.3."""
    _, base_x, _ = SUITE[0]
    good, _ = issue(base_x)
    breaks = {
        "agent empty": lambda p: p["action"].update(agent=""),
        "bad status": lambda p: p.update(settlementStatus="captured"),
        "issuedAt 2^53": lambda p: p.update(issuedAt=2**53),
        "lone surrogate": lambda p: p.update(resourceUrl="\ud800"),
        "float member": lambda p: p.update(issuedAt=1.5),
        "extra member": lambda p: p.update(note="x"),
        "unsorted bindings": lambda p: p.update(bindings=[{"type": "b:b", "value": "1"},
                                                          {"type": "a:a", "value": "1"}]),
        "no identifier": lambda p: p.update(transaction=""),
    }
    problems = [] if self_check(good) else ["self-check refuses the base payload"]
    for label, f in breaks.items():
        p = copy.deepcopy(good)
        f(p)
        try:
            if self_check(p):
                problems.append(f"self-check accepts a payload with {label}")
        except Exception as e:  # noqa: BLE001
            problems.append(f"self-check raises {type(e).__name__} on a payload with {label}")
    return problems


def regenerate() -> None:
    EXCHANGES.mkdir(exist_ok=True)
    for old in EXCHANGES.glob("*.json"):
        old.unlink()
    entries, names = [], set()
    for name, exchange, expect in SUITE:
        if name in names:
            raise SystemExit(f"duplicate exchange name {name}")
        names.add(name)
        (EXCHANGES / f"{name}.json").write_text(json.dumps(exchange, indent=2) + "\n")
        if isinstance(expect, dict):
            entries.append({"file": f"{name}.json", "issued": True, "payload": expected_payload(expect)})
        else:
            entries.append({"file": f"{name}.json", "issued": False, "reason": expect})
    manifest = {
        "profile": "action-receipt", "specDraft": "0.4",
        "note": ("Issuer conformance. For each exchange a conformant issuer either produces "
                 "exactly `payload` (compare the RFC 8785 serializations) or refuses with "
                 "`reason`. Expected payloads were declared by hand as differences from the "
                 "payload printed in spec section 4.7; none was produced by running an issuer."),
        "refusalReasons": ALL_REFUSALS,
        "exchanges": entries,
    }
    (EXCHANGES / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")


def run_suite() -> int:
    manifest = json.loads((EXCHANGES / "MANIFEST.json").read_text())
    failures, reasons, issued = 0, set(), []
    rows = []
    if not manifest.get("exchanges"):
        print("SUITE INVALID: the exchange manifest is empty")
        return 2
    for e in manifest["exchanges"]:
        exchange = json.loads((EXCHANGES / e["file"]).read_text())
        payload, reason = issue(exchange)
        problems = []
        if e["issued"]:
            if payload is None:
                problems.append(f"refused with {reason}")
            else:
                issued.append((e["file"], exchange, payload))
                if A.jcs(payload) != A.jcs(e["payload"]):
                    diff = [k for k in set(payload) | set(e["payload"])
                            if payload.get(k) != e["payload"].get(k)]
                    problems.append(f"payload differs in {sorted(diff)}")
        else:
            reasons.add(reason)
            if payload is not None:
                problems.append("issued, expected a refusal")
            elif reason != e["reason"]:
                problems.append(f"refused with {reason}, expected {e['reason']}")
        rows.append([e, problems])
    trips = round_trips(issued) if issued else {}
    for e, problems in rows:
        problems += trips.get(e["file"], [])
        failures += bool(problems)
        print(f"[{' ok ' if not problems else 'FAIL'}] {e['file']:50s} "
              f"{'issue' if e['issued'] else 'refuse ' + e['reason']}"
              + ("   <- " + "; ".join(problems) if problems else ""))
    structural = []
    if set(ALL_REFUSALS) - reasons:
        structural.append(f"refusal reasons never exercised: {sorted(set(ALL_REFUSALS) - reasons)}")
    listed = {e["file"] for e in manifest["exchanges"]}
    on_disk = {f.name for f in EXCHANGES.glob("*.json")} - {"MANIFEST.json"}
    if listed != on_disk:
        structural.append(f"manifest and exchanges/ differ: {sorted(listed ^ on_disk)}")
    spec = (HERE / "action-receipt.md").read_text()
    sec = spec[spec.index("### 6.2 Procedure"):spec.index("### 6.3")]
    in_spec = re.findall(r"^\| \d+ \| `([a-z_]+)` \|", sec, flags=re.M)
    if in_spec != ALL_REFUSALS:
        structural.append(f"spec §6.2 and code disagree on refusal reasons or their order: {in_spec}")
    for p in self_check_suite():
        print("[FAIL] self-check:", p)
        failures += 1
    for p in signing_suite():
        print("[FAIL] signing:", p)
        failures += 1
    for s in structural:
        print("SUITE INVALID:", s)
    if structural:
        return 2
    if failures:
        print(f"{failures} issuer conformance failure(s)")
        return 1
    n = len(manifest["exchanges"])
    print(f"all {n} exchanges pass ({len(issued)} issued, {n - len(issued)} refused); all "
          f"{len(ALL_REFUSALS)} refusal reasons exercised; every issued receipt, signed by sign(), "
          f"verifies through both verifiers with the §6.3 report; self-check and signing hold")
    return 0


# --- the batch adapter --------------------------------------------------------

MAX_LINE_DEPTH = 64          # deeper than any value the procedure reads (§4.6 allows 8)
_DEEP = {"[": "[" * 9 + "]" * 9, "{": '{"":' * 8 + "{}" + "}" * 8}
_ID_RE = re.compile(r'"id"\s*:\s*("(?:[^"\\]|\\.)*")')
_JSON_TOKEN = re.compile(r'[ \t\n\r]*(?:(?P<s>"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*")'
                         r'|(?P<n>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)'
                         r'|(?P<l>true|false|null)|(?P<p>[\[\]{}:,]))')


def _json_valid(text: str) -> bool:
    """RFC 8259 syntax check without recursion, for lines too deep to hand to
    the recursive parser."""
    stack, i, n = [], 0, len(text)
    expect = "value"            # value | key | colon | comma_or_close | value_or_close | key_or_close
    while True:
        m = _JSON_TOKEN.match(text, i)
        if not m:
            return text[i:].strip(" \t\n\r") == "" and not stack and expect == "end"
        i = m.end()
        tok = m.group(0).strip()
        if expect == "end":
            return False
        if expect in ("value", "value_or_close"):
            if tok == "]" and expect == "value_or_close":
                stack.pop()
            elif tok in ("[", "{"):
                stack.append(tok)
                expect = "value_or_close" if tok == "[" else "key_or_close"
                continue
            elif m.group("s") or m.group("n") or m.group("l"):
                pass
            else:
                return False
        elif expect in ("key", "key_or_close"):
            if tok == "}" and expect == "key_or_close":
                stack.pop()
            elif m.group("s"):
                expect = "colon"
                continue
            else:
                return False
        elif expect == "colon":
            if tok != ":":
                return False
            expect = "value"
            continue
        elif expect == "comma_or_close":
            if tok == ",":
                expect = "value" if stack[-1] == "[" else "key"
                continue
            if (tok == "]" and stack[-1] == "[") or (tok == "}" and stack[-1] == "{"):
                stack.pop()
            else:
                return False
        expect = "comma_or_close" if stack else "end"


def _truncate_depth(text: str) -> str:
    """Replace every container nested deeper than MAX_LINE_DEPTH in the line by a
    small container of the same kind that is itself nested past every bound of
    §4.6. Nothing the procedure reads is that deep, so the answer is unchanged;
    the recursive JSON parser then never sees an unbounded depth (C-F2)."""
    out, start, depth, i, n, in_str = [], 0, 0, 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "[{":
            depth += 1
            if depth > MAX_LINE_DEPTH:
                j, d, s = i, 0, False
                while j < n:
                    cj = text[j]
                    if s:
                        if cj == "\\":
                            j += 2
                            continue
                        if cj == '"':
                            s = False
                    elif cj == '"':
                        s = True
                    elif cj in "[{":
                        d += 1
                    elif cj in "]}":
                        d -= 1
                        if d == 0:
                            j += 1
                            break
                    j += 1
                out.append(text[start:i])
                out.append(_DEEP[c])
                start = i = j
                depth -= 1
                continue
        elif c in "]}":
            depth -= 1
        i += 1
    out.append(text[start:])
    return "".join(out)


def _no_constants(_):
    raise ValueError("NaN and Infinity are not JSON")


def _parse_int(s: str):
    # The value of a number is the IEEE 754 double nearest its text (§4.6); an
    # integer too long for int() is far outside the safe range either way.
    return int(s) if len(s) <= 4000 else float(s)


def parse_line(text: str):
    if text.count("[") + text.count("{") > MAX_LINE_DEPTH:
        shallow = _truncate_depth(text)
        if shallow != text:
            if not _json_valid(text):
                raise ValueError("not JSON")
            text = shallow
    return json.loads(text, parse_constant=_no_constants, parse_int=_parse_int)


def answer(raw: bytes) -> dict:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"id": None, "issued": False, "reason": INVALID_INPUT}
    try:
        case = parse_line(text)
    except (ValueError, RecursionError):
        m = _ID_RE.search(text)
        cid = None
        if m:
            try:
                cid = json.loads(m.group(1))
            except ValueError:
                cid = None
        return {"id": cid, "issued": False, "reason": INVALID_INPUT}
    if not isinstance(case, dict):
        return {"id": None, "issued": False, "reason": INVALID_INPUT}
    payload, reason = issue(case.get("exchange"))
    out = {"id": case.get("id"), "issued": payload is not None}
    out.update({"payload": payload} if payload is not None else {"reason": reason})
    return out


def batch() -> int:
    out = sys.stdout
    for raw in sys.stdin.buffer:
        raw = raw.rstrip(b"\n")
        if raw.strip(b" \t\r") == b"":
            continue
        try:
            line = json.dumps(answer(raw), allow_nan=False)
        except Exception:  # noqa: BLE001
            line = json.dumps({"id": None, "issued": False, "reason": FAULT})
        out.write(line + "\n")
    out.flush()
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--batch" in argv:
        return batch()
    if "--regenerate" in argv:
        regenerate()
        print("regenerated exchanges/")
    return run_suite()


if __name__ == "__main__":
    sys.exit(main())
