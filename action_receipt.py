#!/usr/bin/env python3
"""
action_receipt.py — reference verifier + conformance suite for the x402
`action-receipt` extension (spec: action-receipt.md, draft 0.3).

The receipt is a JWS signed by the RESOURCE SERVER after settlement. It states
what was done, within what scope, with what outcome, and binds that statement to
the settlement, to the payment requirements the client accepted, and (through a
signed `bindings` array) to evidence defined by other extensions.

What changed against draft 0.2.1 (breaking; see the spec's version history):
  * `actionRef` is gone from the payload. The identifier is now `receiptRef`,
    "sha256:" + hex(SHA-256(JWS payload bytes)) — derived, never carried.
  * `receiptId` (issuer-chosen, unique) so two payments under one batch root in
    the same second are two different receipts.
  * `requirementsDigest` binds the accepted PaymentRequirements (amount, asset,
    payTo, scheme, network, timeout).
  * `supersedes` links a later lifecycle receipt to the one it replaces.
  * `bindings`: a signed array of {type, value} slots owned by other extensions.
  * The verifier returns a REPORT of what was and was not checked; "could not
    check" is never folded into PASS or into a forgery finding.

Nothing here is a new cryptographic primitive: JCS (RFC 8785) + JWS (RFC 7515,
ES256/ES256K/EdDSA) + SHA-256, composed.

    python3 action_receipt.py                 # verify committed vectors
    python3 action_receipt.py --regenerate    # rebuild vectors + MANIFEST + VECTORS.md, then verify
    python3 action_receipt.py --verify FILE   # verify one receipt against the "ok" context
    python3 action_receipt.py --worked        # print the spec's worked example

Requires `cryptography`. If `rfc8785` is installed every canonicalization is
cross-checked against it byte for byte; a disagreement is a verifier fault
(verdict ERROR), never a REJECT.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
VECTORS = HERE / "vectors"
SPEC = HERE / "action-receipt.md"

try:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils as asym_utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, load_pem_public_key,
    )
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

try:
    import rfc8785 as _rfc8785
    HAVE_RFC8785 = True
except ImportError:
    HAVE_RFC8785 = False


class VerifierFault(Exception):
    """The verifier itself is wrong (e.g. two canonicalizers disagree). This is
    never evidence about the receipt, so it must not surface as a REJECT."""


# --- RFC 8785 (JCS) over the admitted value domain ------------------------
# Admitted domain (spec §4.6): objects, arrays, strings of well-formed Unicode,
# and integers in the I-JSON safe range. Over that domain this is exactly
# RFC 8785: members sorted by UTF-16 code units, minimal string escaping, integers
# in shortest decimal form.

SAFE_INT_MAX = 2**53 - 1
MAX_DEPTH = 8


def _canon(v) -> str:
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float) and v.is_integer():
        return str(int(v))               # the VALUE is an integer (spec §4.6)
    if v is None:
        return "null"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False, separators=(",", ":")) + ":" + _canon(val)
            for k, val in items
        ) + "}"
    if isinstance(v, list):
        return "[" + ",".join(_canon(x) for x in v) + "]"
    raise TypeError(f"uncanonicalizable type: {type(v)!r}")


def jcs(value) -> bytes:
    mine = _canon(value).encode("utf-8")
    if HAVE_RFC8785:
        ref = _rfc8785.dumps(value)
        if mine != ref:
            raise VerifierFault(f"vendored JCS disagrees with rfc8785: {mine!r} != {ref!r}")
    return mine


def in_domain(v, depth: int = 0) -> bool:
    """True iff `v` lies in the admitted value domain of spec §4.6. `depth` is
    the number of containers enclosing `v`; at most MAX_DEPTH levels of nested
    objects/arrays are admitted."""
    if isinstance(v, str):
        try:
            v.encode("utf-8")           # lone surrogates do not encode
        except UnicodeEncodeError:
            return False
        return True
    if isinstance(v, bool) or v is None:
        return True
    if isinstance(v, int):
        return -SAFE_INT_MAX <= v <= SAFE_INT_MAX
    if isinstance(v, float):
        # The domain is defined on values, not spellings: JSON text "60.0" holds
        # the integer 60, and a parser that keeps it as a float must agree with
        # one that does not.
        return v.is_integer() and -SAFE_INT_MAX <= v <= SAFE_INT_MAX
    if isinstance(v, dict):
        return depth < MAX_DEPTH and all(
            in_domain(k, depth + 1) and in_domain(x, depth + 1) for k, x in v.items())
    if isinstance(v, list):
        return depth < MAX_DEPTH and all(in_domain(x, depth + 1) for x in v)
    return False


NOT_CANONICAL = object()   # sentinel: `None` is a legitimate parsed value (JSON null)


def parse_canonical(data: bytes):
    """Return the value iff `data` is the JCS serialization of a value in the
    admitted domain; otherwise NOT_CANONICAL. Everything a JSON parser could paper over
    lands here: bad UTF-8, non-JSON, lone surrogates, non-integer or out-of-range
    numbers, and any non-canonical byte form. Duplicate member names need no
    separate guard: a parser keeps one of them, so re-serializing never
    reproduces the input bytes."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return NOT_CANONICAL

    def no_constants(_):
        raise ValueError("non-finite number")

    try:
        value = json.loads(text, parse_constant=no_constants)
    except (ValueError, RecursionError):
        return NOT_CANONICAL
    if not in_domain(value):
        return NOT_CANONICAL
    if jcs(value) != data:
        return NOT_CANONICAL
    return value


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")


def b64url_decode(s: str) -> bytes:
    if not isinstance(s, str) or not _B64URL_RE.fullmatch(s) or len(s) % 4 == 1:
        raise ValueError("not unpadded base64url")
    data = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64url(data) != s:                 # non-zero trailing bits: a second spelling
        raise ValueError("non-canonical base64url")
    return data


def sha256_tag(data: bytes) -> str:
    """The digest form used throughout: "sha256:" + 64 lowercase hex."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


# --- payload schema (closed) ----------------------------------------------

PROFILE_VERSION = 1
TYP = "x402-action-receipt+jws"
HEADER_KEYS = {"alg", "kid", "typ"}
TOP_KEYS = {"version", "receiptId", "issuedAt", "network", "resourceUrl", "payer", "payTo",
            "transaction", "settlementRef", "settlementStatus", "requirementsDigest",
            "supersedes", "action", "bindings"}
ACTION_KEYS = {"agent", "actionType", "scope", "outcome"}
BINDING_KEYS = {"type", "value"}
STRING_TOP_FIELDS = {"receiptId", "network", "resourceUrl", "payer", "payTo", "transaction",
                     "settlementRef", "settlementStatus", "requirementsDigest", "supersedes"}
OUTCOMES = {"delivered", "refused", "partial", "disputed"}                   # SERVICE delivery
SETTLEMENT_STATUSES = {"settled", "capturePending", "reversed", "refunded"}  # PAYMENT lifecycle
MAX_BINDINGS = 16

RE_RECEIPT_ID = re.compile(r"[A-Za-z0-9_-]{22,64}")
RE_CAIP2 = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}")
RE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
RE_EVM_ADDRESS = re.compile(r"0x[0-9a-f]{40}")
RE_EVM_TX = re.compile(r"0x[0-9a-f]{64}")
RE_BINDING_TYPE = re.compile(r"[a-z][a-z0-9+.-]{0,63}:[\x21-\x7e]{1,191}")
RE_BINDING_VALUE = re.compile(r"[\x21-\x7e]{1,1024}")

SUPPORTED_ALGS = {"ES256", "ES256K", "EdDSA"}
ALG_CURVE = {"ES256": "secp256r1", "ES256K": "secp256k1"}
CURVE_ORDER = {  # math constants (low-s), not chain constants
    "secp256r1": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    "secp256k1": 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
}

# Binding types this specification itself defines (spec §4.5.2).
BT_ADVERTISED = "action-receipt:advertised-info"
BT_REVERSAL_TX = "action-receipt:reversal-transaction"


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


# --- reject reason codes (spec §5.13) -------------------------------------
R_MALFORMED = "invalid_payload"                              # core §9
R_TYP = "invalid_actionreceipt_typ"
R_UNKNOWN_ALG = "invalid_actionreceipt_alg"
R_NONCANONICAL = "invalid_actionreceipt_canonicalization"
R_UNSUPPORTED_VERSION = "invalid_actionreceipt_version"
R_INVALID_OUTCOME = "invalid_actionreceipt_outcome"
R_INVALID_STATUS = "invalid_actionreceipt_status"
R_BINDING = "invalid_actionreceipt_binding"
R_RESOURCE = "invalid_actionreceipt_resource_mismatch"
R_SIGNER_UNAUTH = "invalid_actionreceipt_signer"
R_KEY_UNRESOLVED = "invalid_actionreceipt_key_unresolved"
R_SIG_INVALID = "invalid_actionreceipt_signature"
R_SETTLEMENT_FAILED = "invalid_transaction_state"           # core §9
R_SETTLEMENT = "invalid_actionreceipt_settlement_mismatch"
R_REQUIREMENTS = "invalid_actionreceipt_requirements_mismatch"
R_STALE = "invalid_actionreceipt_freshness"

ALL_REASONS = {R_MALFORMED, R_TYP, R_UNKNOWN_ALG, R_NONCANONICAL, R_UNSUPPORTED_VERSION,
               R_INVALID_OUTCOME, R_INVALID_STATUS, R_BINDING, R_RESOURCE, R_SIGNER_UNAUTH,
               R_KEY_UNRESOLVED, R_SIG_INVALID, R_SETTLEMENT_FAILED, R_SETTLEMENT,
               R_REQUIREMENTS, R_STALE}
# Codes that mean "the verifier could not obtain what it needed", not "the
# receipt is wrong". A consumer must not read these as a finding against the signer.
INDETERMINATE_REASONS = {R_KEY_UNRESOLVED}

PASS = "PASS"
REJECT = "REJECT"
ERROR = "ERROR"          # verifier fault; says nothing about the receipt


class Context:
    """What the verifier holds besides the receipt (spec §5).

    success / transaction / settlement_ref / network / payer : from the
        SettlementResponse (core §5.3). UNSIGNED input: checks against it are
        consistency checks, not independent corroboration.
    accepted : the PaymentRequirements object the client accepted
        (PaymentPayload.accepted), or None when the verifier does not hold it.
    advertised_info : the `action-receipt` extension `info` object as echoed in
        the PaymentPayload, or None.
    mode : "session" (freshness enforced) or "archival" (age reported).
    """
    def __init__(self, success: bool, transaction: str = "", settlement_ref: str = "",
                 network=None, payer=None, accepted=None, advertised_info=None,
                 now: int = 0, max_age_s: int = 3600, mode: str = "session",
                 paid_resource_url=None):
        self.paid_resource_url = paid_resource_url   # set only by a verifier that paid
        self.success = success
        self.transaction = transaction
        self.settlement_ref = settlement_ref
        self.network = network
        self.payer = payer
        self.accepted = accepted
        self.advertised_info = advertised_info
        self.now = now
        self.max_age_s = max_age_s
        self.mode = mode


def _has(value) -> bool:
    """An unsigned input "has" a value iff it is a non-empty string (spec §5.8)."""
    return isinstance(value, str) and value != ""


def _is_evm(network: str) -> bool:
    return isinstance(network, str) and network.startswith("eip155:")


def _norm_unsigned(network: str, value):
    """Normalize a value taken from an UNSIGNED input before comparing it with a
    signed receipt field. Signed fields are never normalized: they are refused
    when out of grammar (spec §4.6)."""
    if _is_evm(network) and isinstance(value, str):
        return re.sub(r"[A-Z]", lambda m: m.group(0).lower(), value)   # ASCII only
    return value


def requirements_digest(accepted) -> str | None:
    """sha256 over the JCS form of the accepted PaymentRequirements; None when
    the object is outside the admitted value domain (spec §4.4)."""
    if not isinstance(accepted, dict) or not in_domain(accepted):
        return None
    return sha256_tag(jcs(accepted))


def validate_payload(payload) -> str | None:
    """Closed-schema and field-grammar validation (spec §5.3). Returns a reason
    code, or None when the payload is well formed."""
    if not isinstance(payload, dict) or set(payload.keys()) != TOP_KEYS:
        return R_MALFORMED
    if not _is_int(payload["version"]):
        return R_MALFORMED
    if payload["version"] != PROFILE_VERSION:
        return R_UNSUPPORTED_VERSION
    action = payload["action"]
    if not isinstance(action, dict) or set(action.keys()) != ACTION_KEYS:
        return R_MALFORMED
    if not all(isinstance(payload[f], str) for f in STRING_TOP_FIELDS):
        return R_MALFORMED
    if not all(isinstance(action[f], str) for f in ACTION_KEYS):
        return R_MALFORMED
    if not (_is_int(payload["issuedAt"]) and 0 <= payload["issuedAt"] <= SAFE_INT_MAX):
        return R_MALFORMED
    if not RE_RECEIPT_ID.fullmatch(payload["receiptId"]):
        return R_MALFORMED
    network = payload["network"]
    if not RE_CAIP2.fullmatch(network):
        return R_MALFORMED
    if not (payload["resourceUrl"] and payload["payer"] and payload["payTo"]
            and action["agent"] and action["actionType"]):
        return R_MALFORMED
    if not (payload["transaction"] or payload["settlementRef"]):
        return R_MALFORMED                       # at least one settlement identifier
    if _is_evm(network):
        if not (RE_EVM_ADDRESS.fullmatch(payload["payer"])
                and RE_EVM_ADDRESS.fullmatch(payload["payTo"])):
            return R_MALFORMED
        if payload["transaction"] and not RE_EVM_TX.fullmatch(payload["transaction"]):
            return R_MALFORMED
    if not RE_DIGEST.fullmatch(payload["requirementsDigest"]):
        return R_MALFORMED
    if payload["supersedes"] and not RE_DIGEST.fullmatch(payload["supersedes"]):
        return R_MALFORMED
    if action["outcome"] not in OUTCOMES:
        return R_INVALID_OUTCOME
    if payload["settlementStatus"] not in SETTLEMENT_STATUSES:
        return R_INVALID_STATUS
    bindings = payload["bindings"]
    if not isinstance(bindings, list):
        return R_MALFORMED
    if len(bindings) > MAX_BINDINGS:
        return R_BINDING
    previous = None
    for b in bindings:
        if not isinstance(b, dict) or set(b.keys()) != BINDING_KEYS:
            return R_BINDING
        t, v = b["type"], b["value"]
        if not (isinstance(t, str) and isinstance(v, str)):
            return R_BINDING
        if not (RE_BINDING_TYPE.fullmatch(t) and RE_BINDING_VALUE.fullmatch(v)):
            return R_BINDING
        if previous is not None and not previous < t:      # strictly ascending => unique
            return R_BINDING
        previous = t
    return None


def verify_detailed(receipt, ctx: Context, key_registry: dict) -> tuple[str, str | None, dict]:
    """Verify a receipt. Returns (verdict, reason, report).

    verdict  PASS | REJECT | ERROR
    reason   a §5.13 code on REJECT, "verifier_fault" on ERROR, None on PASS
    report   what was and was not evaluated (spec §5.12); {} unless PASS

    Never raises on hostile input. A fault in the verifier itself returns ERROR,
    which says nothing about the receipt.
    `key_registry` is a TEST FIXTURE standing in for anchor and key resolution
    (spec §5.4): kid -> PEM, plus "__service__:<resourceUrl>" and
    "__payTo__:<payTo>|<resourceUrl>" -> list of authorized kids.
    """
    try:
        return _verify(receipt, ctx, key_registry)
    except VerifierFault:
        return ERROR, "verifier_fault", {}
    except Exception:  # noqa: BLE001 — an unexpected exception is OUR bug, not a bad receipt
        return ERROR, "verifier_fault", {}


def verify_action_receipt(receipt, ctx: Context, key_registry: dict) -> tuple[str, str | None]:
    verdict, reason, _ = verify_detailed(receipt, ctx, key_registry)
    return verdict, reason


def _verify(receipt, ctx, key_registry):
    # §5.1 envelope and header -------------------------------------------
    if not isinstance(receipt, dict) or receipt.get("format") != "jws":
        return REJECT, R_MALFORMED, {}
    compact = receipt.get("signature")
    if not isinstance(compact, str) or compact.count(".") != 2:
        return REJECT, R_MALFORMED, {}
    h_b64, p_b64, s_b64 = compact.split(".")
    try:
        header = json.loads(b64url_decode(h_b64).decode("utf-8"))   # str: no encoding sniffing
        payload_bytes = b64url_decode(p_b64)
        raw_sig = b64url_decode(s_b64)
    except (ValueError, RecursionError):
        return REJECT, R_MALFORMED, {}
    if not isinstance(header, dict):
        return REJECT, R_MALFORMED, {}
    if header.get("typ") != TYP:
        return REJECT, R_TYP, {}
    if header.get("alg") not in SUPPORTED_ALGS:
        return REJECT, R_UNKNOWN_ALG, {}
    if set(header.keys()) != HEADER_KEYS or not isinstance(header.get("kid"), str):
        return REJECT, R_MALFORMED, {}
    alg, kid = header["alg"], header["kid"]

    # §5.2 canonical bytes — before any typing, so every parser-level
    # difference between languages lands on one reason code.
    payload = parse_canonical(payload_bytes)
    if payload is NOT_CANONICAL:
        return REJECT, R_NONCANONICAL, {}

    # §5.3 closed schema and field grammar --------------------------------
    reason = validate_payload(payload)
    if reason:
        return REJECT, reason, {}

    # §5.4 signer authorization, BEFORE any key material is used. Both anchors
    # are scoped to the resource. A kid that no anchor authorizes is refused
    # without dereferencing anything the receipt names.
    checks = {}
    if _has(ctx.paid_resource_url):
        if payload["resourceUrl"] != ctx.paid_resource_url:
            return REJECT, R_RESOURCE, {}
        checks["resourceUrl"] = "compared"
    else:
        checks["resourceUrl"] = "not_compared"
    service_kids = key_registry.get("__service__:" + payload["resourceUrl"]) or []
    payto_kids = key_registry.get(
        "__payTo__:" + payload["payTo"] + "|" + payload["resourceUrl"]) or []
    if kid not in service_kids and kid not in payto_kids:
        return REJECT, R_SIGNER_UNAUTH, {}

    # §5.5 key resolution — authorized, but the key could not be obtained.
    pub = _load_key(key_registry.get(kid))
    if pub is None:
        return REJECT, R_KEY_UNRESOLVED, {}

    # §5.6 signature (curve bound to alg; low-s for ECDSA) -----------------
    if not _verify_jws_sig(alg, pub, f"{h_b64}.{p_b64}".encode(), raw_sig):
        return REJECT, R_SIG_INVALID, {}

    # §5.7 settlement success ---------------------------------------------
    if ctx.success is not True or not (_has(ctx.transaction) or _has(ctx.settlement_ref)):
        return REJECT, R_SETTLEMENT_FAILED, {}

    # §5.8 settlement binding. Every identifier the SettlementResponse provides
    # must equal the receipt's, and the receipt must not carry one the response
    # does not provide.
    network = payload["network"]
    if _has(ctx.transaction):
        if payload["transaction"] != _norm_unsigned(network, ctx.transaction):
            return REJECT, R_SETTLEMENT, {}
    elif payload["transaction"]:
        return REJECT, R_SETTLEMENT, {}
    if _has(ctx.settlement_ref):
        if payload["settlementRef"] != ctx.settlement_ref:
            return REJECT, R_SETTLEMENT, {}
    elif payload["settlementRef"]:
        return REJECT, R_SETTLEMENT, {}
    if isinstance(ctx.network, str) and RE_CAIP2.fullmatch(ctx.network):
        if network != ctx.network:
            return REJECT, R_SETTLEMENT, {}
        checks["network"] = "compared"
    else:
        checks["network"] = "not_compared"
    if _has(ctx.payer):
        if payload["payer"] != _norm_unsigned(network, ctx.payer):
            return REJECT, R_SETTLEMENT, {}
        checks["payer"] = "compared"
    else:
        checks["payer"] = "not_compared"

    # §5.9 payment requirements -------------------------------------------
    digest = requirements_digest(ctx.accepted) if ctx.accepted is not None else None
    if digest is None:
        checks["requirements"] = "not_evaluated"
        checks["payTo"] = "not_compared"
    else:
        if payload["requirementsDigest"] != digest:
            return REJECT, R_REQUIREMENTS, {}
        if ctx.accepted.get("network") != network:
            return REJECT, R_REQUIREMENTS, {}
        if _norm_unsigned(network, ctx.accepted.get("payTo")) != payload["payTo"]:
            return REJECT, R_REQUIREMENTS, {}
        checks["requirements"] = "matched"
        checks["payTo"] = "compared"

    # §5.10 freshness ------------------------------------------------------
    age = ctx.now - payload["issuedAt"]
    if age < -60:
        return REJECT, R_STALE, {}
    if ctx.mode == "session":
        if age > ctx.max_age_s:
            return REJECT, R_STALE, {}
        checks["freshness"] = "enforced"
    else:
        checks["freshness"] = "reported"

    # §5.11 bindings — reported per entry, never folded into the verdict.
    binding_report = []
    for b in payload["bindings"]:
        status = "not_evaluated"
        if b["type"] == BT_ADVERTISED and isinstance(ctx.advertised_info, dict) \
                and in_domain(ctx.advertised_info):
            info = ctx.advertised_info
            ok = b["value"] == sha256_tag(jcs(info))
            for member in ("scope", "actionType"):
                if member in info and info[member] != payload["action"][member]:
                    ok = False
            status = "matched" if ok else "mismatched"
        binding_report.append({"type": b["type"], "status": status})

    report = {
        "receiptRef": sha256_tag(payload_bytes),
        "outcome": payload["action"]["outcome"],
        "settlementStatus": payload["settlementStatus"],
        "ageSeconds": age,
        "checks": checks,
        "supersedes": payload["supersedes"],
        "bindings": binding_report,
    }
    return PASS, None, report


def _load_key(pem):
    """The public key for a PEM string, or None when there is no usable key."""
    if not isinstance(pem, str) or not pem:
        return None
    try:
        return load_pem_public_key(pem.encode())
    except (ValueError, TypeError):
        return None


def _verify_jws_sig(alg, pub, signing_input: bytes, raw_sig: bytes) -> bool:
    try:
        if alg in ("ES256", "ES256K"):
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                return False
            if pub.curve.name != ALG_CURVE[alg]:
                return False
            if len(raw_sig) != 64:
                return False
            r = int.from_bytes(raw_sig[:32], "big")
            s = int.from_bytes(raw_sig[32:], "big")
            if s > CURVE_ORDER[ALG_CURVE[alg]] // 2:      # reject high-s (malleability)
                return False
            der = asym_utils.encode_dss_signature(r, s)
            pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            return True
        if alg == "EdDSA":
            if not isinstance(pub, ed25519.Ed25519PublicKey):
                return False
            pub.verify(raw_sig, signing_input)
            return True
    except InvalidSignature:
        return False
    return False


def decode_payload(receipt) -> tuple[bytes, dict]:
    """Suite helper: the JWS payload bytes and their parsed value."""
    raw = b64url_decode(receipt["signature"].split(".")[1])
    return raw, json.loads(raw)


# --- deterministic key material -------------------------------------------

def _es_key(alg):
    curve = ec.SECP256R1() if alg == "ES256" else ec.SECP256K1()
    seed = {"ES256": 0x1111111111111111111111111111111111111111111111111111111111111111,
            "ES256K": 0x2222222222222222222222222222222222222222222222222222222222222222}[alg]
    return ec.derive_private_key(seed, curve)


def _ed_key():
    return ed25519.Ed25519PrivateKey.from_private_bytes(b"\x03" * 32)


def _pem(sk) -> str:
    return sk.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def _sign_jws(alg, kid, sk, payload_bytes: bytes, *, force_high_s=False, header=None) -> str:
    header = {"alg": alg, "kid": kid, "typ": TYP} if header is None else header
    h_b64 = b64url(_canon(header).encode())
    p_b64 = b64url(payload_bytes)
    signing_input = f"{h_b64}.{p_b64}".encode()
    if alg in ("ES256", "ES256K"):
        der = sk.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        n = CURVE_ORDER[ALG_CURVE[alg]]
        s = max(s, n - s) if force_high_s else min(s, n - s)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    elif alg == "EdDSA":
        raw = sk.sign(signing_input)
    else:
        raise ValueError(alg)
    return f"{h_b64}.{p_b64}.{b64url(raw)}"


# --- fixed test inputs -----------------------------------------------------
# Receipt-side EVM identifiers are lowercase (spec §4.6). The SettlementResponse
# and PaymentRequirements fixtures deliberately use other casings where noted.

SETTLEMENT_TX = "0x" + "ab" * 32
BATCH_REF = "batch:voucher:9f3c1d0a-0000-4a11-b2cc-settlement-root-01"
NETWORK = "eip155:8453"
PAYER = "0x857b06519e91e3a54538791bdbb0e22373e36b66"
PAYER_CHECKSUM = "0x857b06519E91e3A54538791bDbb0E22373e36b66"
PAY_TO = "0x209693bc6afc0c5328ba36faf03c514ef312287c"
PAY_TO_CHECKSUM = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
RESOURCE = "https://api.example.com/v1/complete"
ISSUED_AT = 1703123456
VERIFIER_NOW = 1703123500
RECEIPT_ID = "Zm9yLXRlc3Rpbmctb25seS0wMQ"
RECEIPT_ID_2 = "Zm9yLXRlc3Rpbmctb25seS0wMg"

ACCEPTED = {
    "scheme": "exact", "network": NETWORK, "amount": "10000",
    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "payTo": PAY_TO_CHECKSUM, "maxTimeoutSeconds": 60,
    "extra": {"name": "USD Coin", "version": "2"},
}
ADVERTISED_INFO = {"willIssueReceipt": True, "actionType": "inference.completion",
                   "scope": "read:model-x"}

KID_ES256 = "did:web:api.example.com#es256"
KID_ES256K = "did:web:api.example.com#es256k"
KID_ED = "did:web:api.example.com#ed25519"
KID_PAYTO = "did:web:api.example.com#payto"      # authorized via the payTo anchor only
KID_ABSENT = "did:web:api.example.com#rotated"   # authorized, but no key can be resolved
KID_UNUSABLE = "did:web:api.example.com#unusable"  # authorized, but the key does not parse
KID_EVIL = "did:web:evil.example#k"              # has a key, authorized by no anchor


def _base_payload(**overrides) -> dict:
    action = {"agent": "did:web:agent.example", "actionType": "inference.completion",
              "scope": "read:model-x", "outcome": "delivered"}
    action.update(overrides.pop("action", {}))
    p = {"version": PROFILE_VERSION, "receiptId": RECEIPT_ID, "issuedAt": ISSUED_AT,
         "network": NETWORK, "resourceUrl": RESOURCE, "payer": PAYER, "payTo": PAY_TO,
         "transaction": SETTLEMENT_TX, "settlementRef": "", "settlementStatus": "settled",
         "requirementsDigest": requirements_digest(ACCEPTED), "supersedes": "",
         "action": action, "bindings": []}
    p.update(overrides)
    return p


def _registry():
    es, esk, ed = _es_key("ES256"), _es_key("ES256K"), _ed_key()
    payto = ec.derive_private_key(0x5555, ec.SECP256R1())
    evil = ec.derive_private_key(0x4444, ec.SECP256R1())
    return {
        KID_ES256: _pem(es), KID_ES256K: _pem(esk), KID_ED: _pem(ed),
        KID_PAYTO: _pem(payto), KID_EVIL: _pem(evil), KID_UNUSABLE: "not a public key",
        "__service__:" + RESOURCE: [KID_ES256, KID_ES256K, KID_ED, KID_ABSENT, KID_UNUSABLE],
        "__payTo__:" + PAY_TO + "|" + RESOURCE: [KID_PAYTO],
    }, {"ES256": es, "ES256K": esk, "EdDSA": ed, "PAYTO": payto, "EVIL": evil}


# --- verification contexts -------------------------------------------------

C_OK, C_FAILED, C_BATCH, C_BOTH = "ok", "failed", "batch", "both"
C_NOREQ, C_CASE, C_NOPAYER, C_ARCHIVAL, C_ADVERT = (
    "no_requirements", "response_casing", "no_payer", "archival", "advertised")
C_REQ_FLOAT, C_REQ_NONOBJ, C_PAYER_EMPTY = (
    "requirements_float_spelling", "requirements_not_object", "payer_empty_string")
C_REQ_NET = "requirements_other_network"
C_PAID, C_PAID_OTHER = "paid_this_resource", "paid_another_resource"
C_ADVERT_NONSTRING = "advertised_scope_not_a_string"
ADVERTISED_NONSTRING = {"willIssueReceipt": True, "scope": 5}
ACCEPTED_OTHER_NETWORK = dict(ACCEPTED, network="eip155:1")

CONTEXTS = {
    C_OK: Context(True, transaction=SETTLEMENT_TX, network=NETWORK, payer=PAYER,
                  accepted=ACCEPTED, now=VERIFIER_NOW),
    C_FAILED: Context(False, transaction="", network=NETWORK, payer=PAYER,
                      accepted=ACCEPTED, now=VERIFIER_NOW),
    C_BATCH: Context(True, settlement_ref=BATCH_REF, network=NETWORK, payer=PAYER,
                     accepted=ACCEPTED, now=VERIFIER_NOW),
    C_BOTH: Context(True, transaction=SETTLEMENT_TX, settlement_ref=BATCH_REF,
                    network=NETWORK, payer=PAYER, accepted=ACCEPTED, now=VERIFIER_NOW),
    # the verifier does not hold the accepted PaymentRequirements
    C_NOREQ: Context(True, transaction=SETTLEMENT_TX, network=NETWORK, payer=PAYER,
                     now=VERIFIER_NOW),
    # the facilitator returned a checksummed payer and upper-case transaction hex
    C_CASE: Context(True, transaction="0x" + "AB" * 32, network=NETWORK, payer=PAYER_CHECKSUM,
                    accepted=ACCEPTED, now=VERIFIER_NOW),
    # core §5.3 makes `payer` optional
    C_NOPAYER: Context(True, transaction=SETTLEMENT_TX, network=NETWORK, payer=None,
                       accepted=ACCEPTED, now=VERIFIER_NOW),
    # an auditor, 180 days later
    C_ARCHIVAL: Context(True, transaction=SETTLEMENT_TX, network=NETWORK, payer=PAYER,
                        accepted=ACCEPTED, now=ISSUED_AT + 180 * 86400, mode="archival"),
    # found by fuzz cycle 1 ------------------------------------------------
    # the requirements arrived as JSON text spelling an integer "60.0"
    C_REQ_FLOAT: Context(True, transaction=SETTLEMENT_TX, network=NETWORK, payer=PAYER,
                         accepted=dict(ACCEPTED, maxTimeoutSeconds=60.0), now=VERIFIER_NOW),
    # what the verifier holds as "requirements" is not a JSON object
    C_REQ_NONOBJ: Context(True, transaction=SETTLEMENT_TX, network=NETWORK, payer=PAYER,
                          accepted=[], now=VERIFIER_NOW),
    # the response carries payer as an empty string
    C_PAYER_EMPTY: Context(True, transaction=SETTLEMENT_TX, network=NETWORK, payer="",
                           accepted=ACCEPTED, now=VERIFIER_NOW),
    # found by the requirements trace: the response's network is not in CAIP-2
    # form (so §5.8 cannot compare it) and the accepted requirements name another
    C_REQ_NET: Context(True, transaction=SETTLEMENT_TX, network="base", payer=PAYER,
                       accepted=ACCEPTED_OTHER_NETWORK, now=VERIFIER_NOW),
    # the verifier made the payment itself and knows the URL it paid for
    C_PAID: Context(True, transaction=SETTLEMENT_TX, network=NETWORK, payer=PAYER,
                    accepted=ACCEPTED, now=VERIFIER_NOW, paid_resource_url=RESOURCE),
    C_PAID_OTHER: Context(True, transaction=SETTLEMENT_TX, network=NETWORK, payer=PAYER,
                          accepted=ACCEPTED, now=VERIFIER_NOW,
                          paid_resource_url="https://api.example.com/v1/other"),
    # the advertised info carries a scope that is not a string
    C_ADVERT_NONSTRING: Context(True, transaction=SETTLEMENT_TX, network=NETWORK, payer=PAYER,
                                accepted=ACCEPTED, advertised_info=ADVERTISED_NONSTRING,
                                now=VERIFIER_NOW),
    # the verifier also holds the echoed extension info
    C_ADVERT: Context(True, transaction=SETTLEMENT_TX, network=NETWORK, payer=PAYER,
                      accepted=ACCEPTED, advertised_info=ADVERTISED_INFO, now=VERIFIER_NOW),
}

COMPOSED_BINDINGS = [
    {"type": BT_ADVERTISED, "value": sha256_tag(jcs(ADVERTISED_INFO))},
    {"type": "https://example.org/specs/custom-evidence#digest",
     "value": "sha256:" + "5c" * 32},
    {"type": "offer-receipt:authorizationCommitment",
     "value": "0x5d905bbf08a97e04ab551d276d8e94b1abaff7d0737324d360e983c2796af23b"},
    {"type": "offer-receipt:authorizationMethod", "value": "eip3009"},
    {"type": "response-provenance:fixedPointVersion", "value": "GVP-FixedPoint/2"},
    {"type": "response-provenance:responseHash",
     "value": "sha256:81ea1f2227fd9df5b868954e6d26d091810352f148dade483b260844788ede03"},
]

# --- conformance suite: (file, verdict, reason, context) ------------------
# Every negative is ONE mutation of a canonical positive. `reason` is the code of
# the first check that mutation fails under the normative order of spec §5.

SUITE = [
    # positives
    ("pos_es256_valid.json", PASS, None, C_OK),
    ("pos_es256k_valid.json", PASS, None, C_OK),
    ("pos_eddsa_valid.json", PASS, None, C_OK),
    ("pos_payto_signer.json", PASS, None, C_OK),
    ("pos_outcome_refused.json", PASS, None, C_OK),
    ("pos_outcome_partial.json", PASS, None, C_OK),
    ("pos_outcome_disputed.json", PASS, None, C_OK),
    ("pos_batch_settled.json", PASS, None, C_BATCH),
    ("pos_batch_second_payment.json", PASS, None, C_BATCH),
    ("pos_capture_pending.json", PASS, None, C_BATCH),
    ("pos_reversed.json", PASS, None, C_BATCH),
    ("pos_refunded_supersedes.json", PASS, None, C_OK),
    ("pos_bindings_composed.json", PASS, None, C_ADVERT),
    ("pos_bindings_unheld.json", PASS, None, C_OK),
    ("pos_binding_advertised_digest_differs.json", PASS, None, C_ADVERT),
    ("pos_binding_advertised_scope_differs.json", PASS, None, C_ADVERT),
    ("pos_binding_advertised_scope_not_string.json", PASS, None, C_ADVERT_NONSTRING),
    ("pos_requirements_not_held.json", PASS, None, C_NOREQ),
    ("pos_response_casing.json", PASS, None, C_CASE),
    ("pos_payer_absent.json", PASS, None, C_NOPAYER),
    ("pos_archival_180d.json", PASS, None, C_ARCHIVAL),
    ("pos_non_ascii_nfc.json", PASS, None, C_OK),
    ("pos_non_ascii_nfd.json", PASS, None, C_OK),
    ("pos_requirements_float_spelling.json", PASS, None, C_REQ_FLOAT),
    ("pos_requirements_not_object.json", PASS, None, C_REQ_NONOBJ),
    ("pos_payer_empty_string.json", PASS, None, C_PAYER_EMPTY),
    ("pos_resource_paid.json", PASS, None, C_PAID),
    # §5.1 envelope and header
    ("neg_not_jws_format.json", REJECT, R_MALFORMED, C_OK),
    ("neg_base64url_trailing_bits.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_not_object.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_bom.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_utf16.json", REJECT, R_MALFORMED, C_OK),
    ("neg_kid_not_string.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_extra_member.json", REJECT, R_MALFORMED, C_OK),
    ("neg_typ_missing.json", REJECT, R_TYP, C_OK),
    ("neg_typ_wrong.json", REJECT, R_TYP, C_OK),
    ("neg_unknown_alg.json", REJECT, R_UNKNOWN_ALG, C_OK),
    # §5.2 canonical bytes
    ("neg_canon_member_order.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_whitespace.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_number_float.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_number_exponent.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_number_negative_zero.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_number_unsafe_integer.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_duplicate_member.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_lone_surrogate.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_escaped_ascii.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_not_json.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_nesting_depth.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_invalid_utf8.json", REJECT, R_NONCANONICAL, C_OK),
    # §5.3 closed schema and field grammar
    ("neg_schema_not_object.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_null.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_unknown_member.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_missing_member.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_action_scalar.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_issuedat_string.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_issuedat_negative.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_version_boolean.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_no_settlement_id.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_receiptid_short.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_network_not_caip2.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_payer_checksum_case.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_transaction_uppercase.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_digest_base64url.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_supersedes_grammar.json", REJECT, R_MALFORMED, C_OK),
    ("neg_unsupported_version.json", REJECT, R_UNSUPPORTED_VERSION, C_OK),
    ("neg_invalid_outcome.json", REJECT, R_INVALID_OUTCOME, C_OK),
    ("neg_invalid_status.json", REJECT, R_INVALID_STATUS, C_OK),
    ("neg_binding_unsorted.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_duplicate_type.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_extra_member.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_type_grammar.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_value_non_ascii.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_too_many.json", REJECT, R_BINDING, C_OK),
    # §5.4 resource and signer authorization
    ("neg_resource_mismatch.json", REJECT, R_RESOURCE, C_PAID_OTHER),
    ("neg_signer_unauthorized.json", REJECT, R_SIGNER_UNAUTH, C_OK),
    ("neg_signer_unknown_kid.json", REJECT, R_SIGNER_UNAUTH, C_OK),
    ("neg_signer_payto_wrong_resource.json", REJECT, R_SIGNER_UNAUTH, C_OK),
    # §5.5 key resolution
    ("neg_key_unresolved.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    ("neg_key_unusable.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    # §5.6 signature
    ("neg_sig_tampered_payload.json", REJECT, R_SIG_INVALID, C_OK),
    ("neg_sig_high_s.json", REJECT, R_SIG_INVALID, C_OK),
    ("neg_sig_wrong_curve.json", REJECT, R_SIG_INVALID, C_OK),
    # §5.7 settlement success
    ("neg_settlement_failed.json", REJECT, R_SETTLEMENT_FAILED, C_FAILED),
    # §5.8 settlement binding
    ("neg_settlement_transaction_mismatch.json", REJECT, R_SETTLEMENT, C_OK),
    ("neg_settlement_ref_mismatch.json", REJECT, R_SETTLEMENT, C_BATCH),
    ("neg_settlement_network_mismatch.json", REJECT, R_SETTLEMENT, C_OK),
    ("neg_settlement_payer_mismatch.json", REJECT, R_SETTLEMENT, C_OK),
    ("neg_settlement_uncorroborated_transaction.json", REJECT, R_SETTLEMENT, C_BATCH),
    ("neg_settlement_dropped_transaction.json", REJECT, R_SETTLEMENT, C_BOTH),
    # §5.9 payment requirements
    ("neg_requirements_amount_changed.json", REJECT, R_REQUIREMENTS, C_OK),
    ("neg_requirements_payto_mismatch.json", REJECT, R_REQUIREMENTS, C_OK),
    ("neg_requirements_network_mismatch.json", REJECT, R_REQUIREMENTS, C_REQ_NET),
    # §5.10 freshness
    ("neg_freshness_stale.json", REJECT, R_STALE, C_OK),
    ("neg_freshness_future_archival.json", REJECT, R_STALE, C_ARCHIVAL),
]

# Pairs of positives that MUST have different receiptRef values, with the reason.
DISTINCT = [
    ("pos_batch_settled.json", "pos_batch_second_payment.json",
     "two payments under one batch root in the same second"),
    ("pos_non_ascii_nfc.json", "pos_non_ascii_nfd.json",
     "no Unicode normalization is applied: NFC and NFD are different receipts"),
    ("pos_es256_valid.json", "pos_outcome_refused.json",
     "a different statement about the same settlement"),
]
# Groups of positives that MUST share one receiptRef: the identifier names the
# signed statement, not the signature or the key that made it.
SAME = [
    (["pos_es256_valid.json", "pos_es256k_valid.json", "pos_eddsa_valid.json",
      "pos_payto_signer.json", "pos_response_casing.json", "pos_payer_absent.json",
      "pos_requirements_not_held.json", "pos_archival_180d.json",
      "pos_requirements_float_spelling.json", "pos_requirements_not_object.json",
      "pos_payer_empty_string.json", "pos_resource_paid.json"],
     "one statement signed under four keys and verified in nine contexts"),
]

# Hand-declared report expectations (subset match). MANIFEST.json pins the full
# report of every positive, but that pin is written by the verifier itself, so
# these are the independent statement of what each report must say.
_NOT_EVALUATED_ALL = {b["type"]: "not_evaluated" for b in COMPOSED_BINDINGS}
EXPECT_REPORT = {
    "pos_resource_paid.json": {"checks": {"resourceUrl": "compared"}},
    "pos_es256_valid.json": {"checks": {"resourceUrl": "not_compared",
                                        "network": "compared", "payer": "compared",
                                        "requirements": "matched", "payTo": "compared",
                                        "freshness": "enforced"},
                             "ageSeconds": VERIFIER_NOW - ISSUED_AT, "bindings": {}},
    "pos_requirements_not_held.json": {"checks": {"requirements": "not_evaluated",
                                                  "payTo": "not_compared"}},
    "pos_payer_absent.json": {"checks": {"payer": "not_compared"}},
    "pos_payer_empty_string.json": {"checks": {"payer": "not_compared"}},
    "pos_requirements_float_spelling.json": {"checks": {"requirements": "matched",
                                                        "payTo": "compared"}},
    "pos_requirements_not_object.json": {"checks": {"requirements": "not_evaluated",
                                                    "payTo": "not_compared"}},
    "pos_archival_180d.json": {"checks": {"freshness": "reported"}, "ageSeconds": 180 * 86400},
    "pos_bindings_composed.json": {"bindings": dict(_NOT_EVALUATED_ALL, **{BT_ADVERTISED: "matched"})},
    "pos_bindings_unheld.json": {"bindings": _NOT_EVALUATED_ALL},
    "pos_binding_advertised_digest_differs.json": {"bindings": {BT_ADVERTISED: "mismatched"}},
    "pos_binding_advertised_scope_differs.json": {"bindings": {BT_ADVERTISED: "mismatched"}},
    "pos_binding_advertised_scope_not_string.json": {"bindings": {BT_ADVERTISED: "mismatched"}},
    "pos_refunded_supersedes.json": {"settlementStatus": "refunded",
                                     "bindings": {BT_REVERSAL_TX: "not_evaluated"}},
    "pos_outcome_refused.json": {"outcome": "refused"},
}


def report_mismatches(report: dict, want: dict) -> list[str]:
    out = []
    for key, value in want.items():
        if key == "checks":
            for k, v in value.items():
                if report["checks"].get(k) != v:
                    out.append(f"checks.{k}: want {v}, got {report['checks'].get(k)}")
        elif key == "bindings":
            got = {b["type"]: b["status"] for b in report["bindings"]}
            if got != value:
                out.append(f"bindings: want {value}, got {got}")
        elif report.get(key) != value:
            out.append(f"{key}: want {value}, got {report.get(key)}")
    return out


# One mutation per signed member, re-signed and verified in the "ok" context.
# The expected result says what the verifier's context constrains. Members whose
# mutation still PASSes are ISSUER-ASSERTED: nothing the verifier holds bounds them.
_OTHER_ADDR = "0x" + "11" * 20
MUTATIONS = [
    ("version", lambda p: p.update(version=2), R_UNSUPPORTED_VERSION),
    ("receiptId", lambda p: p.update(receiptId=RECEIPT_ID_2), None),
    ("issuedAt", lambda p: p.update(issuedAt=ISSUED_AT + 1), None),
    ("network", lambda p: p.update(network="eip155:1"), R_SETTLEMENT),
    ("resourceUrl", lambda p: p.update(resourceUrl=RESOURCE + "/x"), R_SIGNER_UNAUTH),
    ("payer", lambda p: p.update(payer=_OTHER_ADDR), R_SETTLEMENT),
    ("payTo", lambda p: p.update(payTo=_OTHER_ADDR), R_REQUIREMENTS),
    ("transaction", lambda p: p.update(transaction="0x" + "cd" * 32), R_SETTLEMENT),
    ("settlementRef", lambda p: p.update(settlementRef="batch:other"), R_SETTLEMENT),
    ("settlementStatus", lambda p: p.update(settlementStatus="refunded"), None),
    ("requirementsDigest", lambda p: p.update(requirementsDigest="sha256:" + "00" * 32),
     R_REQUIREMENTS),
    ("supersedes", lambda p: p.update(supersedes="sha256:" + "22" * 32), None),
    ("action.agent", lambda p: p["action"].update(agent="did:web:other.example"), None),
    ("action.actionType", lambda p: p["action"].update(actionType="inference.embedding"), None),
    ("action.scope", lambda p: p["action"].update(scope="write:model-x"), None),
    ("action.outcome", lambda p: p["action"].update(outcome="partial"), None),
    ("bindings", lambda p: p.update(bindings=[{"type": "example:note", "value": "x"}]), None),
]


def regenerate_vectors() -> None:
    if not HAVE_CRYPTO:
        sys.exit("cannot regenerate vectors without `cryptography`")
    VECTORS.mkdir(exist_ok=True)
    for old in VECTORS.glob("*.json"):
        old.unlink()
    registry, keys = _registry()
    es = keys["ES256"]

    def w(name, receipt):
        (VECTORS / name).write_text(json.dumps(receipt, indent=2) + "\n")

    def signed(payload, alg="ES256", kid=KID_ES256, key=None, **kw):
        """Sign the canonical bytes of `payload` (which may be schema-invalid)."""
        return {"format": "jws",
                "signature": _sign_jws(alg, kid, key or keys[alg], _canon(payload).encode(), **kw)}

    def signed_raw(raw: bytes, **kw):
        return {"format": "jws", "signature": _sign_jws("ES256", KID_ES256, es, raw, **kw)}

    base = _base_payload
    base_text = _canon(base())

    # ---- positives ----
    w("pos_es256_valid.json", signed(base()))
    w("pos_es256k_valid.json", signed(base(), "ES256K", KID_ES256K))
    w("pos_eddsa_valid.json", signed(base(), "EdDSA", KID_ED))
    w("pos_payto_signer.json", signed(base(), "ES256", KID_PAYTO, keys["PAYTO"]))
    w("pos_outcome_refused.json", signed(base(action={"outcome": "refused"})))
    w("pos_outcome_partial.json", signed(base(action={"outcome": "partial"})))
    w("pos_outcome_disputed.json", signed(base(action={"outcome": "disputed"})))
    w("pos_batch_settled.json", signed(base(transaction="", settlementRef=BATCH_REF)))
    w("pos_batch_second_payment.json",
      signed(base(transaction="", settlementRef=BATCH_REF, receiptId=RECEIPT_ID_2)))
    w("pos_capture_pending.json",
      signed(base(transaction="", settlementRef=BATCH_REF, settlementStatus="capturePending")))
    w("pos_reversed.json",
      signed(base(transaction="", settlementRef=BATCH_REF, settlementStatus="reversed",
                  receiptId=RECEIPT_ID_2,
                  supersedes=sha256_tag(_canon(base(
                      transaction="", settlementRef=BATCH_REF,
                      settlementStatus="capturePending")).encode()))))
    w("pos_refunded_supersedes.json",
      signed(base(settlementStatus="refunded", receiptId=RECEIPT_ID_2,
                  supersedes=sha256_tag(base_text.encode()),
                  bindings=[{"type": BT_REVERSAL_TX, "value": "0x" + "ef" * 32}])))
    w("pos_bindings_composed.json", signed(base(bindings=COMPOSED_BINDINGS)))
    # the digest matches the info held; a present, non-string scope can never be equal
    w("pos_binding_advertised_scope_not_string.json",
      signed(base(bindings=[{"type": BT_ADVERTISED, "value": sha256_tag(jcs(ADVERTISED_NONSTRING))}])))
    w("pos_bindings_unheld.json", signed(base(bindings=COMPOSED_BINDINGS)))
    w("pos_binding_advertised_digest_differs.json",
      signed(base(bindings=[{"type": BT_ADVERTISED, "value": "sha256:" + "77" * 32}])))
    w("pos_binding_advertised_scope_differs.json",
      signed(base(action={"scope": "write:model-x"},
                  bindings=[{"type": BT_ADVERTISED, "value": sha256_tag(jcs(ADVERTISED_INFO))}])))
    for name in ("pos_requirements_not_held.json", "pos_response_casing.json",
                 "pos_payer_absent.json", "pos_archival_180d.json",
                 "pos_requirements_float_spelling.json", "pos_requirements_not_object.json",
                 "pos_payer_empty_string.json", "pos_resource_paid.json",
                 "neg_resource_mismatch.json"):
        w(name, signed(base()))
    nfc = unicodedata.normalize("NFC", "did:web:café.example")
    nfd = unicodedata.normalize("NFD", "did:web:café.example")
    w("pos_non_ascii_nfc.json",
      signed(base(action={"agent": nfc, "scope": "lire:modèle \U0001d4b3\u0007"})))
    w("pos_non_ascii_nfd.json",
      signed(base(action={"agent": nfd, "scope": "lire:modèle \U0001d4b3\u0007"})))

    # ---- §5.1 envelope and header ----
    good = _sign_jws("ES256", KID_ES256, es, base_text.encode())
    _, p_ok, s_ok = good.split(".")
    w("neg_not_jws_format.json", {"format": "eip712", "signature": good})
    # Same signature bytes, second spelling: the last character of a 64-byte
    # signature carries 2 data bits and 4 padding bits; set a padding bit. A lenient
    # decoder returns identical bytes and would accept two strings for one receipt.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    respelled = good[:-1] + alphabet[alphabet.index(good[-1]) | 1]
    assert respelled != good
    assert base64.urlsafe_b64decode(respelled.split(".")[2] + "==") == b64url_decode(s_ok)
    w("neg_base64url_trailing_bits.json", {"format": "jws", "signature": respelled})
    w("neg_header_not_object.json",
      {"format": "jws", "signature": f"{b64url(_canon(['ES256', KID_ES256, TYP]).encode())}.{p_ok}.{s_ok}"})
    # found by fuzz cycle 2: a parser that sniffs encodings accepts these headers
    hdr_text = _canon({"alg": "ES256", "kid": KID_ES256, "typ": TYP})
    for name, hdr_bytes in (("neg_header_bom.json", b"\xef\xbb\xbf" + hdr_text.encode()),
                            ("neg_header_utf16.json", hdr_text.encode("utf-16"))):
        h_b = b64url(hdr_bytes)
        sig = _sign_jws("ES256", KID_ES256, es, base_text.encode()).split(".")
        raw_sig = es.sign(f"{h_b}.{sig[1]}".encode(), ec.ECDSA(hashes.SHA256()))
        r_, s_ = asym_utils.decode_dss_signature(raw_sig)
        s_ = min(s_, CURVE_ORDER["secp256r1"] - s_)
        w(name, {"format": "jws", "signature":
                 f"{h_b}.{sig[1]}.{b64url(r_.to_bytes(32, 'big') + s_.to_bytes(32, 'big'))}"})
    w("neg_kid_not_string.json",
      signed_raw(base_text.encode(), header={"alg": "ES256", "kid": 123, "typ": TYP}))
    w("neg_header_extra_member.json",
      signed_raw(base_text.encode(),
                 header={"alg": "ES256", "kid": KID_ES256, "typ": TYP, "crit": ["x"]}))
    w("neg_typ_missing.json",
      signed_raw(base_text.encode(), header={"alg": "ES256", "kid": KID_ES256}))
    w("neg_typ_wrong.json",
      signed_raw(base_text.encode(), header={"alg": "ES256", "kid": KID_ES256, "typ": "JWT"}))
    bad_h = b64url(_canon({"alg": "HS256", "kid": KID_ES256, "typ": TYP}).encode())
    w("neg_unknown_alg.json", {"format": "jws", "signature": f"{bad_h}.{p_ok}.{s_ok}"})

    # ---- §5.2 canonical bytes: each is the canonical positive with ONE lexical change ----
    w("neg_canon_member_order.json",
      signed_raw(json.dumps(base(), separators=(",", ":"), ensure_ascii=False).encode()))
    w("neg_canon_whitespace.json", signed_raw(base_text.replace('","', '", "', 1).encode()))
    w("neg_canon_number_float.json",
      signed_raw(base_text.replace('"version":1', '"version":1.0').encode()))
    w("neg_canon_number_exponent.json",
      signed_raw(base_text.replace(f'"issuedAt":{ISSUED_AT}', '"issuedAt":1.703123456E9').encode()))
    w("neg_canon_number_negative_zero.json",
      signed_raw(base_text.replace(f'"issuedAt":{ISSUED_AT}', '"issuedAt":-0').encode()))
    w("neg_canon_number_unsafe_integer.json",
      signed_raw(base_text.replace(f'"issuedAt":{ISSUED_AT}', '"issuedAt":9007199254740993').encode()))
    w("neg_canon_duplicate_member.json",
      signed_raw(base_text.replace('"version":1', '"version":1,"version":1').encode()))
    w("neg_canon_lone_surrogate.json",
      signed_raw(base_text.replace("read:model-x", "read:model-\\ud800").encode()))
    w("neg_canon_escaped_ascii.json",
      signed_raw(base_text.replace("read:model-x", "read:model-\\u0078").encode()))
    w("neg_canon_not_json.json", signed_raw(b"not json at all"))
    # nine levels of nested arrays: canonical bytes, but outside the admitted domain
    w("neg_canon_nesting_depth.json", signed_raw(b"[" * (MAX_DEPTH + 1) + b"]" * (MAX_DEPTH + 1)))
    w("neg_canon_invalid_utf8.json",
      signed_raw(base_text.encode().replace(b"read:model-x", b"read:model-\xff")))
    for name in ("neg_canon_member_order.json", "neg_canon_whitespace.json",
                 "neg_canon_number_float.json", "neg_canon_number_exponent.json",
                 "neg_canon_number_negative_zero.json", "neg_canon_number_unsafe_integer.json",
                 "neg_canon_duplicate_member.json", "neg_canon_lone_surrogate.json",
                 "neg_canon_escaped_ascii.json", "neg_canon_invalid_utf8.json"):
        raw = b64url_decode(json.loads((VECTORS / name).read_text())["signature"].split(".")[1])
        assert raw != base_text.encode(), f"{name}: mutation left the bytes unchanged"

    # ---- §5.3 closed schema and field grammar (canonical bytes, one fault each) ----
    w("neg_schema_not_object.json", signed([base()]))
    # found by fuzz cycle 2: canonical, in the value domain, and not an object
    w("neg_schema_null.json", signed_raw(b"null"))
    unknown = base(); unknown["signature"] = "0xdead"
    w("neg_schema_unknown_member.json", signed(unknown))
    missing = base(); del missing["receiptId"]
    w("neg_schema_missing_member.json", signed(missing))
    w("neg_schema_action_scalar.json", signed(dict(base(), action=7)))
    w("neg_schema_issuedat_string.json", signed(base(issuedAt=str(ISSUED_AT))))
    w("neg_schema_issuedat_negative.json", signed(base(issuedAt=-1)))
    w("neg_schema_version_boolean.json", signed(base(version=True)))
    w("neg_schema_no_settlement_id.json", signed(base(transaction="", settlementRef="")))
    w("neg_schema_receiptid_short.json", signed(base(receiptId="tooshort")))
    w("neg_schema_network_not_caip2.json", signed(base(network="base")))
    w("neg_schema_payer_checksum_case.json", signed(base(payer=PAYER_CHECKSUM)))
    w("neg_schema_transaction_uppercase.json", signed(base(transaction="0x" + "AB" * 32)))
    w("neg_schema_digest_base64url.json",
      signed(base(requirementsDigest=b64url(hashlib.sha256(_canon(ACCEPTED).encode()).digest()))))
    w("neg_schema_supersedes_grammar.json", signed(base(supersedes="previous-receipt")))
    w("neg_unsupported_version.json", signed(base(version=99)))
    w("neg_invalid_outcome.json", signed(base(action={"outcome": "shipped"})))
    w("neg_invalid_status.json", signed(base(settlementStatus="pending")))
    two = [{"type": "a:one", "value": "1"}, {"type": "b:two", "value": "2"}]
    w("neg_binding_unsorted.json", signed(base(bindings=list(reversed(two)))))
    w("neg_binding_duplicate_type.json", signed(base(bindings=[two[0], dict(two[0], value="9")])))
    w("neg_binding_extra_member.json", signed(base(bindings=[dict(two[0], alg="sha256")])))
    w("neg_binding_type_grammar.json", signed(base(bindings=[{"type": "no-colon", "value": "1"}])))
    w("neg_binding_value_non_ascii.json", signed(base(bindings=[{"type": "a:one", "value": "café"}])))
    w("neg_binding_too_many.json",
      signed(base(bindings=[{"type": f"a:{i:02d}", "value": "1"} for i in range(MAX_BINDINGS + 1)])))

    # ---- §5.4 / §5.5 signer authorization and key resolution ----
    w("neg_signer_unauthorized.json", signed(base(), "ES256", KID_EVIL, keys["EVIL"]))
    w("neg_signer_unknown_kid.json", signed(base(), "ES256", "did:web:nobody.example#x", es))
    w("neg_signer_payto_wrong_resource.json",
      signed(base(resourceUrl="https://other.example/x"), "ES256", KID_PAYTO, keys["PAYTO"]))
    w("neg_key_unresolved.json", signed(base(), "ES256", KID_ABSENT, es))
    w("neg_key_unusable.json", signed(base(), "ES256", KID_UNUSABLE, es))

    # ---- §5.6 signature ----
    h_ok = good.split(".")[0]
    tampered = _canon(base(action={"outcome": "refused"})).encode()
    w("neg_sig_tampered_payload.json", {"format": "jws", "signature": f"{h_ok}.{b64url(tampered)}.{s_ok}"})
    w("neg_sig_high_s.json", signed(base(), force_high_s=True))
    w("neg_sig_wrong_curve.json",
      signed_raw(base_text.encode(), header={"alg": "ES256K", "kid": KID_ES256, "typ": TYP}))

    # ---- §5.7 / §5.8 settlement ----
    w("neg_settlement_failed.json", signed(base()))
    w("neg_settlement_transaction_mismatch.json", signed(base(transaction="0x" + "cd" * 32)))
    w("neg_settlement_ref_mismatch.json", signed(base(transaction="", settlementRef="batch:WRONG-ROOT")))
    w("neg_settlement_network_mismatch.json", signed(base(network="eip155:1")))
    w("neg_settlement_payer_mismatch.json", signed(base(payer=_OTHER_ADDR)))
    w("neg_settlement_uncorroborated_transaction.json",
      signed(base(transaction="0x" + "ee" * 32, settlementRef=BATCH_REF)))
    # the upstream #3824 shape: the settlement has the hash, the signed receipt lost it
    w("neg_settlement_dropped_transaction.json", signed(base(transaction="", settlementRef=BATCH_REF)))

    # ---- §5.9 payment requirements ----
    w("neg_requirements_amount_changed.json",
      signed(base(requirementsDigest=requirements_digest(dict(ACCEPTED, amount="1")))))
    w("neg_requirements_payto_mismatch.json", signed(base(payTo=_OTHER_ADDR)))
    # the digest matches what the verifier holds; only the network differs
    w("neg_requirements_network_mismatch.json",
      signed(base(requirementsDigest=requirements_digest(ACCEPTED_OTHER_NETWORK))))

    # ---- §5.10 freshness ----
    w("neg_freshness_stale.json", signed(base(issuedAt=ISSUED_AT - 10_000)))
    w("neg_freshness_future_archival.json", signed(base(issuedAt=ISSUED_AT + 181 * 86400)))

    (VECTORS / "keys.json").write_text(json.dumps(registry, indent=2) + "\n")

    def ctx_json(c):
        return {"paidResourceUrl": c.paid_resource_url,
                "success": c.success, "transaction": c.transaction,
                "settlementRef": c.settlement_ref, "network": c.network, "payer": c.payer,
                "accepted": c.accepted, "advertisedInfo": c.advertised_info,
                "now": c.now, "maxAgeSeconds": c.max_age_s, "mode": c.mode}

    entries = []
    for fname, expect, reason, ckey in SUITE:
        entry = {"file": fname, "expect": expect, "reason": reason, "context": ckey}
        if expect == PASS:
            receipt = json.loads((VECTORS / fname).read_text())
            _, _, report = verify_detailed(receipt, CONTEXTS[ckey], registry)
            entry["report"] = report
        entries.append(entry)
    file_digests = sorted(
        (f.name, hashlib.sha256(f.read_bytes()).hexdigest())
        for f in VECTORS.glob("*.json") if f.name != "MANIFEST.json")
    manifest = {
        "profile": "action-receipt", "version": PROFILE_VERSION, "specDraft": "0.3",
        "note": ("Expected results for the action-receipt conformance vectors. A conformant "
                 "verifier loads keys.json, each vector and the named context, and MUST "
                 "reproduce the verdict, the reason on REJECT, and the report on PASS. "
                 "keys.json is a test fixture standing in for anchor and key resolution."),
        "vectorsDigest": sha256_tag(_canon(dict(file_digests)).encode()),
        "indeterminateReasons": sorted(INDETERMINATE_REASONS),
        "contexts": {k: ctx_json(v) for k, v in CONTEXTS.items()},
        "vectors": entries,
        "distinctReceiptRef": [{"a": a, "b": b, "why": why} for a, b, why in DISTINCT],
        "sameReceiptRef": [{"files": files, "why": why} for files, why in SAME],
    }
    (VECTORS / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    write_vectors_md(manifest)


def write_vectors_md(manifest) -> None:
    """VECTORS.md is generated from the same tables the suite runs, so the prose
    index cannot drift from the code."""
    n_pos = sum(1 for v in manifest["vectors"] if v["expect"] == PASS)
    n_neg = len(manifest["vectors"]) - n_pos
    lines = [
        "# Conformance vectors",
        "",
        "Generated by `python3 action_receipt.py --regenerate`. Do not edit by hand.",
        "",
        f"- {len(manifest['vectors'])} vectors: {n_pos} positive, {n_neg} negative.",
        f"- {len(ALL_REASONS)} reject reason codes, every one exercised.",
        f"- Vector set digest: `{manifest['vectorsDigest']}` (cite this when claiming conformance).",
        "- Every negative is one mutation of a canonical positive. Its reason is the",
        "  code of the first check that mutation fails under the order of spec §5.",
        "- `keys.json` is a test fixture standing in for anchor and key resolution.",
        "",
        "## Vectors",
        "",
        "| File | Context | Expect | Reason |",
        "|---|---|---|---|",
    ]
    for v in manifest["vectors"]:
        lines.append(f"| `{v['file']}` | `{v['context']}` | {v['expect']} | "
                     f"{'`' + v['reason'] + '`' if v['reason'] else ''} |")
    lines += ["", "## Contexts", "",
              "| Context | What the verifier holds |", "|---|---|"]
    notes = {
        C_OK: "successful settlement with a transaction; accepted requirements held",
        C_FAILED: "`success: false`",
        C_BATCH: "successful settlement identified by a settlement reference only",
        C_BOTH: "settlement carrying both a transaction and a settlement reference",
        C_NOREQ: "accepted requirements NOT held",
        C_CASE: "response `payer` in checksum case, `transaction` in upper-case hex",
        C_NOPAYER: "response carries no `payer`",
        C_ARCHIVAL: "archival mode, 180 days after issue",
        C_ADVERT: "the echoed extension `info` is also held",
        C_REQ_FLOAT: "accepted requirements spell an integer as `60.0`",
        C_REQ_NONOBJ: "what is held as accepted requirements is not a JSON object",
        C_PAYER_EMPTY: "response `payer` is the empty string",
        C_REQ_NET: "response `network` is not CAIP-2; accepted requirements name another network",
        C_ADVERT_NONSTRING: "the advertised `info` held has a `scope` that is not a string",
        C_PAID: "the verifier made the payment and paid for this resource",
        C_PAID_OTHER: "the verifier made the payment and paid for a different resource",
    }
    for k in manifest["contexts"]:
        lines.append(f"| `{k}` | {notes[k]} |")
    lines += ["", "## receiptRef relations asserted by the suite", ""]
    for d in manifest["distinctReceiptRef"]:
        lines.append(f"- DIFFERENT: `{d['a']}` and `{d['b']}` — {d['why']}.")
    for s in manifest["sameReceiptRef"]:
        lines.append(f"- SAME: {', '.join('`' + f + '`' for f in s['files'])} — {s['why']}.")
    lines += ["", "## Mutation matrix", "",
              "One change per signed member of `pos_es256_valid.json`, re-signed with the same",
              "key and verified in the `ok` context. A member whose mutation still passes is",
              "issuer-asserted: nothing the verifier holds constrains it.", "",
              "| Member changed | Result in the `ok` context |", "|---|---|"]
    for member, _, reason in MUTATIONS:
        lines.append(f"| `{member}` | {'REJECT `' + reason + '`' if reason else 'PASS (issuer-asserted)'} |")
    lines.append("")
    (HERE / "VECTORS.md").write_text("\n".join(lines))


def run_mutation_matrix(registry) -> list[str]:
    """Re-sign one mutation per signed member and check the result. Returns a
    list of failures (empty when the matrix holds)."""
    _, keys = _registry()
    base = _base_payload()
    base_bytes = _canon(base).encode()
    fails = []
    for member, mutate, want in MUTATIONS:
        p = json.loads(base_bytes)
        mutate(p)
        raw = _canon(p).encode()
        if raw == base_bytes:
            fails.append(f"{member}: mutation left the payload unchanged (no-op guard)")
            continue
        if sha256_tag(raw) == sha256_tag(base_bytes):
            fails.append(f"{member}: receiptRef did not change")
        receipt = {"format": "jws", "signature": _sign_jws("ES256", KID_ES256, keys["ES256"], raw)}
        verdict, reason, _ = verify_detailed(receipt, CONTEXTS[C_OK], registry)
        got = reason if verdict == REJECT else (None if verdict == PASS else verdict)
        if got != want:
            fails.append(f"{member}: want {want or 'PASS'}, got {got or 'PASS'}")
    return fails


def spec_reason_codes() -> set[str] | None:
    """The reason codes listed in the spec's §5.13 table, or None if the spec is
    not present (e.g. the suite was copied without it)."""
    if not SPEC.exists():
        return None
    text = SPEC.read_text()
    start = text.find("### 5.13")
    if start < 0:
        return set()
    end = text.find("\n## ", start)
    return set(re.findall(r"`(invalid_[a-z_]+)`", text[start:end if end > 0 else len(text)]))


def run_suite(regenerate: bool) -> int:
    if not HAVE_CRYPTO:
        sys.exit("`cryptography` is required to run the conformance suite")
    if regenerate:
        regenerate_vectors()
        print("regenerated vectors, MANIFEST.json and VECTORS.md")
    elif not (VECTORS / "keys.json").exists():
        sys.exit("no committed vectors (keys.json missing) — run with --regenerate to produce them")
    registry = json.loads((VECTORS / "keys.json").read_text())
    manifest = json.loads((VECTORS / "MANIFEST.json").read_text())
    expected_reports = {v["file"]: v.get("report") for v in manifest["vectors"]}
    print(f"crypto={HAVE_CRYPTO}  rfc8785_crosscheck={HAVE_RFC8785}"
          + ("  (every canonicalization cross-checked)" if HAVE_RFC8785
             else "  (NOT cross-checked: install rfc8785 for an independent canonicalizer)"))
    print("-" * 104)
    failures, observed, covered, refs = 0, set(), set(), {}
    for fname, expect, reason, ckey in SUITE:
        receipt = json.loads((VECTORS / fname).read_text())
        got, got_reason, report = verify_detailed(receipt, CONTEXTS[ckey], registry)
        observed.add(got)
        if got == REJECT:
            covered.add(got_reason)
        ok = got == expect and got_reason == reason
        if ok and expect == PASS:
            refs[fname] = report["receiptRef"]
            if report != expected_reports.get(fname):
                ok = False
                got_reason = "report differs from MANIFEST"
            declared = report_mismatches(report, EXPECT_REPORT.get(fname, {}))
            if declared:
                ok = False
                got_reason = "; ".join(declared)
        failures += not ok
        print(f"[{' ok ' if ok else 'FAIL'}] {fname:48s} want {expect:6s}/{str(reason):44s} "
              f"got {got:6s}/{got_reason}")
    print("-" * 104)
    structural = []
    if observed != {PASS, REJECT}:
        structural.append(f"verifier did not produce exactly PASS and REJECT (saw {sorted(observed)})")
    if ALL_REASONS - covered:
        structural.append(f"reason codes never exercised: {sorted(ALL_REASONS - covered)}")
    if covered - ALL_REASONS:
        structural.append(f"verifier emitted undeclared codes: {sorted(covered - ALL_REASONS)}")
    listed = {f for f, _, _, _ in SUITE}
    on_disk = {f.name for f in VECTORS.glob("*.json")} - {"keys.json", "MANIFEST.json"}
    if listed != on_disk:
        structural.append(f"suite and vectors/ differ: {sorted(listed ^ on_disk)}")
    for a, b, why in DISTINCT:
        if a in refs and b in refs and refs[a] == refs[b]:
            structural.append(f"receiptRef collision: {a} == {b} ({why})")
    for files, why in SAME:
        if len({refs.get(f) for f in files}) != 1:
            structural.append(f"receiptRef differs within a group that must share it ({why})")
    structural += [f"mutation matrix: {m}" for m in run_mutation_matrix(registry)]
    spec_codes = spec_reason_codes()
    if spec_codes is None:
        print("note: action-receipt.md not present; spec/code reason-code drift check skipped")
    elif spec_codes != ALL_REASONS:
        structural.append(f"spec §5.13 and code disagree on reason codes: "
                          f"{sorted(spec_codes ^ ALL_REASONS)}")
    if structural:
        for s in structural:
            print(f"SUITE INVALID: {s}")
        return 2
    if failures:
        print(f"{failures} conformance failure(s)")
        return 1
    n_neg = sum(1 for _, e, _, _ in SUITE if e == REJECT)
    print(f"all {len(SUITE)} pass ({len(SUITE) - n_neg} positive, {n_neg} negative); both verdicts "
          f"observed; all {len(ALL_REASONS)} reason codes exercised; {len(MUTATIONS)}-member "
          f"mutation matrix holds; receiptRef relations hold"
          + ("; spec and code agree on reason codes" if spec_codes is not None else ""))
    return 0


def print_worked_example() -> None:
    """The numbers quoted in spec §4.7, produced by the code that verifies them."""
    registry, keys = _registry()
    payload = _base_payload()
    raw = _canon(payload).encode()
    accepted_raw = _canon(ACCEPTED).encode()
    jws = _sign_jws("EdDSA", KID_ED, keys["EdDSA"], raw)
    print("accepted PaymentRequirements, JCS (%d bytes):\n%s\n" % (len(accepted_raw), accepted_raw.decode()))
    print("requirementsDigest:\n%s\n" % sha256_tag(accepted_raw))
    print("JWS protected header:\n%s\n" % _canon({"alg": "EdDSA", "kid": KID_ED, "typ": TYP}))
    print("JWS payload, JCS (%d bytes):\n%s\n" % (len(raw), raw.decode()))
    print("receiptRef:\n%s\n" % sha256_tag(raw))
    print("JWS compact (EdDSA is deterministic, so this reproduces exactly):\n%s\n" % jws)
    print("Ed25519 public key (PEM):\n%s" % registry[KID_ED])
    verdict, reason, report = verify_detailed({"format": "jws", "signature": jws},
                                              CONTEXTS[C_OK], registry)
    print("verify in the `ok` context: %s %s\n%s" % (verdict, reason or "", json.dumps(report, indent=2)))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="action-receipt verifier + conformance suite")
    p.add_argument("--regenerate", action="store_true",
                   help="rebuild vectors, MANIFEST.json and VECTORS.md")
    p.add_argument("--verify", metavar="FILE",
                   help="verify one receipt against the committed keys in the `ok` context")
    p.add_argument("--worked", action="store_true", help="print the spec's worked example")
    a = p.parse_args(argv)
    if not HAVE_CRYPTO:
        sys.exit("`cryptography` is required (pip install cryptography)")
    if a.worked:
        print_worked_example()
        return 0
    if a.verify:
        if not (VECTORS / "keys.json").exists():
            sys.exit("no committed keys.json — run with --regenerate first")
        registry = json.loads((VECTORS / "keys.json").read_text())
        try:
            receipt = json.loads(Path(a.verify).read_text())
        except (OSError, ValueError) as e:
            sys.exit(f"cannot read receipt {a.verify!r}: {e}")
        verdict, reason, report = verify_detailed(receipt, CONTEXTS[C_OK], registry)
        print(f"{verdict}  {reason or ''}")
        if report:
            print(json.dumps(report, indent=2))
        return 0 if verdict == PASS else 1
    return run_suite(regenerate=a.regenerate)


if __name__ == "__main__":
    sys.exit(main())
