#!/usr/bin/env python3
"""
action_receipt.py — reference verifier + conformance suite for the x402
`action-receipt` extension (spec: action-receipt.md, draft 0.4).

What changed against draft 0.3 (spec version history; review ledger in
conformance/REVIEW-0.4.md):
  * The JWS header must be the JCS form of a value in the value domain (one
    spelling); `alg` of any non-string type is `invalid_actionreceipt_alg`.
  * The compact string is at most 65536 characters.
  * §5.3 checks an integer `version`, then `version == 1`, then the member set.
  * Network identifiers have a 3..32 namespace; `payer` may be "".
  * The `action-receipt:` binding namespace is closed and its values have a form.
  * One definition of "present" (§4.6) for every unsigned value.
  * §5.4 has three answers; "no answer" is key_unresolved.
  * Only a SubjectPublicKeyInfo public key of a usable kind resolves a key.
  * The verifier's own configuration has a contract; outside it: ERROR.
  * The report carries `checks.advertisement`.

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
import binascii
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
        Encoding, PublicFormat, load_der_public_key,
    )
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
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
OUTCOMES = {"delivered", "partial", "failed"}                                # SERVICE delivery
SETTLEMENT_STATUSES = {"settled", "capturePending", "reversed", "refunded"}  # PAYMENT lifecycle
MAX_BINDINGS = 16

MAX_COMPACT = 65536          # characters in the compact string (spec §3, §5.1)
DEFAULT_MAX_AGE = 3600       # seconds, when the configuration gives none (spec §5, §5.10)

RE_RECEIPT_ID = re.compile(r"[A-Za-z0-9_-]{22,64}")
# A "network identifier" (spec §4.6): the CAIP-2 shape with a 3..32 namespace.
RE_NETWORK = re.compile(r"[-a-z0-9]{3,32}:[-_a-zA-Z0-9]{1,32}")
RE_CAIP2 = RE_NETWORK        # name kept for issuer.py; the grammar is the 0.4 one
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
BT_NAMESPACE = "action-receipt:"     # closed: only the two types above (spec §4.5.1)


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
# The two kinds of ERROR (spec §5 "Outcomes"). Neither is a reason code of §5.13.
E_CONFIG = "invalid_configuration"   # the verifier's own configuration is outside the contract
E_FAULT = "verifier_fault"           # the verifier faulted internally


class _Absent:
    """Marks a configuration input the caller did not give (distinct from None)."""
    _inst = None

    def __new__(cls):
        if cls._inst is None:
            cls._inst = super().__new__(cls)
        return cls._inst

    def __repr__(self):
        return "ABSENT"


ABSENT = _Absent()


class Context:
    """What the verifier holds besides the receipt (spec §5).

    success / transaction / settlement_ref / network / payer : from the
        SettlementResponse (core §5.3). UNSIGNED input: checks against it are
        consistency checks, not independent corroboration. Any value is legal
        here; a malformed one is absent or rejected, never an ERROR.
    accepted : the PaymentRequirements object the client accepted
        (PaymentPayload.accepted), or None when the verifier does not hold it.
    advertised_info : the `action-receipt` extension `info` object as echoed in
        the PaymentPayload, or None.

    The verifier's own CONFIGURATION (spec §5 inputs table). Outside this
    contract verify_detailed returns ERROR / invalid_configuration:
    mode : exactly "session" or "archival".
    now : an integer number of Unix seconds (an integer-valued float, as a JSON
        parser may produce for `1703123500.0`, is that integer; a bool is not).
    max_age_s : ABSENT (meaning 3600) or an integer >= 0. None is not absent.
    paid_resource_url : None/ABSENT (the verifier did not pay), or a string.
    """
    def __init__(self, success: bool, transaction: str = "", settlement_ref: str = "",
                 network=None, payer=None, accepted=None, advertised_info=None,
                 now: int = 0, max_age_s=ABSENT, mode: str = "session",
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
    """An unsigned value is PRESENT iff it is a non-empty string of well-formed
    Unicode (spec §4.6 "Present and absent"); anything else is absent."""
    return isinstance(value, str) and value != "" and in_domain(value)


def _config_int(v):
    """The integer a configuration number denotes, or None when it is not one.
    Judged by value like §4.6 (so JSON `3600.0` is 3600), within the I-JSON
    safe range so that every implementation reads the same number; a bool is
    not an integer."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if -SAFE_INT_MAX <= v <= SAFE_INT_MAX else None
    if isinstance(v, float) and v.is_integer() and -SAFE_INT_MAX <= v <= SAFE_INT_MAX:
        return int(v)
    return None


def configuration(ctx, key_registry):
    """Validate the verifier's own configuration against the contract of spec §5.
    Returns (mode, now, max_age, paid_url) or None when it is outside the
    contract. paid_url is None when the verifier did not pay."""
    if not isinstance(ctx, Context) or not isinstance(key_registry, dict):
        return None
    mode = ctx.mode
    if not (isinstance(mode, str) and mode in ("session", "archival")):
        return None
    now = _config_int(ctx.now)
    if now is None:
        return None
    if ctx.max_age_s is ABSENT:
        max_age = DEFAULT_MAX_AGE
    else:
        max_age = _config_int(ctx.max_age_s)
        if max_age is None or max_age < 0:
            return None
    paid = ctx.paid_resource_url
    if paid is ABSENT:
        paid = None
    if paid is not None and not isinstance(paid, str):
        return None
    return mode, now, max_age, paid


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
    # 1. an object with an integer `version`
    if not isinstance(payload, dict) or "version" not in payload or not _is_int(payload["version"]):
        return R_MALFORMED
    # 2. the version this verifier implements, BEFORE the member set: a later
    #    version may have other members and must not read as malformed
    if payload["version"] != PROFILE_VERSION:
        return R_UNSUPPORTED_VERSION
    # 3. the closed member set, types and grammar
    if set(payload.keys()) != TOP_KEYS:
        return R_MALFORMED
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
    if not RE_NETWORK.fullmatch(network):
        return R_MALFORMED
    # `payer` may be "" on any network (spec §4.3, §4.6)
    if not (payload["resourceUrl"] and payload["payTo"]
            and action["agent"] and action["actionType"]):
        return R_MALFORMED
    if not (payload["transaction"] or payload["settlementRef"]):
        return R_MALFORMED                       # at least one settlement identifier
    if _is_evm(network):
        if not RE_EVM_ADDRESS.fullmatch(payload["payTo"]):
            return R_MALFORMED
        if payload["payer"] and not RE_EVM_ADDRESS.fullmatch(payload["payer"]):
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
        if t.startswith(BT_NAMESPACE):                     # closed namespace (spec §4.5.1)
            if t == BT_ADVERTISED:
                if not RE_DIGEST.fullmatch(v):
                    return R_BINDING
            elif t == BT_REVERSAL_TX:
                if _is_evm(network) and not RE_EVM_TX.fullmatch(v):
                    return R_BINDING
            else:
                return R_BINDING
        if previous is not None and not previous < t:      # strictly ascending => unique
            return R_BINDING
        previous = t
    return None


def verify_detailed(receipt, ctx: Context, key_registry: dict) -> tuple[str, str | None, dict]:
    """Verify a receipt. Returns (verdict, reason, report).

    verdict  PASS | REJECT | ERROR
    reason   a §5.13 code on REJECT; on ERROR "invalid_configuration" (the
             configuration is outside the contract of spec §5) or
             "verifier_fault" (the verifier faulted); None on PASS
    report   what was and was not evaluated (spec §5.12); {} unless PASS

    The configuration is checked FIRST: outside its contract nothing about the
    receipt is said. Never raises on hostile input. A fault in the verifier
    itself returns ERROR, which says nothing about the receipt.
    `key_registry` is a TEST FIXTURE standing in for authorization and key
    resolution (spec §7): kid -> SubjectPublicKeyInfo PEM;
    "__service__:<resourceUrl>" and "__payTo__:<payTo>|<resourceUrl>" -> array
    of authorized kids; "__unavailable__:<resourceUrl>" -> true when the
    authorization source gives no answer for that resource.
    """
    try:
        cfg = configuration(ctx, key_registry)
    except Exception:  # noqa: BLE001
        return ERROR, E_FAULT, {}
    if cfg is None:
        return ERROR, E_CONFIG, {}
    try:
        return _verify(receipt, ctx, cfg, key_registry)
    except VerifierFault:
        return ERROR, E_FAULT, {}
    except Exception:  # noqa: BLE001 — an unexpected exception is OUR bug, not a bad receipt
        return ERROR, E_FAULT, {}


def verify_action_receipt(receipt, ctx: Context, key_registry: dict) -> tuple[str, str | None]:
    verdict, reason, _ = verify_detailed(receipt, ctx, key_registry)
    return verdict, reason


AUTHORIZED, NOT_AUTHORIZED, NO_ANSWER = "authorized", "not_authorized", "no_answer"


def _anchor_kids(key_registry: dict, name: str) -> list:
    """The kids an anchor entry lists. A value that is not an array of strings
    authorizes nothing (spec §7)."""
    v = key_registry.get(name)
    if isinstance(v, list) and all(isinstance(k, str) for k in v):
        return v
    return []


def authorization(key_registry: dict, kid: str, resource_url: str, pay_to: str) -> str:
    """The three answers of spec §5.4, from the fixture authorization source."""
    if key_registry.get("__unavailable__:" + resource_url) is True:
        return NO_ANSWER
    if kid in _anchor_kids(key_registry, "__service__:" + resource_url):
        return AUTHORIZED
    if kid in _anchor_kids(key_registry, "__payTo__:" + pay_to + "|" + resource_url):
        return AUTHORIZED
    return NOT_AUTHORIZED


def _verify(receipt, ctx, cfg, key_registry):
    mode, now, max_age, paid_url = cfg
    # §5.1 envelope and header -------------------------------------------
    if not isinstance(receipt, dict) or receipt.get("format") != "jws":
        return REJECT, R_MALFORMED, {}
    compact = receipt.get("signature")
    if not isinstance(compact, str) or len(compact) > MAX_COMPACT or compact.count(".") != 2:
        return REJECT, R_MALFORMED, {}
    h_b64, p_b64, s_b64 = compact.split(".")
    try:
        header_bytes = b64url_decode(h_b64)
        payload_bytes = b64url_decode(p_b64)
        raw_sig = b64url_decode(s_b64)
    except ValueError:
        return REJECT, R_MALFORMED, {}
    # The header has one spelling: the bytes pass the same canonical-bytes test
    # as the payload (§5.2) and parse to an object. A BOM, another encoding, a
    # repeated or reordered member, NaN, whitespace: all fail here.
    header = parse_canonical(header_bytes)
    if header is NOT_CANONICAL or not isinstance(header, dict):
        return REJECT, R_MALFORMED, {}
    if header.get("typ") != TYP:
        return REJECT, R_TYP, {}
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in SUPPORTED_ALGS:
        return REJECT, R_UNKNOWN_ALG, {}
    if set(header.keys()) != HEADER_KEYS or not isinstance(header.get("kid"), str):
        return REJECT, R_MALFORMED, {}
    kid = header["kid"]

    # §5.2 canonical bytes — before any typing, so every parser-level
    # difference between languages lands on one reason code.
    payload = parse_canonical(payload_bytes)
    if payload is NOT_CANONICAL:
        return REJECT, R_NONCANONICAL, {}

    # §5.3 closed schema and field grammar --------------------------------
    reason = validate_payload(payload)
    if reason:
        return REJECT, reason, {}

    # §5.4 resource, then signer authorization, BEFORE any key material is
    # used. Both anchors are scoped to the resource.
    checks = {}
    if paid_url is not None:
        if payload["resourceUrl"] != paid_url:
            return REJECT, R_RESOURCE, {}
        checks["resourceUrl"] = "compared"
    else:
        checks["resourceUrl"] = "not_compared"
    answer = authorization(key_registry, kid, payload["resourceUrl"], payload["payTo"])
    if answer == NO_ANSWER:
        return REJECT, R_KEY_UNRESOLVED, {}       # not a finding against the signer
    if answer != AUTHORIZED:
        return REJECT, R_SIGNER_UNAUTH, {}

    # §5.5 key resolution — authorized, but no usable key could be obtained.
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
    if isinstance(ctx.network, str) and RE_NETWORK.fullmatch(ctx.network):
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
    age = now - payload["issuedAt"]
    if age < -60:
        return REJECT, R_STALE, {}
    if mode == "session":
        if age > max_age:
            return REJECT, R_STALE, {}
        freshness = "enforced"
    else:
        freshness = "reported"

    # §5.11 bindings — reported per entry, never folded into the verdict --
    info = ctx.advertised_info
    info_held = isinstance(info, dict) and in_domain(info)
    advertisement = "absent" if info_held else "not_evaluated"
    binding_report = []
    for b in payload["bindings"]:
        status = "not_evaluated"
        if b["type"] == BT_ADVERTISED and info_held:
            ok = b["value"] == sha256_tag(jcs(info))
            for member in ("scope", "actionType"):
                if member in info and info[member] != payload["action"][member]:
                    ok = False
            status = "matched" if ok else "mismatched"
            advertisement = status
        binding_report.append({"type": b["type"], "status": status})
    checks["advertisement"] = advertisement
    checks["freshness"] = freshness

    report = {
        "receiptRef": sha256_tag(payload_bytes),
        "outcome": payload["action"]["outcome"],
        "settlementStatus": payload["settlementStatus"],
        "ageSeconds": age,
        "checks": {k: checks[k] for k in REPORT_CHECKS},
        "supersedes": payload["supersedes"],
        "bindings": binding_report,
    }
    return PASS, None, report


REPORT_CHECKS = ("resourceUrl", "network", "payer", "requirements", "payTo",
                 "advertisement", "freshness")

_PEM_RE = re.compile(r"-----BEGIN PUBLIC KEY-----\n((?:[A-Za-z0-9+/=]+\n)+)-----END PUBLIC KEY-----\n?")


def _usable_kind(pub) -> bool:
    """The kinds of public key this verifier can use at all (spec §5.5): the
    keys of the three algorithms of §3. Whether the kind matches `alg` is §5.6."""
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return True
    return isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name in ALG_CURVE.values()


def _load_key(pem):
    """The public key for a fixture entry, or None when there is no usable key.

    Usable means (spec §5 inputs, §5.5, §7): one PEM block armoured
    `PUBLIC KEY` holding a DER SubjectPublicKeyInfo, with nothing around it, in
    canonical base64 and canonical DER (it re-encodes to the same bytes), of a
    kind this verifier can use. A private key, a certificate, a key of an
    unknown algorithm or curve, or anything else: None. The same rule is in
    verify.mjs, so the two cannot disagree through their libraries' leniency."""
    if not isinstance(pem, str):
        return None
    m = _PEM_RE.fullmatch(pem)
    if not m:
        return None
    body = m.group(1).replace("\n", "")
    try:
        der = base64.b64decode(body, validate=True)
    except (ValueError, binascii.Error):
        return None
    if base64.b64encode(der).decode() != body:
        return None
    try:
        pub = load_der_public_key(der)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None
    if not _usable_kind(pub):
        return None
    if pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) != der:
        return None
    return pub


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


def _pem_of_der(der: bytes, label: str = "PUBLIC KEY") -> str:
    b = base64.b64encode(der).decode()
    lines = [b[i:i + 64] for i in range(0, len(b), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def _sign_jws(alg, kid, sk, payload_bytes: bytes, *, force_high_s=False, header=None,
              header_bytes: bytes | None = None, sig_edit=None) -> str:
    """Sign `payload_bytes` under a header. `header` is a dict serialized in JCS
    form; `header_bytes` overrides it with exact bytes (for header negatives).
    `sig_edit` rewrites the raw signature bytes after signing."""
    if header_bytes is None:
        header = {"alg": alg, "kid": kid, "typ": TYP} if header is None else header
        header_bytes = _canon(header).encode()
    h_b64 = b64url(header_bytes)
    p_b64 = b64url(payload_bytes)
    signing_input = f"{h_b64}.{p_b64}".encode()
    if alg in ("ES256", "ES256K"):
        # RFC 6979 deterministic ECDSA, so that --regenerate reproduces every
        # committed vector byte for byte (no silent fallback to random k).
        der = sk.sign(signing_input, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = asym_utils.decode_dss_signature(der)
        n = CURVE_ORDER[ALG_CURVE[alg]]
        s = max(s, n - s) if force_high_s else min(s, n - s)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    elif alg == "EdDSA":
        raw = sk.sign(signing_input)
    else:
        raise ValueError(alg)
    if sig_edit is not None:
        raw = sig_edit(raw)
    return f"{h_b64}.{p_b64}.{b64url(raw)}"


# --- fixed test inputs -----------------------------------------------------
# Receipt-side EVM identifiers are lowercase (spec §4.6). The SettlementResponse
# and PaymentRequirements fixtures deliberately use other casings where noted.

SETTLEMENT_TX = "0x" + "ab" * 32
BATCH_REF = "batch:voucher:9f3c1d0a-0000-4a11-b2cc-settlement-root-01"   # an EVM-network reference (issuer.py)
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

# The one settlement reference draft 0.4 names (spec §4.3): `batch-settlement`
# on `solana:*`, SettlementResponse.extra.commitmentId. A commitment is not yet
# a transfer, so these receipts say `capturePending` (draft 0.3's vectors said
# `settled` for a voucher; spec §4.3 table).
SOL_NET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOL_PAY_TO = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
SOL_TX = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"
COMMITMENT_ID = "3vZ8kq2Yb9WdTq7cCz1xHq5mFJv4p2uHn6rT8sLwXyAe"
COMMITMENT_ID_2 = "9cW1nKq3Zp7Xb2Rt5Yv8Hm4Js6Lf1Dg3Ae5Bc7Nx9Pq"
ACCEPTED_SOL = {
    "scheme": "batch-settlement", "network": SOL_NET, "amount": "10000",
    "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "payTo": SOL_PAY_TO, "maxTimeoutSeconds": 60, "extra": {},
}
# A network that LOOKS like eip155 and is not (spec §4.6: "begins `eip155:`").
LOOKALIKE_NET = "eip1559:1"
LOOKALIKE_PAYER = "0x857B06519E91E3A54538791BDBB0E22373E36B66"   # upper-case hex: fine off eip155
LOOKALIKE_PAY_TO = "Merchant-0x209693Bc"
LOOKALIKE_TX = "0x" + "AB" * 32
ACCEPTED_LOOKALIKE = dict(ACCEPTED, network=LOOKALIKE_NET, payTo=LOOKALIKE_PAY_TO)
CF_NET = "cloudflare:402"                    # not CAIP-2; spec §4.6
CF_PAY_TO = "acct_merchant_0001"
CF_TX = "cf-settlement-000000000001"
ACCEPTED_CF = dict(ACCEPTED, network=CF_NET, payTo=CF_PAY_TO)
# requirements whose member names sort differently by UTF-16 code unit
# (U+D835 U+DCB3 < U+FEFF) than by code point (U+FEFF < U+1D4B3): spec §4.6
ACCEPTED_UTF16 = dict(ACCEPTED, extra={"name": "USD Coin", "version": "2",
                                       "\U0001d4b3": "a", "﻿": "b"})

KID_ES256 = "did:web:api.example.com#es256"
KID_ES256K = "did:web:api.example.com#es256k"
KID_ED = "did:web:api.example.com#ed25519"
KID_PAYTO = "did:web:api.example.com#payto"      # authorized via the payTo anchor only
KID_ABSENT = "did:web:api.example.com#rotated"   # authorized, but no key can be resolved
KID_UNUSABLE = "did:web:api.example.com#unusable"  # authorized, but the key does not parse
KID_EVIL = "did:web:evil.example#k"              # has a key, authorized by no anchor
# authorized, and the entry is key material that is NOT a usable public key (spec §5, §5.5, §7)
KID_PRIVATE_PEM = "did:web:api.example.com#private-key-pem"
KID_CERTIFICATE = "did:web:api.example.com#certificate"
KID_UNKNOWN_ALG = "did:web:api.example.com#unknown-algorithm"
KID_UNKNOWN_CURVE = "did:web:api.example.com#unsupported-curve"
KID_P384 = "did:web:api.example.com#p384"
KID_PEM_SPACES = "did:web:api.example.com#pem-leading-spaces"

# resources whose authorization-source entries exercise spec §5.4 / §7
RES_ANCHOR_STRING = RESOURCE + "?anchor=string"      # list given as a bare string
RES_ANCHOR_OBJECT = RESOURCE + "?anchor=object"      # list given as an object keyed by kid
RES_ANCHOR_MIXED = RESOURCE + "?anchor=mixed"        # array with a non-string member
RES_ANCHOR_NUMBER = RESOURCE + "?anchor=number"      # a number
RES_UNAVAILABLE = RESOURCE + "?source=unavailable"   # the source gave no answer
RES_UNAVAILABLE_LISTED = RESOURCE + "?source=unavailable-listed"  # no answer, though a list exists
RES_UNAVAILABLE_NOT_TRUE = RESOURCE + "?source=unavailable-string"  # marker is "true", not true


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


def _sol_payload(**overrides) -> dict:
    """A batch-settlement commitment on Solana: no transaction yet, no payer."""
    base = dict(network=SOL_NET, payer="", payTo=SOL_PAY_TO, transaction="",
                settlementRef=COMMITMENT_ID, settlementStatus="capturePending",
                requirementsDigest=requirements_digest(ACCEPTED_SOL))
    base.update(overrides)
    return _base_payload(**base)


# SPKI with an unknown algorithm OID (1.2.3.4) and a 32-byte BIT STRING
_SPKI_UNKNOWN_ALG = bytes.fromhex("302a" "3005" "0603" "2a0304" "032100") + b"\x07" * 32
# EC SPKI naming a curve neither library supports (brainpoolP160r1) with a 41-byte point
_SPKI_UNKNOWN_CURVE = (bytes.fromhex("3042" "3014" "0607" "2a8648ce3d0201" "0609" "2b2403030208010101"
                                     "032a00" "04") + b"\x01" * 40)


def _certificate_pem(sk) -> str:
    """A self-signed X.509 certificate for an Ed25519 key (deterministic)."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.example.com")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(sk.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc))
            .sign(sk, None))
    return cert.public_bytes(Encoding.PEM).decode()


def _registry():
    from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption
    es, esk, ed = _es_key("ES256"), _es_key("ES256K"), _ed_key()
    payto = ec.derive_private_key(0x5555, ec.SECP256R1())
    evil = ec.derive_private_key(0x4444, ec.SECP256R1())
    p384 = ec.derive_private_key(0x6666, ec.SECP384R1())
    service = [KID_ES256, KID_ES256K, KID_ED, KID_ABSENT, KID_UNUSABLE, KID_PRIVATE_PEM,
               KID_CERTIFICATE, KID_UNKNOWN_ALG, KID_UNKNOWN_CURVE, KID_P384, KID_PEM_SPACES]
    return {
        KID_ES256: _pem(es), KID_ES256K: _pem(esk), KID_ED: _pem(ed),
        KID_PAYTO: _pem(payto), KID_EVIL: _pem(evil), KID_UNUSABLE: "not a public key",
        KID_PRIVATE_PEM: es.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode(),
        KID_CERTIFICATE: _certificate_pem(ed),
        KID_UNKNOWN_ALG: _pem_of_der(_SPKI_UNKNOWN_ALG),
        KID_UNKNOWN_CURVE: _pem_of_der(_SPKI_UNKNOWN_CURVE),
        KID_P384: _pem(p384),
        KID_PEM_SPACES: "   " + _pem(ed),
        "__service__:" + RESOURCE: service,
        "__payTo__:" + PAY_TO + "|" + RESOURCE: [KID_PAYTO],
        "__service__:" + RES_ANCHOR_STRING: KID_ED,
        "__service__:" + RES_ANCHOR_OBJECT: {KID_ED: True},
        "__service__:" + RES_ANCHOR_MIXED: [KID_ED, 5],
        "__service__:" + RES_ANCHOR_NUMBER: 5,
        "__unavailable__:" + RES_UNAVAILABLE: True,
        "__unavailable__:" + RES_UNAVAILABLE_LISTED: True,
        "__service__:" + RES_UNAVAILABLE_LISTED: [KID_ED],
        "__unavailable__:" + RES_UNAVAILABLE_NOT_TRUE: "true",
        "__service__:" + RES_UNAVAILABLE_NOT_TRUE: [KID_ED],
    }, {"ES256": es, "ES256K": esk, "EdDSA": ed, "PAYTO": payto, "EVIL": evil}


# --- verification contexts -------------------------------------------------
# A context is the JSON object of the adapter protocol (CONFORMANCE.md §3), the
# same object the manifest publishes. `_DROP` removes a member.

_DROP = object()


def _ctx(**kw) -> dict:
    c = {"paidResourceUrl": None, "success": True, "transaction": SETTLEMENT_TX,
         "settlementRef": "", "network": NETWORK, "payer": PAYER, "accepted": ACCEPTED,
         "advertisedInfo": None, "now": VERIFIER_NOW, "maxAgeSeconds": 3600, "mode": "session"}
    c.update(kw)
    return {k: v for k, v in c.items() if v is not _DROP}


def context_from_json(c):
    """The Context an adapter builds from a context JSON value, with no
    defaults for the configuration: a missing `mode` or `now` is outside the
    contract (spec §5) and yields ERROR. A missing `maxAgeSeconds` is absent."""
    if not isinstance(c, dict):
        return None
    return Context(
        success=c.get("success"), transaction=c.get("transaction"),
        settlement_ref=c.get("settlementRef"), network=c.get("network"), payer=c.get("payer"),
        accepted=c.get("accepted"), advertised_info=c.get("advertisedInfo"),
        now=c.get("now", ABSENT),
        max_age_s=c["maxAgeSeconds"] if "maxAgeSeconds" in c else ABSENT,
        mode=c.get("mode", ABSENT), paid_resource_url=c.get("paidResourceUrl"))


C_OK, C_FAILED, C_BATCH, C_BOTH = "ok", "failed", "batch", "both"
C_NOREQ, C_CASE, C_NOPAYER, C_ARCHIVAL, C_ADVERT = (
    "no_requirements", "response_casing", "no_payer", "archival", "advertised")
C_REQ_FLOAT, C_REQ_NONOBJ, C_PAYER_EMPTY = (
    "requirements_float_spelling", "requirements_not_object", "payer_empty_string")
C_REQ_NET = "requirements_other_network"
C_PAID, C_PAID_OTHER = "paid_this_resource", "paid_another_resource"
C_ADVERT_NONSTRING = "advertised_scope_not_a_string"
C_ADVERT_FLOAT = "advertised_info_outside_value_domain"
ADVERTISED_FLOAT = dict(ADVERTISED_INFO, ttl=1.5)
ADVERTISED_NONSTRING = {"willIssueReceipt": True, "scope": 5}
ACCEPTED_OTHER_NETWORK = dict(ACCEPTED, network="eip155:1")
# new in 0.4
C_DEFAULT_AGE = "session_default_max_age"
C_MAX_AGE_100 = "session_max_age_100"
C_LOOSE = "settlement_transaction_only"
C_LOOKALIKE = "lookalike_network"
C_CF = "cloudflare_network"
C_EVM_REF_UPPER = "evm_settlement_reference_upper_case"
C_EVM_REF_MIXED = "evm_settlement_reference_mixed_case"
C_BATCH_ONLY_TX = "batch_response_has_transaction_only"
C_REQ_UTF16 = "requirements_utf16_member_order"
C_ABSENT_FORMS = "response_values_absent_forms"
C_JUNK = "response_values_junk_types"
C_NO_ID = "success_without_identifier"
C_SUCCESS_FALSE = "success_false_with_transaction"
C_SUCCESS_STRING = "success_is_the_string_true"
C_PAID_EMPTY = "paid_resource_empty_string"
C_ARCHIVAL_END = "archival_at_end_of_time"
C_NOW_FLOAT = "clock_integer_valued_float"
C_RESP_NET_OTHER_FORM = "response_network_not_an_identifier"
C_NOPAYER_EVM = "no_payer_receipt_payer_empty"
# configuration outside the contract (spec §5): ERROR
C_ERR = {
    "mode_upper_case": _ctx(mode="SESSION"),
    "mode_missing": _ctx(mode=_DROP),
    "mode_null": _ctx(mode=None),
    "now_boolean": _ctx(now=True),
    "now_fraction": _ctx(now=VERIFIER_NOW + 0.5),
    "now_string": _ctx(now=str(VERIFIER_NOW)),
    "now_missing": _ctx(now=_DROP),
    "now_unsafe_integer": _ctx(now=2**53),
    "max_age_negative": _ctx(maxAgeSeconds=-1),
    "max_age_string": _ctx(maxAgeSeconds="10"),
    "max_age_null": _ctx(maxAgeSeconds=None),
    "max_age_boolean": _ctx(maxAgeSeconds=True),
    "max_age_fraction": _ctx(maxAgeSeconds=10.5),
    "paid_url_number": _ctx(paidResourceUrl=5),
    "paid_url_array": _ctx(paidResourceUrl=[RESOURCE]),
}
C_NULL = "context_null"

CONTEXTS = {
    C_OK: _ctx(),
    C_FAILED: _ctx(success=False, transaction=""),
    C_BATCH: _ctx(transaction="", settlementRef=COMMITMENT_ID, network=SOL_NET, payer=None,
                  accepted=ACCEPTED_SOL),
    C_BOTH: _ctx(transaction=SOL_TX, settlementRef=COMMITMENT_ID, network=SOL_NET, payer=None,
                 accepted=ACCEPTED_SOL),
    # the verifier does not hold the accepted PaymentRequirements
    C_NOREQ: _ctx(accepted=None),
    # the facilitator returned a checksummed payer and upper-case transaction hex
    C_CASE: _ctx(transaction="0x" + "AB" * 32, payer=PAYER_CHECKSUM),
    # core §5.3 makes `payer` optional
    C_NOPAYER: _ctx(payer=None),
    # an auditor, 180 days later
    C_ARCHIVAL: _ctx(now=ISSUED_AT + 180 * 86400, mode="archival"),
    # found by fuzz cycle 1: the requirements arrived as JSON text spelling an integer "60.0"
    C_REQ_FLOAT: _ctx(accepted=dict(ACCEPTED, maxTimeoutSeconds=60.0)),
    # what the verifier holds as "requirements" is not a JSON object
    C_REQ_NONOBJ: _ctx(accepted=[]),
    # the response carries payer as an empty string
    C_PAYER_EMPTY: _ctx(payer=""),
    # the response's network is not a network identifier (so §5.8 cannot compare
    # it) and the accepted requirements name another
    C_REQ_NET: _ctx(network="base", accepted=ACCEPTED_OTHER_NETWORK),
    # the verifier made the payment itself and knows the URL it paid for
    C_PAID: _ctx(paidResourceUrl=RESOURCE),
    C_PAID_OTHER: _ctx(paidResourceUrl="https://api.example.com/v1/other"),
    # the advertised info carries a scope that is not a string
    C_ADVERT_NONSTRING: _ctx(advertisedInfo=ADVERTISED_NONSTRING),
    # the verifier also holds the echoed extension info
    C_ADVERT: _ctx(advertisedInfo=ADVERTISED_INFO),
    # the info held is not in the value domain: nothing about the advertisement is evaluated
    C_ADVERT_FLOAT: _ctx(advertisedInfo=ADVERTISED_FLOAT),
    # ---- draft 0.4 ----
    # no maximum age given: the default 3600 applies (spec §5.10)
    C_DEFAULT_AGE: _ctx(maxAgeSeconds=_DROP),
    C_MAX_AGE_100: _ctx(maxAgeSeconds=100),
    # only the transaction: nothing else held to compare
    C_LOOSE: _ctx(network=None, payer=None, accepted=None),
    C_LOOKALIKE: _ctx(transaction=LOOKALIKE_TX, network=LOOKALIKE_NET, payer=LOOKALIKE_PAYER,
                      accepted=ACCEPTED_LOOKALIKE),
    # the response's values differ from the receipt's only in case, off eip155
    C_CF: _ctx(transaction=CF_TX, network=CF_NET, payer=None, accepted=ACCEPTED_CF),
    C_EVM_REF_UPPER: _ctx(settlementRef=BATCH_REF.upper()),
    C_EVM_REF_MIXED: _ctx(settlementRef="Batch:Voucher:9F3C1D0A-Root-01"),
    C_BATCH_ONLY_TX: _ctx(transaction=SOL_TX, settlementRef="", network=SOL_NET, payer=None,
                          accepted=ACCEPTED_SOL),
    C_REQ_UTF16: _ctx(accepted=ACCEPTED_UTF16),
    # a transaction of the wrong type, a payer with an unpaired surrogate and a
    # null network are all absent (spec §4.6 "Present and absent")
    C_ABSENT_FORMS: _ctx(transaction=123, settlementRef=COMMITMENT_ID, network=None,
                         payer="\ud800", accepted=ACCEPTED_SOL),
    # x402 objects of the wrong type never make the verifier fail (spec §5)
    C_JUNK: _ctx(payer={"a": 1}, network=5, accepted="x", advertisedInfo=[ADVERTISED_INFO]),
    C_NO_ID: _ctx(transaction="", settlementRef=""),
    C_SUCCESS_FALSE: _ctx(success=False),
    C_SUCCESS_STRING: _ctx(success="true"),
    C_PAID_EMPTY: _ctx(paidResourceUrl=""),
    C_ARCHIVAL_END: _ctx(now=SAFE_INT_MAX, mode="archival"),
    C_NOW_FLOAT: _ctx(now=float(VERIFIER_NOW)),
    C_RESP_NET_OTHER_FORM: _ctx(network="Base Mainnet"),
    C_NOPAYER_EVM: _ctx(payer=_DROP),
    C_NULL: None,
    **{"config_" + k: v for k, v in C_ERR.items()},
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
SIXTEEN_BINDINGS = [{"type": f"a:{i:02d}", "value": "1"} for i in range(MAX_BINDINGS)]

# --- conformance suite: (file, verdict, reason, context) ------------------
# Every single-fault negative is ONE mutation of a canonical positive; its reason
# is the code of the first check that mutation fails under the order of spec §5.
# `neg_order_*` vectors carry TWO faults of adjacent steps on purpose: their
# reason is the EARLIER step's, so a verifier that swaps the two steps fails
# them (a single-fault vector cannot observe order). `err_config_*` vectors
# carry a configuration outside the contract of spec §5: ERROR.

SUITE = [
    # positives
    ("pos_es256_valid.json", PASS, None, C_OK),
    ("pos_es256k_valid.json", PASS, None, C_OK),
    ("pos_eddsa_valid.json", PASS, None, C_OK),
    ("pos_payto_signer.json", PASS, None, C_OK),
    ("pos_outcome_failed.json", PASS, None, C_OK),
    ("pos_outcome_partial.json", PASS, None, C_OK),
    ("pos_batch_committed.json", PASS, None, C_BATCH),
    ("pos_batch_second_payment.json", PASS, None, C_BATCH),
    ("pos_capture_pending.json", PASS, None, C_OK),
    ("pos_reversed.json", PASS, None, C_BATCH),
    ("pos_refunded_supersedes.json", PASS, None, C_OK),
    ("pos_bindings_composed.json", PASS, None, C_ADVERT),
    ("pos_bindings_unheld.json", PASS, None, C_OK),
    ("pos_binding_advertised_digest_differs.json", PASS, None, C_ADVERT),
    ("pos_binding_advertised_scope_differs.json", PASS, None, C_ADVERT),
    ("pos_binding_advertised_actiontype_differs.json", PASS, None, C_ADVERT),
    ("pos_binding_advertised_scope_not_string.json", PASS, None, C_ADVERT_NONSTRING),
    ("pos_advertisement_absent.json", PASS, None, C_ADVERT),
    ("pos_advertised_info_outside_domain.json", PASS, None, C_ADVERT_FLOAT),
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
    ("pos_envelope_extra_member.json", PASS, None, C_OK),
    ("pos_compact_at_size_limit.json", PASS, None, C_OK),
    ("pos_network_namespace_3.json", PASS, None, C_LOOSE),
    ("pos_network_namespace_32.json", PASS, None, C_LOOSE),
    ("pos_network_reference_32.json", PASS, None, C_LOOSE),
    ("pos_network_lookalike_not_evm.json", PASS, None, C_LOOKALIKE),
    ("pos_network_cloudflare_empty_payer.json", PASS, None, C_CF),
    ("pos_receiptid_22.json", PASS, None, C_OK),
    ("pos_receiptid_64.json", PASS, None, C_OK),
    ("pos_bindings_16.json", PASS, None, C_OK),
    ("pos_binding_prefix_64.json", PASS, None, C_OK),
    ("pos_binding_name_191.json", PASS, None, C_OK),
    ("pos_binding_value_1024.json", PASS, None, C_OK),
    ("pos_binding_reversal_non_evm_value.json", PASS, None, C_BATCH),
    ("pos_binding_namespace_lookalike.json", PASS, None, C_OK),
    ("pos_issuedat_zero_archival.json", PASS, None, C_ARCHIVAL),
    ("pos_issuedat_max_archival.json", PASS, None, C_ARCHIVAL_END),
    ("pos_freshness_future_60.json", PASS, None, C_OK),
    ("pos_freshness_default_max_age_3600.json", PASS, None, C_DEFAULT_AGE),
    ("pos_freshness_max_age_100.json", PASS, None, C_MAX_AGE_100),
    ("pos_settlement_ref_evm_exact_case.json", PASS, None, C_EVM_REF_MIXED),
    ("pos_settlement_ref_with_transaction.json", PASS, None, C_BOTH),
    ("pos_requirements_utf16_order.json", PASS, None, C_REQ_UTF16),
    ("pos_response_absent_forms.json", PASS, None, C_ABSENT_FORMS),
    ("pos_response_junk_types.json", PASS, None, C_JUNK),
    ("pos_response_network_not_identifier.json", PASS, None, C_RESP_NET_OTHER_FORM),
    ("pos_payer_empty_evm.json", PASS, None, C_NOPAYER_EVM),
    ("pos_authorization_marker_not_true.json", PASS, None, C_OK),
    ("pos_config_clock_integer_float.json", PASS, None, C_NOW_FLOAT),
    # §5.1 envelope and header
    ("neg_not_jws_format.json", REJECT, R_MALFORMED, C_OK),
    ("neg_base64url_trailing_bits.json", REJECT, R_MALFORMED, C_OK),
    ("neg_compact_over_size_limit.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_not_object.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_bom.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_utf16.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_whitespace.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_member_order.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_duplicate_member.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_nan_overwritten.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_escaped_member_name.json", REJECT, R_MALFORMED, C_OK),
    ("neg_kid_not_string.json", REJECT, R_MALFORMED, C_OK),
    ("neg_header_extra_member.json", REJECT, R_MALFORMED, C_OK),
    ("neg_typ_missing.json", REJECT, R_TYP, C_OK),
    ("neg_typ_wrong.json", REJECT, R_TYP, C_OK),
    ("neg_typ_number.json", REJECT, R_TYP, C_OK),
    ("neg_unknown_alg.json", REJECT, R_UNKNOWN_ALG, C_OK),
    ("neg_alg_array.json", REJECT, R_UNKNOWN_ALG, C_OK),
    ("neg_alg_object.json", REJECT, R_UNKNOWN_ALG, C_OK),
    ("neg_alg_number.json", REJECT, R_UNKNOWN_ALG, C_OK),
    ("neg_alg_null.json", REJECT, R_UNKNOWN_ALG, C_OK),
    # §5.2 canonical bytes
    ("neg_canon_member_order.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_whitespace.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_number_float.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_number_exponent.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_number_negative_zero.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_number_unsafe_integer.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_issuedat_2_53.json", REJECT, R_NONCANONICAL, C_ARCHIVAL_END),
    ("neg_canon_duplicate_member.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_lone_surrogate.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_escaped_ascii.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_not_json.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_nesting_depth.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_canon_invalid_utf8.json", REJECT, R_NONCANONICAL, C_OK),
    # §5.3 closed schema and field grammar
    ("neg_schema_not_object.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_null.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_version_missing.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_version_string.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_unknown_member.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_missing_member.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_action_scalar.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_action_extra_member.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_scope_not_string.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_issuedat_string.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_issuedat_negative.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_version_boolean.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_no_settlement_id.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_receiptid_short.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_receiptid_21.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_receiptid_65.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_network_not_caip2.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_network_namespace_2.json", REJECT, R_MALFORMED, C_LOOSE),
    ("neg_schema_network_namespace_33.json", REJECT, R_MALFORMED, C_LOOSE),
    ("neg_schema_network_reference_33.json", REJECT, R_MALFORMED, C_LOOSE),
    ("neg_schema_resourceurl_empty.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_payto_empty_non_evm.json", REJECT, R_MALFORMED, C_LOOSE),
    ("neg_schema_payto_evm_grammar.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_agent_empty.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_actiontype_empty.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_payer_checksum_case.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_transaction_uppercase.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_digest_base64url.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_supersedes_grammar.json", REJECT, R_MALFORMED, C_OK),
    ("neg_schema_bindings_not_array.json", REJECT, R_MALFORMED, C_OK),
    ("neg_unsupported_version.json", REJECT, R_UNSUPPORTED_VERSION, C_OK),
    ("neg_invalid_outcome.json", REJECT, R_INVALID_OUTCOME, C_OK),
    ("neg_outcome_retired_refused.json", REJECT, R_INVALID_OUTCOME, C_OK),
    ("neg_outcome_retired_disputed.json", REJECT, R_INVALID_OUTCOME, C_OK),
    ("neg_invalid_status.json", REJECT, R_INVALID_STATUS, C_OK),
    ("neg_binding_unsorted.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_duplicate_type.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_extra_member.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_type_grammar.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_value_non_ascii.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_too_many.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_prefix_65.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_name_192.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_value_1025.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_reserved_unknown_type.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_advertised_value_form.json", REJECT, R_BINDING, C_OK),
    ("neg_binding_reversal_value_form_evm.json", REJECT, R_BINDING, C_OK),
    # §5.4 resource and signer authorization
    ("neg_resource_mismatch.json", REJECT, R_RESOURCE, C_PAID_OTHER),
    ("neg_resource_paid_empty_string.json", REJECT, R_RESOURCE, C_PAID_EMPTY),
    ("neg_signer_unauthorized.json", REJECT, R_SIGNER_UNAUTH, C_OK),
    ("neg_signer_unknown_kid.json", REJECT, R_SIGNER_UNAUTH, C_OK),
    ("neg_signer_payto_wrong_resource.json", REJECT, R_SIGNER_UNAUTH, C_OK),
    ("neg_signer_anchor_string.json", REJECT, R_SIGNER_UNAUTH, C_OK),
    ("neg_signer_anchor_object.json", REJECT, R_SIGNER_UNAUTH, C_OK),
    ("neg_signer_anchor_mixed_array.json", REJECT, R_SIGNER_UNAUTH, C_OK),
    ("neg_signer_anchor_number.json", REJECT, R_SIGNER_UNAUTH, C_OK),
    ("neg_authorization_no_answer.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    ("neg_authorization_no_answer_listed.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    # §5.5 key resolution
    ("neg_key_unresolved.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    ("neg_key_unusable.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    ("neg_key_private_key_pem.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    ("neg_key_certificate.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    ("neg_key_unknown_algorithm.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    ("neg_key_unsupported_curve.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    ("neg_key_unusable_curve_p384.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    ("neg_key_pem_leading_spaces.json", REJECT, R_KEY_UNRESOLVED, C_OK),
    # §5.6 signature
    ("neg_sig_tampered_payload.json", REJECT, R_SIG_INVALID, C_OK),
    ("neg_sig_high_s.json", REJECT, R_SIG_INVALID, C_OK),
    ("neg_sig_wrong_curve.json", REJECT, R_SIG_INVALID, C_OK),
    ("neg_sig_ecdsa_65_bytes.json", REJECT, R_SIG_INVALID, C_OK),
    ("neg_sig_ecdsa_der.json", REJECT, R_SIG_INVALID, C_OK),
    ("neg_sig_eddsa_key_for_es256.json", REJECT, R_SIG_INVALID, C_OK),
    ("neg_sig_ec_key_for_eddsa.json", REJECT, R_SIG_INVALID, C_OK),
    # §5.7 settlement success
    ("neg_settlement_failed.json", REJECT, R_SETTLEMENT_FAILED, C_FAILED),
    ("neg_settlement_success_without_identifier.json", REJECT, R_SETTLEMENT_FAILED, C_NO_ID),
    ("neg_settlement_success_false_with_transaction.json", REJECT, R_SETTLEMENT_FAILED, C_SUCCESS_FALSE),
    ("neg_settlement_success_string_true.json", REJECT, R_SETTLEMENT_FAILED, C_SUCCESS_STRING),
    # §5.8 settlement binding
    ("neg_settlement_transaction_mismatch.json", REJECT, R_SETTLEMENT, C_OK),
    ("neg_settlement_ref_mismatch.json", REJECT, R_SETTLEMENT, C_BATCH),
    ("neg_settlement_network_mismatch.json", REJECT, R_SETTLEMENT, C_OK),
    ("neg_settlement_payer_mismatch.json", REJECT, R_SETTLEMENT, C_OK),
    ("neg_settlement_payer_dropped.json", REJECT, R_SETTLEMENT, C_OK),
    ("neg_settlement_uncorroborated_transaction.json", REJECT, R_SETTLEMENT, C_BATCH),
    ("neg_settlement_dropped_transaction.json", REJECT, R_SETTLEMENT, C_BOTH),
    ("neg_settlement_uncorroborated_ref.json", REJECT, R_SETTLEMENT, C_BATCH_ONLY_TX),
    ("neg_settlement_dropped_ref.json", REJECT, R_SETTLEMENT, C_BOTH),
    ("neg_settlement_ref_case_not_folded.json", REJECT, R_SETTLEMENT, C_EVM_REF_UPPER),
    ("neg_settlement_non_evm_case_not_folded.json", REJECT, R_SETTLEMENT, C_LOOKALIKE),
    # §5.9 payment requirements
    ("neg_requirements_amount_changed.json", REJECT, R_REQUIREMENTS, C_OK),
    ("neg_requirements_payto_mismatch.json", REJECT, R_REQUIREMENTS, C_OK),
    ("neg_requirements_network_mismatch.json", REJECT, R_REQUIREMENTS, C_REQ_NET),
    # §5.10 freshness
    ("neg_freshness_stale.json", REJECT, R_STALE, C_OK),
    ("neg_freshness_future_archival.json", REJECT, R_STALE, C_ARCHIVAL),
    ("neg_freshness_future_61.json", REJECT, R_STALE, C_OK),
    ("neg_freshness_default_max_age_3601.json", REJECT, R_STALE, C_DEFAULT_AGE),
    ("neg_freshness_max_age_101.json", REJECT, R_STALE, C_MAX_AGE_100),
    # step order: two faults in adjacent steps; the earlier step's code wins
    ("neg_order_header_canonical_before_typ.json", REJECT, R_MALFORMED, C_OK),
    ("neg_order_header_domain_before_typ.json", REJECT, R_MALFORMED, C_OK),
    ("neg_order_typ_before_alg.json", REJECT, R_TYP, C_OK),
    ("neg_order_alg_before_header_members.json", REJECT, R_UNKNOWN_ALG, C_OK),
    ("neg_order_header_before_canonicalization.json", REJECT, R_MALFORMED, C_OK),
    ("neg_order_canonicalization_before_schema.json", REJECT, R_NONCANONICAL, C_OK),
    ("neg_order_version_before_member_set.json", REJECT, R_UNSUPPORTED_VERSION, C_OK),
    ("neg_order_member_set_before_outcome.json", REJECT, R_MALFORMED, C_OK),
    ("neg_order_outcome_before_status.json", REJECT, R_INVALID_OUTCOME, C_OK),
    ("neg_order_status_before_bindings_type.json", REJECT, R_INVALID_STATUS, C_OK),
    ("neg_order_binding_before_resource.json", REJECT, R_BINDING, C_PAID_OTHER),
    ("neg_order_resource_before_signer.json", REJECT, R_RESOURCE, C_PAID_OTHER),
    ("neg_order_signer_before_signature.json", REJECT, R_SIGNER_UNAUTH, C_OK),
    ("neg_order_signature_before_settlement.json", REJECT, R_SIG_INVALID, C_FAILED),
    ("neg_order_success_before_binding.json", REJECT, R_SETTLEMENT_FAILED, C_FAILED),
    ("neg_order_settlement_before_requirements.json", REJECT, R_SETTLEMENT, C_OK),
    ("neg_order_requirements_before_freshness.json", REJECT, R_REQUIREMENTS, C_OK),
    # configuration outside the contract of spec §5: ERROR, whatever the receipt
    *[(f"err_config_{k}.json", ERROR, E_CONFIG, "config_" + k) for k in C_ERR],
    ("err_config_context_null.json", ERROR, E_CONFIG, C_NULL),
    ("err_config_over_malformed_receipt.json", ERROR, E_CONFIG, "config_mode_upper_case"),
]

# Pairs of positives that MUST have different receiptRef values, with the reason.
DISTINCT = [
    ("pos_batch_committed.json", "pos_batch_second_payment.json",
     "two payments under one batch commitment in the same second"),
    ("pos_non_ascii_nfc.json", "pos_non_ascii_nfd.json",
     "no Unicode normalization is applied: NFC and NFD are different receipts"),
    ("pos_es256_valid.json", "pos_outcome_failed.json",
     "a different statement about the same settlement"),
]
# Groups of positives that MUST share one receiptRef: the identifier names the
# signed statement, not the signature or the key that made it.
SAME = [
    (["pos_es256_valid.json", "pos_es256k_valid.json", "pos_eddsa_valid.json",
      "pos_payto_signer.json", "pos_response_casing.json", "pos_payer_absent.json",
      "pos_requirements_not_held.json", "pos_archival_180d.json",
      "pos_requirements_float_spelling.json", "pos_requirements_not_object.json",
      "pos_payer_empty_string.json", "pos_resource_paid.json", "pos_envelope_extra_member.json",
      "pos_response_junk_types.json", "pos_response_network_not_identifier.json",
      "pos_config_clock_integer_float.json"],
     "one statement signed under four keys and verified in thirteen contexts"),
]

# Hand-declared reports. Every positive's report is declared here as changes to
# one default, written by hand from spec §5.12, and the suite compares the FULL
# report (receiptRef is checked separately as the hash of the payload segment).
# MANIFEST.json then publishes the report the verifier produced; the suite
# requires the two to agree, so no published report is only self-written.
_DEFAULT_CHECKS = {"resourceUrl": "not_compared", "network": "compared", "payer": "compared",
                   "requirements": "matched", "payTo": "compared",
                   "advertisement": "not_evaluated", "freshness": "enforced"}
_DEFAULT_REPORT = {"outcome": "delivered", "settlementStatus": "settled",
                   "ageSeconds": VERIFIER_NOW - ISSUED_AT, "checks": _DEFAULT_CHECKS,
                   "supersedes": "", "bindings": []}
_NE = "not_evaluated"
_BATCH_CHECKS = {"payer": "not_compared"}
EXPECT_REPORT = {
    "pos_resource_paid.json": {"checks": {"resourceUrl": "compared"}},
    "pos_outcome_failed.json": {"outcome": "failed"},
    "pos_outcome_partial.json": {"outcome": "partial"},
    "pos_batch_committed.json": {"settlementStatus": "capturePending", "checks": _BATCH_CHECKS},
    "pos_batch_second_payment.json": {"settlementStatus": "capturePending", "checks": _BATCH_CHECKS},
    "pos_capture_pending.json": {"settlementStatus": "capturePending"},
    "pos_reversed.json": {"settlementStatus": "reversed", "checks": _BATCH_CHECKS,
                          "supersedes": "@sha256:pos_batch_committed.json"},
    "pos_refunded_supersedes.json": {"settlementStatus": "refunded",
                                     "supersedes": "@sha256:pos_es256_valid.json",
                                     "bindings": [{"type": BT_REVERSAL_TX, "status": _NE}]},
    "pos_bindings_composed.json": {
        "checks": {"advertisement": "matched"},
        "bindings": [{"type": b["type"], "status": "matched" if b["type"] == BT_ADVERTISED else _NE}
                     for b in COMPOSED_BINDINGS]},
    "pos_bindings_unheld.json": {"bindings": [{"type": b["type"], "status": _NE}
                                              for b in COMPOSED_BINDINGS]},
    "pos_binding_advertised_digest_differs.json": {
        "checks": {"advertisement": "mismatched"},
        "bindings": [{"type": BT_ADVERTISED, "status": "mismatched"}]},
    "pos_binding_advertised_scope_differs.json": {
        "checks": {"advertisement": "mismatched"},
        "bindings": [{"type": BT_ADVERTISED, "status": "mismatched"}]},
    "pos_binding_advertised_actiontype_differs.json": {
        "checks": {"advertisement": "mismatched"},
        "bindings": [{"type": BT_ADVERTISED, "status": "mismatched"}]},
    "pos_binding_advertised_scope_not_string.json": {
        "checks": {"advertisement": "mismatched"},
        "bindings": [{"type": BT_ADVERTISED, "status": "mismatched"}]},
    "pos_advertisement_absent.json": {"checks": {"advertisement": "absent"}},
    "pos_advertised_info_outside_domain.json": {
        "bindings": [{"type": BT_ADVERTISED, "status": _NE}]},
    "pos_requirements_not_held.json": {"checks": {"requirements": _NE, "payTo": "not_compared"}},
    "pos_payer_absent.json": {"checks": {"payer": "not_compared"}},
    "pos_payer_empty_string.json": {"checks": {"payer": "not_compared"}},
    "pos_archival_180d.json": {"checks": {"freshness": "reported"}, "ageSeconds": 180 * 86400},
    "pos_requirements_not_object.json": {"checks": {"requirements": _NE, "payTo": "not_compared"}},
    "pos_network_namespace_3.json": {"checks": {"network": "not_compared", "payer": "not_compared",
                                                "requirements": _NE, "payTo": "not_compared"}},
    "pos_network_namespace_32.json": {"checks": {"network": "not_compared", "payer": "not_compared",
                                                 "requirements": _NE, "payTo": "not_compared"}},
    "pos_network_reference_32.json": {"checks": {"network": "not_compared", "payer": "not_compared",
                                                 "requirements": _NE, "payTo": "not_compared"}},
    "pos_network_cloudflare_empty_payer.json": {"checks": {"payer": "not_compared"}},
    "pos_bindings_16.json": {"bindings": [{"type": b["type"], "status": _NE} for b in SIXTEEN_BINDINGS]},
    "pos_binding_prefix_64.json": {"bindings": [{"type": "a" * 64 + ":b", "status": _NE}]},
    "pos_binding_name_191.json": {"bindings": [{"type": "a:" + "b" * 191, "status": _NE}]},
    "pos_binding_value_1024.json": {"bindings": [{"type": "a:one", "status": _NE}]},
    "pos_binding_reversal_non_evm_value.json": {
        "settlementStatus": "reversed", "checks": _BATCH_CHECKS,
        "bindings": [{"type": BT_REVERSAL_TX, "status": _NE}]},
    "pos_binding_namespace_lookalike.json": {
        "bindings": [{"type": "action-receipt.v2:advertised-info", "status": _NE}]},
    "pos_issuedat_zero_archival.json": {"checks": {"freshness": "reported"},
                                        "ageSeconds": ISSUED_AT + 180 * 86400},
    "pos_issuedat_max_archival.json": {"checks": {"freshness": "reported"}, "ageSeconds": 0},
    "pos_freshness_future_60.json": {"ageSeconds": -60},
    "pos_freshness_default_max_age_3600.json": {"ageSeconds": 3600},
    "pos_freshness_max_age_100.json": {"ageSeconds": 100},
    "pos_response_absent_forms.json": {"settlementStatus": "capturePending",
                                       "checks": {"network": "not_compared", "payer": "not_compared"}},
    "pos_response_junk_types.json": {"checks": {"network": "not_compared", "payer": "not_compared",
                                                "requirements": _NE, "payTo": "not_compared"}},
    "pos_response_network_not_identifier.json": {"checks": {"network": "not_compared"}},
    "pos_payer_empty_evm.json": {"checks": {"payer": "not_compared"}},
    "pos_settlement_ref_with_transaction.json": {"settlementStatus": "capturePending",
                                                 "checks": _BATCH_CHECKS},
}


def expected_report(fname: str, refs: dict) -> dict:
    """The hand-declared report for a positive, without `receiptRef`.
    `@sha256:<file>` stands for the receiptRef of another vector."""
    want = json.loads(json.dumps(_DEFAULT_REPORT))
    for k, v in EXPECT_REPORT.get(fname, {}).items():
        if k == "checks":
            want["checks"].update(v)
        else:
            want[k] = v
    if isinstance(want["supersedes"], str) and want["supersedes"].startswith("@sha256:"):
        want["supersedes"] = refs.get(want["supersedes"][8:], "<unknown>")
    return want


def report_mismatches(report: dict, want: dict) -> list[str]:
    out = []
    got = {k: v for k, v in report.items() if k != "receiptRef"}
    for key in sorted(set(got) | set(want)):
        if key == "checks":
            g, w = got.get("checks", {}), want.get("checks", {})
            for k in sorted(set(g) | set(w)):
                if g.get(k) != w.get(k):
                    out.append(f"checks.{k}: want {w.get(k)}, got {g.get(k)}")
        elif got.get(key) != want.get(key):
            out.append(f"{key}: want {want.get(key)}, got {got.get(key)}")
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


def _sized_receipt(target: int, keys: dict) -> dict:
    """A valid receipt whose compact string is exactly `target` characters,
    padded through `action.scope`. base64url cannot produce every length, so
    the signer (and with it the header length) is chosen to make it exact."""
    signers = [("ES256", KID_ES256, "ES256"), ("ES256K", KID_ES256K, "ES256K"),
               ("EdDSA", KID_ED, "EdDSA"), ("ES256", KID_PAYTO, "PAYTO")]
    n0 = len(_canon(_base_payload(action={"scope": ""})).encode())
    for alg, kid, kname in signers:
        h_len = len(b64url(_canon({"alg": alg, "kid": kid, "typ": TYP}).encode()))
        p_len = target - h_len - 86 - 2
        n = (3 * p_len) // 4
        for cand in (n - 1, n, n + 1):
            if cand >= n0 and len(b64url(b"\0" * cand)) == p_len:
                payload = _base_payload(action={"scope": "x" * (cand - n0)})
                sig = _sign_jws(alg, kid, keys[kname], _canon(payload).encode())
                assert len(sig) == target, (len(sig), target)
                return {"format": "jws", "signature": sig}
    raise AssertionError(f"no signer gives a compact string of {target} characters")


def regenerate_vectors() -> None:
    if not HAVE_CRYPTO:
        sys.exit("cannot regenerate vectors without `cryptography`")
    VECTORS.mkdir(exist_ok=True)
    for old in VECTORS.glob("*.json"):
        old.unlink()
    registry, keys = _registry()
    es, ed = keys["ES256"], keys["EdDSA"]

    def w(name, receipt):
        (VECTORS / name).write_text(json.dumps(receipt, indent=2) + "\n")

    def signed(payload, alg="ES256", kid=KID_ES256, key=None, **kw):
        """Sign the canonical bytes of `payload` (which may be schema-invalid)."""
        return {"format": "jws",
                "signature": _sign_jws(alg, kid, key or keys[alg], _canon(payload).encode(), **kw)}

    def signed_raw(raw: bytes, **kw):
        return {"format": "jws", "signature": _sign_jws("ES256", KID_ES256, es, raw, **kw)}

    def hdr_bytes(text: str) -> bytes:
        return text.encode("utf-8")

    base = _base_payload
    base_text = _canon(base())
    hdr_ok = _canon({"alg": "ES256", "kid": KID_ES256, "typ": TYP})

    # ---- positives ----
    w("pos_es256_valid.json", signed(base()))
    w("pos_es256k_valid.json", signed(base(), "ES256K", KID_ES256K))
    w("pos_eddsa_valid.json", signed(base(), "EdDSA", KID_ED))
    w("pos_payto_signer.json", signed(base(), "ES256", KID_PAYTO, keys["PAYTO"]))
    w("pos_outcome_failed.json", signed(base(action={"outcome": "failed"})))
    w("pos_outcome_partial.json", signed(base(action={"outcome": "partial"})))
    w("pos_batch_committed.json", signed(_sol_payload()))
    w("pos_batch_second_payment.json", signed(_sol_payload(receiptId=RECEIPT_ID_2)))
    # an EVM authorization not yet captured: the transaction names the authorization
    w("pos_capture_pending.json", signed(base(settlementStatus="capturePending")))
    w("pos_reversed.json",
      signed(_sol_payload(settlementStatus="reversed", receiptId=RECEIPT_ID_2,
                          supersedes=sha256_tag(_canon(_sol_payload()).encode()))))
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
    w("pos_binding_advertised_actiontype_differs.json",
      signed(base(action={"actionType": "inference.embedding"},
                  bindings=[{"type": BT_ADVERTISED, "value": sha256_tag(jcs(ADVERTISED_INFO))}])))
    w("pos_advertisement_absent.json", signed(base()))
    w("pos_advertised_info_outside_domain.json",
      signed(base(bindings=[{"type": BT_ADVERTISED, "value": sha256_tag(jcs(ADVERTISED_INFO))}])))
    for name in ("pos_requirements_not_held.json", "pos_response_casing.json",
                 "pos_payer_absent.json", "pos_archival_180d.json",
                 "pos_requirements_float_spelling.json", "pos_requirements_not_object.json",
                 "pos_payer_empty_string.json", "pos_resource_paid.json",
                 "neg_resource_mismatch.json", "pos_response_junk_types.json",
                 "pos_response_network_not_identifier.json", "pos_config_clock_integer_float.json",
                 "neg_resource_paid_empty_string.json", "neg_settlement_failed.json",
                 "neg_settlement_success_without_identifier.json",
                 "neg_settlement_success_false_with_transaction.json",
                 "neg_settlement_success_string_true.json"):
        w(name, signed(base()))
    # §3: other members of the receipt object are ignored and not signed
    w("pos_envelope_extra_member.json",
      dict(signed(base()), payload={"x": 1}, note="ignored", acceptIndex=0))
    nfc = unicodedata.normalize("NFC", "did:web:café.example")
    nfd = unicodedata.normalize("NFD", "did:web:café.example")
    w("pos_non_ascii_nfc.json",
      signed(base(action={"agent": nfc, "scope": "lire:modèle \U0001d4b3\u0007"})))
    w("pos_non_ascii_nfd.json",
      signed(base(action={"agent": nfd, "scope": "lire:modèle \U0001d4b3\u0007"})))
    # size bound (spec §3, §5.1): exactly at the limit, and one character over
    w("pos_compact_at_size_limit.json", _sized_receipt(MAX_COMPACT, keys))
    w("neg_compact_over_size_limit.json", _sized_receipt(MAX_COMPACT + 1, keys))
    # network grammar (spec §4.6): both sides of every length bound
    for name, net in (("pos_network_namespace_3.json", "abc:1"),
                      ("pos_network_namespace_32.json", "a" * 32 + ":1"),
                      ("pos_network_reference_32.json", "abc:" + "R" * 32),
                      ("neg_schema_network_namespace_2.json", "ab:1"),
                      ("neg_schema_network_namespace_33.json", "a" * 33 + ":1"),
                      ("neg_schema_network_reference_33.json", "abc:" + "R" * 33)):
        w(name, signed(base(network=net)))
    # begins "eip1559:", not "eip155:": no EVM grammar, no lowercasing
    w("pos_network_lookalike_not_evm.json",
      signed(base(network=LOOKALIKE_NET, payer=LOOKALIKE_PAYER, payTo=LOOKALIKE_PAY_TO,
                  transaction=LOOKALIKE_TX, requirementsDigest=requirements_digest(ACCEPTED_LOOKALIKE))))
    w("neg_settlement_non_evm_case_not_folded.json",
      signed(base(network=LOOKALIKE_NET, payer=LOOKALIKE_PAYER.lower(), payTo=LOOKALIKE_PAY_TO,
                  transaction=LOOKALIKE_TX.lower(),
                  requirementsDigest=requirements_digest(ACCEPTED_LOOKALIKE))))
    w("pos_network_cloudflare_empty_payer.json",
      signed(base(network=CF_NET, payer="", payTo=CF_PAY_TO, transaction=CF_TX,
                  requirementsDigest=requirements_digest(ACCEPTED_CF))))
    # receiptId bounds
    for name, rid in (("pos_receiptid_22.json", "R" * 22), ("pos_receiptid_64.json", "R" * 64),
                      ("neg_schema_receiptid_21.json", "R" * 21),
                      ("neg_schema_receiptid_65.json", "R" * 65)):
        w(name, signed(base(receiptId=rid)))
    # binding bounds
    w("pos_bindings_16.json", signed(base(bindings=SIXTEEN_BINDINGS)))
    w("pos_binding_prefix_64.json", signed(base(bindings=[{"type": "a" * 64 + ":b", "value": "1"}])))
    w("neg_binding_prefix_65.json", signed(base(bindings=[{"type": "a" * 65 + ":b", "value": "1"}])))
    w("pos_binding_name_191.json", signed(base(bindings=[{"type": "a:" + "b" * 191, "value": "1"}])))
    w("neg_binding_name_192.json", signed(base(bindings=[{"type": "a:" + "b" * 192, "value": "1"}])))
    w("pos_binding_value_1024.json", signed(base(bindings=[{"type": "a:one", "value": "x" * 1024}])))
    w("neg_binding_value_1025.json", signed(base(bindings=[{"type": "a:one", "value": "x" * 1025}])))
    # the closed action-receipt: namespace and its value forms (spec §4.5.1, §4.5.2, §5.3 step 7)
    w("neg_binding_reserved_unknown_type.json",
      signed(base(bindings=[{"type": "action-receipt:settlementStatus", "value": "refunded"}])))
    w("neg_binding_advertised_value_form.json",
      signed(base(bindings=[{"type": BT_ADVERTISED, "value": "sha256:" + "AB" * 32}])))
    w("neg_binding_reversal_value_form_evm.json",
      signed(base(settlementStatus="refunded",
                  bindings=[{"type": BT_REVERSAL_TX, "value": "0x" + "EF" * 32}])))
    w("pos_binding_reversal_non_evm_value.json",
      signed(_sol_payload(settlementStatus="reversed",
                          bindings=[{"type": BT_REVERSAL_TX, "value": "Refund-5VERv8NMvzbJ"}])))
    w("pos_binding_namespace_lookalike.json",
      signed(base(bindings=[{"type": "action-receipt.v2:advertised-info", "value": "x"}])))
    # issuedAt bounds: 0 and 2^53-1 pass; 2^53 is outside the value domain (§5.2)
    w("pos_issuedat_zero_archival.json", signed(base(issuedAt=0)))
    w("pos_issuedat_max_archival.json", signed(base(issuedAt=SAFE_INT_MAX)))
    w("neg_canon_issuedat_2_53.json",
      signed_raw(base_text.replace(f'"issuedAt":{ISSUED_AT}', f'"issuedAt":{2**53}').encode()))
    # freshness bounds, with the default and with an explicit maximum age
    w("pos_freshness_future_60.json", signed(base(issuedAt=VERIFIER_NOW + 60)))
    w("neg_freshness_future_61.json", signed(base(issuedAt=VERIFIER_NOW + 61)))
    w("pos_freshness_default_max_age_3600.json", signed(base(issuedAt=VERIFIER_NOW - 3600)))
    w("neg_freshness_default_max_age_3601.json", signed(base(issuedAt=VERIFIER_NOW - 3601)))
    w("pos_freshness_max_age_100.json", signed(base(issuedAt=VERIFIER_NOW - 100)))
    w("neg_freshness_max_age_101.json", signed(base(issuedAt=VERIFIER_NOW - 101)))
    # settlement references are never normalized (spec §5.8 "Nothing else is normalized")
    w("pos_settlement_ref_evm_exact_case.json",
      signed(base(settlementRef="Batch:Voucher:9F3C1D0A-Root-01")))
    w("neg_settlement_ref_case_not_folded.json", signed(base(settlementRef=BATCH_REF)))
    w("pos_settlement_ref_with_transaction.json", signed(_sol_payload(transaction=SOL_TX)))
    w("neg_settlement_uncorroborated_ref.json", signed(_sol_payload(transaction=SOL_TX)))
    w("neg_settlement_dropped_ref.json", signed(_sol_payload(transaction=SOL_TX, settlementRef="")))
    w("pos_requirements_utf16_order.json",
      signed(base(requirementsDigest=requirements_digest(ACCEPTED_UTF16))))
    w("pos_response_absent_forms.json", signed(_sol_payload()))
    w("pos_payer_empty_evm.json", signed(base(payer="")))
    w("neg_settlement_payer_dropped.json", signed(base(payer="")))
    w("pos_authorization_marker_not_true.json",
      signed(base(resourceUrl=RES_UNAVAILABLE_NOT_TRUE), "EdDSA", KID_ED))

    # ---- §5.1 envelope and header ----
    good = _sign_jws("ES256", KID_ES256, es, base_text.encode())
    _, p_ok, s_ok = good.split(".")
    w("neg_not_jws_format.json", {"format": "eip712", "signature": good})
    w("err_config_over_malformed_receipt.json", {"format": "eip712", "signature": good})
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
    # every header negative below is SIGNED, so only the header rule can reject it
    for name, hb in (
            # found by fuzz cycle 2: a parser that sniffs encodings accepts these
            ("neg_header_bom.json", b"\xef\xbb\xbf" + hdr_ok.encode()),
            ("neg_header_utf16.json", hdr_ok.encode("utf-16")),
            # draft 0.4: the header has one spelling (spec §3)
            ("neg_header_whitespace.json", hdr_bytes(hdr_ok.replace(",", ", "))),
            ("neg_header_member_order.json",
             hdr_bytes(json.dumps({"typ": TYP, "alg": "ES256", "kid": KID_ES256}, separators=(",", ":")))),
            ("neg_header_duplicate_member.json",
             hdr_bytes(hdr_ok.replace('{"alg":"ES256",', '{"alg":"ES256","alg":"ES256",'))),
            # reviewer B-1 / D-01: Python's json accepts NaN; a later duplicate overwrote it
            ("neg_header_nan_overwritten.json",
             hdr_bytes(hdr_ok.replace('{"alg":"ES256",', '{"alg":NaN,"alg":"ES256",'))),
            ("neg_header_escaped_member_name.json", hdr_bytes(hdr_ok.replace('"typ"', '"t\\u0079p"'))),
            # two faults, adjacent steps: the canonical-form test comes before typ
            ("neg_order_header_canonical_before_typ.json",
             hdr_bytes(_canon({"alg": "ES256", "kid": KID_ES256, "typ": "JWT"}).replace(",", ", "))),
            # the value-domain half of the same test (reviewer M-1): canonical text, an unsafe integer
            ("neg_order_header_domain_before_typ.json",
             hdr_bytes(_canon({"alg": "ES256", "kid": KID_ES256, "typ": "JWT"})[:-1] + ',"x":9007199254740993}')),
    ):
        assert hb != hdr_ok.encode()
        w(name, {"format": "jws", "signature": _sign_jws("ES256", KID_ES256, es, base_text.encode(),
                                                         header_bytes=hb)})
    w("neg_kid_not_string.json",
      signed_raw(base_text.encode(), header={"alg": "ES256", "kid": 123, "typ": TYP}))
    w("neg_header_extra_member.json",
      signed_raw(base_text.encode(),
                 header={"alg": "ES256", "kid": KID_ES256, "typ": TYP, "crit": ["x"]}))
    w("neg_typ_missing.json",
      signed_raw(base_text.encode(), header={"alg": "ES256", "kid": KID_ES256}))
    w("neg_typ_wrong.json",
      signed_raw(base_text.encode(), header={"alg": "ES256", "kid": KID_ES256, "typ": "JWT"}))
    w("neg_typ_number.json",
      signed_raw(base_text.encode(), header={"alg": "ES256", "kid": KID_ES256, "typ": 1}))
    bad_h = b64url(_canon({"alg": "HS256", "kid": KID_ES256, "typ": TYP}).encode())
    w("neg_unknown_alg.json", {"format": "jws", "signature": f"{bad_h}.{p_ok}.{s_ok}"})
    # reviewer B-2: a non-string alg is rejected at step 3, never an ERROR
    for name, alg_value in (("neg_alg_array.json", ["ES256"]), ("neg_alg_object.json", {"a": 1}),
                            ("neg_alg_number.json", 5), ("neg_alg_null.json", None)):
        w(name, signed_raw(base_text.encode(), header={"alg": alg_value, "kid": KID_ES256, "typ": TYP}))
    w("neg_order_typ_before_alg.json",
      signed_raw(base_text.encode(), header={"alg": "HS256", "kid": KID_ES256, "typ": "JWT"}))
    w("neg_order_alg_before_header_members.json",
      signed_raw(base_text.encode(), header={"alg": "HS256", "kid": KID_ES256, "typ": TYP, "crit": ["x"]}))
    w("neg_order_header_before_canonicalization.json",
      signed_raw(base_text.replace('","', '", "', 1).encode(),
                 header={"alg": "ES256", "kid": KID_ES256, "typ": TYP, "crit": ["x"]}))

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
    w("neg_order_canonicalization_before_schema.json",
      signed_raw(_canon(base(version=2)).replace('","', '", "', 1).encode()))
    for name in ("neg_canon_member_order.json", "neg_canon_whitespace.json",
                 "neg_canon_number_float.json", "neg_canon_number_exponent.json",
                 "neg_canon_number_negative_zero.json", "neg_canon_number_unsafe_integer.json",
                 "neg_canon_duplicate_member.json", "neg_canon_lone_surrogate.json",
                 "neg_canon_escaped_ascii.json", "neg_canon_invalid_utf8.json",
                 "neg_canon_issuedat_2_53.json"):
        raw = b64url_decode(json.loads((VECTORS / name).read_text())["signature"].split(".")[1])
        assert raw != base_text.encode(), f"{name}: mutation left the bytes unchanged"

    # ---- §5.3 closed schema and field grammar (canonical bytes, one fault each) ----
    w("neg_schema_not_object.json", signed([base()]))
    # found by fuzz cycle 2: canonical, in the value domain, and not an object
    w("neg_schema_null.json", signed_raw(b"null"))
    nover = base(); del nover["version"]
    w("neg_schema_version_missing.json", signed(nover))
    w("neg_schema_version_string.json", signed(base(version="1")))
    unknown = base(); unknown["signature"] = "0xdead"
    w("neg_schema_unknown_member.json", signed(unknown))
    missing = base(); del missing["receiptId"]
    w("neg_schema_missing_member.json", signed(missing))
    w("neg_schema_action_scalar.json", signed(dict(base(), action=7)))
    w("neg_schema_action_extra_member.json", signed(base(action={"note": "x"})))
    w("neg_schema_scope_not_string.json", signed(base(action={"scope": 7})))
    w("neg_schema_issuedat_string.json", signed(base(issuedAt=str(ISSUED_AT))))
    w("neg_schema_issuedat_negative.json", signed(base(issuedAt=-1)))
    w("neg_schema_version_boolean.json", signed(base(version=True)))
    w("neg_schema_no_settlement_id.json", signed(base(transaction="", settlementRef="")))
    w("neg_schema_receiptid_short.json", signed(base(receiptId="tooshort")))
    w("neg_schema_network_not_caip2.json", signed(base(network="base")))
    w("neg_schema_resourceurl_empty.json", signed(base(resourceUrl="")))
    w("neg_schema_payto_empty_non_evm.json", signed(base(network="abc:1", payTo="")))
    w("neg_schema_payto_evm_grammar.json", signed(base(payTo=PAY_TO_CHECKSUM)))
    w("neg_schema_agent_empty.json", signed(base(action={"agent": ""})))
    w("neg_schema_actiontype_empty.json", signed(base(action={"actionType": ""})))
    w("neg_schema_payer_checksum_case.json", signed(base(payer=PAYER_CHECKSUM)))
    w("neg_schema_transaction_uppercase.json", signed(base(transaction="0x" + "AB" * 32)))
    w("neg_schema_digest_base64url.json",
      signed(base(requirementsDigest=b64url(hashlib.sha256(_canon(ACCEPTED).encode()).digest()))))
    w("neg_schema_supersedes_grammar.json", signed(base(supersedes="previous-receipt")))
    w("neg_schema_bindings_not_array.json", signed(base(bindings={})))
    w("neg_unsupported_version.json", signed(base(version=99)))
    w("neg_invalid_outcome.json", signed(base(action={"outcome": "shipped"})))
    # values earlier drafts allowed and this one does not
    w("neg_outcome_retired_refused.json", signed(base(action={"outcome": "refused"})))
    w("neg_outcome_retired_disputed.json", signed(base(action={"outcome": "disputed"})))
    w("neg_invalid_status.json", signed(base(settlementStatus="pending")))
    two = [{"type": "a:one", "value": "1"}, {"type": "b:two", "value": "2"}]
    w("neg_binding_unsorted.json", signed(base(bindings=list(reversed(two)))))
    w("neg_binding_duplicate_type.json", signed(base(bindings=[two[0], dict(two[0], value="9")])))
    w("neg_binding_extra_member.json", signed(base(bindings=[dict(two[0], alg="sha256")])))
    w("neg_binding_type_grammar.json", signed(base(bindings=[{"type": "no-colon", "value": "1"}])))
    w("neg_binding_value_non_ascii.json", signed(base(bindings=[{"type": "a:one", "value": "café"}])))
    w("neg_binding_too_many.json",
      signed(base(bindings=[{"type": f"a:{i:02d}", "value": "1"} for i in range(MAX_BINDINGS + 1)])))
    # two faults, adjacent steps of §5.3
    over = base(version=2); over["futureMember"] = "x"
    w("neg_order_version_before_member_set.json", signed(over))
    extra_bad_outcome = base(action={"outcome": "shipped"}); extra_bad_outcome["signature"] = "0xdead"
    w("neg_order_member_set_before_outcome.json", signed(extra_bad_outcome))
    w("neg_order_outcome_before_status.json",
      signed(base(action={"outcome": "shipped"}, settlementStatus="pending")))
    w("neg_order_status_before_bindings_type.json",
      signed(base(settlementStatus="pending", bindings={})))
    w("neg_order_binding_before_resource.json",
      signed(base(bindings=[{"type": "no-colon", "value": "1"}])))

    # ---- §5.4 / §5.5 signer authorization and key resolution ----
    w("neg_signer_unauthorized.json", signed(base(), "ES256", KID_EVIL, keys["EVIL"]))
    w("neg_signer_unknown_kid.json", signed(base(), "ES256", "did:web:nobody.example#x", es))
    w("neg_signer_payto_wrong_resource.json",
      signed(base(resourceUrl="https://other.example/x"), "ES256", KID_PAYTO, keys["PAYTO"]))
    for name, res in (("neg_signer_anchor_string.json", RES_ANCHOR_STRING),
                      ("neg_signer_anchor_object.json", RES_ANCHOR_OBJECT),
                      ("neg_signer_anchor_mixed_array.json", RES_ANCHOR_MIXED),
                      ("neg_signer_anchor_number.json", RES_ANCHOR_NUMBER),
                      ("neg_authorization_no_answer.json", RES_UNAVAILABLE),
                      ("neg_authorization_no_answer_listed.json", RES_UNAVAILABLE_LISTED)):
        w(name, signed(base(resourceUrl=res), "EdDSA", KID_ED))
    w("neg_key_unresolved.json", signed(base(), "ES256", KID_ABSENT, es))
    w("neg_key_unusable.json", signed(base(), "ES256", KID_UNUSABLE, es))
    w("neg_key_private_key_pem.json", signed(base(), "ES256", KID_PRIVATE_PEM, es))
    w("neg_key_certificate.json", signed(base(), "EdDSA", KID_CERTIFICATE, ed))
    w("neg_key_unknown_algorithm.json", signed(base(), "EdDSA", KID_UNKNOWN_ALG, ed))
    w("neg_key_unsupported_curve.json", signed(base(), "ES256", KID_UNKNOWN_CURVE, es))
    w("neg_key_unusable_curve_p384.json", signed(base(), "ES256", KID_P384, es))
    w("neg_key_pem_leading_spaces.json", signed(base(), "EdDSA", KID_PEM_SPACES, ed))
    w("neg_order_resource_before_signer.json", signed(base(), "ES256", KID_EVIL, keys["EVIL"]))

    # ---- §5.6 signature ----
    h_ok = good.split(".")[0]
    tampered = _canon(base(action={"outcome": "failed"})).encode()
    w("neg_sig_tampered_payload.json", {"format": "jws", "signature": f"{h_ok}.{b64url(tampered)}.{s_ok}"})
    w("neg_sig_high_s.json", signed(base(), force_high_s=True))
    w("neg_sig_wrong_curve.json",
      signed_raw(base_text.encode(), header={"alg": "ES256K", "kid": KID_ES256, "typ": TYP}))
    # reviewer E V53: r || 00 || s is 65 bytes; a verifier that does not check the
    # length and reads r and s from the ends would accept it
    w("neg_sig_ecdsa_65_bytes.json", signed(base(), sig_edit=lambda s: s[:32] + b"\x00" + s[32:]))
    w("neg_sig_ecdsa_der.json", signed(base(), sig_edit=lambda s: asym_utils.encode_dss_signature(
        int.from_bytes(s[:32], "big"), int.from_bytes(s[32:], "big"))))
    # an EdDSA signature by the Ed25519 key, header naming ES256 and that key
    w("neg_sig_eddsa_key_for_es256.json",
      {"format": "jws", "signature": _sign_jws("EdDSA", KID_ED, ed, base_text.encode(),
                                               header={"alg": "ES256", "kid": KID_ED, "typ": TYP})})
    # an Ed25519 signature checked under a P-256 key: the header names EdDSA and the EC kid
    w("neg_sig_ec_key_for_eddsa.json",
      {"format": "jws", "signature": _sign_jws("EdDSA", KID_ES256, ed, base_text.encode())})
    w("neg_order_signer_before_signature.json",
      signed(base(), "ES256", KID_EVIL, keys["EVIL"], sig_edit=lambda s: s[:10] + bytes([s[10] ^ 1]) + s[11:]))
    w("neg_order_signature_before_settlement.json",
      {"format": "jws", "signature": f"{h_ok}.{b64url(tampered)}.{s_ok}"})

    # ---- §5.7 / §5.8 settlement ----
    w("neg_settlement_transaction_mismatch.json", signed(base(transaction="0x" + "cd" * 32)))
    w("neg_settlement_ref_mismatch.json", signed(_sol_payload(settlementRef=COMMITMENT_ID_2)))
    w("neg_settlement_network_mismatch.json", signed(base(network="eip155:1")))
    w("neg_settlement_payer_mismatch.json", signed(base(payer=_OTHER_ADDR)))
    w("neg_settlement_uncorroborated_transaction.json", signed(_sol_payload(transaction=SOL_TX)))
    # the upstream #3824 shape: the settlement has the hash, the signed receipt lost it
    w("neg_settlement_dropped_transaction.json", signed(_sol_payload()))
    w("neg_order_success_before_binding.json", signed(base(transaction="0x" + "cd" * 32)))
    w("neg_order_settlement_before_requirements.json",
      signed(base(transaction="0x" + "cd" * 32, requirementsDigest="sha256:" + "00" * 32)))

    # ---- §5.9 payment requirements ----
    w("neg_requirements_amount_changed.json",
      signed(base(requirementsDigest=requirements_digest(dict(ACCEPTED, amount="1")))))
    w("neg_requirements_payto_mismatch.json", signed(base(payTo=_OTHER_ADDR)))
    # the digest matches what the verifier holds; only the network differs
    w("neg_requirements_network_mismatch.json",
      signed(base(requirementsDigest=requirements_digest(ACCEPTED_OTHER_NETWORK))))
    w("neg_order_requirements_before_freshness.json",
      signed(base(requirementsDigest="sha256:" + "00" * 32, issuedAt=ISSUED_AT - 10_000)))

    # ---- §5.10 freshness ----
    w("neg_freshness_stale.json", signed(base(issuedAt=ISSUED_AT - 10_000)))
    w("neg_freshness_future_archival.json", signed(base(issuedAt=ISSUED_AT + 181 * 86400)))

    # ---- configuration outside the contract: the receipt is the valid positive ----
    for k in C_ERR:
        w(f"err_config_{k}.json", signed(base()))
    w("err_config_context_null.json", signed(base()))

    (VECTORS / "keys.json").write_text(json.dumps(registry, indent=2) + "\n")

    entries = []
    for fname, expect, reason, ckey in SUITE:
        entry = {"file": fname, "expect": expect, "reason": reason, "context": ckey}
        if expect == PASS:
            receipt = json.loads((VECTORS / fname).read_text())
            _, _, report = verify_detailed(receipt, context_from_json(CONTEXTS[ckey]), registry)
            entry["report"] = report
        entries.append(entry)
    manifest = {
        "profile": "action-receipt", "version": PROFILE_VERSION, "specDraft": "0.4",
        "note": ("Expected results for the action-receipt conformance vectors. A conformant "
                 "verifier loads keys.json, each vector and the named context, and MUST "
                 "reproduce the verdict, the reason on REJECT (and on ERROR), and the report "
                 "on PASS. keys.json is a test fixture standing in for authorization and key "
                 "resolution. vectorsDigest is the sha256 over the JCS form of "
                 "{file name: sha256 hex of the file} for every vector file and keys.json."),
        "vectorsDigest": vectors_digest(VECTORS),
        "indeterminateReasons": sorted(INDETERMINATE_REASONS),
        "contexts": CONTEXTS,
        "vectors": entries,
        "distinctReceiptRef": [{"a": a, "b": b, "why": why} for a, b, why in DISTINCT],
        "sameReceiptRef": [{"files": files, "why": why} for files, why in SAME],
    }
    (VECTORS / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    write_vectors_md(manifest)


def vectors_digest(vdir: Path) -> str:
    """sha256 over the JCS form of {name: sha256 hex} for every vector file and
    keys.json (everything in vectors/ except MANIFEST.json). conformance/trace.py
    recomputes it from the files."""
    file_digests = {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                    for f in sorted(vdir.glob("*.json")) if f.name != "MANIFEST.json"}
    return sha256_tag(_canon(file_digests).encode())


def write_vectors_md(manifest) -> None:
    """VECTORS.md is generated from the same tables the suite runs, so the prose
    index cannot drift from the code."""
    n_pos = sum(1 for v in manifest["vectors"] if v["expect"] == PASS)
    n_err = sum(1 for v in manifest["vectors"] if v["expect"] == ERROR)
    n_neg = len(manifest["vectors"]) - n_pos - n_err
    n_order = sum(1 for v in manifest["vectors"] if v["file"].startswith("neg_order_"))
    lines = [
        "# Conformance vectors",
        "",
        "Generated by `python3 action_receipt.py --regenerate`. Do not edit by hand.",
        "",
        f"- {len(manifest['vectors'])} vectors: {n_pos} positive, {n_neg} negative, "
        f"{n_err} configuration (`ERROR`).",
        f"- {len(ALL_REASONS)} reject reason codes, every one exercised.",
        f"- Vector set digest: `{manifest['vectorsDigest']}` (cite this when claiming conformance).",
        "- Every single-fault negative is one mutation of a canonical positive. Its reason is",
        "  the code of the first check that mutation fails under the order of spec §5.",
        f"- {n_order} `neg_order_*` vectors carry two faults in adjacent steps on purpose; the",
        "  earlier step's code is expected, so a verifier that swaps the steps fails them.",
        "- `err_config_*` vectors give the verifier a configuration outside the contract of",
        "  spec §5 (mode, clock, maximum age, paid resource URL); the expected verdict is",
        "  `ERROR` with reason `invalid_configuration`, whatever the receipt.",
        "- Every positive's report is declared by hand in the suite (`EXPECT_REPORT`) and",
        "  compared in full; the manifest publishes the same report.",
        "- `keys.json` is a test fixture standing in for authorization and key resolution.",
        "- ECDSA signatures are deterministic (RFC 6979): `--regenerate` reproduces the files.",
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
        C_BATCH: "Solana batch-settlement commitment: settlement reference only, no payer",
        C_BOTH: "Solana settlement carrying both a transaction and a settlement reference",
        C_NOREQ: "accepted requirements NOT held",
        C_CASE: "response `payer` in checksum case, `transaction` in upper-case hex",
        C_NOPAYER: "response carries no `payer`",
        C_ARCHIVAL: "archival mode, 180 days after issue",
        C_ADVERT: "the echoed extension `info` is also held",
        C_REQ_FLOAT: "accepted requirements spell an integer as `60.0`",
        C_REQ_NONOBJ: "what is held as accepted requirements is not a JSON object",
        C_PAYER_EMPTY: "response `payer` is the empty string",
        C_REQ_NET: "response `network` is not a network identifier; accepted requirements name another network",
        C_ADVERT_NONSTRING: "the advertised `info` held has a `scope` that is not a string",
        C_ADVERT_FLOAT: "the advertised `info` held contains `1.5`, outside the value domain",
        C_PAID: "the verifier made the payment and paid for this resource",
        C_PAID_OTHER: "the verifier made the payment and paid for a different resource",
        C_DEFAULT_AGE: "session mode with NO `maxAgeSeconds`: the default 3600 applies",
        C_MAX_AGE_100: "session mode, `maxAgeSeconds` 100",
        C_LOOSE: "only a successful transaction; no network, payer or requirements held",
        C_LOOKALIKE: "network `eip1559:1` (not `eip155:`) with free-form identifiers",
        C_CF: "network `cloudflare:402`, no payer",
        C_EVM_REF_UPPER: "eip155 settlement with a transaction; the response's settlement reference in upper case",
        C_EVM_REF_MIXED: "eip155 settlement with a transaction and a mixed-case settlement reference",
        C_BATCH_ONLY_TX: "Solana settlement with a transaction and no settlement reference",
        C_REQ_UTF16: "accepted requirements whose member names sort differently by UTF-16 and by code point",
        C_ABSENT_FORMS: "response `transaction` is a number, `payer` has an unpaired surrogate, `network` null",
        C_JUNK: "response `payer` an object, `network` a number, requirements a string, advertised info an array",
        C_NO_ID: "`success: true` with neither a transaction nor a settlement reference",
        C_SUCCESS_FALSE: "`success: false`, though the response names the transaction",
        C_SUCCESS_STRING: "`success` is the string `\"true\"`, not the boolean",
        C_PAID_EMPTY: "the verifier paid, and the URL it gives is the empty string",
        C_ARCHIVAL_END: "archival mode, clock at 2^53 - 1",
        C_NOW_FLOAT: "clock given as the integer-valued JSON number `1703123500.0`",
        C_RESP_NET_OTHER_FORM: "response `network` is `Base Mainnet`, not a network identifier",
        C_NOPAYER_EVM: "response carries no `payer` (member absent)",
        C_NULL: "the context is `null`: configuration outside the contract",
    }
    for k in C_ERR:
        notes["config_" + k] = f"configuration outside the contract: {k.replace('_', ' ')}"
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
        verdict, reason, _ = verify_detailed(receipt, context_from_json(CONTEXTS[C_OK]), registry)
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
    published = {v["file"]: v for v in manifest["vectors"]}
    print(f"crypto={HAVE_CRYPTO}  rfc8785_crosscheck={HAVE_RFC8785}"
          + ("  (every canonicalization cross-checked)" if HAVE_RFC8785
             else "  (NOT cross-checked: install rfc8785 for an independent canonicalizer)"))
    print("-" * 104)
    failures, observed, covered, refs = 0, set(), set(), {}
    for fname, _, _, _ in SUITE:
        if fname.startswith("pos_"):
            try:
                refs[fname] = sha256_tag(decode_payload(json.loads((VECTORS / fname).read_text()))[0])
            except (OSError, ValueError, KeyError, IndexError):
                pass
    for fname, expect, reason, ckey in SUITE:
        receipt = json.loads((VECTORS / fname).read_text())
        got, got_reason, report = verify_detailed(receipt, context_from_json(CONTEXTS[ckey]), registry)
        observed.add(got)
        if got == REJECT:
            covered.add(got_reason)
        ok = got == expect and got_reason == reason
        pub = published.get(fname)
        if pub is None or (pub["expect"], pub["reason"], pub["context"]) != (expect, reason, ckey):
            ok, got_reason = False, "MANIFEST entry differs from the suite table"
        elif pub.get("context") and manifest["contexts"].get(ckey, "<missing>") != CONTEXTS[ckey]:
            ok, got_reason = False, "MANIFEST context differs from the suite table"
        if ok and expect == PASS:
            if report["receiptRef"] != refs.get(fname):
                ok, got_reason = False, "receiptRef is not the hash of the payload segment"
            elif report != pub.get("report"):
                ok, got_reason = False, "report differs from MANIFEST"
            else:
                declared = report_mismatches(report, expected_report(fname, refs))
                if declared:
                    ok, got_reason = False, "; ".join(declared)
        failures += not ok
        print(f"[{' ok ' if ok else 'FAIL'}] {fname:52s} want {expect:6s}/{str(reason):44s} "
              f"got {got:6s}/{got_reason}")
    print("-" * 104)
    structural = []
    if not {PASS, REJECT} <= observed:
        structural.append(f"verifier did not produce both PASS and REJECT (saw {sorted(observed)})")
    if ALL_REASONS - covered:
        structural.append(f"reason codes never exercised: {sorted(ALL_REASONS - covered)}")
    if covered - ALL_REASONS:
        structural.append(f"verifier emitted undeclared codes: {sorted(covered - ALL_REASONS)}")
    listed = {f for f, _, _, _ in SUITE}
    if len(listed) != len(SUITE):
        structural.append("a file is listed twice in the suite table")
    on_disk = {f.name for f in VECTORS.glob("*.json")} - {"keys.json", "MANIFEST.json"}
    if listed != on_disk:
        structural.append(f"suite and vectors/ differ: {sorted(listed ^ on_disk)}")
    if set(published) != listed:
        structural.append(f"suite and MANIFEST differ: {sorted(set(published) ^ listed)}")
    if manifest.get("vectorsDigest") != vectors_digest(VECTORS):
        structural.append("MANIFEST vectorsDigest does not describe the files in vectors/")
    for fname, expect, _, _ in SUITE:
        if expect == PASS and fname not in EXPECT_REPORT and fname not in _DEFAULT_REPORT_OK:
            structural.append(f"{fname}: positive without a hand-declared report")
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
    n_pos = sum(1 for _, e, _, _ in SUITE if e == PASS)
    n_err = sum(1 for _, e, _, _ in SUITE if e == ERROR)
    print(f"all {len(SUITE)} pass ({n_pos} positive, {len(SUITE) - n_pos - n_err} negative, "
          f"{n_err} configuration); all {len(ALL_REASONS)} reason codes exercised; "
          f"every report declared by hand; {len(MUTATIONS)}-member mutation matrix holds; "
          f"receiptRef relations hold; vectorsDigest matches the files"
          + ("; spec and code agree on reason codes" if spec_codes is not None else ""))
    return 0


# Positives whose report is exactly the default (declared here, so a positive
# with no entry at all is a suite error rather than a silent default).
_DEFAULT_REPORT_OK = {
    "pos_es256_valid.json", "pos_es256k_valid.json", "pos_eddsa_valid.json",
    "pos_payto_signer.json", "pos_non_ascii_nfc.json", "pos_non_ascii_nfd.json",
    "pos_response_casing.json", "pos_requirements_float_spelling.json",
    "pos_envelope_extra_member.json", "pos_compact_at_size_limit.json",
    "pos_network_lookalike_not_evm.json", "pos_receiptid_22.json", "pos_receiptid_64.json",
    "pos_settlement_ref_evm_exact_case.json", "pos_requirements_utf16_order.json",
    "pos_authorization_marker_not_true.json", "pos_config_clock_integer_float.json",
}


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
                                              context_from_json(CONTEXTS[C_OK]), registry)
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
        verdict, reason, report = verify_detailed(receipt, context_from_json(CONTEXTS[C_OK]), registry)
        print(f"{verdict}  {reason or ''}")
        if report:
            print(json.dumps(report, indent=2))
        return 0 if verdict == PASS else 1
    return run_suite(regenerate=a.regenerate)


if __name__ == "__main__":
    sys.exit(main())
