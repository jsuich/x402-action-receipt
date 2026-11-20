#!/usr/bin/env python3
"""
fuzz.py — differential and metamorphic fuzzing of action-receipt verifiers.

Generates receipts and verification contexts by applying mutation operators to
valid ones, runs every case through two or more verifier adapters (ADAPTER
PROTOCOL in CONFORMANCE.md), and reports:

  * DISAGREEMENTS  two verifiers returned a different verdict, reason or report
                   for the same input. One of them, or the spec, is wrong.
  * PROPERTY VIOLATIONS  a result broke an invariant that needs no oracle:
        P1  PASS  =>  report.receiptRef == sha256(payload segment bytes)
        P2  PASS  =>  payload bytes re-serialize to themselves (independent JCS)
        P3  PASS with requirements held  =>  PASS without them, same receiptRef
        P4  PASS in session mode  =>  PASS in archival mode
        P5  PASS  =>  the same receipt with one payload bit flipped never passes
        P6  every reason is a declared code, and ERROR never occurs

    python3 conformance/fuzz.py --seed 1 --n 2000
    python3 conformance/fuzz.py --seed 1 --n 2000 --save out/   # write disagreeing cases

Exit 0 iff there are no disagreements and no property violations.
Deterministic for a given (seed, n): ECDSA signatures are derandomized here.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import pathlib
import random
import subprocess
import sys
from collections import Counter, defaultdict

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import action_receipt as A  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils  # noqa: E402

try:
    import rfc8785 as _rfc8785
except ImportError:
    _rfc8785 = None

ADAPTERS = {
    "python": [sys.executable, "-B", str(ROOT / "conformance/adapters/python_adapter.py")],
    "node": ["node", str(ROOT / "conformance/adapters/node_adapter.mjs")],
}
KEYS_FILE = ROOT / "vectors" / "keys.json"
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


# --- serialization that can emit what the strict canonicalizer refuses ------

def loose(v) -> str:
    """Canonical-looking JSON for ANY value, including floats and lone
    surrogates, so a mutated value can still be signed."""
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(loose(k) + ":" + loose(x) for k, x in items) + "}"
    if isinstance(v, list):
        return "[" + ",".join(loose(x) for x in v) + "]"
    raise TypeError(type(v))


def to_bytes(text: str) -> bytes:
    return text.encode("utf-8", "surrogatepass")


def sign(alg_of_key: str, key, signing_input: bytes, *, high_s=False) -> bytes:
    if alg_of_key in ("ES256", "ES256K"):
        try:
            algo = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
            der = key.sign(signing_input, algo)
        except Exception:  # noqa: BLE001 — backend without RFC 6979 support
            der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        n = A.CURVE_ORDER[A.ALG_CURVE[alg_of_key]]
        s = max(s, n - s) if high_s else min(s, n - s)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return key.sign(signing_input)


# --- a case -----------------------------------------------------------------

class Case:
    def __init__(self, rng: random.Random):
        _, keys = A._registry()
        self.rng = rng
        signer = rng.choice([("ES256", A.KID_ES256, "ES256"), ("ES256K", A.KID_ES256K, "ES256K"),
                             ("EdDSA", A.KID_ED, "EdDSA"), ("ES256", A.KID_PAYTO, "PAYTO")])
        self.alg, self.kid, key_name = signer
        self.key_alg, self.key = self.alg, keys[key_name]
        self.all_keys = keys
        batch = rng.random() < 0.3
        self.payload = A._base_payload(
            **({"transaction": "", "settlementRef": A.BATCH_REF} if batch else {}))
        self.header = {"alg": self.alg, "kid": self.kid, "typ": A.TYP}
        self.header_raw = None        # bytes override
        self.payload_raw = None       # bytes override
        self.high_s = False
        self.sig_edit = None          # callable(bytes) -> bytes
        self.compact_edit = None      # callable(str) -> str
        self.receipt_edit = None      # callable(dict) -> any JSON value
        self.context = {
            "success": True,
            "transaction": "" if batch else A.SETTLEMENT_TX,
            "settlementRef": A.BATCH_REF if batch else "",
            "network": A.NETWORK, "payer": A.PAYER,
            "accepted": copy.deepcopy(A.ACCEPTED), "advertisedInfo": None,
            "now": A.VERIFIER_NOW, "maxAgeSeconds": 3600, "mode": "session",
        }
        self.ops = []

    def payload_bytes(self) -> bytes:
        return self.payload_raw if self.payload_raw is not None else to_bytes(loose(self.payload))

    def build(self):
        header = self.header_raw if self.header_raw is not None else to_bytes(loose(self.header))
        h = A.b64url(header)
        p = A.b64url(self.payload_bytes())
        sig = sign(self.key_alg, self.key, f"{h}.{p}".encode(), high_s=self.high_s)
        if self.sig_edit:
            sig = self.sig_edit(sig)
        compact = f"{h}.{p}.{A.b64url(sig)}"
        if self.compact_edit:
            compact = self.compact_edit(compact)
        receipt = {"format": "jws", "signature": compact}
        if self.receipt_edit:
            receipt = self.receipt_edit(receipt)
        return receipt


# --- value pools ------------------------------------------------------------

JUNK = [None, True, False, 0, 1, -1, 2**53 - 1, 2**53, 1.5, 1e300, "", "x", [], {}, [1], {"a": 1}]
STRINGS = ["", "x", " ", "A", "é", "é", "\U0001d4b3", "\u0000", "\u007f", "\ud800",
           "\udc00\ud800", "a\"b", "a\\b", " ", "﻿", "kK", "x" * 300]
ADDRS = [A.PAYER, A.PAY_TO, A.PAYER_CHECKSUM, A.PAY_TO_CHECKSUM, A.PAYER.upper(),
         "0X" + A.PAYER[2:], A.PAYER[:-1], A.PAYER + "0", "0x" + "g" * 40, "0x" + "11" * 20,
         "857b06519e91e3a54538791bdbb0e22373e36b66"]
TXS = [A.SETTLEMENT_TX, "0x" + "AB" * 32, "0X" + "ab" * 32, "0x" + "ab" * 31, "0x" + "ab" * 33,
       "0x" + "cd" * 32, "", "ab" * 32]
NETWORKS = [A.NETWORK, "eip155:1", "EIP155:8453", "eip155:", ":8453", "eip155", "base",
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "a:b", "abc:" + "x" * 32, "abc:" + "x" * 33,
            "abcdefgh:1", "abcdefghi:1", "ab:1", "eip155:84 53", "cosmos:cosmoshub-4"]
DIGESTS = [A.requirements_digest(A.ACCEPTED), "sha256:" + "00" * 32, "sha256:" + "AB" * 32,
           "sha256:" + "0" * 63, "sha256:" + "0" * 65, "SHA256:" + "0" * 64, "sha512:" + "0" * 64,
           "0" * 64, ""]
RECEIPT_IDS = ["a" * 21, "a" * 22, "a" * 64, "a" * 65, "a" * 21 + "=", "a" * 21 + "+",
               "a" * 21 + "/", "a" * 21 + " ", "a" * 21 + "é", A.RECEIPT_ID_2]
BTYPES = ["a:b", "action-receipt:advertised-info", "response-provenance:responseHash",
          "https://example.org/x#y", "a" * 64 + ":b", "a" * 65 + ":b", "a:" + "b" * 191,
          "a:" + "b" * 192, "A:b", "1a:b", "a:", ":b", "ab", "a:b c", "a:bé", "a+b.c-d:e",
          "a::b", "z:z", "b:a"]
BVALUES = ["1", "x" * 1024, "x" * 1025, "", "a b", "café", "sha256:" + "0" * 64, "~", "\u007f"]


def pick_binding(rng):
    b = {"type": rng.choice(BTYPES), "value": rng.choice(BVALUES)}
    r = rng.random()
    if r < 0.06:
        b["extra"] = 1
    elif r < 0.10:
        del b["value"]
    elif r < 0.14:
        b["value"] = rng.choice(JUNK)
    elif r < 0.18:
        b["type"] = rng.choice(JUNK)
    return b


# --- mutation operators: each takes a Case and edits it ---------------------

def op_none(c): pass


def op_member_junk(c):
    target = c.rng.choice(["top", "action"])
    obj = c.payload if target == "top" else c.payload["action"]
    obj[c.rng.choice(sorted(obj))] = c.rng.choice(JUNK + STRINGS)


def op_member_delete(c):
    obj = c.rng.choice([c.payload, c.payload["action"]])
    del obj[c.rng.choice(sorted(obj))]


def op_member_add(c):
    obj = c.rng.choice([c.payload, c.payload["action"]])
    obj[c.rng.choice(["signature", "actionRef", "x", "__proto__", "constructor", "0", ""])] = \
        c.rng.choice(JUNK)


def op_free_string(c):
    k = c.rng.choice(["agent", "actionType", "scope"])
    c.payload["action"][k] = c.rng.choice(STRINGS)


def op_resource(c):
    c.payload["resourceUrl"] = c.rng.choice(
        [A.RESOURCE + "/", A.RESOURCE.upper(), A.RESOURCE + "?a=1", "", "https://other.example/x",
         A.RESOURCE.replace("https", "HTTPS"), A.RESOURCE + "#f"])


def op_enum(c):
    if c.rng.random() < 0.5:
        c.payload["action"]["outcome"] = c.rng.choice(
            sorted(A.OUTCOMES) + ["Delivered", "failed", "", " delivered", 1, None])
    else:
        c.payload["settlementStatus"] = c.rng.choice(
            sorted(A.SETTLEMENT_STATUSES) + ["Settled", "pending", "", "capturepending", 0, None])


def op_version(c): c.payload["version"] = c.rng.choice([0, 2, 99, -1, "1", True, None, 1.0, 2**53])
def op_issued_at(c):
    c.payload["issuedAt"] = c.rng.choice(
        [0, -1, 2**53 - 1, 2**53, A.ISSUED_AT + 1, A.VERIFIER_NOW + 60, A.VERIFIER_NOW + 61,
         A.VERIFIER_NOW - 3600, A.VERIFIER_NOW - 3601, str(A.ISSUED_AT), 1.5, None])


def op_receipt_id(c): c.payload["receiptId"] = c.rng.choice(RECEIPT_IDS)
def op_network(c): c.payload["network"] = c.rng.choice(NETWORKS)
def op_address(c): c.payload[c.rng.choice(["payer", "payTo"])] = c.rng.choice(ADDRS + ["", "x"])
def op_transaction(c): c.payload["transaction"] = c.rng.choice(TXS + ["x"])
def op_settlement_ref(c):
    c.payload["settlementRef"] = c.rng.choice([A.BATCH_REF, "", "batch:other", A.BATCH_REF.upper(), " "])


def op_digest(c):
    c.payload[c.rng.choice(["requirementsDigest", "supersedes"])] = c.rng.choice(DIGESTS)


def op_bindings(c):
    r = c.rng.random()
    if r < 0.15:
        c.payload["bindings"] = c.rng.choice([None, {}, "x", 0, [1], [[]], [None]])
        return
    n = c.rng.choice([1, 1, 2, 2, 3, 16, 17])
    items = [pick_binding(c.rng) for _ in range(n)]
    if n >= 16:
        items = [{"type": f"a:{i:02d}", "value": "1"} for i in range(n)]
    if c.rng.random() < 0.7:
        items.sort(key=lambda b: b["type"] if isinstance(b.get("type"), str) else "")
    c.payload["bindings"] = items


def op_bindings_wellformed(c):
    """Entries that each satisfy the grammar; only their order or uniqueness varies."""
    pool = ["a:one", "b:two", "c:three", "https://example.org/x#y", "z:z", "action-receipt:x"]
    items = [{"type": t, "value": "1"} for t in c.rng.sample(pool, c.rng.choice([2, 3, 4]))]
    r = c.rng.random()
    if r < 0.4:
        items.sort(key=lambda b: b["type"])
    elif r < 0.7:
        items.sort(key=lambda b: b["type"], reverse=True)
    elif r < 0.85:
        items.sort(key=lambda b: b["type"])
        items.insert(1, dict(items[0], value="2"))
    else:
        c.rng.shuffle(items)
    c.payload["bindings"] = items


def op_ctx_number_spelling(c):
    """The held requirements spell an integer as a float, or hold a non-integer."""
    c.context["accepted"]["maxTimeoutSeconds"] = c.rng.choice([60.0, 60.0, 60.5, 6e1, 1e21])


def op_binding_advertised(c):
    info = copy.deepcopy(A.ADVERTISED_INFO)
    r = c.rng.random()
    if r < 0.25:
        info["scope"] = "write:model-x"
    elif r < 0.4:
        info["extra"] = c.rng.choice([1, 1.5, "x", None, [1]])
    elif r < 0.5:
        del info["scope"]
    c.context["advertisedInfo"] = c.rng.choice([info, info, info, None, [], "x", 1])
    # usually commit to the info actually held, so the digest matches and the
    # scope / actionType equality rule is what decides the status
    value = A.sha256_tag(to_bytes(loose(info if c.rng.random() < 0.7 else A.ADVERTISED_INFO)))
    if c.rng.random() < 0.15:
        value = "sha256:" + "77" * 32
    if c.rng.random() < 0.3:
        c.payload["action"][c.rng.choice(["scope", "actionType"])] = "other"
    c.payload["bindings"] = [{"type": A.BT_ADVERTISED, "value": value}]


def _raw(c):
    return c.payload_bytes().decode("utf-8", "surrogatepass")


def op_raw_whitespace(c):
    t = _raw(c)
    spots = [i for i, ch in enumerate(t) if ch in ",:{}[]"]
    i = c.rng.choice(spots)
    c.payload_raw = to_bytes(t[:i + 1] + c.rng.choice([" ", "\n", "\t", "\r"]) + t[i + 1:])


def op_raw_number(c):
    t = _raw(c)
    src, alts = c.rng.choice([
        ('"version":1', ["1.0", "1e0", "1E0", "01", "+1", "1.", "0x1", "1.00", "10e-1", "true"]),
        (f'"issuedAt":{A.ISSUED_AT}',
         ["-0", "1703123456.0", "1.703123456E9", "1.703123456e9", "9007199254740993",
          "9007199254740992", "1e400", "-1e400", "NaN", "Infinity", "1703123456e0",
          "17031234560e-1", "0", "00"]),
    ])
    c.payload_raw = to_bytes(t.replace(src, src.split(":")[0] + ":" + c.rng.choice(alts), 1))


def op_raw_escape(c):
    t = _raw(c)
    sub = c.rng.choice([("read:model-x", "read:model-\\u0078"), ("read:model-x", "read:model-\\ud800"),
                        ("read:model-x", "read:model-\\udc00"), ("read:model-x", "read:model-\\ud835\\udcb3"),
                        ("read:model-x", "read\\u003amodel-x"), ("https://", "https:\\/\\/"),
                        ("read:model-x", "read:model-\\u00E9"), ("read:model-x", "read:model-\\u00e9"),
                        ("read:model-x", "read:model-\\x"), ("read:model-x", "read:model-\u0001"),
                        ('"scope"', '"sc\\u006fpe"'), ("read:model-x", "read:model-\\u0000")])
    c.payload_raw = to_bytes(t.replace(sub[0], sub[1], 1))


def op_raw_structure(c):
    t = _raw(c)
    r = c.rng.randrange(10)
    if r == 0:
        t = t.replace('"version":1', '"version":1,"version":1', 1)
    elif r == 1:
        t = t.replace('"version":1', '"version":2,"version":1', 1)
    elif r == 2:
        t = t + c.rng.choice(["\n", " ", "x", "{}", "\u0000"])
    elif r == 3:
        t = "﻿" + t
    elif r == 4:
        t = t[:c.rng.randrange(1, len(t))]
    elif r == 5:
        t = c.rng.choice(["[]", "1", '"x"', "null", "true", "", "{}", "[" * 9 + "]" * 9,
                          "[" * 8 + "]" * 8, '{"a":' * 8 + "1" + "}" * 8, '{"a":' * 9 + "1" + "}" * 9])
    elif r == 6:
        t = json.dumps(json.loads(c.payload_bytes()), separators=(",", ":"), ensure_ascii=False) \
            if c.payload_raw is None else t
    elif r == 7:
        t = t.replace('"bindings":[]', '"bindings":[ ]', 1)
    elif r == 8:
        t = json.dumps(c.payload, separators=(",", ":"), ensure_ascii=True, sort_keys=True) \
            if c.payload_raw is None else t
    else:
        t = "{" + t[1:-1] + ",}"
    c.payload_raw = to_bytes(t)


def op_raw_bytes(c):
    b = bytearray(c.payload_bytes())
    r = c.rng.randrange(3)
    if r == 0:
        b[c.rng.randrange(len(b))] = c.rng.choice([0xff, 0xc0, 0x80, 0x00, 0xed])
    elif r == 1:
        i = c.rng.randrange(len(b))
        b[i:i] = c.rng.choice([b"\xed\xa0\x80", b"\xc0\x80", b"\xf4\x90\x80\x80", b"\xef\xbb\xbf"])
    else:
        b = bytearray(b"\xef\xbb\xbf") + b
    c.payload_raw = bytes(b)


def op_header(c):
    h = c.header
    r = c.rng.randrange(12)
    if r == 0:
        del h[c.rng.choice(sorted(h))]
    elif r == 1:
        h[c.rng.choice(["crit", "b64", "jwk", "x5c", "__proto__", "cty"])] = c.rng.choice([["x"], False, 1, "x"])
    elif r == 2:
        h["typ"] = c.rng.choice(["JWT", "x402-action-receipt+JWS", "X402-ACTION-RECEIPT+JWS",
                                 "application/x402-action-receipt+jws", "", None, 1, [A.TYP]])
    elif r == 3:
        h["alg"] = c.rng.choice(["none", "es256", "HS256", "RS256", "ES384", "ES256 ", "", None, 5,
                                 "ES256", "ES256K", "EdDSA"])
    elif r == 4:
        h["kid"] = c.rng.choice([A.KID_ES256, A.KID_ES256K, A.KID_ED, A.KID_PAYTO, A.KID_ABSENT,
                                 A.KID_UNUSABLE, A.KID_EVIL, "did:web:nobody.example#x", "",
                                 "__service__:" + A.RESOURCE, 1, None, ["x"]])
    elif r == 5:
        c.header_raw = json.dumps(h, indent=1).encode()                    # non-canonical: allowed
    elif r == 6:
        c.header_raw = json.dumps(dict(reversed(list(h.items())))).encode()  # other order: allowed
    elif r == 7:
        c.header_raw = to_bytes('{"alg":"none",' + loose(h)[1:])              # duplicate alg, last wins
    elif r == 8:
        c.header_raw = c.rng.choice([b"[]", b"null", b'"x"', b"1", b"", b"{", b"\xff", b"{}",
                                     b"\xef\xbb\xbf" + to_bytes(loose(h))])
    elif r == 9:
        c.header_raw = to_bytes(loose(h)) + c.rng.choice([b" ", b"\n", b"x"])
    elif r == 10:
        c.header_raw = to_bytes(loose(h).replace('"typ"', '"t\\u0079p"'))     # escaped member name
    else:
        c.header_raw = to_bytes(loose(h).replace('"ES256"', '"ES\\u003256"')) if h["alg"] == "ES256" \
            else to_bytes(loose(h))


def op_alg_swap(c):
    """Header names another supported algorithm or another authorized key while
    the signing key stays: exercises the binding of key type and curve to alg."""
    if c.rng.random() < 0.6:
        c.header["alg"] = c.rng.choice(sorted(A.SUPPORTED_ALGS - {c.header["alg"]}))
    else:
        c.header["kid"] = c.rng.choice([k for k in (A.KID_ES256, A.KID_ES256K, A.KID_ED)
                                        if k != c.header["kid"]])


def op_header_encoding(c):
    text = loose(c.header)
    c.header_raw = c.rng.choice([b"\xef\xbb\xbf" + to_bytes(text), text.encode("utf-16"),
                                 text.encode("utf-16-le"), text.encode("utf-32"),
                                 b"\xff\xfe" + to_bytes(text)])


def op_payload_scalar(c):
    c.payload_raw = c.rng.choice([b"null", b"true", b"false", b"0", b"1", b'""', b"[]", b"{}",
                                  b'"x"', b"[null]", b"-1"])


def op_signature(c):
    r = c.rng.randrange(8)
    if r == 0:
        c.high_s = True
    elif r == 1:
        c.sig_edit = lambda s: s[:-1]
    elif r == 2:
        c.sig_edit = lambda s: s + b"\x00"
    elif r == 3:
        i = c.rng.randrange(64)
        c.sig_edit = lambda s: s[:i] + bytes([s[i] ^ 1]) + s[i + 1:]
    elif r == 4:
        c.sig_edit = lambda s: b"\x00" * len(s)
    elif r == 5:
        c.sig_edit = lambda s: b""
    elif r == 6:   # sign with a different key of the same family
        c.key = c.all_keys[c.rng.choice(["ES256", "ES256K", "EdDSA", "PAYTO", "EVIL"])]
        c.key_alg = {ec.SECP256R1: "ES256", ec.SECP256K1: "ES256K"}.get(
            type(getattr(c.key, "curve", None)), "EdDSA")
    else:          # DER-encoded ECDSA instead of r||s
        c.sig_edit = lambda s: asym_utils.encode_dss_signature(
            int.from_bytes(s[:32], "big") or 1, int.from_bytes(s[32:], "big") or 1) if len(s) == 64 else s


def op_compact(c):
    r = c.rng.randrange(9)
    seg = c.rng.randrange(3)

    def edit_segment(fn):
        def inner(compact):
            parts = compact.split(".")
            parts[seg] = fn(parts[seg])
            return ".".join(parts)
        return inner
    if r == 0:
        c.compact_edit = edit_segment(lambda s: s + "=" * (-len(s) % 4 or 4))
    elif r == 1:
        c.compact_edit = edit_segment(lambda s: s.replace("-", "+").replace("_", "/"))
    elif r == 2:   # set padding bits in the last character where the segment has any
        def bits(s):
            if len(s) % 4 == 0 or not s:
                return s
            i = B64.index(s[-1])
            return s[:-1] + B64[i | 1]
        c.compact_edit = edit_segment(bits)
    elif r == 3:
        c.compact_edit = edit_segment(lambda s: s[:len(s) // 2] + c.rng.choice([" ", "\n", "=", "*", "."]) + s[len(s) // 2:])
    elif r == 4:
        c.compact_edit = edit_segment(lambda s: "")
    elif r == 5:
        c.compact_edit = lambda s: s + c.rng.choice([".", ".x", " ", "\n"])
    elif r == 6:
        c.compact_edit = lambda s: s.rsplit(".", 1)[0]
    elif r == 7:
        c.compact_edit = edit_segment(lambda s: s + "A")
    else:
        c.compact_edit = edit_segment(lambda s: s[:-1])


def op_envelope(c):
    r = c.rng.randrange(8)
    if r == 0:
        c.receipt_edit = lambda rc: dict(rc, format=c.rng.choice(["JWS", "eip712", "", None, 1]))
    elif r == 1:
        c.receipt_edit = lambda rc: dict(rc, payload={"x": 1}, acceptIndex=0)
    elif r == 2:
        c.receipt_edit = lambda rc: dict(rc, signature=c.rng.choice([None, 1, ["a.b.c"], {"a": 1}, ""]))
    elif r == 3:
        c.receipt_edit = lambda rc: c.rng.choice([None, [], "x", 1, [rc], rc["signature"]])
    elif r == 4:
        c.receipt_edit = lambda rc: {"signature": rc["signature"]}
    elif r == 5:
        c.receipt_edit = lambda rc: {"format": "jws"}
    elif r == 6:
        c.receipt_edit = lambda rc: dict(rc, **{"__proto__": {"format": "jws"}})
    else:
        c.receipt_edit = lambda rc: {"format": ["jws"], "signature": rc["signature"]}


def op_ctx_settlement(c):
    x = c.context
    r = c.rng.randrange(9)
    if r == 0:
        x["success"] = c.rng.choice([False, None, "true", 1, 0, "false"])
    elif r == 1:
        x["transaction"] = c.rng.choice(TXS + [None])
    elif r == 2:
        x["settlementRef"] = c.rng.choice([A.BATCH_REF, "", None, "batch:other"])
    elif r == 3:
        x["network"] = c.rng.choice(NETWORKS + [None, 1])
    elif r == 4:
        x["payer"] = c.rng.choice(ADDRS + [None, ""])
    elif r == 5:
        del x[c.rng.choice(["transaction", "settlementRef", "network", "payer"])]
    elif r == 6:
        x["transaction"], x["settlementRef"] = A.SETTLEMENT_TX, A.BATCH_REF
    elif r == 7:
        x["transaction"], x["settlementRef"] = "", ""
    else:
        x["payer"], x["transaction"] = A.PAYER_CHECKSUM, "0x" + "AB" * 32


def op_ctx_requirements(c):
    acc = c.context["accepted"]
    r = c.rng.randrange(13)
    if r == 0:
        c.context["accepted"] = None
    elif r == 1:
        acc["amount"] = "1"
    elif r == 2:
        acc["payTo"] = c.rng.choice(ADDRS + [None, 1])
    elif r == 3:
        acc["network"] = c.rng.choice(NETWORKS + [None])
    elif r == 4:
        del acc[c.rng.choice(["payTo", "network", "extra", "amount"])]
    elif r == 5:
        acc["maxTimeoutSeconds"] = c.rng.choice([60.0, 60.5, 1e21, 2**53, -1, 0, "60"])
    elif r == 6:
        acc["extra"] = c.rng.choice([None, {}, {"a": [1, {"b": None}]}, {"n": 1.5}, {"n": True},
                                     {"é": "x", "é": "y"}, {"z": 1, "a": 2, "A": 3}])
    elif r == 7:
        c.context["accepted"] = c.rng.choice([[], "x", 1, {}, True])
    elif r == 8:
        acc["extra"] = {"deep": [[[[[[[1]]]]]]]}
    elif r == 9:
        acc["extra"] = {"deep": [[[[[[1]]]]]]}
    elif r == 10:
        acc["extra"] = {"s": c.rng.choice(STRINGS)}
    elif r == 11:
        acc[c.rng.choice(STRINGS)] = "x"
    else:
        # the receipt commits to exactly what the verifier holds: must still pass
        c.payload["requirementsDigest"] = A.sha256_tag(to_bytes(loose(acc)))


def op_ctx_requirements_network(c):
    """The receipt commits to exactly the requirements held, the response's
    network cannot be compared, and the requirements name another network (or
    payTo): only the §5.9 equality rules can catch it."""
    acc = c.context["accepted"]
    if c.rng.random() < 0.6:
        acc["network"] = c.rng.choice(["eip155:1", "eip155:84532", "solana:mainnet"])
    else:
        acc["payTo"] = "0x" + "11" * 20
    c.payload["requirementsDigest"] = A.sha256_tag(to_bytes(loose(acc)))
    if c.rng.random() < 0.7:
        c.context["network"] = c.rng.choice(["base", None, "Base Mainnet"])


def op_ctx_paid_resource(c):
    c.context["paidResourceUrl"] = c.rng.choice(
        [A.RESOURCE, A.RESOURCE, A.RESOURCE + "/", A.RESOURCE.upper(), "", None, 1,
         "https://api.example.com/v1/other"])


def op_ctx_time(c):
    x = c.context
    r = c.rng.randrange(6)
    if r == 0:
        x["mode"] = "archival"
    elif r == 1:
        x["now"] = c.rng.choice([A.ISSUED_AT - 61, A.ISSUED_AT - 60, A.ISSUED_AT, A.ISSUED_AT + 3600,
                                 A.ISSUED_AT + 3601, A.ISSUED_AT + 10**9])
    elif r == 2:
        x["maxAgeSeconds"] = c.rng.choice([0, 1, 43, 44, 45, 10**9])
    elif r == 3:
        x["mode"], x["now"] = "archival", A.ISSUED_AT + 10**9
    elif r == 4:
        x["mode"], x["now"] = "archival", c.rng.choice([A.ISSUED_AT - 61, A.ISSUED_AT - 60])
    else:
        del x["maxAgeSeconds"]


OPERATORS = [
    (op_none, 4), (op_member_junk, 6), (op_member_delete, 3), (op_member_add, 3),
    (op_free_string, 4), (op_resource, 2), (op_enum, 3), (op_version, 2), (op_issued_at, 3),
    (op_receipt_id, 2), (op_network, 4), (op_address, 4), (op_transaction, 3),
    (op_settlement_ref, 2), (op_digest, 3), (op_bindings, 6), (op_binding_advertised, 3),
    (op_raw_whitespace, 2), (op_raw_number, 4), (op_raw_escape, 4), (op_raw_structure, 4),
    (op_raw_bytes, 3), (op_header, 7), (op_signature, 4), (op_compact, 5), (op_envelope, 4),
    (op_ctx_settlement, 6), (op_ctx_requirements, 7), (op_ctx_time, 4),
    (op_alg_swap, 3), (op_header_encoding, 2), (op_payload_scalar, 2),
    (op_bindings_wellformed, 3), (op_ctx_number_spelling, 2),
    (op_ctx_requirements_network, 2), (op_ctx_paid_resource, 3),
]
RAW_OPS = {op_raw_whitespace, op_raw_number, op_raw_escape, op_raw_structure, op_raw_bytes,
           op_payload_scalar}


def generate(seed: int, n: int):
    rng = random.Random(seed)
    ops, weights = zip(*OPERATORS)
    cases = []
    for i in range(n):
        c = Case(rng)
        chosen = rng.choices(ops, weights, k=rng.choice([1, 1, 1, 2, 2, 3]))
        # value-level edits first, raw-text edits after, so raw edits see the final value
        chosen.sort(key=lambda o: o in RAW_OPS)
        for op in chosen:
            try:
                op(c)
                c.ops.append(op.__name__[3:])
            except (KeyError, ValueError, TypeError, IndexError, AttributeError, UnicodeError):
                c.ops.append(op.__name__[3:] + "!skipped")
        try:
            receipt = c.build()
        except (KeyError, ValueError, TypeError, AttributeError, UnicodeError):
            continue
        cases.append({"id": f"{seed}:{i}:{'+'.join(c.ops)}", "receipt": receipt, "context": c.context})
    return cases


# --- running adapters -------------------------------------------------------

def run_adapter(name: str, cases: list) -> dict:
    data = "\n".join(json.dumps(c) for c in cases) + "\n"
    r = subprocess.run(ADAPTERS[name] + [str(KEYS_FILE)], input=data.encode(), capture_output=True)
    if r.returncode != 0:
        sys.exit(f"adapter {name} failed (exit {r.returncode}):\n{r.stderr.decode()[-2000:]}")
    out = {}
    for line in r.stdout.decode().split("\n"):
        if line.strip():
            o = json.loads(line)
            out[o["id"]] = (o["verdict"], o["reason"], o["report"])
    if set(out) != {c["id"] for c in cases}:
        sys.exit(f"adapter {name} returned {len(out)} results for {len(cases)} cases")
    return out


def payload_bytes_of(receipt):
    try:
        seg = receipt["signature"].split(".")[1]
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except Exception:  # noqa: BLE001
        return None


def derived_cases(case, result):
    """Follow-up cases for the metamorphic properties of a PASSing case."""
    out = []
    ctx = case["context"]
    if ctx.get("accepted") is not None:
        out.append(("P3", dict(case, id=case["id"] + "#noreq", context=dict(ctx, accepted=None))))
    if ctx.get("mode") == "session":
        out.append(("P4", dict(case, id=case["id"] + "#archival", context=dict(ctx, mode="archival"))))
    raw = payload_bytes_of(case["receipt"])
    if raw:
        h = int(hashlib.sha256(case["id"].encode()).hexdigest(), 16)
        b = bytearray(raw)
        b[h % len(b)] ^= 1 << (h // len(b) % 8)
        parts = case["receipt"]["signature"].split(".")
        parts[1] = A.b64url(bytes(b))
        out.append(("P5", dict(case, id=case["id"] + "#bitflip",
                               receipt=dict(case["receipt"], signature=".".join(parts)))))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--adapters", default="python,node")
    ap.add_argument("--save", metavar="DIR", help="write disagreeing and violating cases here")
    ap.add_argument("--json", action="store_true", help="print the summary as one JSON object")
    a = ap.parse_args(argv)
    names = a.adapters.split(",")

    cases = generate(a.seed, a.n)
    by_id = {c["id"]: c for c in cases}
    results = {n: run_adapter(n, cases) for n in names}
    ref = results[names[0]]

    followups, origin = [], {}
    for c in cases:
        if ref[c["id"]][0] == A.PASS:
            for prop, d in derived_cases(c, ref[c["id"]]):
                followups.append(d)
                origin[d["id"]] = (prop, c["id"])
    by_id.update({c["id"]: c for c in followups})
    if followups:
        for n in names:
            results[n].update(run_adapter(n, followups))

    disagreements = [cid for cid in by_id
                     if len({json.dumps(results[n][cid], sort_keys=True) for n in names}) > 1]

    violations = []
    for cid, (verdict, reason, report) in ref.items():
        if verdict == A.ERROR or (verdict == A.REJECT and reason not in A.ALL_REASONS):
            violations.append(("P6", cid, f"{verdict}/{reason}"))
        if verdict == A.PASS and cid not in origin:
            raw = payload_bytes_of(by_id[cid]["receipt"])
            if report["receiptRef"] != "sha256:" + hashlib.sha256(raw).hexdigest():
                violations.append(("P1", cid, "receiptRef is not the hash of the payload bytes"))
            if _rfc8785 is not None:
                try:
                    if _rfc8785.dumps(json.loads(raw)) != raw:
                        violations.append(("P2", cid, "payload bytes are not their own JCS form"))
                except Exception as e:  # noqa: BLE001
                    violations.append(("P2", cid, f"independent canonicalizer refused: {e}"))
    for did, (prop, parent) in origin.items():
        verdict, reason, report = ref[did]
        if prop in ("P3", "P4") and (verdict != A.PASS
                                     or report["receiptRef"] != ref[parent][2]["receiptRef"]):
            violations.append((prop, did, f"{verdict}/{reason}"))
        if prop == "P5" and verdict == A.PASS:
            violations.append((prop, did, "a receipt with a flipped payload bit passed"))

    verdicts = Counter(v for v, _, _ in (ref[c["id"]] for c in cases))
    reasons = Counter(r for v, r, _ in (ref[c["id"]] for c in cases) if v == A.REJECT)
    op_seen = Counter(o for c in cases for o in c["id"].split(":", 2)[2].split("+"))
    summary = {
        "seed": a.seed, "requested": a.n, "generated": len(cases), "followups": len(followups),
        "adapters": names, "p2_independent_canonicalizer": _rfc8785 is not None,
        "verdicts": dict(verdicts), "reasons_hit": len(reasons),
        "reasons_never_hit": sorted(A.ALL_REASONS - set(reasons)),
        "operators_never_applied": sorted(o.__name__[3:] for o, _ in OPERATORS
                                          if op_seen[o.__name__[3:]] == 0),
        "disagreements": len(disagreements), "property_violations": len(violations),
    }
    if a.json:
        print(json.dumps(summary))
    else:
        print(f"seed {a.seed}: {len(cases)} cases + {len(followups)} follow-ups through "
              f"{', '.join(names)}")
        print(f"  verdicts ({names[0]}): {dict(verdicts)}")
        print(f"  reason codes hit: {len(reasons)} of {len(A.ALL_REASONS)}"
              + (f"; never hit: {summary['reasons_never_hit']}" if summary["reasons_never_hit"] else ""))
        print(f"  P2 independent canonicalizer: {'active' if _rfc8785 else 'NOT ACTIVE (install rfc8785)'}")
        print(f"  disagreements: {len(disagreements)}   property violations: {len(violations)}")

    if disagreements and not a.json:
        groups = defaultdict(list)
        for cid in disagreements:
            key = " | ".join(f"{n}={results[n][cid][0]}/{results[n][cid][1]}" for n in names)
            groups[key].append(cid)
        print("\nDISAGREEMENTS by result pair:")
        for key, ids in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            ops = Counter(o for i in ids for o in i.split("#")[0].split(":", 2)[2].split("+"))
            print(f"  {len(ids):5d}  {key}")
            print(f"         operators: {dict(ops.most_common(4))}   e.g. {ids[0]}")
    if violations and not a.json:
        print("\nPROPERTY VIOLATIONS:")
        for prop, cid, why in violations[:20]:
            print(f"  {prop}  {cid}  {why}")
    if a.save and (disagreements or violations):
        d = pathlib.Path(a.save)
        d.mkdir(parents=True, exist_ok=True)
        keep = disagreements + [cid for _, cid, _ in violations]
        with open(d / f"seed{a.seed}.jsonl", "w") as f:
            for cid in dict.fromkeys(keep):
                f.write(json.dumps({"case": by_id[cid],
                                    "results": {n: results[n][cid] for n in names}}) + "\n")
        print(f"\nsaved {len(set(keep))} cases to {d / f'seed{a.seed}.jsonl'}")
    return 0 if not disagreements and not violations else 1


if __name__ == "__main__":
    sys.exit(main())
