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
        P6  every REJECT reason is a declared code, and ERROR occurs ONLY when
            the configuration is outside the contract of spec §5
        P7  configuration outside the contract  =>  ERROR invalid_configuration,
            whatever the receipt (the contract is re-stated here, independently
            of both verifiers, in `config_valid`)
      and one oracle, restated from the spec in `expected_charged_amount`:
        P8  PASS  =>  checks.chargedAmount is `compared` exactly when the context
            holds an in-domain `accepted` object with a string `scheme`, and then
            the receipt's chargedAmount is the value the §4.3 table names, or ""
    Every property is evaluated on EVERY implementation's results, not only
    the first adapter's.

    python3 conformance/fuzz.py --seed 1 --n 2000
    python3 conformance/fuzz.py --seed 1 --n 2000 --save out/   # write disagreeing cases
    python3 conformance/fuzz.py --adapter mine="python3 my_adapter.py"   # a third-party verifier

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
import shlex
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
CONFIG_ERROR = "invalid_configuration"


def config_valid(ctx) -> bool:
    """The configuration contract of spec §5, restated from the spec text for
    this harness (not imported from either verifier): mode exactly `session` or
    `archival`; `now` an integer; `maxAgeSeconds` absent or an integer >= 0;
    `paidResourceUrl` absent, null or a string. Integers are judged by value in
    the I-JSON safe range, as JSON numbers reach both verifiers."""
    if not isinstance(ctx, dict):
        return False

    def integer(v):
        if isinstance(v, bool):
            return False
        if isinstance(v, int):
            return abs(v) <= 2**53 - 1
        return isinstance(v, float) and v == v and v not in (float("inf"), float("-inf")) \
            and v.is_integer() and abs(v) <= 2**53 - 1
    if ctx.get("mode") not in ("session", "archival") or not isinstance(ctx.get("mode"), str):
        return False
    if "now" not in ctx or not integer(ctx["now"]):
        return False
    if "maxAgeSeconds" in ctx and not (integer(ctx["maxAgeSeconds"]) and ctx["maxAgeSeconds"] >= 0):
        return False
    paid = ctx.get("paidResourceUrl")
    return paid is None or isinstance(paid, str)
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
        # RFC 6979; no fallback to random k, so a run is reproducible from (seed, n)
        der = key.sign(signing_input, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
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
        shape = rng.random()
        batch = shape < 0.3
        sol = shape < 0.15          # half the batch cases are the 0.4 Solana commitment
        if sol:
            self.payload = A._sol_payload()
        else:
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
            "settlementRef": (A.COMMITMENT_ID if sol else A.BATCH_REF) if batch else "",
            "network": A.SOL_NET if sol else A.NETWORK, "payer": None if sol else A.PAYER,
            "accepted": copy.deepcopy(A.ACCEPTED_SOL if sol else A.ACCEPTED), "advertisedInfo": None,
            "now": A.VERIFIER_NOW, "maxAgeSeconds": 3600, "mode": "session",
        }
        # where the response reports the charge depends on the scheme (spec §4.3)
        if sol:
            self.context["extra"] = {"chargedAmount": A.CHARGED}
        else:
            self.context["amount"] = A.CHARGED
        if rng.random() < 0.2:
            del self.context["maxAgeSeconds"]      # the default applies
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
            "abcdefgh:1", "abcdefghi:1", "ab:1", "abc:1", "eip155:84 53", "cosmos:cosmoshub-4",
            "a" * 32 + ":1", "a" * 33 + ":1", "cloudflare:402", "eip1559:1", "eip155x:1",
            "eip155:8453\n"]
DIGESTS = [A.requirements_digest(A.ACCEPTED), "sha256:" + "00" * 32, "sha256:" + "AB" * 32,
           "sha256:" + "0" * 63, "sha256:" + "0" * 65, "SHA256:" + "0" * 64, "sha512:" + "0" * 64,
           "0" * 64, ""]
RECEIPT_IDS = ["a" * 21, "a" * 22, "a" * 64, "a" * 65, "a" * 21 + "=", "a" * 21 + "+",
               "a" * 21 + "/", "a" * 21 + " ", "a" * 21 + "é", A.RECEIPT_ID_2]
BTYPES = ["a:b", "action-receipt:advertised-info", "action-receipt:reversal-transaction",
          "action-receipt:x", "action-receipt.v2:x", "response-provenance:responseHash",
          "https://example.org/x#y", "a" * 64 + ":b", "a" * 65 + ":b", "a:" + "b" * 191,
          "a:" + "b" * 192, "A:b", "1a:b", "a:", ":b", "ab", "a:b c", "a:bé", "a+b.c-d:e",
          "a::b", "z:z", "b:a"]
BVALUES = ["1", "x" * 1024, "x" * 1025, "", "a b", "café", "sha256:" + "0" * 64, "~", "\u007f",
           "sha256:" + "AB" * 32, "0x" + "ef" * 32, "0x" + "EF" * 32]


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
            sorted(A.OUTCOMES) + ["Delivered", "refused", "disputed", "", " delivered", 1, None])
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
    c.payload["settlementRef"] = c.rng.choice([A.BATCH_REF, "", "batch:other", A.BATCH_REF.upper(), " ",
                                               A.COMMITMENT_ID, A.COMMITMENT_ID.lower()])


# charged amounts on both sides of every rule of spec §4.6 and §5.8
AMOUNTS = ["", "0", "00", "010", "1", A.CHARGED, "9999", "2500", "1e4", "-1", "+1", " 10000", "10000 ",
           "10000.0", "9" * 78, "1" + "0" * 78, "1" + "0" * 77, "\uff11", "0x10", "1_000"]


def op_charged_amount(c):
    """The signed `chargedAmount`: in and out of the grammar of spec §4.6."""
    c.payload["chargedAmount"] = c.rng.choice(AMOUNTS + [10000, None, 0])


def op_ctx_charged(c):
    """The response's `amount` and `extra.chargedAmount` (spec §4.3, §5.8): which
    one the scheme names, the present/absent reading and no normalization decide."""
    x = c.context
    r = c.rng.randrange(7)
    if r == 0:
        x["amount"] = c.rng.choice(AMOUNTS + [None, 10000, "\ud800", "25\udc00"])
    elif r == 1:
        x.pop("amount", None)
    elif r == 2:
        x["extra"] = {"chargedAmount": c.rng.choice(AMOUNTS + [None, 2500, "\ud800", "25\udc00"])}
    elif r == 3:
        x["extra"] = c.rng.choice([None, [], "2500", 1, {}, {"chargedamount": "2500"}, [{"chargedAmount": "2500"}]])
    elif r == 4:
        # the receipt carries what extra reports, the top-level amount says otherwise
        v = c.rng.choice(AMOUNTS)
        x["extra"] = {"chargedAmount": v, "commitmentId": A.COMMITMENT_ID}
        c.payload["chargedAmount"] = v if c.rng.random() < 0.8 else x.get("amount", "")
    elif r == 5:
        # the receipt and the response agree on a value, which may be out of grammar
        v = c.rng.choice(AMOUNTS)
        x["amount"] = v
        x.pop("extra", None)
        c.payload["chargedAmount"] = v
    else:
        # both locations carry a value; the receipt takes one of them, or neither
        a, e = c.rng.choice(AMOUNTS), c.rng.choice(AMOUNTS)
        x["amount"], x["extra"] = a, {"chargedAmount": e}
        c.payload["chargedAmount"] = c.rng.choice([a, e, ""])


# accepted.scheme values on both sides of the table of spec §4.3 (exact match only)
SCHEMES = ["exact", "upto", "batch-settlement", "auth-capture", "streaming", "Exact", "UPTO",
           "batch-Settlement", "batch_settlement", "exact ", "", 5, None, ["exact"], {"s": "exact"}]


def op_ctx_scheme(c):
    """The accepted scheme decides where the charged amount is (spec §4.3, §5.8),
    and whether it is compared at all. The receipt commits to the requirements
    held, so §5.9 does not decide; the receipt's value sits at one location."""
    acc = c.context.get("accepted")
    if not isinstance(acc, dict):
        acc = copy.deepcopy(A.ACCEPTED)
        c.context["accepted"] = acc
    s = c.rng.choice(SCHEMES + ["<absent>"])
    if s == "<absent>":
        acc.pop("scheme", None)
    else:
        acc["scheme"] = s
    c.payload["requirementsDigest"] = A.sha256_tag(to_bytes(loose(acc)))
    x, r = c.context, c.rng.random()
    v = c.rng.choice(AMOUNTS[:8])
    if r < 0.35:
        x["amount"] = v
        c.payload["chargedAmount"] = v
    elif r < 0.7:
        x["extra"] = {"chargedAmount": v}
        c.payload["chargedAmount"] = v
    elif r < 0.85:
        x["amount"], x["extra"] = v, {"chargedAmount": c.rng.choice(AMOUNTS[:8])}
        c.payload["chargedAmount"] = c.rng.choice([v, x["extra"]["chargedAmount"], ""])
    else:
        c.payload["chargedAmount"] = ""


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
        c.header_raw = json.dumps(h, indent=1).encode()                    # non-canonical: rejected (0.4)
    elif r == 6:
        c.header_raw = json.dumps(dict(reversed(list(h.items())))).encode()  # other order: rejected (0.4)
    elif r == 7:
        c.header_raw = to_bytes('{"alg":"none",' + loose(h)[1:])              # duplicate alg
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


def op_header_value(c):
    """A header member of a type the spec does not allow, in otherwise canonical
    bytes: `alg` must be rejected at step 3 (never an ERROR), `typ` at step 2,
    `kid` at step 4 (reviewer B-2)."""
    member = c.rng.choice(["alg", "alg", "typ", "kid"])
    c.header[member] = c.rng.choice([
        [c.header.get(member, "ES256")], {"a": 1}, {}, [], 5, 0, -1, 2**53 - 1, True, False, None,
        [[["ES256"]]], {"alg": "ES256"}, ["ES256", "EdDSA"], "", "\ud800"])


def op_header_text(c):
    """Header bytes a lenient JSON parser accepts and the canonical-bytes test of
    §5.1 step 1 refuses: non-JSON tokens, duplicates, reordering, huge integers,
    deep nesting, a BOM (reviewers B-1, M-1, D-01, D-08)."""
    h = dict(c.header)
    text = loose(h)
    r = c.rng.randrange(14)
    if r == 0:
        t = text.replace('{"alg":', '{"alg":NaN,"alg":', 1)
    elif r == 1:
        t = text.replace('"kid":', '"kid":Infinity,"kid":', 1)
    elif r == 2:
        t = text.replace('"typ":', '"typ":-Infinity,"typ":', 1)
    elif r == 3:
        t = text.replace('{"alg":', '{"alg":"none","alg":', 1)
    elif r == 4:
        t = text.replace('"typ":', '"typ":"JWT","typ":', 1)
    elif r == 5:
        t = text[:-1] + ',"x":' + "9" * c.rng.choice([17, 400, 5000]) + "}"
    elif r == 6:
        d = c.rng.choice([8, 9, 50, 5000])
        t = text[:-1] + ',"x":' + "[" * d + "]" * d + "}"
    elif r == 7:
        t = "\ufeff" + text
    elif r == 8:
        t = json.dumps(dict(sorted(h.items(), reverse=True)), separators=(",", ":"))
    elif r == 9:
        t = text.replace(",", ", ")
    elif r == 10:
        t = text[:-1] + ',"x":1.5}'
    elif r == 11:
        t = text[:-1] + ',"x":"\\ud800"}'
    elif r == 12:
        h["typ"] = "JWT"
        t = loose(h)[:-1] + ',"x":9007199254740993}'
    else:
        t = text.replace('"x402-action-receipt+jws"', '"x402-action-receipt\\u002bjws"')
    c.header_raw = to_bytes(t)


def op_ctx_config(c):
    """The verifier's own configuration outside (and at the edges of) the
    contract of spec §5. P7 requires ERROR invalid_configuration exactly when
    `config_valid` says the contract is broken."""
    x = c.context
    r = c.rng.randrange(7)
    if r == 0:
        x["mode"] = c.rng.choice(["SESSION", "Archival", "", None, 1, True, ["session"], "session ",
                                  "archival", "session"])
    elif r == 1:
        x["now"] = c.rng.choice([True, False, A.VERIFIER_NOW + 0.5, str(A.VERIFIER_NOW), None,
                                 2**53, -(2**53), float(A.VERIFIER_NOW), 2**53 - 1, [A.VERIFIER_NOW]])
    elif r == 2:
        x["maxAgeSeconds"] = c.rng.choice([-1, "10", None, True, 10.5, 3600.0, 2**53, 0, 44, 43,
                                           2**53 - 1, [3600], {}])
    elif r == 3:
        x["paidResourceUrl"] = c.rng.choice([5, [], {}, True, "", A.RESOURCE, None, [A.RESOURCE]])
    elif r == 4:
        del x[c.rng.choice(["mode", "now"])]
    elif r == 5:
        c.context = c.rng.choice([None, [], "x", 1, True])
    else:
        x["mode"], x["now"] = c.rng.choice([("archival", 1.0e9), ("session", A.VERIFIER_NOW * 1.0)])


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
    r = c.rng.randrange(10)
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
    elif r == 8:   # a byte inserted at the r/s boundary: 65 bytes (reviewer E, V53)
        c.sig_edit = lambda s: s[:32] + b"\x00" + s[32:]
    elif r == 9:   # a byte removed at the r/s boundary: 63 bytes
        c.sig_edit = lambda s: s[:31] + s[32:]
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
        # upper case and lower case references: never normalized (spec §5.8, reviewer E V61b)
        x["settlementRef"] = c.rng.choice([A.BATCH_REF, "", None, "batch:other", A.BATCH_REF.upper(),
                                           A.COMMITMENT_ID, A.COMMITMENT_ID.upper(), 7, "\ud800"])
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
        # no maximum age: the default 3600 decides, so put the age on both sides of it
        x.pop("maxAgeSeconds", None)
        if isinstance(c.payload.get("issuedAt"), int) and not isinstance(c.payload.get("issuedAt"), bool):
            x["now"] = c.payload["issuedAt"] + c.rng.choice([3599, 3600, 3601, 7200, 36000])


def op_payer_free(c):
    """`payer` may be "" on any network (spec §4.6); off eip155 it is any string."""
    c.payload["payer"] = c.rng.choice(["", "", "Payer-ABC", A.PAYER.upper()])
    if c.rng.random() < 0.5:
        c.context["payer"] = c.rng.choice([None, "", c.payload["payer"], A.PAYER])


def op_network_non_evm(c):
    """Move the case to a non-eip155 network with free-form identifiers, keeping
    requirements consistent so the §4.6 / §5.8 false branches decide."""
    net = c.rng.choice([A.LOOKALIKE_NET, A.CF_NET, "abc:1", "a" * 32 + ":" + "R" * 32, A.SOL_NET])
    pay_to = c.rng.choice(["Merchant-0x209693Bc", A.PAY_TO_CHECKSUM, "acct_1"])
    tx = c.rng.choice([A.SETTLEMENT_TX.upper(), "cf-tx-1", A.SOL_TX, "0x" + "AB" * 32])
    held = c.context.get("accepted")
    acc = dict(held if isinstance(held, dict) else A.ACCEPTED, network=net, payTo=pay_to)
    payer = c.rng.choice(["", "Payer-ABC", A.PAYER_CHECKSUM])
    c.payload.update(network=net, payTo=pay_to, transaction=tx, settlementRef="", payer=payer,
                     requirementsDigest=A.sha256_tag(to_bytes(loose(acc))))
    c.context.update(network=net, transaction=c.rng.choice([tx, tx, tx.lower(), tx.upper()]),
                     settlementRef="", accepted=acc,
                     payer=c.rng.choice([None, payer, payer.lower()]))


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
    (op_header_value, 4), (op_header_text, 5), (op_ctx_config, 5), (op_payer_free, 2),
    (op_network_non_evm, 4), (op_charged_amount, 3), (op_ctx_charged, 4), (op_ctx_scheme, 4),
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


def derived_cases(case):
    """Follow-up cases for the metamorphic properties of a PASSing case."""
    out = []
    ctx = case["context"]
    if not isinstance(ctx, dict):
        return out
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


# --- an independent oracle for the charged amount (spec §4.3 table, §5.8) ----
# Restated here from the spec text, not imported from either verifier.

def _well_formed(s: str) -> bool:
    try:
        s.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def _in_value_domain(v, level: int = 0) -> bool:
    """Spec §4.6 over a parsed JSON value: safe integers by value, well-formed
    strings and member names, containers at most 8 levels deep."""
    if v is None or isinstance(v, bool):
        return True
    if isinstance(v, int):
        return abs(v) <= 2**53 - 1
    if isinstance(v, float):
        return v == v and abs(v) <= 2**53 - 1 and v.is_integer()
    if isinstance(v, str):
        return _well_formed(v)
    if isinstance(v, list):
        return level < 8 and all(_in_value_domain(x, level + 1) for x in v)
    if isinstance(v, dict):
        return level < 8 and all(_well_formed(k) and _in_value_domain(x, level + 1) for k, x in v.items())
    return False


def expected_charged_amount(ctx):
    """None when the verifier must not compare (no in-domain `accepted` object
    with a string `scheme`); else the charged amount the table names, or ""."""
    acc = ctx.get("accepted") if isinstance(ctx, dict) else None
    if not (isinstance(acc, dict) and _in_value_domain(acc) and isinstance(acc.get("scheme"), str)):
        return None
    scheme = acc["scheme"]
    if scheme in ("exact", "upto"):
        v = ctx.get("amount")
    elif scheme == "batch-settlement":
        extra = ctx.get("extra")
        v = extra.get("chargedAmount") if isinstance(extra, dict) else None
    else:
        v = None
    return v if isinstance(v, str) and v != "" and _well_formed(v) else ""


def properties(name: str, res: dict, by_id: dict, origin: dict) -> list:
    """Oracle-free properties P1..P7, and the charged-amount oracle P8, on ONE
    implementation's results."""
    violations = []
    for cid, (verdict, reason, report) in res.items():
        valid = config_valid(by_id[cid]["context"])
        if verdict == A.PASS and isinstance(report, dict):
            want = expected_charged_amount(by_id[cid]["context"])
            got = (report.get("checks") or {}).get("chargedAmount")
            if got != ("not_compared" if want is None else "compared"):
                violations.append(("P8", name, cid, f"checks.chargedAmount {got}, the table says "
                                                    f"{'not_compared' if want is None else 'compared'}"))
            elif want is not None:
                try:
                    signed = json.loads(payload_bytes_of(by_id[cid]["receipt"]) or b"{}").get("chargedAmount")
                except (ValueError, AttributeError):
                    signed = None
                if signed != want:
                    violations.append(("P8", name, cid, f"PASS with chargedAmount {signed!r}; the response's "
                                                        f"charged amount is {want!r}"))
        if not valid and (verdict, reason) != (A.ERROR, CONFIG_ERROR):
            violations.append(("P7", name, cid, f"configuration outside the contract gave {verdict}/{reason}"))
        if valid and verdict == A.ERROR:
            violations.append(("P6", name, cid, f"ERROR on a valid configuration: {reason}"))
        if verdict == A.REJECT and reason not in A.ALL_REASONS:
            violations.append(("P6", name, cid, f"undeclared reason {reason}"))
        if verdict == A.PASS and cid not in origin:
            raw = payload_bytes_of(by_id[cid]["receipt"])
            if not isinstance(report, dict) or report.get("receiptRef") != \
                    "sha256:" + hashlib.sha256(raw or b"").hexdigest():
                violations.append(("P1", name, cid, "receiptRef is not the hash of the payload bytes"))
            if _rfc8785 is not None:
                try:
                    if _rfc8785.dumps(json.loads(raw)) != raw:
                        violations.append(("P2", name, cid, "payload bytes are not their own JCS form"))
                except Exception as e:  # noqa: BLE001
                    violations.append(("P2", name, cid, f"independent canonicalizer refused: {e}"))
    for did, (prop, parent) in origin.items():
        if did not in res or parent not in res:
            continue
        verdict, reason, report = res[did]
        p_verdict, _, p_report = res[parent]
        if p_verdict != A.PASS:
            continue                       # the property is about THIS implementation's PASSes
        if prop in ("P3", "P4") and (verdict != A.PASS or report["receiptRef"] != p_report["receiptRef"]):
            violations.append((prop, name, did, f"{verdict}/{reason}"))
        if prop == "P5" and verdict == A.PASS:
            violations.append((prop, name, did, "a receipt with a flipped payload bit passed"))
    return violations


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--adapters", default="python,node",
                    help="comma-separated built-in adapter names (python, node) and names given by --adapter")
    ap.add_argument("--adapter", action="append", default=[], metavar="NAME=COMMAND",
                    help="a third-party verifier adapter (CONFORMANCE.md §3); the key fixture path is "
                         "appended to COMMAND. Repeatable; each NAME is added to --adapters")
    ap.add_argument("--save", metavar="DIR", help="write disagreeing and violating cases here")
    ap.add_argument("--json", action="store_true", help="print the summary as one JSON object")
    a = ap.parse_args(argv)
    names = [n for n in a.adapters.split(",") if n]
    for spec in a.adapter:
        if "=" not in spec:
            ap.error(f"--adapter needs NAME=COMMAND, got {spec!r}")
        name, cmd = spec.split("=", 1)
        ADAPTERS[name] = shlex.split(cmd)
        if name not in names:
            names.append(name)
    unknown = [n for n in names if n not in ADAPTERS]
    if unknown:
        ap.error(f"unknown adapter(s) {unknown}; give them with --adapter NAME=COMMAND")

    cases = generate(a.seed, a.n)
    by_id = {c["id"]: c for c in cases}
    results = {n: run_adapter(n, cases) for n in names}

    followups, origin = [], {}
    for c in cases:
        if any(results[n][c["id"]][0] == A.PASS for n in names):
            for prop, d in derived_cases(c):
                followups.append(d)
                origin[d["id"]] = (prop, c["id"])
    by_id.update({c["id"]: c for c in followups})
    if followups:
        for n in names:
            results[n].update(run_adapter(n, followups))

    disagreements = [cid for cid in by_id
                     if len({json.dumps(results[n][cid], sort_keys=True) for n in names}) > 1]
    violations = []
    for n in names:
        violations += properties(n, results[n], by_id, origin)

    ref = results[names[0]]
    verdicts = Counter(v for v, _, _ in (ref[c["id"]] for c in cases))
    reasons = Counter(r for v, r, _ in (ref[c["id"]] for c in cases) if v == A.REJECT)
    errors = Counter(r for v, r, _ in (ref[c["id"]] for c in cases) if v == A.ERROR)
    op_seen = Counter(o for c in cases for o in c["id"].split(":", 2)[2].split("+"))
    summary = {
        "seed": a.seed, "requested": a.n, "generated": len(cases), "followups": len(followups),
        "adapters": names, "p2_independent_canonicalizer": _rfc8785 is not None,
        "verdicts": dict(verdicts), "reasons_hit": len(reasons),
        "reasons_never_hit": sorted(A.ALL_REASONS - set(reasons)),
        "errors_never_hit": sorted({CONFIG_ERROR} - set(errors)),
        "operators_never_applied": sorted(o.__name__[3:] for o, _ in OPERATORS
                                          if op_seen[o.__name__[3:]] == 0),
        "disagreements": len(disagreements), "property_violations": len(violations),
    }
    if a.json:
        print(json.dumps(summary))
    else:
        print(f"seed {a.seed}: {len(cases)} of {a.n} cases + {len(followups)} follow-ups through "
              f"{', '.join(names)}")
        print(f"  verdicts ({names[0]}): {dict(verdicts)}")
        print(f"  reason codes hit: {len(reasons)} of {len(A.ALL_REASONS)}"
              + (f"; never hit: {summary['reasons_never_hit']}" if summary["reasons_never_hit"] else ""))
        print(f"  P2 independent canonicalizer: {'active' if _rfc8785 else 'NOT ACTIVE (install rfc8785)'}")
        print(f"  disagreements: {len(disagreements)}   property violations: {len(violations)}"
              f" (properties evaluated on {', '.join(names)})")

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
        for prop, name, cid, why in violations[:20]:
            print(f"  {prop}  {name}  {cid}  {why}")
    if a.save and (disagreements or violations):
        d = pathlib.Path(a.save)
        d.mkdir(parents=True, exist_ok=True)
        keep = disagreements + [cid for _, _, cid, _ in violations]
        with open(d / f"seed{a.seed}.jsonl", "w") as f:
            for cid in dict.fromkeys(keep):
                f.write(json.dumps({"case": by_id[cid],
                                    "results": {n: results[n][cid] for n in names}}) + "\n")
        print(f"\nsaved {len(set(keep))} cases to {d / f'seed{a.seed}.jsonl'}")
    return 0 if not disagreements and not violations and len(cases) == a.n else 1


if __name__ == "__main__":
    sys.exit(main())
