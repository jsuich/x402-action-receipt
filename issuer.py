#!/usr/bin/env python3
"""
issuer.py — reference issuer + issuer conformance suite for `action-receipt`
(spec §6).

An EXCHANGE is what a resource server holds when it decides to issue: the
PaymentRequired it sent, the PaymentPayload it received, the SettlementResponse,
the scheme's settlement reference if any, and its own statement. The issuer
either builds the receipt payload or refuses with one of ten reasons.

    python3 issuer.py                 # run the exchange suite (exchanges/MANIFEST.json)
    python3 issuer.py --regenerate    # rewrite exchanges/ from the tables below, then run
    python3 issuer.py --batch         # adapter: exchanges as JSON lines on stdin

Batch adapter (ISSUER ADAPTER PROTOCOL in CONFORMANCE.md):
    in : {"id": ..., "exchange": {...}}
    out: {"id": ..., "issued": true,  "payload": {...}}
         {"id": ..., "issued": false, "reason": "<refusal reason>"}
"""
from __future__ import annotations

import copy
import json
import pathlib
import re
import sys

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import action_receipt as A  # noqa: E402

EXCHANGES = HERE / "exchanges"

# refusal reasons, in step order (spec §6.2)
X_SETTLEMENT = "settlement_not_successful"
X_NO_ID = "no_settlement_identifier"
X_REQUIREMENTS = "requirements_not_hashable"
X_NETWORK = "network_unusable"
X_RESOURCE = "resource_unavailable"
X_PAYER = "payer_unavailable"
X_GRAMMAR = "identifier_out_of_grammar"
X_STATEMENT = "invalid_statement"
X_ADVERT = "advertisement_conflict"
X_BINDINGS = "invalid_bindings"
ALL_REFUSALS = [X_SETTLEMENT, X_NO_ID, X_REQUIREMENTS, X_NETWORK, X_RESOURCE, X_PAYER,
                X_GRAMMAR, X_STATEMENT, X_ADVERT, X_BINDINGS]
FAULT = "issuer_fault"     # the issuer itself failed; never a conformant answer


def _obj(v):
    return v if isinstance(v, dict) else {}


def _had(v) -> bool:
    """A value is "had" iff it is a non-empty string of well-formed Unicode
    (spec §6.1). An unpaired surrogate cannot be serialized, so it is not had."""
    return isinstance(v, str) and v != "" and A.in_domain(v)


def _lower_evm(v: str) -> str:
    """ASCII lowercasing of hex identifiers (spec §6.2): A-F to a-f, 0X to 0x."""
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
    """Return (payload, None) or (None, refusal reason). Never raises on junk."""
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
    reference = x.get("settlementReference")

    # 1
    if resp.get("success") is not True:
        return None, X_SETTLEMENT
    # 2
    transaction = resp.get("transaction") if _had(resp.get("transaction")) else ""
    reference = reference if _had(reference) else ""
    if not (transaction or reference):
        return None, X_NO_ID
    # 3
    accepted = pay.get("accepted")
    digest = A.requirements_digest(accepted)
    if digest is None:
        return None, X_REQUIREMENTS
    # 4
    network = accepted.get("network")
    if not (isinstance(network, str) and A.RE_CAIP2.fullmatch(network)):
        return None, X_NETWORK
    resp_net = resp.get("network")
    if isinstance(resp_net, str) and A.RE_CAIP2.fullmatch(resp_net) and resp_net != network:
        return None, X_NETWORK
    # 5
    resource = _obj(required.get("resource")).get("url")
    if not _had(resource):
        return None, X_RESOURCE
    # 6
    payer = resp.get("payer")
    if not _had(payer):
        payer = _obj(_obj(pay.get("payload")).get("authorization")).get("from")
    if not _had(payer):
        return None, X_PAYER
    # 7
    pay_to = accepted.get("payTo")
    if not _had(pay_to):
        return None, X_GRAMMAR
    if network.startswith("eip155:"):
        payer, pay_to, transaction = _lower_evm(payer), _lower_evm(pay_to), _lower_evm(transaction)
        if not (A.RE_EVM_ADDRESS.fullmatch(payer) and A.RE_EVM_ADDRESS.fullmatch(pay_to)):
            return None, X_GRAMMAR
        if transaction and not A.RE_EVM_TX.fullmatch(transaction):
            return None, X_GRAMMAR
    # 8
    action = st.get("action")
    issued_at = _int_value(st.get("issuedAt"))
    supersedes = st.get("supersedes", "")
    if supersedes is None:
        supersedes = ""
    ok = (isinstance(action, dict)
          and _had(action.get("agent")) and _had(action.get("actionType"))
          and isinstance(action.get("scope"), str) and A.in_domain(action["scope"])
          and isinstance(action.get("outcome"), str) and action["outcome"] in A.OUTCOMES
          and isinstance(st.get("settlementStatus"), str)
          and st["settlementStatus"] in A.SETTLEMENT_STATUSES
          and isinstance(st.get("receiptId"), str) and A.RE_RECEIPT_ID.fullmatch(st["receiptId"])
          and issued_at is not None and 0 <= issued_at <= A.SAFE_INT_MAX
          and isinstance(supersedes, str)
          and (supersedes == "" or A.RE_DIGEST.fullmatch(supersedes)))
    if not ok:
        return None, X_STATEMENT
    # 9
    ext = _obj(required.get("extensions")).get("action-receipt")
    info = _obj(ext).get("info") if isinstance(ext, dict) else None
    advertised = isinstance(info, dict)
    if advertised:
        for member in ("actionType", "scope"):
            if member in info and info[member] != action[member]:
                return None, X_ADVERT
    # 10
    extra = st.get("bindings", [])
    if extra is None:
        extra = []
    if not isinstance(extra, list):
        return None, X_BINDINGS
    bindings = list(extra)
    # types this specification defines are added by the issuer, never supplied
    if any(isinstance(b, dict) and isinstance(b.get("type"), str)
           and b["type"].startswith("action-receipt:") for b in bindings):
        return None, X_BINDINGS
    if advertised:
        if not A.in_domain(info):
            return None, X_BINDINGS
        bindings.append({"type": A.BT_ADVERTISED, "value": A.sha256_tag(A.jcs(info))})
    if _had(st.get("reversalTransaction")):
        bindings.append({"type": A.BT_REVERSAL_TX, "value": st["reversalTransaction"]})
    if len(bindings) > A.MAX_BINDINGS:
        return None, X_BINDINGS
    seen = set()
    for b in bindings:
        if not (isinstance(b, dict) and set(b.keys()) == A.BINDING_KEYS
                and isinstance(b["type"], str) and isinstance(b["value"], str)
                and A.RE_BINDING_TYPE.fullmatch(b["type"])
                and A.RE_BINDING_VALUE.fullmatch(b["value"])) or b["type"] in seen:
            return None, X_BINDINGS
        seen.add(b["type"])
    bindings = sorted(({"type": b["type"], "value": b["value"]} for b in bindings),
                      key=lambda b: b["type"])

    payload = {
        "version": A.PROFILE_VERSION, "receiptId": st["receiptId"], "issuedAt": issued_at,
        "network": network, "resourceUrl": resource, "payer": payer, "payTo": pay_to,
        "transaction": transaction, "settlementRef": reference,
        "settlementStatus": st["settlementStatus"], "requirementsDigest": digest,
        "supersedes": supersedes,
        "action": {k: action[k] for k in ("agent", "actionType", "scope", "outcome")},
        "bindings": bindings,
    }
    return payload, None


# --- the exchange suite ------------------------------------------------------
# Expected payloads are DECLARED BY HAND as differences from the payload printed
# in spec §4.7, which the suite reads out of the spec file. No expectation is
# produced by running the issuer.

def base_exchange() -> dict:
    return {
        "paymentRequired": {
            "x402Version": 2,
            "resource": {"url": A.RESOURCE, "description": "Text completion"},
            "accepts": [copy.deepcopy(A.ACCEPTED)],
            "extensions": {},
        },
        "paymentPayload": {
            "x402Version": 2,
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


ADVERT = {"info": copy.deepcopy(A.ADVERTISED_INFO),
          "schema": {"type": "object", "required": ["willIssueReceipt"]}}
ADVERT_DIGEST_LITERAL = "sha256:33df93fe0564655d6fa711a9b0b6a390396132ca577f0b7cfac2f6cd3dbffd76"
SOL_NET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOL_PAYER = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
SOL_PAYTO = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
SOL_TX = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"


def E(name, expect, **edit):
    """One exchange: `edit` holds dotted-path assignments; `expect` is a dict of
    payload differences from the spec's worked example, or a refusal reason."""
    x = base_exchange()
    for path, value in edit.items():
        obj = x
        keys = path.split("__")
        for k in keys[:-1]:
            obj = obj[k]
        if value is DELETE:
            del obj[keys[-1]]
        else:
            obj[keys[-1]] = value
    return name, x, expect


DELETE = object()
_ACC_SOL = dict(A.ACCEPTED, network=SOL_NET, payTo=SOL_PAYTO,
                asset="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
_MANY = [{"type": f"n:{i:02d}", "value": "1"} for i in range(16)]

SUITE = [
    # ---- issued -------------------------------------------------------------
    E("issue_basic", {}),
    E("issue_payer_from_authorization", {}, settlementResponse__payer=DELETE),
    E("issue_response_uppercase_hex", {},
      settlementResponse__transaction="0X" + "AB" * 32,
      settlementResponse__payer="0X" + A.PAYER[2:].upper()),
    E("issue_response_network_not_caip2", {}, settlementResponse__network="base"),
    E("issue_requirements_float_spelling", {}, paymentPayload__accepted__maxTimeoutSeconds=60.0),
    E("issue_batch", {"transaction": "", "settlementRef": A.BATCH_REF},
      settlementResponse__transaction="", settlementReference=A.BATCH_REF),
    E("issue_both_identifiers", {"settlementRef": A.BATCH_REF}, settlementReference=A.BATCH_REF),
    E("issue_advertised",
      {"bindings": [{"type": "action-receipt:advertised-info", "value": ADVERT_DIGEST_LITERAL}]},
      **{"paymentRequired__extensions": {"action-receipt": ADVERT}}),
    E("issue_refund",
      {"settlementStatus": "refunded", "receiptId": A.RECEIPT_ID_2,
       "supersedes": "sha256:5ea130c2d5c3750da8e54ea640cdbf653056202c08a2af4c43677947becda7c2",
       "bindings": [{"type": "action-receipt:reversal-transaction", "value": "0x" + "ef" * 32}]},
      statement__settlementStatus="refunded", statement__receiptId=A.RECEIPT_ID_2,
      statement__supersedes="sha256:5ea130c2d5c3750da8e54ea640cdbf653056202c08a2af4c43677947becda7c2",
      statement__reversalTransaction="0x" + "ef" * 32),
    E("issue_bindings_sorted",
      {"bindings": [{"type": "action-receipt:advertised-info", "value": ADVERT_DIGEST_LITERAL},
                    {"type": "offer-receipt:authorizationMethod", "value": "eip3009"},
                    {"type": "response-provenance:responseHash", "value": "sha256:" + "81" * 32}]},
      **{"paymentRequired__extensions": {"action-receipt": ADVERT}},
      statement__bindings=[{"type": "response-provenance:responseHash", "value": "sha256:" + "81" * 32},
                           {"type": "offer-receipt:authorizationMethod", "value": "eip3009"}]),
    E("issue_outcome_failed", {"action": {"agent": "did:web:agent.example",
                                           "actionType": "inference.completion",
                                          "scope": "read:model-x", "outcome": "failed"}},
      statement__action__outcome="failed"),
    E("issue_non_evm",
      {"network": SOL_NET, "payer": SOL_PAYER, "payTo": SOL_PAYTO, "transaction": SOL_TX,
       "requirementsDigest": "@accepted"},
      paymentPayload__accepted=_ACC_SOL,
      settlementResponse__network=SOL_NET, settlementResponse__payer=SOL_PAYER,
      settlementResponse__transaction=SOL_TX),
    E("issue_sixteen_bindings", {"bindings": _MANY}, statement__bindings=list(reversed(_MANY))),
    E("issue_issuedat_float_spelling", {}, statement__issuedAt=float(A.ISSUED_AT)),
    E("issue_null_means_absent", {}, statement__supersedes=None, statement__bindings=None,
      statement__reversalTransaction=None),
    E("issue_advertisement_info_not_object", {},
      **{"paymentRequired__extensions": {"action-receipt": {"info": "yes"}}}),
    E("issue_action_extra_member_ignored", {}, statement__action__note="ignored"),
    E("issue_transaction_wrong_type_with_reference", {"transaction": "", "settlementRef": A.BATCH_REF},
      settlementResponse__transaction=123, settlementReference=A.BATCH_REF),
    # ---- refused, one per step ---------------------------------------------
    E("refuse_settlement_failed", X_SETTLEMENT, settlementResponse__success=False),
    E("refuse_settlement_truthy_string", X_SETTLEMENT, settlementResponse__success="true"),
    E("refuse_no_identifier", X_NO_ID, settlementResponse__transaction=""),
    E("refuse_requirements_non_integer", X_REQUIREMENTS,
      paymentPayload__accepted__extra={"rate": 1.5}),
    E("refuse_requirements_missing", X_REQUIREMENTS, paymentPayload__accepted=None),
    E("refuse_network_not_caip2", X_NETWORK, paymentPayload__accepted__network="base"),
    E("refuse_network_not_caip2_either_side", X_NETWORK, paymentPayload__accepted__network="base",
      settlementResponse__network="base"),
    E("refuse_network_conflict", X_NETWORK, settlementResponse__network="eip155:1"),
    E("refuse_no_resource", X_RESOURCE, paymentRequired__resource={"description": "x"}),
    E("refuse_no_payer", X_PAYER, settlementResponse__payer=None,
      paymentPayload__payload={"signature": "0x00"}),
    E("refuse_payto_role_constant", X_GRAMMAR, paymentPayload__accepted__payTo="merchant"),
    E("refuse_transaction_not_hex", X_GRAMMAR, settlementResponse__transaction="0x1234"),
    E("refuse_payto_missing", X_GRAMMAR, paymentPayload__accepted__payTo=DELETE),
    E("refuse_outcome_unknown", X_STATEMENT, statement__action__outcome="shipped"),
    E("refuse_outcome_retired_value", X_STATEMENT, statement__action__outcome="refused"),
    E("refuse_receiptid_short", X_STATEMENT, statement__receiptId="tooshort"),
    E("refuse_issuedat_fraction", X_STATEMENT, statement__issuedAt=1703123456.5),
    # found by the clean-room issuer: readings the text had left open
    E("refuse_advertised_scope_not_string", X_ADVERT,
      **{"paymentRequired__extensions": {"action-receipt": {"info": {"willIssueReceipt": True,
                                                                     "scope": 5}}}}),
    E("refuse_advertised_scope_conflict", X_ADVERT,
      **{"paymentRequired__extensions": {"action-receipt": ADVERT}},
      statement__action__scope="write:model-x"),
    E("refuse_binding_duplicates_advertisement", X_BINDINGS,
      **{"paymentRequired__extensions": {"action-receipt": ADVERT}},
      statement__bindings=[{"type": "action-receipt:advertised-info", "value": "sha256:" + "00" * 32}]),
    E("refuse_advertised_info_not_hashable", X_BINDINGS,
      **{"paymentRequired__extensions": {"action-receipt": {"info": {"willIssueReceipt": True,
                                                                     "weight": 1.5}}}}),
    # found by issuer fuzz cycle 1
    E("refuse_binding_reserved_type", X_BINDINGS,
      statement__bindings=[{"type": "action-receipt:advertised-info", "value": "sha256:" + "00" * 32}]),
    E("refuse_scope_unpaired_surrogate", X_STATEMENT, statement__action__scope="read:\ud800"),
    E("refuse_binding_duplicate_type", X_BINDINGS,
      statement__bindings=[{"type": "a:one", "value": "1"}, {"type": "a:one", "value": "2"}]),
    E("refuse_binding_grammar", X_BINDINGS, statement__bindings=[{"type": "no-colon", "value": "1"}]),
    E("refuse_seventeen_bindings", X_BINDINGS,
      statement__bindings=_MANY + [{"type": "n:16", "value": "1"}]),
    E("refuse_bindings_not_array", X_BINDINGS, statement__bindings={"type": "a:b", "value": "1"}),
    # ---- order: two faults, the earlier step's reason wins ------------------
    E("refuse_order_settlement_before_statement", X_SETTLEMENT,
      settlementResponse__success=False, statement__receiptId="tooshort"),
    E("refuse_order_statement_before_advertisement", X_STATEMENT,
      **{"paymentRequired__extensions": {"action-receipt": ADVERT}},
      statement__action__scope="write:model-x", statement__action__outcome="shipped"),
]


def spec_example_payload() -> dict:
    """The payload printed in spec §4.7, read from the spec file."""
    text = (HERE / "action-receipt.md").read_text()
    m = re.search(r'^(\{"action":\{"actionType".*\})$', text, flags=re.M)
    if not m:
        raise SystemExit("cannot find the worked-example payload in action-receipt.md")
    return json.loads(m.group(1))


def expected_payload(expect: dict, exchange: dict) -> dict:
    p = spec_example_payload()
    for k, v in expect.items():
        if v == "@accepted":
            v = A.sha256_tag(A.jcs(exchange["paymentPayload"]["accepted"]))
        p[k] = v
    return p


def verification_context(exchange: dict, payload: dict) -> A.Context:
    """The context a verifier holding this same exchange would verify in."""
    resp = exchange["settlementResponse"]
    ext = exchange["paymentRequired"].get("extensions", {}).get("action-receipt")
    return A.Context(
        resp.get("success"), transaction=resp.get("transaction"),
        settlement_ref=exchange.get("settlementReference"), network=resp.get("network"),
        payer=resp.get("payer"), accepted=exchange["paymentPayload"]["accepted"],
        advertised_info=ext["info"] if isinstance(ext, dict) else None,
        now=payload["issuedAt"] + 1, paid_resource_url=exchange["paymentRequired"]["resource"]["url"])


def round_trip(exchange: dict, payload: dict) -> list[str]:
    """Sign the issued payload with a test key and verify it in the context of
    its own exchange. Returns problems (empty when the round trip holds)."""
    registry, keys = A._registry()
    jws = A._sign_jws("ES256", A.KID_ES256, keys["ES256"], A.jcs(payload))
    ctx = verification_context(exchange, payload)
    verdict, reason, report = A.verify_detailed({"format": "jws", "signature": jws}, ctx, registry)
    if verdict != A.PASS:
        return [f"issued receipt does not verify: {verdict}/{reason}"]
    out = []
    want = {"resourceUrl": "compared", "requirements": "matched", "payTo": "compared"}
    for k, v in want.items():
        if report["checks"].get(k) != v:
            out.append(f"checks.{k} is {report['checks'].get(k)}")
    for b in report["bindings"]:
        if b["type"] == A.BT_ADVERTISED and b["status"] != "matched":
            out.append("advertised-info binding is " + b["status"])
    return out


def regenerate() -> None:
    EXCHANGES.mkdir(exist_ok=True)
    for old in EXCHANGES.glob("*.json"):
        old.unlink()
    entries = []
    for name, exchange, expect in SUITE:
        (EXCHANGES / f"{name}.json").write_text(json.dumps(exchange, indent=2) + "\n")
        if isinstance(expect, dict):
            entries.append({"file": f"{name}.json", "issued": True,
                            "payload": expected_payload(expect, exchange)})
        else:
            entries.append({"file": f"{name}.json", "issued": False, "reason": expect})
    manifest = {
        "profile": "action-receipt", "specDraft": "0.3",
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
    failures, reasons, issued_n = 0, set(), 0
    for e in manifest["exchanges"]:
        exchange = json.loads((EXCHANGES / e["file"]).read_text())
        payload, reason = issue(exchange)
        problems = []
        if e["issued"]:
            if payload is None:
                problems.append(f"refused with {reason}")
            else:
                issued_n += 1
                if A.jcs(payload) != A.jcs(e["payload"]):
                    diff = [k for k in set(payload) | set(e["payload"])
                            if payload.get(k) != e["payload"].get(k)]
                    problems.append(f"payload differs in {sorted(diff)}")
                problems += round_trip(exchange, payload)
        else:
            reasons.add(reason)
            if payload is not None:
                problems.append("issued, expected a refusal")
            elif reason != e["reason"]:
                problems.append(f"refused with {reason}, expected {e['reason']}")
        failures += bool(problems)
        print(f"[{' ok ' if not problems else 'FAIL'}] {e['file']:46s} "
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
    for s in structural:
        print("SUITE INVALID:", s)
    if structural:
        return 2
    if failures:
        print(f"{failures} issuer conformance failure(s)")
        return 1
    n = len(manifest["exchanges"])
    print(f"all {n} exchanges pass ({issued_n} issued, {n - issued_n} refused); all "
          f"{len(ALL_REFUSALS)} refusal reasons exercised; every issued receipt verifies in the "
          f"context of its own exchange; spec and code agree on refusal reasons and order")
    return 0


def batch() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        case = json.loads(line)
        payload, reason = issue(case.get("exchange"))
        out = {"id": case["id"], "issued": payload is not None}
        out.update({"payload": payload} if payload is not None else {"reason": reason})
        sys.stdout.write(json.dumps(out) + "\n")
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
