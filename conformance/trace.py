#!/usr/bin/env python3
"""
trace.py — the requirements trace for action-receipt.

conformance/requirements.json is the hand-written catalogue: one entry per
requirement, with an id, the role it binds, an `anchor` (text copied verbatim
from the spec), how it is tested, and the vectors that test it. This script
checks the catalogue against the spec and the suite, and renders CONFORMANCE.md
from it.

    python3 conformance/trace.py --list     # every normative sentence in the spec
    python3 conformance/trace.py --check    # verify the trace (exit 0 iff it holds)
    python3 conformance/trace.py --render   # rewrite CONFORMANCE.md, then check

What --check asserts:
  T1  every anchor occurs in the spec exactly as written (whitespace-insensitive)
  T2  every normative sentence of the spec (one using MUST, SHOULD, MAY or
      RECOMMENDED in capitals) is covered by at least one anchor
  T3  every requirement tested by vectors names vectors that exist in the manifest
  T4  every vector in the manifest is named by at least one requirement
  T5  every requirement that is not tested says why, from a closed list of reasons
  T6  the verifier-testable requirements with no vector are listed and counted,
      never silently accepted
  T7  CONFORMANCE.md is exactly what --render would write
  T8  the manifest's vectorsDigest is the digest of the files in vectors/ (so a
      vector overwritten or edited by hand is seen), recomputed here
  T9  no two manifest entries have identical receipt and context content (a
      vector overwritten with a copy of another stops testing its rule)
  T10 every file the manifest names exists in vectors/
  T3 also applies to any requirement that lists vectors, whatever `tested_by`
  says: a cited vector must exist.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = ROOT / "action-receipt.md"
REQS = ROOT / "conformance" / "requirements.json"
MANIFEST = ROOT / "vectors" / "MANIFEST.json"
XMANIFEST = ROOT / "exchanges" / "MANIFEST.json"
OUT = ROOT / "CONFORMANCE.md"

NORMATIVE = re.compile(r"\b(MUST NOT|MUST|SHOULD NOT|SHOULD|MAY|RECOMMENDED)\b")
ROLES = {"issuer", "verifier", "consumer", "client"}
# how a requirement is established
TESTED = {"vector", "exchange", "matrix", "fuzz", "suite"}
UNTESTED_REASONS = {
    "issuer-behaviour": "binds how a receipt is produced; needs an issuer under test",
    "consumer-behaviour": "binds how a result is used after verification",
    "needs-network": "needs live key or anchor resolution, or a payment rail",
    "informative": "permission or recommendation with nothing to observe",
    "not-observable": "cannot be provoked or observed from outside the implementation",
    "caller-context": "depends on something the caller knows that the adapter protocol does not carry",
}


def squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def spec_units():
    """Yield (section, text) for each paragraph, list item or table row of the
    spec, with code blocks removed."""
    section, buf, in_code = "0", [], False
    for line in SPEC.read_text().splitlines():
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        m = re.match(r"^#{2,4} ([0-9]+(?:\.[0-9]+)*)", line)
        heading = line.startswith("#")
        new_item = re.match(r"^\s*(?:[-*]|\d+\.)\s", line) or line.startswith("|")
        if heading or not line.strip() or new_item:
            if buf:
                yield section, squash(" ".join(buf))
                buf = []
            if m:
                section = m.group(1)
            if heading or not line.strip():
                continue
        buf.append(line)
    if buf:
        yield section, squash(" ".join(buf))


def normative_sentences():
    out = []
    for section, unit in spec_units():
        for sent in re.split(r"(?<=[.;:])\s+(?=[A-Z`(*])", unit):
            if NORMATIVE.search(sent):
                out.append((section, sent.strip()))
    return out


def load():
    reqs = json.loads(REQS.read_text())["requirements"]
    manifest = json.loads(MANIFEST.read_text())
    manifest["_exchanges"] = json.loads(XMANIFEST.read_text())
    return reqs, manifest


def vectors_digest(vdir: pathlib.Path) -> str:
    """sha256 over the RFC 8785 form of {file name: sha256 hex of the file} for
    every .json in vectors/ except MANIFEST.json (the definition the manifest's
    note states). Written here independently of action_receipt.py: names and
    values are ASCII, so sorted keys and no whitespace are the JCS form."""
    digests = {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
               for f in vdir.glob("*.json") if f.name != "MANIFEST.json"}
    text = json.dumps(digests, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def manifest_checks(manifest) -> list[str]:
    """T8, T9, T10: the manifest against the files it describes."""
    errs = []
    vdir = MANIFEST.parent
    if manifest.get("vectorsDigest") != vectors_digest(vdir):
        errs.append(f"T8 vectorsDigest {manifest.get('vectorsDigest')} does not describe the files in "
                    f"vectors/ (recomputed {vectors_digest(vdir)})")
    seen = {}
    for v in manifest["vectors"]:
        f = vdir / v["file"]
        if not f.exists():
            errs.append(f"T10 manifest names a vector file that does not exist: {v['file']}")
            continue
        try:
            receipt = json.loads(f.read_text())
        except ValueError:
            receipt = f.read_text()
        key = json.dumps([receipt, manifest["contexts"].get(v["context"])], sort_keys=True)
        if key in seen:
            errs.append(f"T9 {v['file']} has the same receipt and context as {seen[key]}")
        else:
            seen[key] = v["file"]
    return errs


def render(reqs, manifest) -> str:
    vectors = {v["file"] for v in manifest["vectors"]}
    by_role = {}
    for r in reqs:
        by_role.setdefault(r["role"], []).append(r)
    tested = [r for r in reqs if r["tested_by"] in TESTED]
    untested = [r for r in reqs if r["tested_by"] not in TESTED]
    L = [
        "# action-receipt conformance",
        "",
        "Generated by `python3 conformance/trace.py --render` from",
        "`conformance/requirements.json`. Do not edit by hand.",
        "",
        "This document says what it means to conform to `action-receipt.md`, which",
        "requirements the suite tests, and which it does not.",
        "",
        "## 1. Conformance classes",
        "",
        "**Verifier.** An implementation conforms as a verifier if, driven through the",
        "adapter protocol of section 3, it reproduces every entry of",
        "`vectors/MANIFEST.json`: the verdict, the reason code on `REJECT`, the report",
        "on `PASS`, and the `receiptRef` relations. A claim cites the manifest's",
        f"`vectorsDigest` (currently `{manifest['vectorsDigest']}`).",
        "",
        "**Issuer.** An implementation conforms as an issuer if, driven through the",
        "issuer adapter protocol of section 3, it handles every exchange in",
        "`exchanges/MANIFEST.json` as stated there: it produces exactly the expected",
        "payload (compared by RFC 8785 serialization) or refuses with the expected",
        "reason, for the exchange as published and for a follow-up of it with a fresh",
        "`receiptId` and `issuedAt`, and answers the adapter-protocol cases of section 3.",
        "Signing is not part of this class: the exchanges compare payloads. The",
        "reference issuer's `sign()` (spec §6.3) is tested by its own suite, through",
        "both verifiers. Issuer requirements that an exchange cannot show (randomness",
        "of `receiptId`, key retention) are listed in section 4 as untested.",
        "",
        "**Consumer.** Requirements on how a verification result is used are listed for",
        "completeness. They are not testable through this suite.",
        "",
        "## 2. Counts",
        "",
        f"- {len(reqs)} requirements: {len(tested)} tested, {len(untested)} not tested.",
    ]
    for reason, why in UNTESTED_REASONS.items():
        n = sum(1 for r in untested if r["tested_by"] == reason)
        L.append(f"  - {n} not tested, `{reason}`: {why}.")
    L += [
        f"- {len(vectors)} vectors, each named by at least one requirement.",
        f"- {len(manifest['_exchanges']['exchanges'])} exchanges, each named by at least one requirement.",
        "",
        "## 3. Adapter protocol",
        "",
        "A verifier under test is a program that takes the path of the key fixture as",
        "its only argument, reads cases from standard input and writes results to",
        "standard output, one JSON object per line.",
        "",
        "Input line:",
        "",
        "```json",
        '{"id": "any string", "receipt": <any JSON value>, "context": {',
        '   "paidResourceUrl": "https://..." or null,',
        '   "success": true, "transaction": "0x...", "settlementRef": "",',
        '   "network": "eip155:8453", "payer": "0x...", "accepted": {...} or null,',
        '   "advertisedInfo": {...} or null, "now": 1703123500,',
        '   "maxAgeSeconds": 3600, "mode": "session"}}',
        "```",
        "",
        "Output line:",
        "",
        "```json",
        '{"id": "same string", "verdict": "PASS", "reason": null, "report": {...}}',
        '{"id": "same string", "verdict": "REJECT", "reason": "invalid_...", "report": null}',
        '{"id": "same string", "verdict": "ERROR", "reason": "invalid_configuration", "report": null}',
        "```",
        "",
        "- `context` is the verifier input of spec §5. Five of its members are x402",
        "  values from the `SettlementResponse` (`success`, `transaction`,",
        "  `settlementRef`, `network`, `payer`) and two are optional objects",
        "  (`accepted`, `advertisedInfo`); all are unsigned. Any of them may be absent,",
        "  `null` or of the wrong type, and nothing in them may make the verifier",
        "  return `ERROR` (spec §5).",
        "- The rest is the verifier's own configuration and has the contract of spec §5:",
        "  `mode` exactly `session` or `archival`; `now` an integer; `maxAgeSeconds`",
        "  absent (3600) or an integer `>= 0`; `paidResourceUrl` absent, `null` (the",
        "  verifier did not pay) or a string. Integers are read by value within",
        "  `±(2^53 - 1)`, so `1703123500.0` is an integer and `true` is not. A `null`",
        "  `maxAgeSeconds` is a value the verifier cannot read, not an absence. A",
        "  context outside this contract, or one that is not an object, gets",
        "  `ERROR` with reason `invalid_configuration`; the `err_config_*` vectors",
        "  test it. An `ERROR` on any other vector is a conformance failure.",
        "- The key fixture is `vectors/keys.json` (spec §7): `__service__:` and",
        "  `__payTo__:` entries are arrays of authorized kids (anything else authorizes",
        "  nothing), `__unavailable__:<resourceUrl>` set to `true` means the source gave",
        "  no answer, and a kid maps to a SubjectPublicKeyInfo PEM.",
        "- `verdict` is `PASS`, `REJECT` or `ERROR`; `reason` is set on `REJECT` and",
        "  `ERROR`.",
        "",
        "Two adapters are in `conformance/adapters/`: Python (the reference verifier)",
        "and Node (the second verifier, `verify.mjs`).",
        "`python3 conformance/run_vectors.py -- <adapter command>` drives any adapter",
        "over the manifest and compares every entry (verdict, reason, full report),",
        "with opaque case ids and metamorphic follow-ups; it never trusts the",
        "adapter's exit code. `python3 conformance/fuzz.py --adapter NAME=COMMAND`",
        "puts a third-party adapter in the differential fuzzer.",
        "",
        "### Issuer adapter protocol",
        "",
        "An issuer under test reads exchanges and writes results, one JSON object per",
        "line, with no arguments.",
        "",
        "```json",
        '{"id": "any string", "exchange": {"paymentRequired": {...}, "paymentPayload": {...},',
        '   "settlementResponse": {...}, "settlementReference": "..." or null,',
        '   "statement": {"receiptId": "...", "issuedAt": 1703123456, "action": {...},',
        '      "settlementStatus": "settled", "supersedes": "", "reversalTransaction": null,',
        '      "bindings": []}}}',
        "```",
        "",
        "```json",
        '{"id": "same string", "issued": true, "payload": {...}}',
        '{"id": "same string", "issued": false, "reason": "settlement_not_successful"}',
        "```",
        "",
        "- `payload` is the receipt payload object of spec section 6.3, not signed and",
        "  not serialized. `reason` is a refusal reason of spec section 6.2, or one of",
        "  three answers that are not refusals: `invalid_input` (the line is not a JSON",
        "  object; `id` is the line's if it can be read, else `null`), `issuer_fault`",
        "  (the issuer itself failed) and `self_check_failed` (the payload it built",
        "  failed its own §5.2/§5.3 check, spec §6.3). An issuer never reports its own",
        "  failure as a refusal, and a conforming issuer gives none of the three for a",
        "  JSON exchange.",
        "- Any part of an exchange may be missing or malformed; the issuer must answer",
        "  every line, including valid JSON of any nesting depth or with integers of",
        "  any length (the value of a number is its IEEE 754 double, spec §4.6).",
        "- `python3 issuer.py --batch` and `node issuer.mjs` are the two issuers here.",
        "  `conformance/run_exchanges.py <command>` runs any issuer against the manifest",
        "  with opaque random ids in a shuffled order, a follow-up per exchange whose",
        "  answer follows from spec §6, and ten protocol cases (deep nesting, huge",
        "  integers, lines that are not JSON); it never trusts the adapter's exit code.",
        "  `python3 conformance/fuzz_issuer.py --issuer NAME=COMMAND` puts a third-party",
        "  issuer in the issuer fuzzer.",
        "",
        "## 4. Requirements",
        "",
        "`Tested by`: `vector` = the named vectors; `exchange` = the named exchanges;",
        "`matrix` = the suite's mutation",
        "matrix or `receiptRef` relations; `fuzz` = a property the fuzzer asserts on",
        "every case; `suite` = a structural check of the suite itself.",
        "",
    ]
    order = ["verifier", "issuer", "consumer", "client"]
    for role in order:
        if role not in by_role:
            continue
        L += [f"### {role.capitalize()}", "", "| ID | Spec | Level | Requirement | Tested by |",
              "|---|---|---|---|---|"]
        for r in by_role[role]:
            if r["tested_by"] == "vector":
                how = ", ".join(f"`{v[:-5]}`" for v in r["vectors"])
            elif r["tested_by"] == "exchange":
                how = ", ".join(f"`{v[:-5]}`" for v in r["exchanges"])
            elif r["tested_by"] in TESTED:
                how = f"{r['tested_by']}: {r['note']}"
            else:
                how = f"not tested (`{r['tested_by']}`)"
            L.append(f"| {r['id']} | §{r['section']} | {r['level']} | {r['text']} | {how} |")
        L.append("")
    gaps = [r for r in reqs if r["role"] == "verifier" and r["tested_by"] not in TESTED]
    L += ["## 5. Verifier requirements the suite does not test", ""]
    if gaps:
        L += [f"{len(gaps)} requirements bind a verifier and have no test here:", ""]
        L += [f"- {r['id']} (§{r['section']}): {r['text']} Reason: `{r['tested_by']}`." for r in gaps]
    else:
        L.append("None.")
    L += ["", "## 6. Test cycle", "",
          "`python3 conformance/cycle.py` runs every stage and returns one exit code.",
          "A stage that cannot run is reported as VOID and fails the cycle.", "",
          "| Stage | What it establishes |", "|---|---|",
          "| trace | this document matches the spec and the suite (checks T1 to T7 in `conformance/trace.py`) |",
          "| python | the reference verifier's own suite: hand-declared verdicts, reasons and full reports, the mutation matrix, `receiptRef` relations, an independent RFC 8785 library cross-checking every canonicalization |",
          "| python-a | the Python adapter, driven by `run_vectors.py`, reproduces every manifest entry |",
          "| node | the Node adapter, driven by `run_vectors.py`, reproduces every manifest entry |",
          "| example | the second verifier reproduces the spec's worked example from the spec text |",
          "| flips | every listed check of either verifier, disabled, makes a named vector disagree |",
          "| fuzz | the two verifiers agree on generated cases and seven oracle-free properties hold on both; VOID below 500 cases per seed, FAIL if fewer cases ran than requested or a reason code, the configuration `ERROR` or an operator never fired |",
          "| issuer | the reference issuer reproduces the exchange manifest; every receipt it issues, signed by its `sign()`, passes both verifiers with the §6.3 report; its self-check refuses broken payloads; 400 randomized ECDSA signatures per algorithm pass both verifiers |",
          "| issuer-n | the second issuer, driven by `run_exchanges.py`, reproduces the manifest, the follow-ups and the protocol cases |",
          "| issuer-fl | every listed sub-check of either issuer, disabled, makes a named exchange or suite check disagree; a crash counts as broken, not caught |",
          "| issuer-fz | the two issuers agree on generated exchanges; five properties hold on both; every issued payload, signed, passes both verifiers with the §6.3 report; VOID below 500 cases, FAIL if fewer ran or a refusal never fired |",
          "",
          "`python3 flip_probe.py <repo> <scratch> --fuzz N` additionally measures the",
          "fuzzer: how many disabled checks it detects in N cases.",
          "",
          "The history of cycles, with what each found, is in `conformance/CYCLES.md`.",
          ""]
    return "\n".join(L)


def check(reqs, manifest) -> list[str]:
    errs = []
    spec = squash(re.sub(r"```.*?```", " ", SPEC.read_text(), flags=re.S))
    ids = [r["id"] for r in reqs]
    if len(ids) != len(set(ids)):
        errs.append("T0 duplicate requirement ids")
    vectors = {v["file"] for v in manifest["vectors"]}
    named, xnamed = set(), set()
    xfiles = {e["file"] for e in manifest["_exchanges"]["exchanges"]}
    anchors = []
    for r in reqs:
        a = squash(r["anchor"])
        anchors.append(a)
        if a not in spec:
            errs.append(f"T1 {r['id']}: anchor not found in the spec: {a[:70]!r}")
        if r["role"] not in ROLES:
            errs.append(f"T0 {r['id']}: unknown role {r['role']}")
        for v in r.get("vectors", []):
            named.add(v)
            if v not in vectors:
                errs.append(f"T3 {r['id']}: names a vector that does not exist: {v}")
        if r["tested_by"] == "vector":
            if not r.get("vectors"):
                errs.append(f"T3 {r['id']}: tested by vectors but names none")
        elif r["tested_by"] == "exchange":
            if not r.get("exchanges"):
                errs.append(f"T3 {r['id']}: tested by exchanges but names none")
            for v in r.get("exchanges", []):
                xnamed.add(v)
                if v not in xfiles:
                    errs.append(f"T3 {r['id']}: names an exchange that does not exist: {v}")
        elif r["tested_by"] in TESTED:
            if not r.get("note"):
                errs.append(f"T5 {r['id']}: tested by {r['tested_by']} but has no note saying how")
        elif r["tested_by"] not in UNTESTED_REASONS:
            errs.append(f"T5 {r['id']}: untested without a listed reason: {r['tested_by']}")
    for section, sent in normative_sentences():
        s = squash(sent)
        if not any(a in s or s in a or _overlap(a, s) for a in anchors):
            errs.append(f"T2 §{section}: normative sentence not covered: {s[:90]!r}")
    for v in sorted(vectors - named):
        errs.append(f"T4 vector named by no requirement: {v}")
    errs += manifest_checks(manifest)
    for v in sorted(xfiles - xnamed):
        errs.append(f"T4 exchange named by no requirement: {v}")
    if OUT.exists():
        if OUT.read_text() != render(reqs, manifest):
            errs.append("T7 CONFORMANCE.md is stale: run conformance/trace.py --render")
    else:
        errs.append("T7 CONFORMANCE.md does not exist: run conformance/trace.py --render")
    return errs


def _overlap(anchor: str, sentence: str) -> bool:
    """An anchor covers a sentence if they share a run of at least 40 characters
    that contains the sentence's normative keyword."""
    for m in NORMATIVE.finditer(sentence):
        lo, hi = max(0, m.start() - 40), min(len(sentence), m.end() + 40)
        window = sentence[lo:hi]
        for i in range(0, max(1, len(window) - 39)):
            piece = window[i:i + 40]
            if len(piece) == 40 and m.group(0) in piece and piece in anchor:
                return True
    return False


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--list" in argv:
        sents = normative_sentences()
        for section, s in sents:
            print(f"§{section}\t{s}")
        print(f"{len(sents)} normative sentences", file=sys.stderr)
        return 0
    reqs, manifest = load()
    if "--render" in argv:
        OUT.write_text(render(reqs, manifest))
    errs = check(reqs, manifest)
    for e in errs:
        print(e)
    tested = sum(1 for r in reqs if r["tested_by"] in TESTED)
    gaps = sum(1 for r in reqs if r["role"] == "verifier" and r["tested_by"] not in TESTED)
    print(f"trace: {len(reqs)} requirements ({tested} tested, {len(reqs) - tested} not tested, "
          f"{gaps} untested verifier requirements), {len(manifest['vectors'])} vectors, "
          f"{len(manifest['_exchanges']['exchanges'])} exchanges, "
          f"{len(normative_sentences())} normative sentences, {len(errs)} errors")
    return 0 if not errs else 1


if __name__ == "__main__":
    sys.exit(main())
