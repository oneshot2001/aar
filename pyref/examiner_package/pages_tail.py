"""Pages 05, 06, 07 and the prohibited-claims appendix."""

from __future__ import annotations

import json
import unicodedata

from .core import REPO
from .text import INVISIBLE_RANGES, escape_code, escaped, visible


def page_05(texts, payloads, body: bool) -> str:
    nonzero = [t for t in texts if t["invisible"]]
    zero = [t for t in texts if not t["invisible"]]
    not_decoded = [p for p in payloads if p["kind"] in ("not-decoded", "opaque")]
    identifiers = [p for p in payloads if p["kind"] == "identifier"]
    decoded = [p for p in payloads if p["kind"] == "decoded"]
    ranges = ", ".join(f"U+{lo:04X}" + (f"–U+{hi:04X}" if hi != lo else "") for lo, hi in INVISIBLE_RANGES)
    header = [
        "# 05 — text fields" if body else "# Appendix — text fields with zero findings, and identifier-sized byte strings", "",
        "Contract. Traversal of the decoded bundle (`01-copy/bundle.cbor`), not a schema whitelist: every text key and "
        "value, with envelope payloads, COSE structures and protected headers decoded under the artifact categories and "
        "the embedded `delegation`/`presentation` slots, and the byte strings `parameters_cbor`, `canonical_command`, "
        "`canonical_cbor` and `canonical_bytes` decoded where they decode as deterministic CBOR. Every other byte string "
        "is inventoried: 16- and 32-byte strings as identifier-sized (appendix), all others as not decoded (this page) "
        "with path, length and SHA-256. Unicode data version `" + unicodedata.unidata_version + "`. "
        f"Counted set, by inclusive range: {ranges}. C0/C1 controls, DEL, U+2028/2029 and format characters outside the "
        "counted set are escaped but not counted. Positions are zero-based code-point indexes. Escaped form: every code "
        "point outside printable ASCII as `\\uXXXX`, supplementary-plane as `\\u{XXXXX}`, backslash as `\\\\`. Visible "
        "column and every path column: counted and escaped-uncounted code points replaced by their escape, "
        "Markdown-active ASCII backslash-escaped, so no active control reaches the reader. Nothing is normalized or "
        "stripped; raw bytes stay in `01-copy/bundle.cbor`.", ""]
    table = ["| path | visible | invisible count | positions | escaped |", "|---|---|---|---|---|"]
    rows = nonzero if body else zero
    for t in rows:
        positions = ", ".join(f"{i}:{escape_code(c)}" for i, c in t["invisible"]) or "—"
        table.append(f"| {visible(t['path'])} | {visible(t['text'])} | {len(t['invisible'])} | {positions} | `{escaped(t['text'])}` |")
    if not rows:
        table = ["(none)"]
    if not body:
        lines = header + [f"{len(zero)} rows, zero invisible code points each.", "", *table, "",
                          f"## Identifier-sized byte strings, not text ({len(identifiers)})", "",
                          "| path | bytes | sha256 |", "|---|---|---|"]
        lines += [f"| {visible(p['path'])} | {len(p['bytes'])} | `{p['sha256']}` |" for p in identifiers]
        return "\n".join(lines) + "\n"
    lines = header + [f"Text rows: {len(texts)}; rows with invisible code points: {len(nonzero)} (below); rows with zero "
                      f"findings: {len(zero)} (`appendix/text-fields-zero.md`); embedded payloads decoded: {len(decoded)}; "
                      f"not decoded: {len(not_decoded)} (below); identifier-sized byte strings: {len(identifiers)} (appendix).", "",
                      "## Rows with invisible code points", "", *table, "",
                      "## Not decoded (byte strings never decoded as text; listed separately from decoded-with-zero-findings)", ""]
    lines += [f"- {visible(p['path'])}: {len(p['bytes'])} bytes, SHA-256 `{p['sha256']}`, "
              + (f"decode failed: {p['error']}" if p["kind"] == "not-decoded" else "no decode attempted")
              + (f", extracted to `{p['file']}`" if p.get("file") else "") for p in not_decoded] or ["(none)"]
    lines += ["", "## Extracted payloads (for access; the escrow is `01-copy/bundle.cbor`)", ""]
    lines += [f"- `{p['file']}` ← {visible(p['path'])}, {len(p['bytes'])} bytes, SHA-256 `{p['sha256']}`, {p['kind']}"
              for p in payloads if p.get("file")]
    lines += ["", "## Schema evidence", "",
              "No CDDL schema check was run on this specimen. The release oracle (D-74, `spec/DECISIONS.md`) covers the "
              "fixtures and the demo bundles, not this bundle; the verifier's runtime checks are the only schema evidence "
              "here and they are what run 1 reports.", ""]
    return "\n".join(lines)


def page_06(pinned, decoded, acquisition, files, still_digest) -> str:
    limits = decoded["verdict"]["limits"] if decoded else {}
    hashes = "; ".join(f"`{f['name']}` `{f['destination_sha256']}`" for f in files)
    return f"""# 06 — worksheet, FRE 902(14)

DRAFT. Not reviewed by counsel. A verifier report is not a 902(13)/(14) certification. Federal 902(14)
needs a qualified person's certification and notice and inspection; a Pennsylvania state court applies
Frye to the expert method under Pa.R.E. 702. These are separate questions.

| field | software-filled (from the signed record and the acquisition record) | sworn (left blank) |
|---|---|---|
| hash set | {hashes}; still `{still_digest}`; verdict `bundle_digest` `{pinned['bundle_digest']}`; full list `01-copy/inventory.json` | |
| copy process | {acquisition.get('copy_method')}; collection time `{acquisition.get('collection_time_utc')}` (build host clock, a label); source roots {json.dumps(acquisition.get('source', {}).get('roots'), sort_keys=True)} | |
| tool versions | {json.dumps(acquisition.get('tool_versions'), sort_keys=True)}; platform `{acquisition.get('platform')}` | |
| verifier identity | run 1: published corpus test key, kid `{pinned.get('verdict_kid')}`; run 3: the examiner's own leaf (not pinned here) | |
| time evidence class | `maximum_time_class = {limits.get('maximum_time_class')}`; evaluation time `{pinned['evaluated_at']}` from a producer file | |
| spec version | wire `application/aar-receipt+cbor;v=0.2`, verdict `application/aar-verdict+cbor;v=0.4` (v 6), verifier pyref `v0.4.0` | |
| who can certify collection | the collector label is "{acquisition.get('source', {}).get('collector_label')}" (a label, not a certification) | name: |
| who can explain verification | — | name: |
| qualified person's statement | — | |
| notice given / inspection offered | — | date: |
"""


def page_07(pick, decoded) -> str:
    time_class = decoded["verdict"]["limits"]["maximum_time_class"] if decoded else "n/a"
    return f"""# 07 — the nine questions (2026-10-20)

Each item of evidence an answer relies on is marked **supplied** (with its package path), **unavailable**
(it does not exist for this specimen) or **not collected** (it may exist but is not in this package).

1. **Keep the yes or no with the hash.** Signature and digest checks — supplied: `02-verify/run1.*`, `01-copy/inventory.json`. No similarity score is used anywhere; the still match is an exact SHA-256 identity (`00-READ-FIRST.md` section 5).
2. **Matching stills to frames.** Exact still digest equal to both committed digests — supplied: `01-copy/{pick['still']}`, `00-READ-FIRST.md` section 5. Frame-correspondence evidence — unavailable (this still is a single-JPEG fetch; no video exists for it). A recompressed derivative fails the identity test; there is no threshold.
3. **The footage.** The file is unchanged since the producer committed its digest — supplied (`02-verify`). Camera clock correctness, aim, and what the scene shows — unavailable; `source_authenticity: not_established` is signed on the verdict.
4. **The timestamp.** Receipt times come from the producer host's clock (`maximum_time_class = {time_class}`) — supplied as that label. Independent time evidence — unavailable.
5. **Context.** Camera model and firmware as the producer recorded them — supplied (`05-text-fields.md`, `source_device`/`observer`). Camera settings, position, a second camera, or any context from a source the producer does not control — not collected.
6. **The agent log.** Operator records — supplied: `04-operator-records/` (same administrative domain as the producer, not AAR custody; `chain.jsonl` is an identified derivative, see its companion). Explicit refusals are wire-emitted when they occur, but refusals do not enumerate unattempted actions; off-ontology tool calls are in other logs (onvif-mcp `docs/aar-alignment.md:91`) — not collected.
7. **The AI's instructions.** The inference receipt's prompt, retrieval and transcript manifests are producer-generated placeholders (`00-READ-FIRST.md` section 4, `05-payloads/`) — supplied as placeholders. The AI's actual instructions and conversation — not collected.
8. **The keys and the checker.** Key holders: per-agent key directories under one administration (`00-READ-FIRST.md` section 4) — supplied as a label. The checker: run 3 lets the examiner sign under their own key (`02-verify/README.md`); which verifier code ran is identified, not proven (`03-source-and-run.md`). Independent testing of the verifier by a party other than its author — unavailable.
9. **Admissibility.** `legal_admissibility: not_established` is signed on every verdict. The 902(14) worksheet is a draft with sworn fields blank (`06-worksheet-902-14.md`). Frye/Daubert material (error rate, general acceptance, peer review) — unavailable.
"""


def prohibited_claims() -> str:
    text = (REPO / "docs" / "admissibility-crosswalk-v0.1.md").read_text(encoding="utf-8")
    start = text.index("## 5. Prohibited claims")
    end = text.index("\n## ", start + 1)
    return ("# Appendix — prohibited claims\n\nCopied from `docs/admissibility-crosswalk-v0.1.md` section 5 at the commit "
            "named in `03-source-and-run.md`.\n\n" + text[start:end].strip() + "\n")
