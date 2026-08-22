# Related-work addendum — 2026-08-21

Status: adversarially reviewed 2026-08-22 (round-1 FIX-FIRST: 2 P2 —
publicization date pinned to launch commit 72e529e 2026-08-04, RFC 9943
web-verified; 1 P3 — applied). Pending merge into `related-work-v0.2.md` as §4/§5.
Same citation discipline: every external artifact is pinned; re-verify pins
before quoting externally. Surveyed 2026-08-21 (Claude + Codex dual review of
Wake; §B is a full read of the IETF draft's plain-text archive copy).

---

## A. Wake — local multi-agent session-transcript aggregator

**Pin:** github.com/iAmCorey/Wake @ `bc43026` (2026-08-20, v0.2.0; MIT;
first release 2026-08-18). macOS, Rust + GPUI, ~10.7k LoC, solo author.

### What it specifies

Nothing normative — Wake is a product, not a spec. It reads twelve coding
agents' local session stores read-only (Claude Code JSONL, Codex
`state_5.sqlite`, Copilot/OpenCode/Antigravity SQLite, Gemini/Pi/Grok/Kimi/
Kiro/Cursor variants), normalizes them into one transcript model with stable
per-message sequence numbers and tool-call/result correlation, and indexes
them with SQLite FTS5. External databases are opened `SQLITE_OPEN_READ_ONLY`
with WAL/SHM copied aside (`crates/wake-core/src/adapters/sqlite_ro.rs`).
A contract test suite runs against all twelve adapters
(`crates/wake-core/tests/adapter_contracts.rs`).

### What AAR should cite it for

1. **The most complete open survey of what agent runtimes actually record.**
   Wake's adapter layer is a working map of twelve heterogeneous local log
   formats — which record model identity, session origin, tool inputs/outputs,
   subagent sidechains — and which don't. If AAR ever specifies a
   retrospective/backfill evidence tier (receipts minted from pre-existing
   session logs), Wake's adapters are the extraction prior art, and its README
   support matrix is the coverage baseline.
2. **A worked demonstration of the evidence class AAR must NOT be confused
   with.** Session transcripts are producer-self-reported testimony about what
   the runtime says happened — not proof at the execution boundary. Wake makes
   the gap concrete: normalization is lossy (32 KiB message / 16 KiB tool-I/O
   clips in `adapters/parse_utils.rs`; malformed lines skipped; unknown-record
   counts discarded at `db.rs` upsert), freshness is mtime-based not
   integrity-based, exports are unsigned uncanonicalized JSON
   (`services/exporter.rs`), and tombstones are UX state, not deletion
   receipts. Every one of those absences is an AAR feature; citing Wake lets
   the spec name the "transcript-derived, self-reported" assurance tier
   precisely and place it below boundary-attested receipts.

### Structural differences

Wake answers "find and resume a past conversation"; AAR answers "prove what an
agent did." No signer, no hash chain, no canonical encoding, no trusted time,
no verifier. Convergences worth recording anyway: local-first / zero-network
operation, index-rebuildable-from-source-of-truth, read-only ingestion of
other parties' records, and explicit honesty about encrypted/cloud-only
sources it cannot read — the same disclosure posture AAR's non-guarantees
section takes.

### Disposition

Cite, don't depend. Young (first release 2026-08-18), solo-maintained,
macOS-only, presentation-oriented data model. If a retrospective tier is ever
built, vendor the parsing knowledge (formats, correlation rules, sidechain
layouts) rather than the crate, and put a lossless layer beneath it: raw
record locator, original event ID, source-artifact digest, causality.

---

## B. draft-sahu-agent-action-receipts-00 — Signed, Hash-Chained Action Receipts for AI Agents

**Pin.** `draft-sahu-agent-action-receipts-00`, Nancy Sahu, kriya native
(nancysahu@kriyanative.com, India), Informational individual submission, no
IETF working group, dated 2026-08-16, expires 2027-02-17. Retrieved 2026-08-21
as `https://www.ietf.org/archive/id/draft-sahu-agent-action-receipts-00.txt`
(1064 lines). **Full read of the primary text**, same round-1 adversarial
review required before external citation.

### B.1 What it specifies

A minimal wire format for "action receipts": one JSON object per action,
newline-delimited into a per-signer log. Nine members: `step_id`, `action_id`,
`params` (any JSON), `success` (boolean), `ts_ms` (host-asserted epoch ms),
optional `actor` (`agent`/`user`, self-asserted), optional `prev_hash`, plus
carried-but-unsigned `public_key` and `signature` (Ed25519, RFC 8032,
lowercase hex). Canonicalization (§4) is bespoke: fixed **non-lexicographic**
outer member order, code-point-sorted member names inside `params` only,
integer-only number guidance. Chain linkage (§6): `prev_hash` = SHA-256 of the
**transmitted octets** of the previous line, including its signature and any
unrecognized members — the draft's one claimed distinguishing construction
(chain verification needs no canonicalizer and covers extensions). Verification
(§7) is a pure offline function of the log plus an out-of-band trust anchor;
unparseable lines MUST surface as failures, and key-to-identity binding (step
6) is explicitly non-optional. Requests media type
`application/agent-receipt+json`. Three in-prose test vectors (test key = 0x01
×32). Implementation status: deployed in kriya native's commercial macOS
agent-governance product, four verifier implementations claimed; the vectors'
`action_id` values (`kriya.gate.decision`, `kriya.gate.approval`) show the
deployed use is **gate/policy decisions**, with signer = the enforcement point
co-located with the agent, not the agent itself.

### B.2 What it gets right

1. **Verify-over-received-bytes discipline** at the chain layer — the same
   ruling AAR's CDDL makes for COSE ("the received bytes, never a
   re-encoding"). Independent convergence worth citing when defending that
   choice.
2. **An honest non-guarantees register** (§9) in AAR's own voice:
   tamper-evidence not tamper-proofing, compromised-signer forgery, unrecorded
   actions leave no trace, head truncation undetectable without external
   state, `ts_ms` asserted not attested, canonicalization as attack surface.
3. **Loud verification failure**: a malformed line MUST NOT be silently
   skipped — kin to D-61's refusal to emit verdicts from a malfunctioning
   path (though sahu still returns a structured failure rather than crashing).
4. **Privacy floor** (§10): digests/identifiers/decisions in `params`, never
   payloads or prompts; selective disclosure deferred to
   `draft-mih-scitt-agent-action-capsule-sel-disc` — composing cleanly because
   the chain digests transmitted octets.
5. **A candid §1.1** naming eight concurrent drafts and disclaiming novelty
   for signing, chaining, and offline verification as such.

### B.3 Structural differences

| Axis | sahu -00 | AAR v0.2-rc7 |
|---|---|---|
| Wire | JSON, bespoke canonical order (JCS adoption an open issue) | deterministic CBOR end-to-end, floats unrepresentable |
| Signature | raw Ed25519 over canonical bytes, no domain separation (open issue) | detached COSE_Sign1, ES256/RFC 6979, low-S |
| Topology | single linear chain, one writer per log; no sequence numbers (open issue) | receipt DAG: observation → inference → authorization → action_attempt → outcome, multi-principal roles |
| Authorization | one boolean-outcome record of a policy decision; delegation/credential status absent | native delegation claims, scope, replay_domain, 300 s credential status, anti-masking |
| Outcome | `success: true/false`, producer-asserted | independent-observer outcome discipline; "verified" barred without a named observer identity |
| Completeness | disclaimed — "says nothing about actions the signer declined to record"; head assertions deferred to future revision | producer-declared epoch contents, census/reconciliation-conditional, anchored manifests |
| Anchoring | none required by design (air-gap constraint); RFC 3161 / SCITT / ledger named as compositions | RFC 6962 v1 anchor floor (F22 disclosure) |
| Conformance | 3 in-prose vectors, one producer + verifiers from the same vendor | 191 byte-pinned KATs, two independent implementations, class-boundary/negative fixtures |
| Domain | generic software actions (deploy, DB, payments); no actuation | physical-security actuation: live PTZ/stream legs, restore semantics, degraded-mode matrix |
| Status | Informational, individual, commercial deployment behind it | independent public spec, ratify path open |

None of these differences is a defect in sahu — it optimizes for smallest
verifiable record in disconnected deployments, and its §9 discloses precisely
what that costs. It answers "has this log been altered"; AAR answers "what is
independently provable about what the agent saw, was authorized to do, and
actually did."

### B.4 The name collision, precisely

The draft's filename (`agent-action-receipts`) and requested media type occupy
AAR's exact public name; its title does not use the phrase, and the acronym
"AAR" appears nowhere in it. AAR's public artifacts under this name predate
the draft: repository created 2026-07-15 (gh API), public since 2026-08-04
(launch commit 72e529e), both before sahu -00 (2026-08-16). Handling:
any AAR public text should cite the draft by full name on first use and state
the scope difference in one line (record format for log integrity vs
conformance profiles for evidence-grade actuation). Do not claim the draft
"took" the name — convergence on obvious words is the acknowledged norm in
this cohort (sahu's own Acknowledgments make the same point) — but do not
cede the name either: AAR's usage is prior and continuously published.

### B.5 Cohort notes

sahu's §1.1/§15 confirm and extend the cohort mapped in the 2026-08-19
addendum §A.6. New names not previously listed there:
`draft-farley-acta-signed-receipts-02` (predecessor-linked decision receipts),
`draft-marques-asqav-compliance-receipts-07` (regulatory profile **of
farley** — a profile-of-a-profile, sign of a maturing cluster),
`draft-msebenzi-evidence-action-00` (post-hoc recomputable evidence — nearest
to the retrospective tier discussed in §A above),
`draft-sharif-agent-audit-trail-00`, `draft-melegassi-opsawg-mvps-logging-00`
(head-assertion construction sahu defers to),
`draft-kuehlewind-audit-architecture-00` (Kuehlewind + Birkholz —
**IESG/SCITT-chair-adjacent authors; the architecture document this cluster
will likely organize under; priority read**), `draft-noa-scitt-ai-agent-receipt-01`,
and normative anchors [ISO/IEC FDIS 24970] (AI system logging) and
[EU-AI-ACT] Art. 12 — the same regulatory hooks AAR's RFP language should
cite. RFC 9943 (SCITT architecture) independently verified against
rfc-editor.org 2026-08-22.

### B.6 Disposition

Cite as **the minimal-record pole of the cohort**: the smallest offline-
verifiable receipt with deployed code behind it, and the cleanest published
statement of what self-anchored chains cannot prove. AAR's uncovered
contributions against it are the same list as against mih -02, plus:
DAG-vs-chain, independent-observer outcomes, census-conditional
completeness (census machinery planned, R-15), and a
conformance corpus. Convergences to cite in AAR's defense file:
received-bytes verification, honest-non-guarantees register, loud failure.

Recommended actions (Matthew's call):
1. Fold this survey into `related-work-v0.2.md` after round-1 adversarial
   review, alongside the mih -02 read.
2. The align-don't-file recommendation from the 08-19 addendum §A.7
   strengthens: three-plus independent receipt formats now exist; a fourth
   generic format would add noise, while AAR's actuation/outcome/completeness
   layers remain unclaimed by all of them.
3. Read `draft-kuehlewind-audit-architecture-00` next (architecture the
   cohort may organize under) and `draft-msebenzi-evidence-action-00`
   (retrospective-tier overlap), before any public comparison essay.
4. Add the one-line name-disambiguation sentence (§B.4) to the README the
   next time it is touched.

---

## Proposed §3 additions (not yet surveyed)

- **DeltaDB (Zed Delta)** — already on the operator's watch-list as AAR prior
  art; not read. Named here so its absence is visible.
- From sahu's citation graph, in priority order:
  `draft-kuehlewind-audit-architecture-00`,
  `draft-msebenzi-evidence-action-00`,
  `draft-farley-acta-signed-receipts-02` +
  `draft-marques-asqav-compliance-receipts-07`,
  `draft-emirdag-scitt-ai-agent-execution-00`,
  `draft-noa-scitt-ai-agent-receipt-01`,
  `draft-sharif-agent-audit-trail-00`,
  `draft-melegassi-opsawg-mvps-logging-00`,
  `draft-fassbender-scitt-time-anchor-03`, ISO/IEC FDIS 24970.
