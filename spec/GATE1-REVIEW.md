# Gate 1 — Claude review of the v0.2 CDDL candidate
2026-07-14. Reviewed: `aar-core.cddl` (51492fa), `CONFORMANCE.md` (a7ef6fe),
`DECISIONS.md` (af13d19) against `docs/v02-wire-rubric.md` and
`docs/threat-model-v0.1.md`. Verdict: **APPROVED WITH CHANGES** — one MAJOR,
four MINOR, one accepted-deferral note. D-01..D-35 are ratified except as
modified below. Gate 2 (KAT generation) may begin only after the fix pass is
re-reviewed.

## Findings

**G1-1 — MAJOR — the Agent-signed request artifact is missing.**
D-08's root *descriptor* is ratified for graph-root representation, but the
threat model's T-H2/R-15 requires the **Agent's own signed request stream** as
the other half of cross-stream reconciliation (threat model: "the requesting
Agent's signed request receipt … creates the other half of the record").
`correlation-binding` ships `phase: "request"` with no signed production able
to carry the Agent's side: the six node kinds don't include it, and the signer
matrix gives inference to Agent only. Freezing without it forces a wire bump
when R-15's verifier feature lands. **Fix:** add a small `request-envelope`
artifact (raw detached COSE, `artifact-cose-sign1` pattern, content type
`application/aar-request+cbor;v=0.2`): claims = request_id (id16),
request_commitment preimage fields (action intent digest, target_ep_kid,
tenant/site), correlation-binding, freshness, legal-context. The
root-descriptor's `request_commitment` MUST equal SHA-256 of the exact request
claims bytes when kind is `agent_request` (human_request/standing_condition
keep commitment-only). Add envelope-mechanics + reason codes
(`request/commitment-mismatch`, plus the generic cose/schema families) and a
bundle artifact array slot. Reconciliation behavior stays out of v0.2 (D-21
unchanged) — only the artifact and its binding land now.

**G1-2 — MINOR — `requested_by` edge lacks a claim sentence.** The matrix
permits observation/inference parents for `requested_by`, which reads oddly
against the v0.1 spec where requests were the origin. Add one normative
sentence to CONFORMANCE §2.1 defining exactly what claim a `requested_by`
edge makes (proposal: "the child was created in response to the parent's
content; the *originating external request* is carried by the root descriptor
/ request artifact, never by this edge").

**G1-3 — MINOR — `inference-body.consumption_manifest_id` has no resolution
rule.** State normatively what it must resolve to: the `manifest_digest` of a
consumption manifest carried by a parent observation (via `derived_from`) or
a bundle `canonical-manifest-payload`; add a reason code
(`receipt/consumption-ref-unresolved`) and its validation-order position
(step 10).

**G1-4 — MINOR — `epoch_id` is unbounded `uint`.** Everything else numeric is
capped (D-31 caps times at 2^53−1). Bound `epoch_id` (and `-70003`) to
`uint .le 9007199254740991` for consistency and JS-safe interop.

**G1-5 — MINOR — reserved ingress-completeness enum values are unreachable in
v0.2.** `census_supported` / `reconciliation_supported` are correct
forward-compat, but add one normative sentence: a v0.2 verifier MUST emit only
`not_established`; the other values are reserved for the R-15/census feature
and MUST NOT be emitted by a verifier that does not implement it.

**G1-6 — NOTE (accepted deferral) — bundles are unsigned.** A malicious
exporter is unattributed at the bundle layer; the verdict binds bytes but not
the export *act*. Accepted for v0.2 — export/custody lineage is R-35
(threat-model deferred set). Record in DECISIONS as D-36 so it reads as a
choice, not an omission.

## Dispositions on the eight gate questions

| Q | Disposition |
|---|---|
| 1 · Protected labels | **Approve provisional `-70000..-70006`** (COSE private-use range, < −65536). Registration is a launch-time task, not a freeze blocker. |
| 2 · Outcome count | **Six labels stand.** The rubric's "5 outcome" was a rubric typo — the spec's §5.2 vocabulary (6, with contradicted/unknown as unordered terminal states) governs. Gate-2 class-boundary KATs cover the 4-step ordered ladder; contradicted/unknown get dedicated terminal-state KATs, not boundary KATs. Rubric erratum noted here; no rubric edit needed. |
| 3 · AAR-1/2 status age | **Approve 86,400 s** (= lease). Consistent and conservative. |
| 4 · Epoch max duration | **Approve 86,400 s** matching base anchor cadence for v0.2. |
| 5 · Root representation | **Approve root descriptors** — as modified by G1-1 (agent_request roots bind to the new signed request artifact). No seventh node kind. |
| 6 · `complete` terminology | **Approve producer-declared semantics** with the mandatory `ingress_completeness_not_established` observation — this is exactly the narrowed G3. |
| 7 · Anchor floor | **Approve RFC 6962 v1** as the sole base-tier proof protocol. A published-checkpoint second profile is post-v0.2 if ever. |
| 8 · Resource ceilings | **Approve D-30 constants** incl. 16 MiB / 10,000 nodes; committed in verdict config, revisable at a future wire version with data. |

## Ratifications worth naming
- D-01/D-02 (EdgeProof detached-object + single ES256 profile) — exact intent.
- D-05 emission definition — resolves threat-model T-E1/E2 to the extent v0.2
  can; pre-commit equivocation residual correctly retained.
- D-11/D-09 dominance + closed edge matrix — this is R-29 made testable; the
  "removing the authorization disconnects the dispatch" phrasing is the right
  property.
- D-19/D-20 contiguous temporal slices + producer-declared `complete` — the
  honest-completeness design survived contact with the wire.
- D-23 six outcome labels + separate body state — correct reading of the spec
  over the rubric typo.
- Verdict schema hardcoding `source_authenticity`/`legal_admissibility` to
  `not_established` — verdict-laundering resistance built into the type
  system. Keep this exact shape.

## Fix-pass instructions
Apply G1-1..G1-5 (G1-6 = DECISIONS entry only). Update `aar-core.cddl`,
`CONFORMANCE.md` (validation order + reason codes + §2.1 sentence),
`DECISIONS.md` (amend D-08, add D-36, record the Q1–Q8 dispositions as
locked). No KATs, no fixtures, no harness. Commit in logical units. Gate 1
closes when the fix pass is re-reviewed against this document.
