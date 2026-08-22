# Related work addendum — 2026-08-19 reads

Status: **adversarially reviewed 2026-08-22** (round-1 FIX-FIRST: 2 P1 — R-16
overclaim, B.4 marked internal-only; 3 P2 — priority-claim softened, RFC 9943
web-verified, onvif-mcp wire grade qualified; 2 P3 — all applied). Safe as a
source for external quoting EXCEPT §B.4 (internal-only). Written against
`v0.2-rc7` + D-58..D-61 (`65bdf8c`). Same scope rules and citation discipline
as `related-work-v0.2.md`: pins + retrieval dates on every external claim,
verbatim quotes where wording matters, no ranking of products, no claim that a
difference from AAR is a defect. §A below is written from a **full read of the
primary text**; §B from a delegated citation-grade extraction against a pinned
clone (extraction method noted in place). Both sections require the same
round-1 adversarial review the base document received before anything here is
cited in ratification material or quoted externally.

Context for these two reads: the 2026-08-19 competitive board
(vault: `08-Agent-Output/2026-08-19-aar-competitive-board/COMPETITIVE-BOARD.md`)
identified them as the two gates in front of AAR's public positioning — §A
decides align-vs-file at IETF; §B is the open-source convergence the public
comparison essay must survive.

---

## A. draft-mih-scitt-agent-action-capsule-02 — Agent Action Capsules (SCITT profile)

**Pin.** `draft-mih-scitt-agent-action-capsule-02`, 2026-07-06, expires
2027-01-07. Author: Steven Mih, Action State Group, Inc. (spec@actionstate.ai).
Intended status: **Standards Track**; individual submission; stated discussion
venue scitt@ietf.org. Retrieved 2026-08-19 as
`https://www.ietf.org/archive/id/draft-mih-scitt-agent-action-capsule-02.txt`
(1,961 lines) and read in full. Per BCP 79 boilerplate this is a work in
progress and must be cited as such; every claim below is version-pinned to -02.

**One-line relation.** The closest external design to AAR found to date, on a
different substrate: JSON capsules inside COSE_Sign1 SCITT Signed Statements,
anchored (optionally) in any SCITT Transparency Service, recording
verdict-level dispositions — including refusals — with a structural may/did
binding. Its own framing of the split AAR also lives on: *"authorization
records prove permission was granted (may); Capsules prove what occurred
(did)"* (§10).

### A.1 What it specifies

- **Envelope:** COSE_Sign1 Signed Statement per SCITT (RFC 9943 — the SCITT
  architecture RFC; verified against rfc-editor.org 2026-08-22). CWT claims: `iss` (signing
  agent identity), `sub` (`urn:agent-action-capsule:OPERATOR:ACTION_ID`,
  provisional), plus closed `capsule_*` claims (`capsule_statement_type`
  "agent_action"/"outcome", `capsule_action_type`, `capsule_decision_id`).
  Payload media type `application/agent-action-capsule+json`.
- **Payload:** JSON. All digests are `JSON-DIGEST` =
  `HEX(SHA-256(JCS(normalize(v))))` — RFC 8785 canonicalization after
  removing null/empty members bottom-up. *"Monetary and quantity values
  anywhere in a Capsule MUST be exact decimal strings, never JSON
  floating-point numbers; digests are not reproducible across implementations
  otherwise."* (§5.1)
- **Identity:** `capsule_id` content-addresses the envelope (minus itself and
  chain linkage); `operator` (accountable tenant) and `developer` (agent
  identity+version) are payload strings deliberately stable across signing-key
  rotation (§13).
- **Configuration epochs (§5.2):** operator-assigned `epoch_id` rotated on
  behavioral discontinuities (model swap, policy-manifest revision), with an
  epoch-boundary Capsule (`chain.relation: "epoch_opens"`). NOTE: *not* AAR's
  journal epochs — same word, different object (see A.4).
- **Effect Record (§5.3):** `status` ∈ planned / dispatched / confirmed /
  failed / reverted, with the **confirmed-effect invariant**: *"a producer
  MUST NOT emit status: 'confirmed' without a response_digest over the
  actually observed response"* — *"A producer cannot present an attempt as a
  completion"* (§1). Plus `irreversibility_class` (two_way →
  one_way_terminal, ordered) and `effect_attestation` grading WHO vouches:
  seeded `gate_executed` / `runtime_claimed`, with *"unknown never grades
  up."*
- **Disposition (§5.5):** decision, closed `approver` ∈ {human, policy}, and
  the honest HITL flag: `human_disposed: true` REQUIRES `approver: "human"`,
  enforced structurally at construction. `verdict_class` vocabulary of 13
  seeded values (executed, blocked, hitl_dispatched, denied, timeout, errored,
  engine_failure, deferred, needs_decision, expired, escalated, resolved,
  epoch_boundary). **A Capsule on every verdict** (§5.5.3): *"An evidence
  trail that records only successes is survivorship-biased and cannot prove
  its gates ever fired."*
- **Chaining:** single-parent `{parent_capsule_id, relation}` with seeded
  relations supersedes / epoch_opens; HITL resolution is a second Capsule
  superseding the sealed dispatch Capsule; append-only; earliest supersedes in
  ledger order is authoritative.
- **Assurance (§5.4):** attestation_mode (self_attested/anchored),
  effect_mode (not_applicable/dispatched_unconfirmed/confirmed), ledger_mode
  (standalone/chained/anchored) — each **rederived by the verifier from
  evidence actually checked**, overclaims reported.
- **Verification (§6–§8):** two conformance classes. Class 1 = eight ordered
  checks from the record bytes + registries (+ producer store for chain
  checks); *"A verifier MUST return a structured result, never throw"*; *"A
  verifier MUST NOT consult a model, a clock-dependent heuristic, or network
  state to decide ok."* Class 2 adds manifest-aware constraint checks.
  Constraint Records: *"re-running a non-deterministic check is not
  verification."*
- **Registries (§12):** six payload vocabularies under IANA Specification
  Required; *"verifiers MUST treat unregistered values as informational and
  MUST NOT reject a Capsule for carrying one. Registration governs shared
  meaning, never acceptance."*
- **Outcomes (§3.3):** async consequences (reversal, dispute, confirmation)
  are separate Signed Statements correlated by subject/decision id — the
  original is never mutated.
- **Companions:** selective disclosure (SD-JWT/SD-CWT-aligned) and bilateral
  attestation drafts, both referenced not yet read.

### A.2 What it gets right (and AAR should credit, not re-claim)

1. **The honesty boundary, stated as well as anywhere.** §13: *"Tamper-
   evidence is for record bytes, not recorder honesty… A dishonest runtime
   with no external witness can produce an internally valid record of a
   fiction."* This is AAR's G4 exclusion, independently
   arrived at; mih states it in an IETF venue, AAR's threat model v0.1
   (2026-07-14) is an independent statement of the same boundary — no
   priority claim either way. Registration *"bounds the timing of such
   a record and makes its omission or later substitution detectable; it does
   not make its content true."*
2. **Refusals as affirmative evidence.** The same rule AAR proved at Gate 5
   S3 (zero-attributable-dispatch) and onvif-mcp's wire-emitted denials in AAR vocabulary
   (AAR wire conformance in progress) —
   here made a producer MUST over an extensible registry rather than an
   enumerated list.
3. **Verifier-rederived assurance with overclaim reporting** — convergent
   with AAR's verifier rules (G4 "artifacts satisfy declared class") and the
   calibration bar barring "verified" absent an independent observer.
4. **Substrate reuse.** Inclusion proofs, receipts, and log operation are
   inherited from SCITT by reference instead of respecified. AAR's anchoring
   (RFC 6962 v1 floor, same-operator anchor log disclosed as F22) solves the
   same problem with more machinery and a weaker deployment story.
5. **Evidence-grade vocabulary with a floor rule** (`effect_attestation`,
   unknown never grades up) — structurally the same move as AAR's
   provenance-strength classes.

### A.3 Structural differences

| Axis | mih -02 | AAR v0.2-rc7 |
|---|---|---|
| Payload wire | JSON + JCS digests; float ban by prose rule | deterministic CBOR end-to-end; float unrepresentable in the schema |
| Determinism assurance | one in-prose Class 1 test vector; no KAT corpus, no second implementation named | 191 byte-pinned fixtures; two independent impls (one clean-room), 0 divergences; D-56 lesson that same-text impls miss corpus-shaped bugs |
| Authorization ("may") | out of scope — deferred to munoz permit-profile / AgentROA | native: delegation claims, scope, replay_domain, credential status (300 s at AAR-2A/3), D-52 anti-masking, D-60 coordinate checks |
| Outcome evidence ceiling | `confirmed` = producer bound the observed response bytes; strongest seeded grade is `gate_executed` (the engine observed its own boundary) | `outcome-observation` requires a **named independent observer device identity**; "verified" barred without one; dispatch latches at action-bearing send; `contradicted` only on positively observed off-tolerance readback |
| Completeness | registration bounds omission/back-dating timing; no census object | producer-declared epoch contents + census/reconciliation-conditional completeness (G3 narrowed), anchored manifests |
| Verifier failure mode | structured result, never throw | D-61: internal error = loud crash, never a signed verdict — a deliberate opposite ruling worth defending on evidentiary grounds (a verdict emitted by a malfunctioning verifier is itself unsafe evidence) |
| Extensibility | IANA registries, unknown-informational | closed pinned ontology (2 actions), extension = spec revision |
| Anchor | any SCITT Transparency Service (VDS-agnostic) | operator-run RFC 6962 v1 log (F22 same-operator disclosure) |
| Physical world | effect types seeded write_order / send_payment; no actuation legs claimed | live PTZ/stream legs on real cameras, restore semantics (F19), degraded-mode matrix (R-16 — planned mitigation; one crash-cut fault leg exercised at Gate 5 S5) |

### A.4 Collisions to handle in any public text

- **"Epoch" means different things.** mih: configuration epoch (model/policy
  version window). AAR: journal epoch (producer emission window with
  epoch_owner_kid + anchoring). Any joint text must rename or qualify one.
  mih's configuration-epoch idea is real and AAR lacks it: AAR records model
  identity in narrative fields but has no boundary record for "the agent's
  behavior changed here."
- **"Outcome" likewise:** mih outcomes are asynchronous later statements; AAR
  outcome_observations are in-bundle observations. Complementary, not
  identical.

### A.5 The plug-in point (the reason to align rather than compete)

§12.1 registry 5, designated-expert guidance, verbatim: *"plausible future
registrations exist and are deliberately not seeded — for example,
**independent sensor confirmation of a claimed effect**, or hardware- or
TEE-anchored execution; a registration states where its grade sits relative to
the seeded values."*

That unseeded value is the layer AAR has already specified, implemented twice,
and exercised on live hardware. AAR's independent-observer outcome discipline
is an existence proof for the exact `effect_attestation` grade the draft
anticipates; conversely, a SCITT Transparency Service is a conforming
replacement for AAR's weakest disclosed component (F22 same-operator
anchoring). The two designs interoperate at the anchor and grading layers
without either abandoning its wire.

### A.6 The cohort (from §10 — none yet read; listed so absence is visible)

The draft's own related-work section reveals the SCITT agent-evidence space is
a cohort, not a pair: draft-munoz-scitt-permit-profile (pre-execution
authorization — the "may" side AAR carries natively),
draft-emirdag-scitt-ai-agent-execution (operator-signed records + independent
evidence custodian + redaction receipts), draft-kamimura-scitt-refusal-events
/ -scitt-vcp / **-vap-framework** (the last claims hash-chaining, signatures,
SCITT anchoring *and a completeness invariant* — priority follow-up read
against AAR's G3), draft-dawkins-scitt-ai-article50 (EU AI Act Art. 50
receipts), draft-sato-soos-gar (session-level governance records),
draft-nivalto-agentroa (route authorization), NotarizedAgents
(arXiv:2606.04193, witness-cosigned Merkle log), ERC-8004, Mastercard
Verifiable Intent. All individual submissions; none WG-adopted as of the -02
text.

### A.7 Disposition

Cite mih -02 as **the nearest-neighbor evidence model on a standards
substrate**, convergent on: refusal receipts, may/did, verifier-rederived
assurance, evidence-grade floors, and the G4 honesty boundary. AAR's
distinct, uncovered contributions against it: independent-observer outcomes,
native authorization/credential-status machinery, census-conditional
completeness, two-impl byte-pinned conformance discipline, deterministic-CBOR
payloads, and physical-actuation experience (irreversibility, restore).

**Recommendation (Matthew's call): align, don't file a parallel capsule
draft.** Concretely: (1) subscribe scitt@ietf.org; (2) introduce AAR to the
list and the author with the two-impl/live-hardware data — the D-55/D-56/D-57
class of findings is exactly what a WG values; (3) explore contributing the
independent-observer grade as an `effect_attestation` registration and/or a
physical-actuation profile informed by AAR's Gate-5 legs; (4) evaluate a
SCITT Transparency Service as an AAR anchor class (closes F22). Filing an
AAR-shaped I-D remains open as a later move — as a *complementary profile*
(physical-actuation evidence) rather than a competing capsule format.

**Prohibited framings.** Do not describe mih -02 as lacking outcomes or
refusing honesty disclosures (it has both, differently shaped). Do not claim
AAR is SCITT-conformant (it defines no registration flow). Do not quote -02
text as stable — it is a work in progress and must be cited as such. Do not
present "align" as settled — it is a recommendation pending Matthew's ruling
and this document's round-1 review.

---

## B. Obsigna / Agent Receipts (agent-receipts org)

**Pin.** `github.com/agent-receipts/obsigna` (monorepo: spec + tooling) at
HEAD `07448fa95ac2eeffb65ee57db2d18bdf5aef2f0d` (authored 2026-08-11);
shallow-cloned and read 2026-08-19. Repo root Apache-2.0; `spec/` MIT. Sole
human contributor: Otto Jongerius (@ojongerius; 1,119 commits + dependabot).
Created 2026-04-02; 20★/3 forks. Latest full spec = **v0.5.0, Draft,
2026-06-09** (`spec/v0.5.0/spec.md`); protocol versions 0.1.0→0.6.0 in
CHANGELOG (0.6.0 has no spec directory in tree). Frozen cross-SDK vector sets
v0.2.0–v0.5.0 ("Frozen — never regenerate"). Extraction method: delegated
citation-grade read against the pinned clone; quotes below are from in-repo
files at that commit unless marked otherwise. Live-site paraphrases are
excluded per the extractor's own flag — quote from `site/src/content/docs/**`
at the commit pin instead if needed.

**One-line relation.** The nearest same-layer open-source convergence: an
open, generically-named "Agent Receipt Protocol" — *"an open protocol for
producing cryptographically signed, tamper-evident records of AI agent
actions"* (README.md:35) — with Ed25519 over RFC 8785 canonical JSON,
per-chain hash linking, frozen MUST-reject conformance vectors, an offline
verify CLI, and unusually honest limitation disclosures. Obsigna is the
reference toolset; the org owns the `agent-receipts` handle and
**agentreceipts.ai**.

### B.1 What it specifies

- **Envelope:** W3C VC Data Model 2.0-shaped (`type:
  ["VerifiableCredential","AgentReceipt"]`, proof `Ed25519Signature2020`) with
  three disclosed deviations: *"the signing input is intentionally
  simplified… This differs from the full W3C Data Integrity signing
  algorithm"* (§10.2); VC 1.x `issuanceDate` retained (*"The VC 2.0 name
  `validFrom` is not used"*, §4.3.2); base64url `proofValue` instead of
  base58btc (§10.9).
- **Canonicalization/signing:** RFC 8785 JCS with `proof` removed; strict
  null-handling (only `previous_receipt_hash` is required-nullable; optional
  nulls MUST NOT be emitted).
- **Chain:** per-chain linear `previous_receipt_hash` (sha256 of canonical
  predecessor), genesis `null` + `sequence: 1`, strict sequence contiguity,
  single issuer per chain; sub-agents get new chains linked via `delegation`;
  key rotation in-chain (7-field `keyRotation` signed with outgoing key),
  genesis key out-of-band.
- **Schema highlights:** `credentialSubject.{principal, action{id, type,
  risk_level, timestamp, parameters_hash, trusted_timestamp(RFC 3161),
  peer_credential, parameters_disclosure(HPKE)}, intent{conversation_hash,
  prompt_preview, reasoning_hash}, outcome{status, error, reversible,
  reversal_*, state_change{before_hash, after_hash}, response_hash},
  authorization{scopes, granted_at, expires_at, grant_ref}, delegation,
  chain{chain_id, sequence, previous_receipt_hash, terminal, status}}`.
  Hierarchical action taxonomy (filesystem/system/communication/documents/
  financial/data + `unknown` + reverse-DNS custom); risk levels *"MAY
  escalate but MUST NOT downgrade"* (§6).
- **Key custody:** the trust anchor is an out-of-process daemon — *"The agent
  process is untrusted with respect to the receipt chain"*
  (docs/threat-model.md) — own OS user, sole owner of keys and store, captures
  OS peer credentials at accept() into the signed receipt; in-process signing
  allowed as *"a deliberate deployment model, not a footgun"*; AWS KMS signer
  shipped, HSM deferred.
- **Verification:** ordered normative algorithm (§7.8): schema → DID
  resolution (mechanism unspecified, §9.6) → signature → RFC 3161 if present
  → chain (§7.3) → delegation (§7.6). Offline `obsigna verify` static binary;
  `--against-anchor` checks truncation against a checkpoint sink (shipped
  reference sinks: `file:`, `git:`, `syslog:` only).
- **Formal work (ADR-0039):** **Alloy 6** bounded model checking of chain
  invariants, CI-gated — Modification/Insertion/Interior-Deletion/Reorder/
  CrossChainSplice/AppendAfterTerminal detected; master property
  `Soundness_VerifiedIsGenuinePrefix` (*"any verifying log is a genuine chain
  in issuer order, possibly tail-truncated"*). Scopes ≤ 8, non-vacuity runs.
- **Conformance:** 74 frozen vectors (44 canonicalization, 11 MUST-reject
  incl. 4 chain classes, 11 version-pinned, others); three same-author SDKs
  (Go/TS/Python) cross-verify each other's vectors in CI, four workflows.

### B.2 What it gets right (credit, don't re-claim)

1. **Disclosed limitations of unusual quality.** Verbatim: *"Tail truncation
   of an open (non-terminal) chain without any external witness **cannot** be
   detected by any mechanism defined in this specification"* (§7.3.1);
   *"Chain verification proves the integrity of the receipts the verifier is
   given… The receipt store is therefore a trusted component for completeness
   claims"* (§7.3.5); *"a compromised agent key allows production of
   validly-signed but fraudulent receipts that are indistinguishable from
   legitimate ones"* (§10.8); and the anchor-conditional headline: *"Without
   an anchor, post-compromise integrity remains aspirational."*
   (docs/threat-model.md). This is the same honesty register as AAR's
   guarantees section, independently arrived at.
2. **Frozen, never-regenerated vectors + MUST-reject corpora** — the same
   byte-pinning instinct as AAR's KATs.
3. **Machine-checked chain invariants (Alloy 6).** AAR's equivalent
   properties (content-addressed acyclicity by construction, D-19 range
   rules, splice families) are enforced by fixtures and two-impl agreement
   but are NOT model-checked. This is a technique worth adopting, cited to
   ADR-0039.
4. **Process-boundary key custody with OS-attested peer credentials** — a
   deployment-layer answer to "which process asked for this signature" that
   AAR's demo EP does not model.
5. **The self-diagnosis AAR proved empirically.** Verbatim:
   *"because the SDKs share a single author, it does not catch a
   spec-interpretation ambiguity encoded identically into all three"* and
   *"catching spec-interpretation ambiguity would require implementations
   from independent parties, which do not exist yet."* This is precisely
   AAR's recurring lesson (D-56/D-57/D-60 family: under-determination is
   invisible to same-text implementations) — stated by Obsigna as an unmet
   need, and met by AAR's clean-room second implementation with 20 adjudicated
   divergences. It is the sharpest single differentiator between the projects
   and it is one Obsigna's own text validates.

### B.3 Structural differences

| Axis | Obsigna v0.5.0 | AAR v0.2-rc7 |
|---|---|---|
| Wire | JSON + JCS, VC-shaped with 3 disclosed deviations from VC/Data Integrity | deterministic CBOR + COSE_Sign1 throughout |
| Independent implementation | none (*"do not exist yet"*, self-stated); 3 SDKs, one author | clean-room pyref vs TS harness; 46/46 + 191/191, 0 open divergences |
| Completeness | mid-chain gaps = hard failure; open-chain tail truncation undetectable in-band; checkpoint sinks file/git/syslog | producer-declared epoch contents, census/reconciliation-conditional (G3), anchored manifests (RFC 6962 v1 floor; F22 same-operator disclosure) |
| Time | *"Honest system clock"* is a listed trust assumption; timestamps issuer-asserted; RFC 3161 optional | verifier-supplied evaluation time, time classes ranked by provenance, externally_anchored = prior-epoch anchor sandwich |
| Authorization | optional `authorization.scopes` + grant_ref; opt-in grounded-principal tier | signed delegation claims, scope, replay_domain, one_time use, credential status w/ 300 s bound at AAR-2A/3, D-52 anti-masking, D-60 coordinate checks |
| Outcome evidence | producer-asserted `outcome` + before/after state hashes; no observer identity | independent observer device identity required for "verified"; dispatch latches at send; contradicted only on positively observed off-tolerance readback |
| Policy decisions | not in schema | authorization receipts incl. wire-emitted denials in AAR vocabulary (onvif-mcp; AAR wire conformance in progress) |
| Revocation/status | planned v1.5 | shipped (status snapshots, profile-bound max age) |
| Ontology | broad hierarchical taxonomy + `unknown` fallback | closed 2-action pinned ontology (deliberate scope) |
| Verdict | verify result codes; no signed verdict object | signed verdicts binding bundle_digest; a bare PASS is never conformant |

### B.4 Trajectory and collision facts

**INTERNAL ONLY — DO NOT QUOTE OR PARAPHRASE EXTERNALLY.** The roadmap and
cadence observations below describe another author's unlaunched work; using
them outbound would read as surveilling and pre-empting it. Nothing in this
subsection may appear in any public or outbound text.

- Roadmap: an explicit HN launch is planned (*"Post 3"* = OpenClaw/Claude
  Code demo *"published to HN"*, drafted against *"the failure mode that gets
  quoted in the top comment"*), then v1 public protocol release, v1.5
  regulated-industries work (RFC 3161 anchoring, revocation, object-lock
  sinks). Commit cadence tapering through August; no monetization found
  anywhere in repo or site sources.
- Positioning language stakes the generic ground: *"The EU AI Act mandates
  traceability for high-risk AI systems. The regulation exists. The standard
  for how to comply doesn't."* and the gap table row *"| **Action receipts**
  | **Nothing** | **This specification** |"* (spec.md:31) — written as if
  AAR, the mih cohort, and cMCP (the TEE policy-gateway
  project from the 2026-08-19 competitive board) do not exist. That is a survey gap on their
  side, not malice; AAR's public materials must not mirror it.
- Names/domains held: `agent-receipts` org, agentreceipts.ai, obsigna.dev,
  npm `@obsigna/sdk-ts`, PyPI `obsigna`, Go `obsigna.dev/sdk/go`, and an
  `agent-receipts/ar/mcp-proxy` module path (note the `ar` segment).
  Combined with the dormant third-party `botindex-aar-python` ("Agent Action
  Receipts"), the generic name space around AAR's expansion is now
  substantially occupied. AAR's disambiguator is its domain qualifier:
  evidence profiles for agents on **physical-security systems**.

### B.5 Disposition

Cite Obsigna as **the nearest same-layer open-source convergence** and as
independent validation of AAR's method choices (byte-pinned vectors,
MUST-reject corpora, offline verification, honesty disclosures). AAR's
distinct contributions against it: the independent second implementation
Obsigna's own conformance page names as the unmet requirement;
verifier-supplied time vs an honest-clock assumption; anchored
census-conditional completeness vs undetectable open-chain truncation;
authorization/credential-status machinery; independent-observer outcomes;
signed verdicts; deterministic CBOR. Adopt from it: Alloy-style
machine-checked chain/graph invariants (candidate for the gate rubric);
OS-attested peer credentials at the EP seam (candidate, deployment layer).

Engagement is plausibly welcome: the author publicly wants independent-party
implementations and shares the honesty register. A conformance-methodology
exchange (their Alloy work ↔ AAR's two-impl adjudication record) is a
natural, non-zero-sum opening.

**Prohibited framings.** Do not call Obsigna a single-author toy — 1,119
commits, formal methods, and disclosure discipline make it the most serious
open project in the cluster. Do not claim AAR is "more adopted" — both are at
effectively zero adoption. Do not cite the VC-conformance deviations as
defects — they are disclosed design choices. Do not quote the live
agentreceipts.ai pages from fetch-tool paraphrases — quote `site/` sources at
the commit pin. Do not frame the "Nothing → This specification" gap-table row
as bad faith — frame it, if at all, as evidence the category lacks a shared
related-work map.

---

## C. Combined verdict (round-0; Matthew rules)

1. **IETF: align, don't fork.** mih -02 anticipates AAR's
   independent-observer layer as an unseeded `effect_attestation`
   registration and inherits the anchor AAR lacks (any SCITT Transparency
   Service vs F22 same-operator anchoring). Entry: scitt@ietf.org + author
   contact; contribution: the independent-observer grade, physical-actuation
   profile experience, and the two-impl adjudication record. An AAR-shaped
   I-D stays open as a later *complementary profile*, not a competing capsule
   format.
2. **Open source: differentiated coexistence with Obsigna.** The public essay
   credits their method and honesty, then differentiates on the five axes in
   B.5 — led by the fact their own conformance page states the requirement
   only AAR currently meets.
3. **Timing pressure is real.** Obsigna has a planned HN launch and the mih
   cohort is ~10 drafts deep. AAR's Show HN and SCITT introduction should not
   wait on ratification.
4. **Naming:** the generic space ("Agent Receipts", "action receipts", the
   AAR acronym) is occupied. Keep AAR's identity anchored to the
   physical-security qualifier in all public text; a rename decision remains
   open but is not blocking.
5. **Adopt-from-the-board candidates** (gate-rubric material, not urgent):
   Alloy-style invariant checking (Obsigna ADR-0039); configuration-epoch
   boundary records (mih §5.2); standing rubric line already earned by AAR's
   own history: the two-impl bar proves unambiguity over corpus coverage,
   never rule completeness — now externally corroborated by Obsigna's
   same-author disclosure.

Follow-up reads queued (visible-absence list): draft-kamimura-vap-framework
(claims a completeness invariant — bears on G3),
draft-munoz-scitt-permit-profile (the "may" side),
draft-emirdag-scitt-ai-agent-execution (evidence custodian + redaction
receipts vs AAR §8), NotarizedAgents (arXiv:2606.04193), Obsigna ADR-0019 /
ADR-0038 in full.
