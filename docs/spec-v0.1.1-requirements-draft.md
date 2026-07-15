# Agent Action Receipts (AAR) — v0.1.1 REQUIREMENTS DRAFT
## Toward conformance profiles for AI agents acting on physical-security systems

> **STATUS: v0.1.1 REQUIREMENTS DRAFT — 2026-07-14. Not a conformance specification.**
> v0.1.1 folds in errata E-1..E-5 raised by the threat model
> (`07-threat-model-v0.1.md` §10); threat-derived requirement stubs R-15..R-38
> live there and extend §7's register.
> Normative wire objects (CDDL, canonical bytes, signature inputs, validation
> order, KATs) arrive at v0.2 under the edgeproof rc-gate process; until then this
> document pins *requirements and object semantics* only, and nothing in it may be
> cited as testable conformance. Lineage: Claude v0 draft → Codex adversarial
> challenge (26 findings, `01-codex-challenge.md`) → Claude gate
> (`02-gate-dispositions.md`) → this revision. Working name open (§11).
> Independent IP (EdgeProof/Vigil lane). Builds on `edgeproof-sdr` wire discipline
> by reference; resolves the "Phase-2 agent-attestation problem" deferred by
> wire-format-v2 §9.

---

## 1. Thesis, and what AAR does and does not guarantee

Physical security is crossing from recording and decision support into
*delegated authority*. Every vendor will ship an operator agent with Ask / Watch
/ Act modes and a proprietary audit log that proves its own system behaved. No
vendor can certify another vendor's agent. Mixed-vendor enterprises, courts,
insurers, and regulators need proof that survives outside the originating
vendor's trust boundary.

**AAR guarantees, when its requirements are met:**
- **Attribution** — every claim is bound to an identified principal's key, with
  a credential lifecycle that answers "who was authorized at that time."
- **Post-emission tamper evidence** — any alteration of an emitted receipt,
  chain link, or export bundle is detectable by an offline verifier.
  *Emission* must be pinned as an observable protocol event (content-derived
  receipt IDs, issuer sequence/epoch coordinates, equivocation and duplicate
  verdicts — v0.2, R-26); until then a documented equivocation window exists
  (erratum E-5; threat model T-E1/T-E2).
- **Tamper evidence over producer-declared epoch contents** (erratum E-1;
  narrowed from "completeness"). An anchored epoch manifest proves the
  manifest existed by the anchor time; it cannot prove the manifest was
  complete — a compromised EP can acknowledge, omit, and anchor a sanitized
  manifest. Full *completeness* ("nothing admitted was omitted") is claimed
  only where an independently committed ingress census exists or cross-stream
  reconciliation (R-15) is performed.

**AAR does NOT guarantee:**
- Protection against a compromised signer fabricating claims *before* emission.
  A compromised Enforcement Point holding its legitimate key can sign lies. AAR
  makes the lie durable, attributable, and contradictable (§6 outcome levels,
  role-key separation, optional witnesses) — it does not make it impossible.
- Correctness of any inference. Receipts prove identity, authority, and
  outcome — not that the model was right.
- Legal compliance. AAR records purpose and authority claims (§8); it does not
  establish that collection, retention, disclosure, or use was lawful.

## 2. Roles, keys, and the signer matrix

Roles: **Agent** (proposes/requests), **Enforcement Point (EP)** (admits,
decides, dispatches, observes), **Authority Source** (issues delegations and
policy), **Approver** (human principal approving gated actions), **Outcome
Observer** (source of post-action state evidence; may be a distinct device),
**Verifier** (offline third party).

**Role-key separation is normative:** Agent, EP, and Authority Source MUST NOT
share signing keys. Colluding roles signed by one operator remain a documented
residual risk at base tier; independent witnesses / hardware-backed keys are a
stronger optional profile.

Signer matrix (finding 8):

| Object | Signer | Character of claim |
|---|---|---|
| Agent request, inference claims, consumption manifest | Agent | **Agent-attributed** (self-asserted unless provenance level raises it, §5.3) |
| Delegation | Authority Source | Authoritative issuance |
| Approval + presentation manifest | Approver (or EP on approver's strongly-authenticated session) | Delivery/approval, never cognition |
| Ingress acknowledgment, decision record, dispatch | EP | Authoritative for the EP's own conduct |
| Outcome observation | Outcome Observer | Independent to the degree §6 level claims |

Countersignatures are preserved; nothing collapses into a single EP assertion.

### 2.1 Credential profile (minimal, finding 5)
Every signing principal carries a credential binding: issuer root; principal
type (human / service / workload-instance / model-endpoint); tenant/site
binding; validity interval; key id; rotation continuity (successor-of);
compromise/status object. Verifier behavior: signatures within validity and
before a declared compromise time verify with status noted; after compromise
declaration, fail. Status snapshots are **stapled** into authorization decisions
(finding 7) with a profile-maximum staleness; offline EPs operate on leases and
fail closed at lease expiry. Full PKI hierarchy design remains out of scope;
credential *semantics* are in scope.

## 3. Receipt objects and the provenance graph

Encoding discipline inherited from edgeproof-sdr v1.1 by reference
(deterministic CBOR, closed schemas, COSE_Sign1 ES256, strict first-failure
reason codes, externally generated byte-pinned KATs) — binding becomes normative
at v0.2.

Receipts form a DAG with **typed edges** (finding 6): `derived_from`,
`requested_by`, `authorized_by`, `triggered_by`, `attempted_as`,
`observed_outcome`, `supports`. Permitted roots: agent request, human request,
standing condition trigger. Multi-parent ordered sets are permitted (batch
inference over many observations; one inference supporting several attempts).
Agent-to-agent handoffs are explicit nodes. There is no fixed four-stage walk;
the verifier validates edge-type legality, not a single chain shape.

### 3.1 `observation`
Source device identity; **ordered consumption manifest** (finding 10): item ids,
media commitments (hashes), transformations applied (decode/crop/embed/OCR/
truncation), disposition (used/discarded). Native signed-media attestations
(Axis Signed Video, C2PA) carried as assertion + pointer. Time evidence per §5.1.

### 3.2 `inference`
Edges to observations consumed. Model identity (provider/model/version), prompt
hash, retrieval-context hash, tool-transcript hash — all over canonical
manifests included in the verification bundle. Structured conclusion + declared
uncertainty. **Provenance strength level (§5.3) is mandatory and visible** —
base level is self-asserted; conformance never implies independent completeness
of a self-asserted transcript (finding 11).

### 3.3 `authorization`
Delegation reference (reusable, immutable — §4.1) + EP-signed **decision
record** (finding 12): policy-set root hash, effective epoch, evaluated inputs,
decision (permit / deny / permit-with-approval), deterministic decision
commitment, relevant counter/rate state, stapled credential-status snapshots.
For approved actions: approver identity + **presentation manifest** (finding
13) — exact rendered artifacts, deterministic transforms, UI version, delivery
time, session, approval scope. Claims delivery and scope, never what the human
understood.

### 3.4 `action_attempt` / `dispatch` / `outcome_observation` (finding 15)
- **`action_attempt`**: normalized action + canonical command manifest
  (per-adapter; secrets and volatile headers excluded — finding 17) + the
  decision it proceeds under. A refusal is an attempt with `not_dispatched`.
- **`dispatch`** (optional stage): the EP actually issued the command; target
  response status + body hash.
- **`outcome_observation`**: post-action state evidence at a declared **outcome
  evidence level** (§5.2). `outcome_unknown` is a legal, honest state (finding
  16) — crash recovery and reconciliation receipts are required behavior, and
  certainty is never manufactured.

### 3.5 Standing conditions (finding 9)
Watch conditions are **reusable immutable condition receipts** (compiled policy
hash, activation, edit, pause — each lifecycle change receipted) plus
lightweight per-trigger **instance receipts** carrying trigger id and edges to
the condition and its evidence. High-frequency triggers MAY be batched under a
Merkle commitment with per-item extraction proofs. **(E-4)** Batching provides
**membership and tamper evidence only** — an inclusion proof shows membership
in one root, never that every trigger was included; trigger-completeness
claims require an independently enumerable trigger census. Domain-separated
hashing, canonical leaf bytes, index/size binding, root-epoch binding, and
proof limits are pinned at v0.2 (R-28).

### 3.6 Suppression (the sergeant's clause, retained)
Auto-clearing, downgrading, or deduplicating an alert is a consequential
automated action: it requires AAR-2A or AAR-3 (§4). The decision *not* to act
is a use of authority; the suppressed alarm is what opposing counsel subpoenas.
Suppression is *specified* in v0.1 but sits in the experimental appendix for
implementation (gate ruling on finding 18).

## 4. Profiles

Cumulative: AAR-3 ⊇ AAR-2 ⊇ AAR-1; AAR-2A is a subprofile addable to AAR-2.
Requirements are decomposed **per role** (Agent / EP / Authority Source /
Adapter / Bundle / Verifier — finding 21); the tables below name the claim, the
matrices live in the requirements register (§7).

**Completeness boundary (all tiers making completeness claims, finding 4):** the
receipt obligation begins at a **signed EP ingress acknowledgment**. Epochs
carry signed manifests; epoch digests are periodically **externally anchored**
(published checkpoint / independent log / trusted timestamp). Sequence numbers
alone are insufficient. **(E-1)** Anchoring bounds *when* a manifest existed,
not *whether it was complete*: completeness claims additionally require an
independently committed ingress census or cross-stream reconciliation (R-15);
the anchor service is trusted for existence/order by time only (R-24).

### AAR-1 · Observe (read-only; the adoption on-ramp)
| # | Claim |
|---|---|
| 1.1 | Key-bound agent identity under the §2.1 credential profile; signed requests |
| 1.2 | Every admitted query emits observation + inference receipts (obligation from ingress ack) |
| 1.3 | Time evidence class declared per §5.1 (asserted allowed; "trusted" reserved) |
| 1.4 | Standard export bundle; offline Verifier validates attribution + tamper evidence |
| 1.5 | Consumption manifest discloses the full consumed set, ordered, incl. discarded items |

### AAR-2 · Advise (standing conditions; humans execute)
Adds: condition lifecycle receipts (§3.5); presentation manifests on every
recommendation acted upon; human disposition receipts linking to the inference
relied upon. **No automated consequential actions at AAR-2.**

### AAR-2A · Advise+Automation subprofile (finding 3)
Automated dispositions (suppress / downgrade / dedupe / auto-close) carry the
full AAR-3 authorization requirements (delegation, EP decision record,
fail-closed, revocation, completeness anchoring) even though no physical
actuation occurs.

### AAR-3 · Act (bounded physical actions)
Adds: delegation objects validated at the EP before execution; pre-action
decision at the EP, never inside the Agent; canonical command binding; outcome
observation at the strongest supported evidence level (§5.2); fail-closed with
refusal receipts; revocation honored within a profile-bounded, tested staleness
(lease model, §2.1); override/rollback/manual-intervention receipts; epoch
manifests + external anchoring.

## 5. Evidence calibration (the honesty layer)

### 5.1 Time evidence classes (finding 19)
`asserted` (wall clock + monotonic + boot/session id) → `boot-bound`
(monotonic continuity within an attested boot epoch) → `externally-anchored`
(timestamp authority / anchored checkpoint). Only `externally-anchored` may be
called trusted. A consistently falsified clock is detectable only relative to
external anchors — stated, not hidden.

### 5.2 Outcome evidence levels (finding 14)
`accepted` → `dispatched` → `device-acknowledged` → `independently-sensed` →
`contradicted` / `unknown`. "Verified" language is barred unless the action's
ontology entry defines a qualifying independent observer (e.g. door position
sensed by a device other than the controller commanded). Read-back through the
same API is `device-acknowledged`, never `independently-sensed`.

### 5.3 Inference provenance strength (finding 11)
`self-asserted` → `proxy-captured` (independent runtime/gateway recorded the
model I/O) → `provider-attested` (model provider signs the transcript). Level is
carried in the receipt and surfaces in verifier output.

## 6. Action ontology (v0 — cut to two, finding 18)

| Action | Class | Adapter targets |
|---|---|---|
| `camera.stream.view` | read-only (resource side effects noted) | VAPIX; ONVIF/VMS |
| `camera.ptz.preset` | informationally reversible / **operationally lossy** | VAPIX; ONVIF/VMS |

**(E-2)** Reversibility is split into two classes: *informational* (the device
state can be restored) and *operational* (the consequences can be undone).
`camera.ptz.preset` is informationally reversible but operationally lossy —
repositioning a camera can permanently lose incident evidence or open a
coverage gap even if the camera later returns; coverage-loss is a modeled
side effect, not incidental. Each entry defines parameters, both reversibility
classes, required outcome evidence level, and profile floor. **Experimental appendix (specified, not implemented):**
`alert.suppress` (AAR-2A's urgent case), `evidence.bookmark`, `audio.talkdown`,
`notify.send`, `case.create`. **Out of v0 entirely:** access control, evidence
export, relay control — their authorization and outcome models differ too much
to fake equivalence (no-false-parity rule).

## 7. Requirements register (successor to v0's A-1..A-14)

Assertions from v0 are re-scoped per findings 22–25 and held as **requirements**
until the v0.2 wire freeze turns them into pass/fail tests. The register is
extended by threat-derived stubs **R-15..R-38** (`07-threat-model-v0.1.md` §6),
which carry equal standing at the v0.2 freeze:

- R-1 expired delegation → refusal, no dispatch — tested against an
  **instrumented adapter** recording dispatches, not final state alone.
- R-2 one-time vs reusable authorization distinguished; invocation ids, nonce
  scope, restart persistence, idempotency defined.
- R-3..R-6 mutation detection over the verification bundle (media, identity
  manifests, active-policy-set, post-commit transcript) — detection of
  *pre-hash omission* is claimed only at `proxy-captured`+ provenance.
- R-7 time-inconsistency detection scoped per §5.1 classes.
- R-8 contradiction receipts prove *conflicting reports*, attributably — not
  which party lied.
- R-9 completeness: gap, tail-truncation, and epoch-replacement detection via
  anchored epoch manifests.
- R-10 suppression census: receipts reconcile against an independently
  committed alert census (canary + census, not canary alone).
- R-11 presentation manifests use normative deterministic transforms.
- R-12 cross-vendor: shared abstract-command fixtures + adapter-specific effect
  tests (no claim of semantic equivalence of effects).
- R-13 verification split: offline bundle verification vs online
  producer/adapter conformance — separate suites.
- R-14 injected-content forensics require the disclosed consumption manifest in
  the bundle.

## 8. Lawfulness, retention, redaction (finding 20 — new, load-bearing)

- Receipts carry **purpose-of-use, jurisdiction, data-classification, and
  retention-class identifiers**, and legal-hold status.
- **Durable metadata is separated from sensitive payloads**: hashes, identities,
  decisions, and timings are durable; media and biometric-adjacent content live
  in encryptable, erasable stores referenced by commitment. Deletion of payload
  under a retention schedule, sealing, or expungement order leaves a
  **derivation receipt** (what was removed, under what authority, when, by whom)
  so deletion is **attributably recorded**. **(E-3)** A derivation receipt is
  a signed deletion *assertion* — it does not itself establish that replicas
  and backups were erased, that legal hold was honored, or that the deletion
  was not spoliation; those are custody and legal determinations (verifier
  statuses and attestation requirements: R-36).
- Redaction and export are receipted actions.
- AAR records authority claims; it does not establish lawfulness. RFP language
  and certification materials MUST repeat this.

## 9. Relationship to existing work
Unchanged from v0 (edgeproof-sdr = wire discipline + deferred Phase-2; Axis
Signed Video / C2PA = carried media provenance; ONVIF = conformance-regime
template and graduation path; NIST agent-standards initiative = the vacuum being
instantiated; Vigil App Intents = reference Agent surface + AAR-3 EP prototype).

## 10. Non-goals (v0.1)
No wire CDDL (v0.2); no streaming transport; no PKI hierarchy design (credential
semantics only); no correctness claims for inference; no always-on detection
plane receipts; no UI/SaaS; no mandatory witness infrastructure at base tier
(optional stronger profile); no access-control actions.

## 11. Open questions (carried + new)
1. Name (AAR vs alternatives; the after-action-report collision may be a feature).
2. Transparency-log vs published-checkpoint anchoring at base tier — cost floor.
3. Delegation token format: raw COSE vs Biscuit/UCAN-profile — offline-verifiable.
4. Presentation-manifest transform set: what is deterministic across UI stacks?
5. Provider-attested provenance: which model providers can sign transcripts today?
6. Certification economics: SPDX-style self-attestation + published KATs vs
   ONVIF-style paid testing at launch.
7. Approval latency as a receipted quantity for remote approvers.

## 12. Changelog
- **v0.1.1 (2026-07-14):** errata E-1..E-5 from the threat-model gate
  (`06-gate-dispositions-threat-model.md`): G3 narrowed to
  producer-declared-contents tamper evidence (completeness =
  census/reconciliation-conditional); G2 emission-definition requirement +
  equivocation window documented; PTZ reversibility split
  informational/operational with coverage-loss modeled; "demonstrably not
  spoliation" retracted → "attributably recorded"; Merkle batching scoped to
  membership evidence only. §7 register extended by R-15..R-38.
- **v0.1 (2026-07-14):** Codex-gated revision. Guarantee narrowed (attribution /
  tamper evidence / anchored completeness); requirements-draft status; AAR-2A
  subprofile; ingress-ack completeness boundary + epoch anchoring; credential
  profile; typed-edge DAG; attempt/dispatch/outcome split with `outcome_unknown`;
  signer matrix; evidence calibration layer (§5); ontology cut to two actions;
  lawfulness/retention/redaction section; A-register → R-register.
- **v0 (2026-07-14):** initial Claude draft (`00-spec-v0-draft.md`).

---
*Next gates: threat-model full draft (month-1 artifact) → v0.2 wire CDDL + KATs
under the edgeproof rc-gate process → reference Verifier → two-adapter
demonstration (VAPIX + one VMS) → RFP language.*
