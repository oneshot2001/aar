# AAR Threat Model — v0.1
## Adversaries, attack surface, and residual risk for Agent Action Receipts

> **STATUS: v0.1 THREAT MODEL — 2026-07-14. Companion to `03-spec-v0.1.md`
> (requirements draft).** Lineage: Claude v0 draft (`04-threat-model-v0.md`) →
> Codex adversarial challenge (30 findings, `05-codex-challenge-threat-model.md`)
> → Claude gate (`06-gate-dispositions-threat-model.md`) → this revision.
> Scoring rule inherited from the gate: **planned v0.2 work is never cited as a
> v0.1 counter.** Coverage vocabulary: `planned` (v0.2 requirement stub exists)
> / `partial` (structural counter exists in v0.1 requirements) / `disclosed`
> (residual made visible by class or label — no likelihood or impact reduced)
> / `residual` (no control) / `n/a`. This document raises five errata against
> `03-spec-v0.1.md` (§10) to be folded in at the next spec revision.

---

## 1. Scope, trust boundaries, and data flow

Modeled: the **receipt system** per `03-spec-v0.1.md` — six roles, the receipt
DAG, epochs and anchoring, export bundles, the offline Verifier. The physical
security system (cameras, VMS, controllers, networks) is *outside the
conformance boundary but inside the threat model*: its compromise is a
first-class adversary capability (§3), because false-but-faithfully-receipted
sensor evidence and out-of-band actions are the principal physec attack paths
(gate finding 4).

**The instrumented-control boundary.** AAR covers only actions that traverse
the instrumented EP, and only claims *as asserted by* the named source device.
Actions dispatched around the EP (direct VMS console, vendor app, physical
access to the device) produce no receipts and are undetectable by AAR alone.
This boundary statement is normative context for every completeness claim in
this document.

Trust boundaries (flows cross these; each crossing is attack surface):

```
[Scene / physical world]          ← TB-0: sensors observe; attacker-controllable
      │
[Source devices / Outcome Observers]  ← TB-1: device ↔ EP (signed observations)
      │
[Agent] ──requests──▶ [EP] ◀──delegations── [Authority Source]
      │                 │  ▲
      │                 │  └─approvals── [Approver session]   ← TB-2: human UI
      │            dispatch
      │                 ▼
      │            [Adapters → targets]                        ← TB-3: adapter seam
      │
[Receipt store / epochs] ──export──▶ [Bundle] ──▶ [Verifier]   ← TB-4: evidence phase
      │
[External anchor service(s)]                                   ← TB-5: anchoring
[Issuer roots / status service]                                ← TB-6: credential plane
```

**Assets** (what attacks target): signing keys and credentials; receipt bytes
pre- and post-emission; the DAG's edge structure; epoch manifests and anchor
records; consumption/presentation/command manifests; the census of what
*should* have receipts; bundle scope claims; verifier verdicts; and the
sensitive content receipts commit to (privacy asset).

## 2. Defended claims

- **G1 Attribution** — every claim binds to an identified principal's key,
  with credential lifecycle answering "who was authorized at that time."
- **G2 Post-emission tamper evidence** — alteration of an emitted receipt,
  chain link, or bundle is detectable offline. **Emission must be defined as
  an observable protocol event** (receipt acquires a content-derived ID +
  issuer sequence/epoch coordinates at a defined commit point); until v0.2
  pins this, G2 has a documented equivocation window (T-E1/T-E2).
- **G3 (narrowed, gate finding 1)** — at base tier: **tamper evidence over the
  producer-declared contents of anchored epochs.** True *completeness* —
  "nothing admitted was omitted" — is claimed only where an independently
  committed ingress census exists or cross-stream reconciliation (R-15) is
  performed. An anchored manifest proves a manifest existed by a time; it
  cannot prove the manifest was complete. *(Erratum E-1 against spec §1.)*
- **G4 (demoted from guarantee to verifier rule, gate finding 3)** — the
  Verifier confirms that **artifacts satisfy the declared evidence class**
  (time §5.1, outcome §5.2, provenance §5.3) and never reports more:
  "artifacts satisfy declared class X," not "the process deserved class X."
  A distinct observer key does not prove sensor independence; a provider
  signature does not prove transcript completeness. Qualification predicates
  per class (failure-domain independence, coverage semantics, anchor
  semantics) are v0.2 normative work (R-18).

## 3. Adversary model — capabilities, principals, coalitions

Per gate finding 8, adversaries are modeled as **atomic capabilities**
composed into principals and coalitions, not a numbered severity ladder.

**Atomic capabilities:**

| Cap | Meaning |
|---|---|
| C-key(role) | Possess a role's signing key (or live signing-oracle access — key theft and oracle access differ in detectability, not power) |
| C-presign(role) | Control bytes before that role signs (malware on the signer host) |
| C-store | Control the persistent receipt store / epoch machinery |
| C-net | Observe/modify/replay/drop traffic between roles |
| C-scene | Control observed physical content (scene staging, planted text, occlusion) |
| C-device | Control a source device or Outcome Observer (firmware, config, video replay into it) |
| C-oob | Operate targets out-of-band, bypassing the EP entirely |
| C-trust | Control a trust anchor: issuer root, status service, anchor service, verifier trust store |
| C-export | Control bundle assembly / evidence custody |
| C-present | Control how verdicts/evidence are presented to a decision-maker (court, auditor) |

**Named principals** (each gets its own residual treatment — gate finding 8
split these from the old "colluding operator"): malicious Agent (C-key(Agent)
+ C-presign(Agent)); compromised EP (C-key(EP) + C-presign(EP) + C-store);
malicious Authority Source; compromised credential issuer / root admin
(C-trust); malicious status/revocation service (C-trust); compromised Outcome
Observer (C-device + C-key(Observer)); compromised source device (C-device);
malicious insider user/approver (valid credentials, lawful-looking scope —
including the **LE insider**, §4.9); out-of-band operator (C-oob); scene
manipulator (C-scene, *no keys at all*); anchor-service adversary (C-trust);
malicious exporter/custodian (C-export); evidence-phase adversary (C-export +
C-present); network attacker (C-net); availability attacker (any capability
used to exhaust rather than forge); malicious bundle presenter / trojan
verifier (C-present).

**Coalitions that matter:** single-administrator control of all role keys
(one admin, separate keys — this requires *no collusion*, gate finding 17);
EP + exporter (sanitized history end-to-end); insider + approver (formally
valid abuse); device + EP (false observation with consistent countersigning).

**Exclusions (out of model, stated):** cryptanalytic breaks of ES256/SHA-256;
hardware side channels; the model provider as a global adversary beyond §5.3's
reach; coercion of courts. *Not* excluded (v0 wrongly did): the physical
security system, adapter/runtime substitution, evidence custody.

## 4. Threat enumeration

Format: threat → capabilities required → claim attacked → v0.1 status
(`partial`/`disclosed`/`planned`/`residual`) → v0.2 hook. Grouped rows from v0
are split per gate finding 6.

### 4.1 Credential plane (G1) — TB-6

| ID | Threat | Caps | Status | Counter / hook |
|---|---|---|---|---|
| T-I1 | Principal minting under compromised/sloppy issuer root | C-trust | **residual** (root compromise) / partial (out-of-tenant detection) | §2.1 tenant binding; tenant-scoped root *acceptance* rules = planned (R-19); KAT: out-of-tenant credential → distinct failure code |
| T-I2 | Post-compromise signing, backdating into unanchored history | C-key | partial | §2.1 status objects + pre/post-compromise verifier behavior; anchored epochs pin what existed; unanchored asserted-time history = **disclosed** via time class |
| T-I3 | Rotation-seam confusion / orphaned chains | C-key | partial | §2.1 successor-of continuity; KAT planned |
| T-I4 | Stapled-status staleness gaming | C-key(EP) | **planned** | v0.1 names the mechanism but defines **no numeric profile maxima** (gate finding 13) — R-20 sets per-profile lease/staleness numbers; until then this cell is not a counter |
| T-I5 | Path-construction ambiguity, key-usage confusion, algorithm downgrade | C-presign | planned | R-19: path/usage/algorithm rules + trust-store snapshot in bundle |
| T-I6 | Status-service equivocation; malicious retroactive compromise time | C-trust | **residual** | split from generic "revocation"; independent status witnessing = stronger profile |
| T-I7 | Cloned key signing concurrently at two sites | C-key | **residual** | detectable only via sequence/epoch overlap analysis = planned verifier feature |

### 4.2 Receipt production — fabrication & class inflation (G1, G4 rule)

**T-P1 — Signer fabrication within authority.** Caps: C-key + C-presign for
one role. A lone compromised EP signs an internally consistent decision,
dispatch, manifest, and `device-acknowledged` outcome — key separation does
not stop this (gate finding 17). Status: **partial** — attribution holds (the
lie is signed and durable); cross-role contradiction is *possible* when
another role independently observes and exports; nothing more. The four
separations (key / principal / administrative-domain / failure-domain) are
distinct rungs; base tier requires only key separation. **The spec's headline
residual (RR-1/RR-2).**
*Hook:* R-8 contradiction receipts; witness profile definition (R-21) is what
makes stronger claims real — until it exists, "witness profile" may not be
cited as a bound.

**T-P2 — Evidence-class inflation.** Caps: C-presign. Claiming
`externally-anchored` time / `provider-attested` provenance /
`independently-sensed` outcome without qualifying artifacts. Status:
**planned** — the G4 verifier rule needs R-18 qualification predicates plus
per-class-boundary KATs; v0.1 only mandates visible labels. Verdict language
is capped at "artifacts satisfy declared class."

**T-P3 — Consumption-manifest sanitization.** Caps: C-presign(Agent). Status:
**disclosed** at `self-asserted` provenance (omission undetectable by design,
said out loud); partial at `proxy-captured`+ — and even proxies miss
provider-side retrieval, caches, system prompts, multimodal preprocessing
(gate finding 18). Proxy coverage attestation = planned (R-22).

**T-P4 — Injected-content action laundering.** Caps: C-scene or corpus
control; *no keys*. The camera scene is attacker input. Status: **partial,
conditional** — forensic value exists only at a defined capture boundary and
provenance level; the verdict is "the item was disclosed among captured
inputs," never "causal chain reconstructed." At base provenance the injected
item may simply be absent (T-P3). Residual RR-8.

**T-P5 — Approval-context manipulation / approval forgery.** Caps:
C-presign(EP) or C-net. Spec §2 lets the EP sign approvals "on the approver's
strongly-authenticated session" — a compromised EP can therefore assert both
presentation *and* approval (gate finding 19). Status: **partial** at best.
Hooks: R-23 — approver-originated proof-of-possession over a fresh challenge
binding action + decision + presentation digest + session + expiry; evidence
ladder `assembled → delivered → rendered → human-approved`, each a distinct
claim; trusted-client capture = stronger profile. Cognition, inattention,
deception-within-faithful-manifest, coercion: **residual** (RR-7).

### 4.3 History integrity — omission, equivocation, epochs (G2/G3)

**T-H1 — Post-ingress drop with sanitized manifest.** Caps: C-key(EP) +
C-store. The EP acks a request, omits ack + descendants from the manifest,
anchors the sanitized manifest, exports clean. **The v0 model wrongly marked
this countered (gate finding 1).** Status: **residual at base tier**; becomes
partial only with an independently committed ingress census or R-15
cross-stream reconciliation. This is why G3 is narrowed (§2).

**T-H2 — Pre-ingress drop.** Caps: C-key(EP) or C-net. No ack ever issued.
Status: **residual** single-sided; R-15 makes it *detectable-but-unattributable*
(verdicts below).

**T-H3 — Tail truncation / stale-head export.** Caps: C-export. Status:
**partial, conditional** — "visibly incomplete" requires the verifier to have
a trusted evaluation time, a declared maximum anchor cadence, and the expected
current head (gate finding 20); absent those, staleness is invisible offline.
Hooks: R-24 anchor-freshness semantics.

**T-H4 — Cherry-picked bundle / subjective scope.** Caps: C-export. Status:
**partial** — objective selectors (tenant/site, type, subject ID, interval) +
committed selector + range proofs against manifests = planned (R-25); semantic
relevance ("everything about incident X") is **presenter-attested, always**.
Exports without range proofs are labeled *valid subset*, never *complete*.

**T-H5 — Suppression-census gaming.** Caps: C-key(EP). Status: extension
surface (suppression is experimental, spec §3.6); the census is only as strong
as its committer's independence — same-EP census is defeated by the same
compromise. Marked `planned/experimental`.

**T-E1 — Equivocation / reissuance (NEW, gate finding 2).** Caps: C-key.
Signer emits receipt A to one recipient, conflicting receipt B with the same
semantic identity elsewhere, omits A pre-anchor. No byte altered; both
signatures valid. Status: **residual** until emission is defined. Hooks: R-26
— content-derived IDs, issuer sequence coordinates, identity-reuse
prohibition, duplicate/equivocation verdicts, fork-consistency fixtures.
Pre-commit equivocation window remains **residual** (RR-13).

**T-E2 — Emission denial.** Caps: C-key. "We never emitted that receipt."
Status: **residual** absent recipient acknowledgment, witness submission, or
bounded-time external commitment (R-26).

**T-E3 — Epoch machinery attacks (NEW, gate finding 11).** Caps: C-store.
Overlapping epochs, ID reuse, retroactive boundary moves, late insertion,
premature close, phantom empty epochs, rollback to an old anchor cursor, two
manifests for one epoch, forked anchor targets, incident-straddling epoch
sizing. Status: **planned** — R-27 epoch state machine (monotonic IDs,
predecessor digest, first/last sequence, item count, open/close + late-arrival
+ max-duration rules, anchor deadline, fork handling); verifier distinguishes
"valid prefix" from "complete through time T."

**T-M1 — Merkle batching attacks (NEW, gate finding 16).** Caps: C-store.
Duplicate leaves, ambiguous serialization, missing index/size binding,
leaf/internal confusion, proof reuse under another batch, root substitution,
withheld extraction proofs, root never bound to an epoch. Status: **planned**
— R-28 (domain-separated hashing, canonical leaf bytes, batch ID + tree size +
index, root signer + epoch binding, proof limits, KATs). Until then batching
is described as **membership/tamper evidence only** — never trigger
completeness. *(Erratum E-4 against spec §3.5.)*

### 4.4 Graph semantics (NEW family, gate finding 7) — G1/G2

**T-G1 — Graph splicing / provenance laundering.** Caps: C-presign or
C-export. Attach a real authorization to the wrong attempt; splice a favorable
observation subgraph from another incident/tenant/epoch; duplicate node
identities; dangling parents; substitute one valid parent for another;
present `supports` edges as causation. A syntactically valid, acyclic graph
can launder an action through an unrelated valid delegation. Status:
**planned** — R-29: per-node/per-edge invariants, tenant/site/epoch binding on
every node, referential closure of bundles, **dominator requirement** (every
dispatched action is graph-dominated by exactly its valid decision +
delegation), root allowlists, cross-epoch edge rules, adversarial graph
fixtures. Until R-29, edge-type legality checking (spec §3) is **partial**.

**T-G2 — Object replay across contexts (generalized replay, gate finding 22).**
Caps: C-net or C-export. Replay of signed *queries* (disclosure/exhaustion),
trigger instances, human dispositions, approvals transplanted to other
actions, observations/inferences/proofs reused in other graphs. Applies at
**every profile**, not just AAR-2A/3. Status: **planned** — R-2 broadened:
freshness + replay domain per object type; intended-parent binding inside
signatures; durable invocation/idempotency state; crash-safe duplicate
semantics.

### 4.5 Authorization plane (G1)

**T-A1 — Authorization replay** — merged into T-G2 (replay is graph-wide).
**T-A2 — Active-policy fabrication.** Caps: C-key(EP). Split per gate finding
21: *post-emission* substitution of policy bytes = **partial** (decision
record + anchor pins the claim); *pre-emission* fabrication — EP picks a
favorable policy root and input set at decision time — = **residual** unless
the Authority Source independently commits policy activation/precedence per
epoch (R-30, planned).
**T-A3 — Scope creep within valid delegation.** Caps: valid credentials only.
Status: **disclosed** — the record makes over-delegation auditable; AAR does
not prevent it. RFP guidance: least-scope delegation.

### 4.6 Time (supporting all claims)

**T-T1 — Consistent clock falsification.** Status: **disclosed** within
`asserted` class; partial against external anchors (existence-by-time bounds
only). **T-T2 — Cross-boot monotonic games.** Status: partial (§5.1
boot/session ids). Clock-challenge in court belongs to §4.10.

### 4.7 Crash windows (G3 local)

**T-R1 — Side-effect-before-persistence crash.** v0 cited "atomic
persistence-before-dispatch" as a counter; **the spec never requires it**
(gate finding 23 — conceded). `outcome_unknown` names the state; it does not
close the window, and reconciliation can itself duplicate effects. Status:
**planned** — R-31: write-ahead state machine (`prepared → dispatching →
acknowledged → reconciled`), fsync/durability boundary, adapter idempotency
contract, invocation-ID propagation, per-action reconciliation; instrumented-
adapter crash-cut tests. **n/a below AAR-3** (no consequential dispatch).

### 4.8 Availability & flooding (NEW scope, gate finding 24)

**T-R2 — Receipt-path outage as kill switch.** Caps: any exhaustion vector.
The v0 degraded-mode sketch was **unsafe** (gate finding 5). Status:
**planned** — R-16 rebuilt as an **action-specific safety matrix**:
- Failure domains separated: credential status / signer / primary journal /
  replica / exporter / anchor. Anchoring is asynchronous and **never gates
  dispatch**.
- Pre-allocated append-only emergency journal; bounded backlog + anchor
  deadlines; break-glass manual paths with signed entry/exit + reconciliation
  receipts.
- Hazard analysis selects fail-safe / fail-secure / fail-operational **per
  ontology action**; normative principle: **AAR never overrides the site's
  life-safety control design.**
- The degraded flag is signed by the same possibly-compromised EP —
  independent health/anchor monitoring is the only honest visibility
  (**residual** at base tier without it).

**T-R3 — Producer-side exhaustion / audit flooding.** Receipt-ID, disk,
signing-throughput, trigger-cardinality, proof-generation, anchor-quota
exhaustion; refusal storms; AAR's own fan-out as amplifier. Status:
**planned** — R-32: per-tenant quotas, bounded fan-out and object sizes,
reserved audit capacity, backpressure disposition receipts, rate-state
persistence; "what evidence is lost when no receipt can be written" stated
per failure domain.

### 4.9 Physical system & out-of-band paths (NEW family, gate finding 4)

**T-S1 — Compromised source device.** Caps: C-device. Perfectly signed false
observations: replayed video into the encoder, tampered firmware, staged
analytics. Status: **residual** — AAR proves *what the named device asserted*,
never sensor truth. Native signed-media (Axis Signed Video, C2PA) narrows the
replay window when present and verified — partial where deployed.
**T-S2 — Compromised Outcome Observer.** Caps: C-device + C-key(Observer). A
distinct key on the same device/stack/admin-domain is not independence (gate
finding 17); `independently-sensed` requires topology/credential assertions
establishing a qualifying independent sensor in a distinct failure domain
(R-18 predicates). Status: **planned**.
**T-S3 — Scene manipulation.** Caps: C-scene, no keys. Staged events, planted
text (couples to T-P4), occlusion, lighting attacks. Status: **residual** —
out of AAR's power by construction; stated so RFP language can't imply
otherwise.
**T-S4 — Out-of-band operation.** Caps: C-oob. Direct VMS console, vendor
app, physical device access — no receipts exist. Status: **residual** at the
AAR layer; mitigation is deployment architecture (route all agentic and,
where feasible, human control through the EP) — deployment guidance, not
conformance.
**T-D1 — Adapter/runtime substitution.** Caps: C-presign(EP-host). Receipt
carries adapter name/version = self-assertion; certified-then-swapped binary
is **in-scope residual** at base tier (v0 wrongly dismissed it as supply
chain); measured/attested runtime identity = stronger profile (R-33).
`camera.ptz.preset` is **operationally irreversible** when repositioning
loses incident coverage — ontology reversibility split into informational vs
operational classes; coverage-loss is a modeled side effect. *(Erratum E-2
against spec §6.)*

### 4.10 Insider misuse & the evidence phase (NEW families, gate findings 9–10)

**T-L1 — LE insider misuse within valid authority.** Caps: valid credentials.
Stalking, selective surveillance, retaliation targeting, fishing without a
case, tipping an associate, repositioning a camera away before misconduct.
Purpose/case IDs are self-asserted metadata; supervisor collusion defeats
approval gates. Status: **disclosed** at base tier — AAR *attributes*
in-policy misuse (who viewed what, when, under which claimed purpose) and
makes patterns auditable; it does not prevent or adjudicate. Stronger-profile
/ deployment items (R-34, planned): case/subject binding, requestor≠approver
separation, designated-use two-person approval, rate/anomaly review exports,
emergency-use follow-up receipts. Mandating these at base tier would kill
adoption (gate calibration); the residual is stated plainly (RR-14).

**T-J1 — Evidence-chain & admissibility attacks.** Caps: C-export +
C-present. Substitution at acquisition, omitted exculpatory material, custody
breaks, transformation without lineage, sealed-record leakage, legal-hold
override, and *verdict laundering in court* — presenting signature validity
as authenticity or admissibility. Status: **partial** for technical
integrity; everything else **residual or presenter-attested**. Verdict
language MUST separate: technical integrity / source authenticity / custody
continuity / discovery completeness / legal admissibility — AAR speaks only
to the first, and to custody only where access/export/transform lineage
receipts exist (R-35, planned). A derivation receipt is a **signed deletion
assertion** — "demonstrably not spoliation" is retracted. *(Erratum E-3
against spec §8.)*

**T-X1 — Metadata inference & dictionary attacks.** Caps: C-export or bundle
access. Low-entropy commitments (presets, plates, condition parameters) are
dictionary-testable *even salted* if the salt ships in the bundle; withheld
salts break verification; reused salts correlate (gate finding 15). Cleartext
identifiers, graph shape, timing, and cardinality leak regardless of hashing.
Status: **planned** — R-17 rebuilt: classify protected fields × threat
actors; keyed commitments (HMAC) / randomized encryption / purpose-scoped
decommitment with key custody, rotation, erasure semantics; verifier states
for `decommitment unavailable`; confidentiality *and* later-evidentiary
tests. Timing/cardinality leakage: **disclosed**.

**T-X2 — Retention conflict / spoliation trap.** Caps: legal process. A
deletion receipt proves a deletion *claim* — not replica/backup erasure, key
destruction, hold compliance, or authority validity (gate finding 28).
Durable commitments may themselves be identifying. Status: **partial** —
verifier statuses split: `payload intentionally unavailable` /
`commitment matches supplied payload` / `deletion independently attested`
(R-36: tombstone semantics, replica/key-erasure attestations, hold-decision
provenance). Residuals: undiscovered copies, custodian fabrication, hash
privacy, legal adjudication.

**T-X3 — Anchor cadence as activity oracle.** Status: partial via
fixed-cadence anchoring guidance (pad empty epochs).

### 4.11 Anchoring & verification infrastructure

**T-C1/C2/C3 — Anchor withholding / retroactive substitution / split-view.**
Caps: C-trust(anchor). Scored **separately** (gate finding 6): withholding =
partial once R-24 head-freshness + multi-target independence rules exist
(planned); retroactive substitution = partial with append-only/witnessed
anchor selection guidance; split-view = **residual at base tier** — gossip/
witnessing is the stronger profile, and until R-21 defines it, it may not be
cited as a bound. The anchor is trusted **only for existence/order by time**
— never completeness (§2 table corrected per gate finding 12).

**T-V1 — Hostile bundles vs the Verifier.** Parser exploits, DAG blowup,
proof-size exhaustion. Status: **planned** — resource bounds, cycle
rejection, fail-closed parsing = v0.2 normative; KATs cover known vectors
only, so implementation assurance (fuzzing, memory safety, reproducible
builds) is scored separately (R-37).
**T-V2 — Parser divergence.** Status: **planned** — deterministic encoding +
byte-pinned KATs + pinned validation order arrive at v0.2 (this is the point
of the edgeproof inheritance; it does not exist yet and is not cited as
existing).
**T-V3 — Verdict laundering.** Status: **planned** — R-38: no bare-PASS
output; signed machine-readable verdicts binding bundle digest + verifier
build/config + trust-policy inputs; scope/profile/class limits in the
verdict. Courtroom misuse of even perfect verdicts: **residual** (couples to
T-J1).
**T-V4 — Trojan / modified verifier.** Status: **partial** — reference
verifier + published KATs create the *opportunity* for independent
re-verification, not a control (gate finding 25); reproducible builds +
differential fuzzing = planned; false testimony about verifier output =
residual.

## 5. Profile coverage matrix (re-scored)

`n/a` = the profile has no such surface. No cell may say more than §4 does.

| Threat | AAR-1 | AAR-2 | AAR-2A | AAR-3 |
|---|---|---|---|---|
| T-I1 root compromise | residual | residual | residual | residual |
| T-I2 post-compromise signing | partial | partial | partial | partial |
| T-I3 rotation seams | partial | partial | partial | partial |
| T-I4 staleness gaming | planned | planned | planned | planned |
| T-I5 path/usage/downgrade | planned | planned | planned | planned |
| T-I6 status-service equivocation | residual | residual | residual | residual |
| T-I7 cloned keys | residual | residual | residual | residual |
| T-P1 signer fabrication | partial (attribution) | partial | partial | partial |
| T-P2 class inflation | planned | planned | planned | planned |
| T-P3 manifest sanitization | disclosed / partial@proxy+ | same | same | same |
| T-P4 injection laundering | partial-conditional | same | same | same |
| T-P5 approval manipulation | n/a | partial | partial | partial |
| T-H1 post-ingress drop | **residual** (partial w/ R-15/census) | same | same | same |
| T-H2 pre-ingress drop | residual (R-15 → detectable-unattributable) | same | same | same |
| T-H3 stale-head export | partial-conditional | same | same | same |
| T-H4 cherry-picked bundle | partial (subset-labeling) | same | same | same |
| T-H5 census gaming | n/a | n/a | planned/experimental | planned/experimental |
| T-E1/E2 equivocation, emission denial | residual | residual | residual | residual |
| T-E3 epoch machinery | planned | planned | planned | planned |
| T-M1 Merkle batching | planned | planned | planned | planned |
| T-G1 graph splicing | planned | planned | planned | planned |
| T-G2 object replay | planned | planned | planned | planned |
| T-A2 policy fabrication (pre-emission) | n/a | n/a | residual (R-30 planned) | same |
| T-A3 scope creep | disclosed | disclosed | disclosed | disclosed |
| T-T1 clock falsification | disclosed | disclosed | disclosed | disclosed |
| T-R1 crash window | n/a | n/a | planned | planned |
| T-R2 receipt-path outage | planned | planned | planned | planned |
| T-R3 flooding | planned | planned | planned | planned |
| T-S1 source-device compromise | residual (partial w/ signed media) | same | same | same |
| T-S2 observer non-independence | n/a | n/a | n/a | planned |
| T-S3 scene manipulation | residual | residual | residual | residual |
| T-S4 out-of-band operation | residual | residual | residual | residual |
| T-D1 adapter substitution | residual (base) / planned (attested profile) | same | same | same |
| T-L1 LE insider misuse | disclosed | disclosed | disclosed | disclosed |
| T-J1 evidence-chain/admissibility | partial (technical integrity only) | same | same | same |
| T-X1 metadata/dictionary | planned | planned | planned | planned |
| T-X2 retention trap | partial | partial | partial | partial |
| T-C1 anchor withholding | planned | planned | planned | planned |
| T-C2 retroactive substitution | partial | partial | partial | partial |
| T-C3 split-view | residual | residual | residual | residual |
| T-V1..V4 verifier | planned (V4 partial) | same | same | same |

Reading of the matrix: at v0.1 **nothing is fully countered**, because no
normative wire object exists yet — the honest headline. What the requirements
draft buys today is *attribution* (partial nearly everywhere) plus a complete,
priced list of what v0.2 must build. This matrix is the RFP author's artifact.

## 6. Requirement stubs raised for v0.2 (threat-derived)

Extends spec §7's register. Each stub carries its threat and becomes pass/fail
at wire freeze.

| ID | Requirement (stub) | From |
|---|---|---|
| R-15 | Cross-stream reconciliation: correlation IDs binding request↔ack↔manifest; target-EP + transport binding; verdicts `unacknowledged` / `acknowledged-but-unaccounted` / `ambiguous`; never assigns cause; delivery unprovable without mutually-authenticated ack or witness | T-H1/T-H2 |
| R-16 | Degraded-mode **action-specific safety matrix**; failure domains separated; anchoring never gates dispatch; emergency journal; break-glass receipts; hazard-analysis-selected failure behavior per action; AAR never overrides life-safety design | T-R2 |
| R-17 | Low-entropy field protection: field classification, keyed commitments / randomized encryption, decommitment semantics, key custody/rotation/erasure, verifier `decommitment unavailable` state | T-X1 |
| R-18 | Evidence-class qualification predicates (failure-domain independence for observers, transcript coverage semantics, anchor semantics); verdict = "artifacts satisfy declared class" | T-P2/T-S2 |
| R-19 | Credential path construction, key-usage, algorithm pinning, trust-store snapshot in bundle, tenant-scoped root acceptance | T-I1/T-I5 |
| R-20 | Numeric per-profile staleness/lease maxima | T-I4 |
| R-21 | Witness profile definition (until defined, never cited as a bound) | T-P1/T-C3 |
| R-22 | Proxy capture-boundary + coverage attestation for provenance levels | T-P3 |
| R-23 | Approver proof-of-possession challenge binding action/decision/presentation/session/expiry; `assembled/delivered/rendered/human-approved` ladder | T-P5 |
| R-24 | Anchor semantics: inclusion/consistency proofs, max submission delay, head freshness, target independence, offline-verifier behavior without a current head | T-H3/T-C1 |
| R-25 | Bundle selectors: objective scope commitment + range proofs; subset vs complete labeling | T-H4 |
| R-26 | Emission definition: content-derived IDs, issuer sequence coordinates, equivocation/duplicate verdicts, fork-consistency fixtures | T-E1/T-E2 |
| R-27 | Epoch state machine (IDs, predecessor digest, open/close, late-arrival, max duration, anchor deadline, fork handling) | T-E3 |
| R-28 | Merkle batching: domain separation, canonical leaves, index/size binding, root-epoch binding, proof limits, KATs; membership-only claims | T-M1 |
| R-29 | Graph invariants: node binding (tenant/site/epoch), referential closure, dominator requirement, root allowlists, cross-epoch rules, adversarial fixtures | T-G1 |
| R-30 | Authority Source commits policy activation/precedence per epoch | T-A2 |
| R-31 | Dispatch write-ahead state machine + adapter idempotency contract + crash-cut tests | T-R1 |
| R-32 | Quotas, bounded fan-out, reserved audit capacity, backpressure receipts | T-R3 |
| R-33 | Adapter artifact/config identity pinning; measured runtime = stronger profile; re-conformance after update | T-D1 |
| R-34 | LE-misuse controls (stronger profile / deployment guidance): case/subject binding, requestor≠approver, designated-use two-person approval, anomaly-review exports | T-L1 |
| R-35 | Access/export/transform/tombstone lineage receipts for custody claims | T-J1 |
| R-36 | Tombstone semantics, replica/key-erasure attestation, hold-decision provenance | T-X2 |
| R-37 | Verifier implementation assurance: fail-closed parsing, resource bounds, reproducible builds, differential fuzzing | T-V1 |
| R-38 | Signed machine-readable verdicts; no bare-PASS; scope/class/limits in verdict | T-V3 |

## 7. Residual-risk register (rebuilt — gate finding 27)

"Disclosed only" = visibility, zero risk reduction. Every residual's
acceptance owner is Matthew (single-owner project) until a design partner
exists.

| # | Residual | Precondition | Actual control today | Remaining exposure |
|---|---|---|---|---|
| RR-1 | Signer fabrication within own authority, pre-emission | one role's C-key+C-presign | attribution; possible cross-role contradiction | lie is durable + attributable, still a lie |
| RR-2 | Single-administrator control of all role keys | common admin domain (typical single-vendor deployment!) | none at base tier — **not "collusion," just ownership** | wholesale history authorship; anchors pin only *when* |
| RR-3 | Post-ingress drop w/ sanitized anchored manifest | C-key(EP)+C-store | none at base (R-15/census planned) | G3 base claim narrowed accordingly |
| RR-4 | Pre-ingress drop | C-key(EP) or C-net | none single-sided | detectable-unattributable at best (R-15) |
| RR-5 | Equivocation before anchor commit | C-key | none until R-26 | conflicting signed histories |
| RR-6 | Events after last anchor / destroyed-before-anchor | timing | declared cadence (planned R-24) | unprotected window = cadence |
| RR-7 | Approver cognition; deception within faithful manifests; coercion | — | disclosed only | delivery ≠ understanding |
| RR-8 | Manifest omission at self-asserted provenance; uninstrumented channels at proxy level | Agent control of pre-sign bytes | disclosed only (provenance label) | injected/exculpatory content absent from record |
| RR-9 | Sensor truth: replayed/staged/false scene faithfully receipted | C-device or C-scene | signed media where deployed (partial) | receipts preserve a false world honestly |
| RR-10 | Out-of-band actions bypassing the EP | C-oob | deployment architecture only | AAR blind spot by construction |
| RR-11 | Issuer-root / status-service compromise | C-trust | root scoping limits blast radius (partial) | principal minting; status equivocation |
| RR-12 | Anchor split-view at base tier | C-trust(anchor) | none (witness profile undefined) | forked histories to different audiences |
| RR-13 | Clock falsification within asserted class | EP clock control | disclosed only | wrong times, consistently |
| RR-14 | LE insider misuse within valid authority | valid credentials | disclosed only at base (attribution + audit trail) | prevention/adjudication out of scope |
| RR-15 | Adapter/runtime substitution post-certification | C-presign(EP host) | self-asserted identity only | certified behavior ≠ running behavior |
| RR-16 | Receipt-path DoS → operational/life-safety impact | exhaustion vectors | none until R-16 matrix | evidence layer as attack lever |
| RR-17 | Evidence-phase: custodian fabrication, exculpatory-scope selection, undiscovered copies, verdict misrepresentation in court | C-export/C-present | subset-labeling + verdict language (partial) | legal outcomes turn on more than cryptography |
| RR-18 | Hash/commitment privacy: dictionary attacks, timing/cardinality leakage | bundle access | none until R-17; timing = disclosed only | watched-for content inferable |
| RR-19 | Inference correctness | — | out of scope by definition | model can be confidently wrong, receipts intact |
| RR-20 | Legal compliance of collection/retention/use | — | §8 records claims only | lawfulness never established by AAR |

## 8. Traceability

Threat → requirement → (future) test: every §4 threat carries either an R-x
stub in §6, an existing spec-§7 R-number, or an RR-entry — no prose-only
hooks (gate finding 30). The reverse index is mechanical (grep `T-` in §6) —
maintained at v0.2 when tests get IDs.

## 9. Method notes
Trust boundaries + capability composition per gate finding 8/30; quantitative
likelihood scoring deliberately omitted (single-owner project; qualitative
"remaining exposure" column suffices — gate calibration). Exclusions listed
in §3 are the *complete* set; anything not listed there is in scope.

## 10. Errata raised against `03-spec-v0.1.md`
- **E-1 (§1 G3):** completeness wording overclaims — narrow to
  producer-declared-contents tamper evidence; completeness =
  census/reconciliation-conditional. (Finding 1)
- **E-2 (§6):** `camera.ptz.preset` reversibility split into
  informational/operational; coverage-loss modeled. (Finding 26)
- **E-3 (§8):** "deletion is demonstrably not spoliation" → "deletion is
  attributably recorded." (Finding 10)
- **E-4 (§3.5):** Merkle batching = membership evidence only. (Finding 16)
- **E-5 (§1 G2):** emission must be defined; equivocation handling required.
  (Finding 2)

## 11. Changelog
- **v0.1 (2026-07-14):** Codex-gated revision — 30 findings, all accepted
  (2 calibrations, 1 right-sizing). G3 narrowed; G4 demoted to verifier rule;
  physical-system + LE-insider + evidence-phase + graph + epoch + Merkle +
  equivocation + availability threat families added; adversaries rebuilt as
  capabilities×coalitions; matrix re-scored planned/partial/disclosed/
  residual/n/a; R-15..R-38 stubs raised; residual register rebuilt with
  "disclosed only" honesty; 5 spec errata raised.
- **v0 (2026-07-14):** initial Claude draft (`04-threat-model-v0.md`).

---
*Next gates (unchanged order, this artifact done): v0.2 wire CDDL + KATs under
the edgeproof rc-gate process (now carrying R-15..R-38 + errata E-1..E-5) →
reference Verifier → two-adapter demo → RFP language.*
