# Attestation Spec Deltas — Phase-2 Proposal (v0.3 candidates)

**Status:** 2026-08-22, adversarially reviewed (round-1 FIX-FIRST 4 P1 + 7 P2
+ 6 P3 → round-2 FIX-FIRST 1 P1 + 4 P2 + 3 P3 → round-3 verify: all fixes
confirmed genuine, 2 sentence-level findings applied → SHIP). Companion to
`attestation-threat-model.md` (the argument) and the Phase-2 item of the
attestation-first plan. Everything here is a **proposal against a future v0.3
wire**; nothing changes v0.2-rc7 bytes. The D-51 verdict preimages, the frozen
fixture corpus, and D-01..D-61 stand untouched. Each delta is filed as a
decision candidate (D-62..D-65) for ratification in the usual way.

Framing rule carried over from the threat model: the vantage point (who signs,
from where) is the architectural decision. These deltas make the vantage point
**declarable and rankable on the wire**, so that a verifier can say not just
"this bundle is internally valid" but "this bundle is valid *and* was recorded
from a position that defeats A1 / A1+A2 / neither."

## What the wire already has (map before delta)

Read this section first — the deltas below are scoped to the genuine gaps
only:

| Threat-model concept | Existing wire machinery | Gap |
|---|---|---|
| Signer identity | `kid` in every protected header; `principal-type` × `principal-role` (`agent` / `enforcement_point` / `outcome_observer` / …); credential chain w/ SPKI | No role or key usage for an **L2 harness recorder**; no field declaring the *vantage* of the producer relative to the agent |
| Attestation class | `provenance-class` (`self_asserted` / `proxy_captured` / `provider_attested`) on **inference evidence only** (other kinds MUST omit it, per `evidence/provenance-class-unsatisfied`) | Provenance labels an inference's *source material*, not the *position of the receipt producer*. The two axes are orthogonal and today only one exists |
| Session-close record | `epoch-close` + signed `epoch-manifest` (`item_count`, `sequence_span`, `receipt_index`, `anchor_plan`) | Epochs are **journal batching under one EP owner**, sized by duration/size policy — not agent-session-bounded. There is no record that says "agent session S comprised N actions"; a session may span epochs and an epoch may span sessions. No per-receipt chain linkage exists (`previous_event_digest` is epoch-event-level) |
| Verdict semantics | Trinary `conformant` / `nonconformant` / `indeterminate`; the **signed** verdict already carries completeness signal — `observations` (`producer_declared_complete`, `ingress_completeness_not_established`, `valid_prefix`, …), `scope.coverage`, `scope.ingress_completeness`, `limits.discovery_completeness`. Only `empty_scope` / `stateful_not_evaluated` are report-layer | The signed verdict carries **no attestation-vantage signal** and no **session-scoped** completeness claim — its completeness fields speak to bundle coverage and ingress census, not "session S closed and intact" |

## D-62 (candidate) — `attestation_point` + recorder role

Add to the receipt (payload, not protected header — it is a claim to be
verified against the signer's credential, not a routing coordinate):

```cddl
attestation-point = "harness_hook" / "tool_boundary"

; new optional receipt field
? attestation: attestation-evidence

attestation-evidence = {
  point: attestation-point,
  recorder_kid: kid,      ; MUST equal the envelope signer kid
  agent_kid: kid / nil,   ; the reported-on agent's kid, nil iff unresolvable
}
```

Enum and usage edits (the base CDDL declares every enum closed — v0.3 simply
edits them; no extension-socket notation is implied):

- `principal-role` gains `"harness_recorder"`.
- `key-usage` gains `"recorder_signing"`, gated by `trust-root.
  allowed_key_usages` like every other usage; a receipt claiming
  `harness_hook` signed under a credential without `recorder_signing` rejects
  with the existing `credential/usage-mismatch`.

Semantics:

- `tool_boundary` (L3) is claimable only by a signer whose credential carries
  role `enforcement_point` (the existing EP position *is* L3 — the demo-EP and
  onvif-mcp producers need no new role, only the declaration).
- `harness_hook` (L2) is claimable only by role `harness_recorder` with usage
  `recorder_signing`.
- `agent_kid` names the agent principal the recorder reports on. The
  producer resolves it from the credential the agent authenticated to the
  harness/EP with; where no agent credential exists at the boundary,
  `agent_kid` is `nil` and the receipt ranks as if undeclared for
  self-report purposes (a recorder that cannot name its subject cannot prove
  it is not its subject). `agent_kid == recorder_kid` is a verifier reject —
  a self-report dressed as a hook, L1 in costume. The comparand is this
  field, never an inferred identity: for rooted receipts the verifier
  additionally cross-checks `agent_kid` against the `agent_request` root's
  request-envelope signer kid when that root kind is present
  (`attestation/agent-kid-mismatch` on disagreement); non-rooted receipts
  have only the declared field.
- Absent `attestation` field = undeclared, ranked below `harness_hook` by
  verifiers. Existing v0.2 bundles therefore remain valid and simply rank as
  undeclared — the upgrade path is declarative, per the threat model §3.
- **Omission-downgrade residual (normative disclosure):** a producer that
  would trip `attestation/recorder-is-agent` can instead omit the field and
  rank undeclared (⚠ under D-64's display contract, never ✓) — provided it
  also omits any session-close: a close over undeclared receipts trips
  `session/close-coordinate-mismatch` (D-63) and lands at ✗. This is
  accepted disclosure posture, not enforcement — the reject exists to stop
  *false claims of vantage*, not to force declaration; nothing at the wire
  layer can force an honest declaration from a dishonest producer (G4). A
  deployment that requires declaration expresses it in trust policy /
  procurement language, not conformance.
- L1 gets **no enum value on purpose**. Transcripts are ingress, never
  receipts; giving L1 a wire value would invite "attested: transcript" claims
  the threat model exists to kill.
- Orthogonality note (normative): `attestation.point` ranks the **producer's
  vantage**; `provenance-class` ranks an inference's **source material**.
  Neither implies the other and verifiers MUST NOT substitute one for the
  other.

New reason codes (names provisional, registered at ratification):
`attestation/role-mismatch` (point claimed by wrong role),
`attestation/recorder-is-agent` (`agent_kid == recorder_kid`),
`attestation/recorder-kid-mismatch` (field vs envelope signer),
`attestation/agent-kid-mismatch` (declared vs `agent_request` root signer).
Malformed-coordinate handling follows D-60: a malformed field is a
disagreement, never a skip.

## D-63 (candidate) — session chain + session-close record

Two additive receipt fields plus one new signed artifact. The chain is
per-receipt, exactly as the threat model §4 step 1 requires ("every receipt
carries the digest of its predecessor") — a session-close without the chain
would keep the vocabulary and lose the property.

```cddl
; new optional receipt fields (present together or not at all)
? session_id: id16                    ; distinct from presentation-manifest's
                                      ; approval-UI session_id; no relation
? session_prev_digest: digest32 / nil ; SHA-256 of the exact preceding
                                      ; in-session receipt payload bstr
                                      ; (the signed bytes); nil iff this is
                                      ; the session's first receipt

session-close-envelope = [
  payload: bstr .cbor session-close,
  signature: bstr .cbor artifact-cose-sign1,
]

session-close = {
  v: 3,                          ; pairs with the ;v=0.3 content type, per the
                                 ; observed ;v=0.2 <-> v:2 pairing; whether the
                                 ; whole wire's v bumps at v0.3 = ratification Q
  close_id: digest32,
  session_id: id16,
  tenant_id: id16,
  site_id: id16,
  recorder_kid: kid,             ; MUST equal opener kid or its
                                 ; rotation-continuity successor
  attestation_point: attestation-point,
  opened_at: unix-time,
  closed_at: unix-time,
  item_count: uint .le 10000,    ; matches epoch/bundle caps
  first_receipt_digest: digest32 / nil, ; SHA-256 of first receipt payload
                                        ; bstr; nil iff item_count == 0
  final_chain_digest: digest32 / nil,   ; SHA-256 of last receipt payload
                                        ; bstr; nil iff item_count == 0
  close_reason: "session_end" / "recorder_shutdown" / "administrative",
}

; close_id = SHA-256(deterministic-CBOR([
;   "AAR-SESSION-CLOSE-ID-v1", session-close with close_id absent ]))
; protected header 3 = "application/aar-session-close+cbor;v=0.3"
;   (registered in artifact-content-type)
; carried in bundle-artifacts in its own sorted slot, keyed by close_id,
;   alongside the existing artifact families
```

Semantics:

- **Chain definition.** The session chain is the linked list induced by
  `session_prev_digest`: genesis = the receipt with `session_prev_digest:
  nil`; order = successor linkage; both endpoints use the same identifier
  scheme (payload-bstr digest). Deletion or reordering of an interior
  receipt breaks the linkage. `issuer_seq` is not the chain — sessions
  interleave on one issuer.
- **Verifier evaluation** (total, deterministic, per D-51 discipline): for
  each `session_id` referenced by any selected receipt, if a session-close
  for it is carried, the verifier checks, over **carried** receipts of that
  session, in this order: (1) exactly one genesis (`session_prev_digest:
  nil`) exists; (2) genesis payload digest equals `first_receipt_digest`;
  (3) **successor uniqueness** — no two carried in-session receipts share a
  `session_prev_digest` value (a fork is a chain break, never a
  path-search: the walk MUST be a function, so every carried in-session
  receipt lies on the single walk); (4) every `session_prev_digest`
  resolves to a carried in-session receipt; (5) the walk from genesis
  terminates at a receipt whose payload digest equals `final_chain_digest`;
  (6) walked length equals `item_count`. Any failure →
  `session/chain-broken`. A carried close whose session's chain cannot be
  fully walked because receipts are absent from the bundle is a chain break
  — under a session-close the absence of an interior receipt is exactly the
  A3 evidence the record exists to surface. The partial-view path is
  omitting the close and taking `not_established` (the omission-downgrade
  posture, D-62).
- **Close/receipt coordinate agreement** (the D-60 pattern — no duplicated
  coordinate pair is left unchecked): `close.tenant_id` / `close.site_id`
  MUST equal the binding coordinates of every walked receipt; every walked
  receipt MUST carry `attestation` with `point == close.attestation_point`;
  `closed_at` MUST be ≥ `opened_at`, and every walked receipt's
  `committed_at` MUST lie within `[opened_at, closed_at]`. Any disagreement
  → `session/close-coordinate-mismatch`. Malformed coordinates are
  disagreements per D-60, never skips.
- The totality claim is the threat model §4 construction: "this session
  comprised N actions, final digest H," **producer-declared**. A verified,
  intact session-close yields `session_close_declared`, never a completeness
  proof. The T-H1-shaped residual (pre-close starvation by a compromised
  recorder — an action never entering chain or count) is restated in the
  record's spec text, not papered over.
- **Close authority.** `session_id` is minted by the recorder that signs the
  session's genesis receipt; that kid (or its rotation-continuity successor,
  via the existing rotation machinery) is the only valid close signer.
  A close signed by any other kid → `session/close-signer-mismatch`. Exactly
  one close per `session_id`: a second close from an authorized kid →
  `session/duplicate-close`. `recorder_shutdown` covers the crash-cut case
  (Gate-5 S5 shape): a resuming recorder MUST NOT re-close.
- Anchoring: a session-close is an anchorable artifact under the existing
  anchor classes. Unanchored, it defeats A3 only against presenters who
  don't control the recorder key; anchored, it defeats A2's retroactive
  re-close. Same disclosure posture as F22.

New reason codes (provisional): `session/chain-broken`,
`session/close-coordinate-mismatch`, `session/duplicate-close`,
`session/close-signer-mismatch`, `session/fields-inconsistent` (one of `session_id` / `session_prev_digest`
present without the other, or close endpoint/count fields inconsistent with
`item_count == 0`).

## D-64 (candidate) — attestation + session completeness in the signed verdict

The existing signed verdict already carries bundle-coverage and
ingress-census completeness (`scope.coverage`, `scope.ingress_completeness`,
`observations`). What it cannot express is the attestation vantage and the
session-scoped claim D-63 introduces. The v0.3 wire bump promotes two fields
into `verdict-fields`:

```cddl
attestation_floor: attestation-point / "undeclared",
session_completeness: "session_close_anchored" / "session_close_declared"
                    / "not_established",
```

- **Total orders (normative — the display contract depends on them):**
  `undeclared < harness_hook < tool_boundary` and
  `not_established < session_close_declared < session_close_anchored`.
- `attestation_floor` = the minimum, under that order, of the
  `attestation.point` values among evaluated receipts, where absent-field
  and `agent_kid: nil` both count as `undeclared`. A mixed bundle ranks at
  its floor. Empty evaluated set (`empty_scope`) → `"undeclared"` —
  consistent with empty-scope asserting nothing.
- **Early-failure sentinels (D-51 discipline):** on any `nonconformant` or
  `indeterminate` result — including decode-failure paths — evaluation of
  both fields is skipped and the signed verdict carries the fixed sentinels
  `attestation_floor: "undeclared"`, `session_completeness:
  "not_established"`. Never producer-derived values on a reject path.
- `session_completeness` is a total function over (selected receipt set ×
  carried session-closes): it is `session_close_declared` iff **every**
  selected receipt carries a `session_id`, every referenced session has
  exactly one carried, verified, chain-intact close (per D-63), and no
  selected receipt falls outside its session's walked chain;
  `session_close_anchored` additionally requires each such close to pass the
  existing anchor verification. **Any** other case — sessionless receipts
  selected, a session sliced by the selector, a session missing its close —
  is `not_established`. Empty evaluated set → `not_established`. This field
  neither replaces nor modifies `scope.ingress_completeness` or the existing
  observations; the two speak to different scopes (ingress census vs
  session close) and are reported side by side.
- Display contract (report layer, normative for the reference verifier's
  human output, mirroring the zoe tree: session → agents → tool tally →
  verdict column):
  - **✓ attested** = `conformant` ∧ floor ≥ `harness_hook` ∧
    session_completeness ≥ `session_close_declared`
  - **⚠ gap** = `conformant` ∧ (floor = `undeclared` ∨
    session_completeness = `not_established`)
  - **✗ tampered/invalid** = `nonconformant`; `indeterminate` renders as its
    own state, never folded into ⚠ — an unavailable key is not a gap in the
    chain. ⚠ can never mask ✗: any chain break or attestation reject is a
    reason code, hence `nonconformant`, hence ✗.
- The trinary signed verdict result is **unchanged**. ✓/⚠/✗ is a display
  contract over (result × floor × session_completeness), not a fourth
  verdict state — everything the glyph derives from is in the signed bytes
  once v0.3 lands.

## D-65 (candidate) — non-goals section becomes spec text

Promote `attestation-threat-model.md` §5 verbatim into the v0.3 spec front
matter (today non-goals live in review prose and the README's claim
boundary): not observability/tracing; not a transcript format; occurrence at
a boundary, never intent; no compromised-signer immunity — guarantee remains
attribution + post-emission tamper evidence + census-conditional
completeness.

## Sequencing / compatibility

- v0.2-rc7 untouched. All four candidates are v0.3 wire-bump material. Under
  the closed-map rule ("a key not written in its production is invalid"),
  D-62's `attestation` field and D-63's receipt fields already force the
  version bump on their own; D-64 additionally changes verdict preimages.
- Ratification order: D-62 → D-63 → D-64 (each depends on the previous),
  D-65 independent.
- KAT bar carries over: no candidate is ratified without fixtures covering
  its reject codes in both impls, per the standing lesson that two-impl
  byte-identity proves unambiguity only over corpus coverage (D-56/D-57/D-60
  lineage — a rule never written is invisible to both impls).
- External-draft alignment (Phase 3 consumers of this doc): `attestation_point`
  is the property mih-SCITT's capsule and Obsigna's chain both leave implicit;
  the session-close + SCITT-registration pairing is the concrete "defeats
  A2/A3 via external anchor" story.

## Honesty Ledger (round-0 → round-2)

- **fixed_in_round_2:** chain walk was not total under forks — impl A/impl B
  could return ✗ vs ⚠ on the same bundle, a live masking path (P1 — fixed:
  successor-uniqueness rule, fork = chain break, walk MUST be a function);
  no early-failure sentinels for the two new verdict fields (fixed: fixed
  sentinels on every reject path); `first_receipt_digest` signed but never
  verified (fixed: walk step 2); session-close duplicated coordinates with
  no agreement checks, incl. a consumption-less `close.attestation_point`
  (fixed: `session/close-coordinate-mismatch` + time-window check); total
  orders for the display contract never written (fixed: normative orders);
  `;v=0.3` vs `v: 2` pairing (fixed: `v: 3`, whole-wire bump flagged as
  ratification question); incoherent "sessionless selector" escape hatch
  (fixed: partial view = omit the close).

- **fixed_in_round_1:** session chain had no per-receipt linkage while
  keeping chain vocabulary (P1-1 — the load-bearing catch); "completeness
  observations don't enter signed bytes" was false (P1-2); recorder-is-agent
  had no comparand on the wire (P1-3); session_completeness undefined off
  session boundaries (P1-4); provenance scope misstated (P2-1);
  omission-downgrade left implicit (P2-2); no recorder key usage (P2-3);
  session-close unsignable under the closed content-type enum (P2-4); empty
  evaluated set undefined (P2-5); close authority unowned (P2-6); invented
  100000 cap, `v: 1`, `/=` socket notation, endpoint-scheme mismatch,
  session_id collision, bump-attribution (P3s).
- **noticed_not_fixed:** `agent_kid` is producer-resolved and
  producer-declared — a lying producer can name a fake agent; only the
  rooted-receipt cross-check binds it to anything signed. Consistent with
  G4, disclosed here rather than solved.
- **residual_uncertainty:** whether `session/chain-broken` on
  absent-interior-receipts is too strict for legitimate partial
  presentations (omitting the close is the current answer); whether `recorder_signing` should instead reuse an existing
  usage.
- **verification_gap:** no fixtures exist for any D-62..D-64 code — this doc
  is a proposal, and per the KAT bar nothing here is ratifiable until both
  impls carry covering fixtures.
