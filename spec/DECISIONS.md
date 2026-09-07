# AAR v0.2 gate-1 decision ledger

Status: every item below is a **gate-1 review candidate**, not an already approved
architecture decision. The governing rubric's locked decisions are repeated where
they constrain the result. Rejection or modification at the CDDL gate should update
the CDDL, conformance order, and this ledger together before any KAT work begins.

## D-01 — Preserve the EdgeProof detached-object shape

**Decision.** A signed artifact is `[exact-payload-bstr,
exact-serialized-untagged-detached-COSE_Sign1-bstr]`. The COSE payload slot is
`nil`; the protected bstr and payload bstr
are verified as received, never re-encoded for signature verification.

**Why.** This carries forward the EdgeProof SDR v1.1 anti-masquerade rule and makes
canonical-payload validation independent from the bytes covered by the signature.

**Alternatives considered.** Embedded COSE payloads; signing a decoder's
re-encoding; a map wrapper around claims and signature. The first diverges from the
inherited detached-payload discipline, and the latter two lose byte identity.

## D-02 — One ES256 signature profile for every AAR signed object

**Decision.** All signed objects use P-256/SHA-256, 64-byte P1363, low-S, RFC 6979,
empty external AAD, empty unprotected headers, and a protected kid/content type.

**Why.** The rubric imports the EdgeProof v1.1 wire discipline and explicitly locks
raw COSE delegation. A second signature profile would create parser and KAT
branches without a stated requirement.

**Alternatives considered.** DER ECDSA, randomized ECDSA, EdDSA, object-specific
external AAD. Deferred to a new wire version if ever required.

## D-03 — Provisional negative integer protected-header labels

**Decision.** Receipt-only protected coordinates use labels `-70000..-70006` for
principal type, tenant, site, epoch ID, epoch sequence, issuer sequence, and role.
All are mandatory and must equal the detached payload.

**Why.** Integer labels follow the existing COSE discipline, stay compact, and make
header closure testable. The values are deliberately conspicuous provisional
allocations pending the gate's registration decision.

**Alternatives considered.** Long collision-resistant text labels; payload-only
coordinates; requesting registered labels before the format is stable. Text labels
avoid provisional allocation but increase every receipt; payload-only fields fail
W-1's explicit protected-header requirement.

## D-04 — Receipt-ID self-reference is resolved with an ID-less preimage

**Decision.** `receipt_id` is SHA-256 of deterministic CBOR
`["AAR-RECEIPT-ID-v1", exact-protected-bstr, receipt-without-receipt_id]`. The
signature then covers the complete payload including the computed ID.

**Why.** This is finite, independently computable, binds identity to signer and all
emission/epoch coordinates, and detects later ID substitution.

**Alternatives considered.** Hash the whole receipt including a zero placeholder;
exclude all envelope data; define ID as signature hash; random UUID. Placeholder
rules are easy to implement inconsistently, signature IDs vary with signature
encoding, and random IDs do not meet W-2.

## D-05 — Emission is durable coordinate commitment plus release

**Decision.** A receipt is emitted when its exact envelope is durably committed at
both issuer and epoch coordinates and is released or made retrievable. Exact byte
re-observation is a duplicate; same ID/different bytes is identity reuse; same
coordinate/different ID is equivocation. Pre-commit drafts are not emitted.

**Why.** This gives R-26 an observable system boundary while honestly retaining the
pre-commit denial/equivocation residual from the threat model.

**Alternatives considered.** Signature completion alone; recipient acknowledgment;
external anchoring. Signature completion is not observable, recipient ack adds a
protocol outside the freeze, and anchoring would leave up to 24 hours undefined.

## D-06 — Two sequence domains are independently enforced

**Decision.** `issuer_seq` is monotonic per signing kid. `epoch_seq` is unique and
monotonic per epoch owner/epoch. Epoch IDs must increase but need not be contiguous.

**Why.** A role signer and the EP-owned epoch journal are different ordering
authorities. Keeping both detects signer reissuance and journal insertion without
requiring all principals to share one counter.

**Alternatives considered.** One global site counter; contiguous epoch IDs. Both
make distributed issuance brittle and convert administrative gaps into false
integrity failures.

## D-07 — Graph direction is parent to child, encoded on the child

**Decision.** Every receipt carries incoming edges. `parent-edge` means
`parent_id -> current receipt`; it therefore does not carry a redundant `child_id`.

**Why.** The signed child commits to intended provenance and the model avoids a
second receipt-ID self-reference through `child_id`. Referential closure still
materializes an ordinary directed DAG in the verifier.

**Alternatives considered.** Outgoing edges on parents; separate signed edge
objects; edges carrying both endpoints. These complicate streaming emission,
permit endpoint drift, or recreate ID self-reference.

## D-08 — Root requests are descriptors, not a seventh node type

**Decision.** A parentless observation, inference, or authorization carries a
closed `root` descriptor for agent request, human request, or standing-condition
trigger. The root descriptor is part of that receipt's signed identity. An
`agent_request` descriptor resolves to the Agent's raw detached signed request
artifact, and its `request_commitment` is SHA-256 of the exact request claims
bytes. Human-request and standing-condition roots remain commitment-only.

**Why.** W-3 explicitly freezes six node types while W-4 requires a root allowlist.
This represents the allowed external origin without silently creating node seven,
while preserving the Agent-signed half of later R-15 cross-stream reconciliation.

**Alternatives considered.** Add request/condition node kinds; treat every
observation as an implicit root. The first violates the stated six-object freeze;
the second loses the root-origin commitment.

## D-09 — Edge legality is a closed matrix, not a free vocabulary

**Decision.** `CONFORMANCE.md` enumerates every legal parent-kind, edge, child-kind
combination. `supports` is explicitly noncausal and does not satisfy authorization
dominance by itself.

**Why.** A closed enum without endpoint rules would not stop graph laundering.

**Alternatives considered.** Validate only the edge text; force a fixed stage
chain. The former is insufficient for R-29 and the latter contradicts the DAG
requirement.

## D-10 — Cross-epoch links are narrow, explicit, and anchored

**Decision.** Same tenant/site is absolute. Only historical `derived_from` and
`supports`, plus long-running/late `observed_outcome`, may cross epochs. The source
must be earlier, closed, and named by an exact manifest and valid anchor.
Authorization, request, trigger, and attempt edges never cross epochs.

**Why.** This permits legitimate historical evidence and delayed outcomes without
letting stale authorization or requests migrate into a new epoch.

**Alternatives considered.** Forbid all cross-epoch edges; allow any edge with an
anchor. The former cannot represent late physical outcomes, and the latter enables
authorization replay.

## D-11 — Dominance is exact authorization plus one raw-COSE delegation

**Decision.** Every dispatch resolves one action attempt, exactly one dominating
authorization, and exactly one valid delegation in that authorization. Scope is
rechecked against action, target, purpose, tenant/site, profile, and invocation.

**Why.** This translates the rubric's “exactly its decision + delegation” into a
testable graph property rather than merely requiring those artifacts somewhere in
the bundle.

**Alternatives considered.** Any authorization ancestor; a list of cumulative
authorizations; dominance by decision commitment only. Each permits ambiguity or
substitution.

## D-12 — Delegations are detached raw COSE with adjacent claims bytes

**Decision.** The delegation token itself is the serialized bytes of an AAR-profile
COSE_Sign1. Its exact
detached claims bytes are adjacent in `delegation-envelope`; authorization embeds
the claims and raw token directly. No Biscuit, UCAN, JWT, or attenuation language
is accepted.

**Why.** This implements the locked raw-COSE decision while retaining the inherited
detached-payload rule.

**Alternatives considered.** Embedded-payload COSE; Biscuit/UCAN; token URI. The
first creates a second COSE profile and the latter two contradict the locked gate.

## D-13 — Profile numbers are literal wire constants

**Decision.** AAR-1/2 use status age and lease maxima of 86,400 seconds. AAR-2A/3
use status age 300 seconds and lease 3,600 seconds. Every profile uses 86,400
seconds for anchor cadence.

**Why.** Lease and AAR-2A/3 staleness values are locked. The requirements also say
every status snapshot has a profile maximum, so the unstated AAR-1/2 status age is
set equal to its lease rather than left symbolic.

**Alternatives considered.** No AAR-1/2 status maximum; 300 seconds at every tier;
a policy-supplied value. The first leaves R-20 incomplete, the second changes the
accepted strawman, and the third fails the gate's numeric freeze.

## D-14 — Credentials pin path, use, algorithm, and tenant/site

**Decision.** Paths are explicit credential-ID arrays capped at eight; roots are
accepted by tenant/site and key usage. Role key separation is checked by kid, and
ES256/P-256 is repeated in credential claims.

**Why.** This makes R-19 deterministic and prevents path-building, use, and
algorithm ambiguity.

**Alternatives considered.** X.509 path discovery; kid-only trust; arbitrary path
length. Full PKI is out of scope and implicit discovery is hostile to offline
determinism.

## D-15 — Status before compromise can validate with the compromise noted

**Decision.** A signature/use at or after the declared compromise/revocation time
fails. A signature within credential validity and before compromise may validate,
even when evaluated later, with the status inputs bound into the verdict.

**Why.** This is the exact credential behavior required by the requirements draft
and avoids retroactively invalidating already anchored history without saying that
the old act was truthful.

**Alternatives considered.** Reject all history after any compromise declaration;
ignore compromise time. Both erase needed temporal semantics.

## D-16 — Epoch duration is fixed at 24 hours for v0.2

**Decision.** An epoch's signed `max_duration_s` is exactly 86,400 and close beyond
that duration fails. Closed epochs are immutable; late arrivals go only into the
next epoch with `late_for_epoch_id`.

**Why.** R-27 requires a numeric max duration and late-arrival rule. Matching the
locked base anchor cadence keeps the first profile simple and bounds the unclosed
window.

**Alternatives considered.** Policy-selected duration; one hour; reopen-on-late.
The first leaves a gate number open, one hour is unsupported by the rubric, and
reopening defeats manifest immutability.

## D-17 — Empty epochs exist only as declared cadence padding

**Decision.** A zero-item manifest is valid only with close reason `padding` and a
nil sequence span. Nonempty manifests require first/last sequence and exact count.

**Why.** Fixed-cadence padding limits the activity oracle noted by the threat model,
while the explicit close reason makes phantom-empty substitution detectable.

**Alternatives considered.** Forbid empty epochs; allow untyped empty epochs. The
former leaks activity through anchor absence, and the latter invites phantom epoch
ambiguity.

## D-18 — The objective manifest index is a signed time-ordered full index

**Decision.** Each epoch manifest commits the full ordered index of receipt ID,
kind, signer/sequence coordinates, committed time, subject IDs, and R-15 correlation
IDs. Ordering is `(committed_at, epoch_seq, receipt_id)` and the index has its own
domain-separated Merkle root.

**Why.** A complete range proof needs an objective order and enough committed
metadata to evaluate type/subject/correlation selectors. Epoch sequence alone
cannot prove a time interval boundary; opaque receipt IDs cannot evaluate a subject
selector.

**Alternatives considered.** Receipt-ID-only manifests; separate secondary indexes;
subjective exporter-generated index. The first cannot prove selectors, the second
multiplies roots/proofs, and the third lets the exporter define relevance after the
fact.

## D-19 — Range completeness uses contiguous temporal slices

**Decision.** Range proofs carry every objective index entry in the selected time
slice, including nonmatching kinds/subjects, with contiguous indices and boundary
proofs. The verifier then applies all selector predicates locally.

**Why.** Membership proofs for only matching entries cannot prove that a match was
not omitted. A contiguous slice plus boundary entries can.

**Alternatives considered.** One inclusion proof per exported receipt; a sparse
multi-index for every predicate; SNARK range proofs. The first proves membership
only and the latter choices are needless complexity for v0.2.

## D-20 — `complete` is explicitly producer-declared completeness

**Decision.** Bundle `complete` means all matching receipts in the selected signed
manifest indexes plus graph closure. It does not mean all ingress or all incident-
relevant evidence. Verdicts separately enumerate ingress completeness, which is
`not_established` without an independent census or later R-15 reconciliation.

**Why.** This preserves the narrowed G3 guarantee and still gives W-10's
`valid_subset` versus `complete` label an objective meaning.

**Alternatives considered.** Forbid `complete` until R-15 ships; let exporters
claim semantic completeness. The former makes W-10's label unusable and the latter
reintroduces the threat-model overclaim.

## D-21 — R-15 ships as fields, not reconciliation behavior

**Decision.** Receipts carry correlation ID, phase, target EP kid, transport ID,
and peer-binding digest; manifest indexes and selectors carry correlation IDs. No
v0.2 verdict attempts to attribute an unacknowledged or unaccounted event.

**Why.** The rubric explicitly includes fields and defers the verifier feature.

**Alternatives considered.** Implement reconciliation verdicts now; omit fields
until then. Both violate the stated freeze boundary.

## D-22 — Freshness is mandatory and signed for every receipt

**Decision.** Every receipt has issue/expiry, nonce, replay domain, invocation ID,
one-time/reusable mode, and an exact ordered intended-parent list. Action-flow
receipts share invocation ID; one-time state is durable verifier/EP input.

**Why.** R-2/T-G2 applies replay protection to every profile and object type, not
only authorization.

**Alternatives considered.** Nonce only on delegation; infer parents from graph;
stateless duplicate detection. None prevents cross-context transplant.

## D-23 — Evidence strength and terminal outcome are wire-visible

**Decision.** Time and provenance use the exact three-level enums from the draft.
Outcome carries the six draft labels (`accepted`, `dispatched`,
`device_acknowledged`, `independently_sensed`, `contradicted`, `unknown`) plus an
outcome body's `consistent/contradicted/unknown` state. Required qualification
artifact IDs are explicit.

**Why.** The prose requirements name all six labels, and contradiction/unknown must
not be manufactured into success. Qualification is recomputed rather than trusted
from the label.

**Alternatives considered.** Four ordinal strength levels plus a separate terminal
state only; treat contradicted/unknown as strength levels. The chosen form preserves
the published vocabulary while the separate body state prevents implying an
ordering between contradiction and unknown.

## D-24 — Merkle formats are domain separated and promote odd nodes

**Decision.** AAR batch and manifest-index trees hash deterministic-CBOR domain
arrays, bind batch/tree/index/epoch in each leaf, promote an odd unpaired node, and
cap paths at 20 or 14 siblings respectively. Claims are always `membership_only`.

**Why.** This closes every R-28 ambiguity and binds proofs to one batch/index.

**Alternatives considered.** Duplicate the final odd node; RFC 6962 hashing for
internal AAR batches; unindexed leaves. All are valid constructions, but mixing
them without an explicit choice causes parser divergence.

## D-25 — External anchors use RFC 6962 v1 proofs

**Decision.** Base-tier anchor targets expose RFC 6962 v1 inclusion and consistency
proofs. The AAR anchor leaf has a domain-separated deterministic-CBOR payload and is
then hashed with RFC 6962's `0x00` leaf prefix. Every target receipt declares only
existence/order by time.

**Why.** W-7 requires concrete proof formats. A named standard avoids inventing a
second transparency-tree algorithm and supports split-history consistency checks.

**Alternatives considered.** Published signed checkpoints without inclusion
proofs; target-defined protocol strings; the internal AAR Merkle algorithm. The
first does not satisfy W-7 as written and target-defined behavior is not a wire
freeze.

## D-26 — Independence is declared and policy-checked, not inferred from count

**Decision.** Anchor plans name operator and failure-domain IDs in independence
groups. Multiple targets count as independent only when both differ.

**Why.** Two endpoints operated in one failure domain do not address withholding
or split view. The declaration is still an assertion; the verdict binds the policy
that accepted it.

**Alternatives considered.** Any two targets; URI-host comparison; mandatory
witnessing. The first two are cosmetic and the witness profile is deferred.

## D-27 — Bundle and verdict digests are external to their objects

**Decision.** A bundle has no `bundle_id`; its digest is SHA-256 of exact canonical
bundle bytes and is bound by the verdict. The verdict uses the same ID-less-preimage
pattern as receipts.

**Why.** This avoids a second self-reference and lets custody systems identify the
exact exported byte string.

**Alternatives considered.** Zero-placeholder bundle IDs; hash of parsed content;
unsigned random export ID. These weaken byte identity or add special encoding.

## D-28 — Missing trust state is indeterminate, malformed evidence is nonconformant

**Decision.** Missing external key, replay state, expected head, or trust policy
produces a signed `indeterminate` verdict. Invalid bundle bytes or failed artifact
semantics produce `nonconformant`. Only full success is `conformant`.

**Why.** Absence of verifier context is not evidence that the producer emitted an
invalid object. The result enum prevents a misleading binary PASS/FAIL collapse.

**Alternatives considered.** Fail closed as nonconformant for all missing inputs;
unsigned operational errors. The first overstates evidence and the second violates
R-38.

## D-29 — Verdicts enumerate claim limits, including negative limits

**Decision.** Every verdict binds exact bundle, selector, verifier build/config/
resource limits, trust store/policy, expected heads, replay state, scope/profile,
and maximum supported evidence classes. It must state that source authenticity and
legal admissibility are not established; custody and discovery have closed limited
enums.

**Why.** This directly blocks verdict laundering and “signature valid therefore
authentic/admissible” output.

**Alternatives considered.** A signed boolean; free-text caveats; limits in human
documentation only. None are machine-checkable.

## D-30 — Resource limits are conservative v0.2 constants

**Decision.** Bundle 16 MiB, 10,000 nodes, 50,000 edges, 64 parents, DAG depth 128,
width 4,096, CBOR nesting 32, individual proof 64 KiB, aggregate proofs 4 MiB,
credential paths eight.

**Why.** Receipts carry commitments and canonical manifests, not bulk media. These
limits accommodate incident bundles while bounding parser, graph, and proof work.
They are committed in verdict configuration so a stricter verifier cannot
masquerade as evaluating the same contract.

**Alternatives considered.** Unbounded structures; much smaller online-message
limits; policy-only limits. Unbounded inputs fail T-V1, online limits make offline
bundles impractical, and unbound policy limits undermine verdict comparison.

## D-31 — Integer seconds and no CBOR floats

**Decision.** All times are unsigned Unix seconds capped at the exact-integer range
`2^53-1`; uncertainty is integer basis points; floats and CBOR tags are forbidden.

**Why.** This follows the EdgeProof pinned-numeric spirit while eliminating float
width, NaN, negative-zero, and tagged-time ambiguity.

**Alternatives considered.** RFC 3339 strings; tagged epoch time; milliseconds;
float probabilities. Seconds meet the current lease/anchor granularity and keep
canonical comparisons simple.

## D-32 — Canonical embedded data remains opaque bytes plus a digest

**Decision.** Structured conclusions, commands, parameters, and auxiliary
manifests are bounded canonical byte strings with media/schema identifiers and
SHA-256 commitments. Their application schemas are outside `aar-core.cddl`.

**Why.** The core wire must bind heterogeneous adapter/model data without opening
its maps or pretending to standardize every command dialect at gate 1.

**Alternatives considered.** `any` inside core maps; one universal JSON schema;
hash-only references. `any` defeats closed-schema discipline, universal schemas
are false parity, and hash-only references prevent offline verification.

## D-33 — Legal-purpose metadata is common receipt metadata

**Decision.** Purpose, jurisdiction, data classification, retention class, and
legal-hold status occur on every receipt and are signed into its identity.

**Why.** The requirements call these load-bearing and they must not be optional
export annotations. The verdict still does not establish lawfulness.

**Alternatives considered.** Authorization-only fields; bundle-only metadata;
optional legal context. These allow downstream receipts to lose the claimed basis.

## D-34 — No gate-2 artifacts in this change

**Decision.** This gate contains CDDL and normative/review prose only. There are no
KATs, fixtures, encoders, decoders, verifier code, or harness scaffolds.

**Why.** The rubric explicitly requires the CDDL gate before independent KAT
generation; premature fixtures would fossilize unreviewed choices.

## D-35 — Presentation claims retain their own signer

**Decision.** A presentation manifest is a nested detached signed object inside
the EP-signed authorization receipt. `signer_mode` selects an Approver signature or
an EP signature from the approver's authenticated session; the outer EP decision
signature does not replace it.

**Why.** The signer matrix says presentation/approval and EP decision are distinct
claims and explicitly says countersignatures are preserved.

**Alternatives considered.** Let the outer authorization signature cover the
presentation alone; create presentation as a seventh DAG node. The first collapses
claimants, while the second violates the six-node freeze.

## D-36 — Unsigned bundles defer export attribution to R-35

**Decision.** The v0.2 bundle is unsigned. A signed verdict binds the exact bundle
bytes by digest, but neither attributes the export act nor identifies an exporter.
Export and custody lineage remain an accepted deferral to R-35.

**Why.** The frozen bundle proves the evaluated byte set without claiming custody
semantics that v0.2 does not define.

**Alternatives considered.** Add a bundle-exporter signature now; infer export
attribution from the verifier's signature. The first pulls deferred custody
lineage into this wire gate, and the second confuses evaluation with export.

## D-37 — Signed artifact primary IDs are content-derived without self-reference

**Decision.** Delegation, credential, status, rotation, epoch-event, anchor, and
Merkle-batch IDs are SHA-256 of deterministic-CBOR domain arrays containing the
artifact claims with that ID absent. Merkle leaves exclude `batch_id`; producers
compute leaves, then the root, then `batch_id`. Credential paths contain the
ordered issuer chain only, excluding the subject credential; self-signed roots
use an empty path and are accepted only through the trust store.

**Why.** Content-derived bundle sort keys make ID substitution detectable. The
leaf and credential exclusions remove the two circular preimages in the initial
WQ-1 ruling while preserving tenant/site/epoch binding.

**Alternatives considered.** Opaque artifact IDs; zero-placeholder hashing;
including `batch_id` in its own Merkle root; including the subject credential in
its own path. The first permits substitution, the second invents a special
encoding rule, and the latter two are circular.

## D-38 — Epoch event links hash the exact preceding payload bstr

**Decision.** `previous_event_digest` is SHA-256 of the exact preceding signed
epoch-event payload bstr.

**Why.** Linking signed bytes gives one unambiguous chain target without depending
on envelope re-encoding or reducing the link to a content ID.

**Alternatives considered.** Hash the complete envelope, a decoded/re-encoded
event, or `event_id`. Each targets different bytes and would cause verifier
divergence.

## D-39 — Anchor manifest digests pin exact signed manifest payload bytes

**Decision.** An anchor record's `manifest_digest` is SHA-256 of the exact
epoch-manifest payload bstr. `manifest_id` remains the content-derived identifier.

**Why.** The digest pins exact signed bytes while the ID pins manifest content;
both bindings are useful and intentionally distinct.

**Alternatives considered.** Make both fields equal; hash the complete signed
envelope; omit the digest. These lose either exact-payload binding or the separate
content identity.

## D-40 — The EP signs journal artifacts in v0.2

**Decision.** Epoch events, epoch manifests, and Merkle batches require
`ep_signing`, and the signing kid equals `epoch_owner_kid`. A Merkle batch's
`signer_kid` also equals `epoch_owner_kid`; the extra field remains a future
delegated-journal seam.

**Why.** Journal ownership and signing authority must be closed in the base
profile rather than inferred by implementations.

**Alternatives considered.** A separate journal signer now; allow any service
credential; remove `signer_kid`. The first two introduce an unruled delegation
model, while removal discards an intentional future-version seam.

## D-41 — Credentials carry their verification SPKI

**Decision.** Every credential carries DER SubjectPublicKeyInfo in `public_key`.
Verifiers require `SHA-256(public_key) == subject_kid` and use that key for
signature verification.

**Why.** A carried credential must supply the public key for fully offline bundle
verification; the kid-to-key self-check prevents substitution.

**Alternatives considered.** Require an external key registry; carry raw SEC1
points; carry JWK. The registry violates the offline premise, and alternate key
encodings add unnecessary wire choices beside the already-defined SPKI kid.

## D-42 — Key selection has no separate COSE kid-mismatch code

**Decision.** Delete `cose/kid-mismatch`. The protected `kid` selects the
verification key; failure is completely classified by `key/not-found`,
`credential/kid-key-mismatch`, or `sig/verify-failed`.

**Why.** A selected key cannot independently disagree with the value that selected
it, so the deleted trigger had no distinct reachable state.

## D-43 — Credential algorithm mismatch is a schema failure

**Decision.** Delete `credential/algorithm-mismatch`. The credential schema fixes
`cose_alg=-7` and `curve="P-256"`; any other value fails first as
`schema/enum-unknown`.

**Why.** A semantic algorithm code would duplicate an earlier closed-enum failure
and violate first-failure ordering.

## D-44 — Receipt identity reuse is relative to prior evaluated state

**Decision.** `identity/reuse` means that a receipt ID names nonidentical envelope
bytes relative to prior evaluated state.

**Why.** Within one bundle, repeated primary IDs are rejected earlier as
`schema/duplicate-entry`; prior evaluated state is the reachable identity-reuse
boundary.

## D-45 — Stateful negative KATs use paired prior-state files

**Decision.** A negative KAT requiring prior evaluated state uses
`kats/negative/stateful/{name}.bundle.cbor` with `{name}.prior.json` and a
descriptor carrying the exact expected code.

**Why.** The pair keeps the wire bundle immutable while making the verifier state
that triggers the failure explicit and reproducible.

## D-46 — Consumption is a derivation edge

**Decision.** An inference that consumes an observation's content links that
observation with `derived_from`. `requested_by` may coexist but means only that
the inference was created in response to the parent's content. Step 10 resolves
observation consumption manifests through `derived_from` parents only.

**Why.** Consumption is derivation; keeping response-to and content-dependency
semantics on distinct edge types prevents a request edge from silently claiming
provenance.

## D-47 — Receipt graphs are acyclic by construction

**Decision.** Delete `graph/cycle` as a conformance rejection. After receipt IDs
are recomputed, every parent ID is inside the child ID preimage, so a directed
cycle would require a SHA-256 fixed point. Implementations may retain a
non-normative receipt-count traversal guard as a defensive internal bound.

**Why.** The former code was unreachable after step 7 without a cryptographic
break and therefore could not have a valid negative KAT under first-failure order.

## D-48 — Duplicate Merkle leaves compare index-less proven content

**Decision.** Keep `merkle/duplicate-leaf`. Within one signed batch it means two
successful membership proofs carried in one bundle have different indices but
the same `(tenant_id, site_id, epoch_id, item_digest)`. `leaf_index` remains in
the actual leaf hash preimage, and unproven leaves are outside the claim.

**Why.** This detects duplicated content while preserving positional binding and
does not pretend that an offline verifier can inspect the rest of the batch.

## D-49 — Evidence attestation bytes are opaque in v0.2

**Decision.** Required boot, capture, provider, and qualification IDs resolve to
hash-bound, media-typed `canonical-manifest-payload` bytes in the bundle; absence
is `manifest/payload-missing`. v0.2 class limits mean declared and structurally
supported. Deep cryptographic interpretation of TPM quotes, provider signatures,
or predicate formats is deferred to v0.3 or a stronger profile.

**Why.** The base wire can prove that the declared artifact bytes were committed
without freezing every provider- or platform-specific verification protocol.

## D-50 — External time anchoring uses a prior-epoch lower bound

**Decision.** An `externally_anchored` receipt names a verified anchor from an
earlier epoch under the same owner, tenant, and site, and that anchor has
`accepted_at <= committed_at`. The prior anchor supplies the lower bound; a
separately verified anchor for the receipt's own epoch, when present, supplies the
upper bound.

**Why.** A same-epoch `anchor_id` is self-referential because the receipt commits
the ID of an anchor whose manifest commits the receipt.

## D-51 — Verdict digest preimages and early-failure sentinels are frozen

**Decision.** `limits_digest`, `anchor_heads_digest`, and supplied
`replay_state_digest` use the domain strings `AAR-VERDICT-LIMITS-v1`,
`AAR-VERDICT-HEADS-v1`, and `AAR-VERDICT-REPLAY-v1` over the closed preimages in
CONFORMANCE section 5. No supplied replay state uses a zero digest. Build and
configuration digests are implementation-defined but stable and documented.
Before bundle scope/trust can be decoded, verdicts use the section 5 zero/default
sentinel while retaining the real evaluation time and any explicitly configured
requested values.

**Why.** Verdict producers now bind identical interoperable inputs identically,
while early parse failures still yield complete, unambiguous signed verdicts.

## D-52 — Status-snapshot content checks precede reference resolution

**Decision.** Step 8 evaluates the content of EVERY carried status snapshot —
referenced or not — before resolving any decision `status_snapshot_ids`
reference. Content defects fire their specific codes (`lease-too-long`,
`status-stale`, `revoked`, `compromised`, `status-unknown`, `not-yet-valid`,
`lease-expired`, in that order); `credential/status-missing` fires only after
all carried snapshots pass.

**Why.** Adversarial masking: if reference resolution fired first, a producer
could downgrade a `credential/compromised` verdict to the milder
`status-missing` by also breaking the reference. Content-before-reference makes
the worst carried evidence non-suppressible. (Gate-4 clean-room divergence,
credential family — pyref's reference-first reading was textually defensible,
which is exactly why this needed pinning.)

## D-53 — The evaluated delegation is the embedded one, selected by no heuristic

**Decision.** The delegation evaluated in step 13 is the `delegation-envelope`
embedded in the authorization body. `decision.delegation_id` MUST equal the
embedded delegation's `delegation_id`; a mismatch or unresolvable dominating
path is `graph/dominator-missing`. The top-level `delegations` array exists to
resolve `parent_delegations` chains. Selection by position, cardinality
("the only one carried"), or subject is forbidden, and delegation evaluation
is never skipped on a failed reference.

**Why.** Gate-4 found the reference implementation selecting "the single
carried delegation" as a fallback and silently skipping evaluation when that
heuristic failed — a fail-open path and an interop divergence (the clean-room
implementation evaluated the embedded copy and reached the opposite verdict on
four fixtures). Two conformant verifiers MUST pick the same delegation by
construction, not by luck.

## D-54 — Intra-step check order is normative

**Decision.** Within a validation step, checks evaluate in the order the
CONFORMANCE section 2 prose lists them, and the first failing check supplies
the reason code. Step 15 is explicitly ordered: entry-level index requirements
(order, contiguity, uniqueness, entry-to-receipt equality, counts/spans) before
root recomputation/comparison; `manifest/index-root-mismatch` fires last.

**Why.** First-failure-wins is only deterministic across implementations if
the intra-step order is pinned. Gate-4 surfaced five fixtures (manifest-index
family, epoch/late-insertion) where two correct-by-their-own-reading
implementations produced different codes on multi-defect inputs.

## D-55 — Range slices carry nonmatching entries (D-19 reaffirmed against the reference implementation)

**Decision.** A range's `entries` MUST carry every objective index entry in the
half-open temporal slice, including entries whose kind, subject, or issuer do
not match the selector. Selector predicates apply locally after slice
completeness is established. A matching-only slice fails
`bundle/range-boundary`. The reference implementation's step-18 check and its
fixture generator (`makeCompleteRange`) violated D-19 by filtering to
selector-matching entries; both are corrected, and the affected fixtures are
regenerated.

**Why.** D-19's rationale stands: membership proofs over only matching entries
cannot prove a match was not omitted. This was the gate-4 flagship catch — the
clean-room implementation enforced the locked decision and the reference
implementation did not. The divergence (`bundle/artifact-out-of-scope`
expected, `bundle/range-boundary` produced) was pyref being RIGHT.

## Gate-1 questions requiring an explicit disposition

1. **Protected labels:** approve provisional `-70000..-70006`, switch to
   collision-resistant text labels, or reserve/register another integer range?
2. **Outcome count mismatch:** the requirements name six outcome labels while the
   rubric's KAT sentence says “5 outcome.” Should gate 2 test six labels, or should
   contradiction/unknown be only terminal states outside the level enum?
3. **AAR-1/2 status age:** approve the inferred 86,400-second maximum, or make
   status snapshots nonrequired at those profiles while retaining the locked
   86,400-second lease?
4. **Epoch duration:** approve the selected 86,400-second maximum, or freeze a
   different number independently of anchor cadence?
5. **Root representation:** approve root descriptors inside the six node types, or
   expand W-3 with explicit request/condition/handoff node types?
6. **`complete` terminology:** approve “complete over selected producer-declared
   manifest indexes,” with ingress completeness separately `not_established`, or
   reserve the bare word `complete` for census/reconciliation-supported bundles?
7. **Anchor floor:** approve RFC 6962 v1 as the required base proof protocol, or
   define a second published-checkpoint profile before the freeze?
8. **Resource ceilings:** approve the D-30 constants as the interoperable floor,
   especially the 16 MiB bundle and 10,000-node limits?

## Gate-1 dispositions — LOCKED

| Q | Locked disposition |
|---|---|
| 1 · Protected labels | Approve provisional `-70000..-70006` (COSE private-use range, < −65536). Registration is a launch-time task, not a freeze blocker. |
| 2 · Outcome count | Six labels stand. The rubric's “5 outcome” was a rubric typo — the spec's §5.2 vocabulary (6, with contradicted/unknown as unordered terminal states) governs. Gate-2 class-boundary KATs cover the 4-step ordered ladder; contradicted/unknown get dedicated terminal-state KATs, not boundary KATs. Rubric erratum noted here; no rubric edit needed. |
| 3 · AAR-1/2 status age | Approve 86,400 seconds (= lease). Consistent and conservative. |
| 4 · Epoch max duration | Approve 86,400 seconds matching base anchor cadence for v0.2. |
| 5 · Root representation | Approve root descriptors — as modified by G1-1 (`agent_request` roots bind to the new signed request artifact). No seventh node kind. |
| 6 · `complete` terminology | Approve producer-declared semantics with the mandatory `ingress_completeness_not_established` observation — this is exactly the narrowed G3. |
| 7 · Anchor floor | Approve RFC 6962 v1 as the sole base-tier proof protocol. A published-checkpoint second profile is post-v0.2 if ever. |
| 8 · Resource ceilings | Approve D-30 constants including 16 MiB / 10,000 nodes; committed in verdict config, revisable at a future wire version with data. |

## D-56 — Reference encoder four-byte uint defect; corpus regenerated with lab-era times

**Decision.** `harness/cbor.ts` wrote the first payload byte of a four-byte
unsigned integer as `value / 2^32` (which truncates to zero) instead of
`value >>> 24`, silently zeroing the high byte of every unsigned integer in
`[2^24, 2^32)` — the range containing every realistic Unix timestamp. The
encoder is corrected; a boundary KAT test (`harness/cbor-boundary.test.ts`)
pins RFC 8949 core-deterministic bytes for all width transitions, each value
cross-checked against the pyref encoder. The corpus is regenerated: fixture
builders always intended lab-era times (`BASE_TIME = 1_735_689_600`), so
217 fixture files change bytes. Five corruption-era constants that had been
hardcoded from the *encoded* (corrupted) values are restored to their
intended values (`anchor/submission-late` mutation, `epoch/late-insertion`,
DAG depth/width `committed_at`/`expires_at`, and pyref's
`KAT_EVALUATION_TIME` `7_636_552` → `1_735_689_800`).

**Why.** Found in gate 5 slice D1 (G5-D1-004): the demo EP, building on the
harness encoder with a current Unix timestamp, produced bundles whose carried
`evaluation_time` disagreed with `--at` under pyref. Gates 1–4 could not
catch this: the corpus was *generated* by the defective encoder, so its bytes
were internally consistent (valid CBOR of the wrong small integers), pyref
matched the bytes clean-room, and byte-identity held. Two-implementation
agreement proves spec unambiguity over the corpus's value coverage — not
beyond it. The wire text is unchanged and needs no erratum: RFC 8949
deterministic encoding is unambiguous; this is an implementation and
fixture-value defect only.

**Verification.** After correction: harness 30/30 (1,180 assertions incl.
14 boundary KATs), pyref C1 43/43 round-trip/ID/signature byte-identity,
pyref C2 188/188 verdict + reason agreement, determinism 188/188, zero
divergences — the two-implementation bar re-met on the corrected corpus.
Tagged `v0.2-rc3`.

## D-57 — `maximum_outcome_level` aggregation is order-independent; terminal labels dominate

**Decision.** Step 19's verdict field `maximum_outcome_level` is a pure
function of the multiset of committed receipts' `evidence.outcome.level`
values, independent of receipt-ID sort order: `contradicted` if any receipt
declares it; else `unknown` if any receipt declares it; else the
highest-ranked declared level (`independently_sensed` >
`device_acknowledged` > `dispatched` > `accepted`); else `not_evaluated`.
CONFORMANCE step 19 gains the normative sentence. Both implementations are
corrected: the reference implementation let a ranked level encountered after
a terminal label silently overwrite it (guarded lookup, last-wins); pyref
raised `KeyError` on the same ordering (`outcome_order[maximum]` with a
terminal maximum). The demo producer's interim workaround — grinding the
outcome receipt's freshness nonce until its receipt ID sorted after the
action-attempt and dispatch receipts (G5-D2a-007 D2a reading) — is removed;
conformant producers need no ordering discipline. Fixture coverage is added
for ranked-after-terminal and for bundles carrying both `contradicted` and
`unknown` in both sort orders; existing corpus verdict bytes must be shown
unchanged.

**Why.** Found in gate 5 slice D2a (G5-D2a-007): S6's terminal outcomes gave
the outcome-observation receipt a content-addressed ID that sorts before the
dispatch receipt roughly half the time, crashing the public reference
verifier on wire-valid conformant input. The spec sentence "Contradicted and
unknown remain honest terminal labels" implied dominance but never pinned the
aggregation, so the two clean-room implementations improvised divergently —
in a **signed verdict field**. Gates 1–4 could not see it because no corpus
fixture carried a ranked level sorting after a terminal one (the D-56 lesson
restated: two-implementation agreement proves unambiguity only over the
corpus's coverage). Terminal-dominates is the honesty-first reading: a run
whose outcome was contradicted or unresolved must not report a stronger
level because a lower-ranked receipt happened to sort last; `contradicted`
outranks `unknown` because it is a positive observation of contradiction,
not mere absence of evidence.

## D-58 — Signing-key resolution is bundle-plus-explicit-configuration; platform trust stores are out of scope

**Decision (verifier-testable rule).** A verifier resolves signing keys only
from credentials carried in the bundle. Any kid unresolvable from bundle
credentials plus explicit configuration yields a signed indeterminate
`key/not-found` — the existing semantics (step 6 for artifact signers, step 20
for the verifier credential); no new reason code. An
implementation MAY additionally accept explicitly configured external keys;
the mechanism and format are implementation-defined, MUST be reflected in the
verdict's `config_digest`, and MUST never be sourced from a platform trust
store. No such mechanism exists in either reference implementation; an
interoperable external-key format is deferred (v0.3 candidate).

**Policy (not conformance).** No conformant workflow may require installing an
AAR root, issuer, or device credential into an operating-system or browser
trust store, and a verifier must not consult platform trust stores when
validating any signed object. Documentation and tooling shipped with the spec
must never instruct an operator to broaden OS-level trust to make verification
succeed. These clauses are not observable in any verdict byte and are recorded
as policy per the G4 precedent (checkable rules stay conformance; the rest is
recorded explicitly as policy).

**Scope note.** Default *trust* (roots, anchor heads, policy digest) is
producer-declared via `bundle.trust_inputs`; the verifier-configured path is
the pyref `--trust-policy` pin, which can pin but never add. The
verifier-configured claim in this entry is about *key resolution*, which both
reference implementations already perform bundle-only (no filesystem, network,
environment, or platform API in the resolution path).

**Why.** The existing conformance order already behaves this way for key
resolution (`key/not-found` is defined against configured keys), but the
constraint was implicit. Field evidence 2026-08-08: Trustlix (Commend
Österreich, an Axis TIP) ships on-camera PKI whose first-run flow installs a
camera-generated root CA into the Windows Trusted Root store (Local Machine),
giving a single edge device certificate-minting power over every workstation
that follows the manual. Real vendors get this wrong; stating the principle
makes the failure mode a recorded rule rather than a deployment accident.
Teardown: vault `08-Agent-Output/2026-08-08-cmdoe-trustlix-review/review.md`.

**Alternatives considered.** Staying silent (status quo — leaves integrators
free to replicate the Trustlix pattern in AAR tooling); allowing OS trust
stores as an optional key source (imports every platform store's revocation
and scoping semantics into the verdict, untestable across platforms);
defining a trust-bundle file format now (rejected — a normative surface with
zero corpus coverage that two clean-room implementations would improvise
divergently; the D-56/D-57 failure shape).

## D-59 — One signing key per physical device (producer provisioning requirement; policy, not conformance)

**Decision.** A producer deployment MUST provision a distinct signing key per
physical device; for non-device roles, per logical principal, where a
`workload_instance` principal is exactly one runtime instance and a
`"service"` principal MUST NOT be used to share one key across multiple hosts
or devices. Provisioning one key or credential across a fleet is nonconformant
*producer* behavior. Attestation-bound keys remain the recommended profile,
not the floor.

**Recorded as policy-not-conformance.** The v0.2 credential schema carries no
device binding of any kind (`principal-type` has no device value;
`credential-profile-object` carries no device identifier; the only wire-level
device identity is the producer-asserted `device-identity` inside
observation/outcome bodies, which no verification step checks). Cross-device
key sharing is therefore not wire-decidable by any verifier — single-bundle or
fleet-level — and no reason code is defined. `credential/usage-mismatch` is
NOT overloaded for this: that code means key usage does not authorize the
signed object or role, and cross-device reuse is not a usage failure.

**Why.** A receipt signed by a fleet-shared key proves an action came from
*some* holder of that key — attribution, the product's core claim, collapses,
and revoking one compromised device (revocation acts on `subject_kid` via
status snapshots) revokes the whole fleet. `credential/role-key-reuse` already
bars cross-role sharing; this records the cross-device requirement where the
wire cannot yet enforce it. Same field evidence: Trustlix's fleet deployment
explicitly supports pushing one certificate to many cameras, destroying
per-device identity and individual revocation in a shipping product marketed
as zero trust. Recording the producer requirement as policy follows G4 (the
verifier confirms "artifacts satisfy declared class", never producer honesty)
and the D-26/D-58 pattern: the wire-checkable half is a verifier rule, the
rest is explicit policy.

**Revisit-if.** A device-binding field (credential-level device identifier or
attestation evidence) enters the credential schema — then define
`credential/device-key-reuse` as a deterministic step-8 check with KAT
coverage, and decide the HA-failover case (single logical EP with
rotation-record handover via the existing predecessor/successor machinery, vs.
per-node keys) in the same amendment. Multi-imager cameras are one physical
device, one key, as written.

**Alternatives considered.** SHOULD-level guidance only (leaves the
attribution guarantee soft exactly where a real vendor already broke it);
enforcing via credential count limits (doesn't bind keys to devices);
attestation-bound keys as a MUST (right direction, but hardware attestation
availability varies — kept as the recommended profile, not the floor).

## D-60 — An `agent_request` root's request must agree with the receipt binding on tenant, site, and enforcement point

**Decision.** At step 7, after the `request_commitment` digest check, a verifier MUST
require the resolved request's `tenant_id` and `site_id` to equal the receipt
binding's, its `target_ep_kid` to equal the binding's `epoch_owner_kid`, and its
`correlation.target_ep_kid` to equal its own top-level `target_ep_kid`. Any
disagreement is `request/coordinate-mismatch`.

**Why.** `request/commitment-mismatch` proves the carried bytes are the ones the
agent signed. It does not prove the agent signed them *for this tenant, this site,
or this enforcement point* — and the request duplicates all three coordinates that
the receipt binding independently asserts. Every other artifact pair in this spec
that duplicates coordinates is already required to agree:
`cose/receipt-coordinate-mismatch` (protected vs payload),
`merkle/batch-binding` (proof vs signed batch), `anchor/manifest-binding` (record
vs signed manifest), `graph/parent-metadata-mismatch` (child vs resolved parent),
`graph/tenant-site-splice` (parent vs child). The request envelope was the only
duplicated-coordinate pair left unchecked, and the omission is not recorded as a
decision anywhere — so this closes an asymmetry rather than adding a new class of
rule. `target_ep_kid` is the sharpest case: that field exists solely to bind a
request to one enforcement point, and without this check a request the agent signed
naming EP X is accepted as the authorizing root for actions performed and signed by
EP Y. `delegation/scope` does not cover it — it scopes the *receipt* against the
delegation, which stays correctly scoped while the request diverges.

**Measured before the change.** Three bundles (tenant, site, and `target_ep_kid`
divergent, each with the request genuinely re-signed by the agent key and the root
commitment repaired) verified **`conformant`, all 20 steps, `evaluated_profile:
AAR-2A`** in *both* the reference harness and clean-room `pyref`. A control with a
stale commitment rejected `request/commitment-mismatch` at step 7, confirming the
request is resolved and examined there. Two independent implementations agreed
because both faithfully implemented an under-specified rule — the third instance of
under-determination that byte-identity between implementations cannot detect, after
D-56 (a corpus generated by the defective encoder that produced it) and D-57
(ordering the corpus never covered). The two-implementation bar proves unambiguity
over the corpus's value coverage; it never proves the rule set is complete.

**Scope, and what this does not claim.** This is a verifier-side artifact-agreement
check. It does not assert that any current producer emits a divergent bundle — the
demo EP stamps its own tenant and site — so it is not a producer defect report, and
G4 (guarantee = "artifacts satisfy declared class", never producer honesty) still
holds. The check earns its place because the disagreement is wire-visible and cheap
to detect at a step that already has both artifacts in hand. A missing or
non-conforming coordinate on either side is treated as disagreement (same code,
normative in CONFORMANCE step 7 — an adversarial review found both reference
implementations diverging off-corpus on malformed coordinates, one crashing
without a signed verdict). A signed request carried in `bundle.artifacts.requests`
that no `agent_request` root references asserts nothing and is deliberately checked
by nothing — orphan requests are consistent with this entry's scope and G4, not a
gap.

**Conformance impact.** Bundles that previously verified `conformant` now reject if
their request coordinates disagree. No wire fields change and no verdict bytes
change for bundles that already agreed, so the positive corpus and all 191 existing
fixtures are unaffected; the new code is additive. Producers that stamp their own
coordinates (the expected implementation) are unaffected.

**What the `target_ep_kid` clause depends on, and when to revisit it.** The
`tenant_id` and `site_id` clauses rest on invariants the spec states normatively
(§2 "All edges are same tenant/site", `graph/tenant-site-splice`). The
`target_ep_kid` clause rests on a narrower footing and should be read with it in
view: WQ-4 (`spec/GATE2-SLICE-A-REVIEW.md`) makes the EP sign its own journal and
requires the signing kid to equal `epoch_owner_kid` in v0.2, which is what makes
`epoch_owner_kid` an EP identity rather than merely a journal label. Two gaps sit
under that. First, nothing in this spec requires one epoch **owner** per bundle —
§2 constrains edges to the same tenant, site, and epoch (`epoch_id`), and the only
"same owner" language anywhere is a CDDL comment on anchor time-evidence — so a
multi-EP deployment is not defined rather than forbidden. Second, WQ-4 deliberately
keeps a Merkle batch's separate `signer_kid` "as a seam for a future
delegated-journal profile," i.e. the authors already anticipate separating the
signer from the epoch owner. What holds the clause up today: §2 also says
"Authorization, request, trigger, and attempt edges never cross an epoch boundary,"
so a request-rooted receipt stays inside one epoch. **Revisit if** a profile ever
defines multi-owner bundles or delegated journaling; at that point the identity a
request addresses may legitimately differ from the owner of the epoch journaling
its root-bearing receipt, and this clause — not the tenant/site clauses — is the
one to relax. Recorded because the omission this entry closes was itself an
unrecorded assumption; leaving a new one undocumented would repeat the mistake.

**Alternatives considered.** A DECISIONS entry declaring request-declared
coordinates deliberately unchecked (defensible under G4, but leaves the one
asymmetry in a spec whose credibility rests on checking every duplicated
coordinate, and leaves the `target_ep_kid` case with no owner); comparing
`target_ep_kid` against the *signer* of the root-bearing receipt instead of
`epoch_owner_kid` (wrong — the receipt carrying an `agent_request` root is signed by
the agent, not the EP, so that comparison would reject every conformant bundle);
reporting per-field codes (`request/tenant-mismatch` and siblings) instead of one
family code (rejected for consistency with `cose/receipt-coordinate-mismatch`, which
covers principal, role, tenant, site, epoch, and sequence under a single code).

## D-61 — Behavior on internal verifier error: internal error is a loud crash, never a signed verdict

**Decision.** When a verifier hits an internal defect on input that survived
decode (a bug, not a malformed-input rejection), it crashes loudly with no
signed verdict (pyref: `internal error`, exit 70; harness: uncaught throw).
A verifier MUST NOT sign a verdict whose reason attests to its own defect: an
internal error is an operational failure, not a verification outcome, and
signing it risks laundering a verifier bug into evidence-grade output. The
"verifier always emits a signed verdict" property is therefore scoped:
guaranteed for all decodable-but-malformed input (the 2026-08-15 guard
families), never for verifier defects.

**History.** A 2026-08-15 hardening pass briefly added a harness catch that
signed a `resource/internal-error` verdict; the gate review removed it: the
code is not in CONFORMANCE §3's closed table (a signed verdict's `reason`
MUST be a section-3 code), and it created a one-sided parity split (harness
signing internal errors while pyref exits unsigned).

**Alternatives considered.** Registering `resource/internal-error` in §3 with
a matching signed backstop in both implementations (rejected: the reason
would attest to a verifier defect rather than a bundle property, and KAT
coverage is inherently impossible — the trigger is by definition an unknown
bug). Both implementations already implement this decision; ratified
2026-08-15.

## D-66 — AAR-3 commits action-attempt evidence before dispatch and fails closed when no journal is available

**Decision.** For every AAR-3 action, the enforcement point MUST durably commit
the signed `action_attempt` receipt to its primary or pre-allocated emergency
journal before the action-bearing send. If neither journal can accept that
commitment, the EP MUST refuse dispatch and emit a `not_dispatched`
`action_attempt` with `refusal_reason="journal/unavailable"`. The verifier treats
an AAR-3 dispatch whose linked attempt has no prior epoch commitment as
`nonconformant` with `journal/uncommitted-dispatch`. The prior-commitment test is
the exact step-13 order rule in CONFORMANCE: same epoch owner/id, lower attempt
`epoch_seq`, and attempt `committed_at <= dispatched_at`.
It runs only after the existing dominance, delegation, scope, and delegation-time
checks (D-54).

The exception is an action class that the site's hazard matrix marks
`life_safety` and the verifier's bound trust policy lists in
`life_safety_action_names`. AAR MUST NOT override that design: the EP proceeds,
signs `degraded.reason="journal/unavailable"` on the attempt, and the verifier
records `degraded_dispatch`. The normalized action carries the explicit
`hazard_class="life_safety"` marker, but that EP assertion never establishes the
exemption by itself; absence from the bound list, or absence of the list, is
`receipt/hazard-class-unbound`. Absence of the marker means the ordinary
fail-closed path. Anchoring remains asynchronous and never gates dispatch
(R-16).

**Claimed property.** Under AAR-3's trusted EP, key, clock, and complete-mediation
assumptions, no AAR-3 executed action lacks a committed `action_attempt` receipt,
except an explicitly marked life-safety fail-operational dispatch. This is a
profile-bounded claim, not a claim that an offline verifier can detect a lying or
compromised EP, an unmediated side channel, or later journal tail truncation.
In particular, the verifier cannot detect a compromised EP that omits the
life-safety marker and lies about the attempt's commit time; that remains
residual risk under the trusted-EP and clock assumptions.

**Why.** R-16 named the degraded-mode matrix, emergency journal, and life-safety
override boundary but left the pre-send journal-unreachable case undefined.
D2a's dispatch latch closes the post-send honesty window; it does not decide
whether to send when evidence cannot first be committed. D-66 adopts the C5
control in Muruaga et al., *Bounded Agents: Delegation Security for Multi-Agent
AI Systems*, [arXiv:2608.15888 §C5](https://arxiv.org/abs/2608.15888), scoped to
AAR-3 and the R-16 hazard exception. The optional wire markers and additive
step-13 rule leave all pre-existing verdict preimages and fixture bytes unchanged
(D-51).

## D-67 — Optional mediator countersignature is a standalone v0.2 artifact

**Decision.** A bundle MAY carry `mediator_countersignatures`. Each artifact is
a detached COSE_Sign1 under a carried credential with the existing
`principal_role="outcome_observer"` and `key_usage="outcome_signing"`. It signs
the SHA-256 of the exact pre-dispatch `action_attempt` receipt-envelope, the
SHA-256 of the canonical command bytes the mediator verified on dispatch, and
the mediator's observation time. It is never required in v0.2; omission follows
the pre-D-67 wire and verdict path byte-for-byte. D-62 through D-65 remain
unratified candidates and are neither prerequisites nor implied changes.

Validation follows D-54: optional-array shape and ordering at step 3; artifact
COSE, signature, SPKI, role, and usage at step 6; the domain-separated artifact
ID at step 7; credential-chain acceptance at step 8; and receipt plus command
digest agreement at the end of step 10. A fully verified carried set adds
`mediator_countersigned` to the signed verdict. The closed failure codes are
`countersign/invalid`, `countersign/digest-mismatch`, and
`countersign/credential-invalid`.

**Claim boundary.** The artifact proves that an accepted in-tenant credential
with `principal_role="outcome_observer"` and `key_usage="outcome_signing"`
signed an observation of those two digests and carried an observation time. The
v0.2 verifier does not bind that credential's `kid` to "the mediator"; any such
accepted credential validates. Mediator-`kid` pinning in trust policy is a v0.3
question. The verifier also does not compare `mediator_observed_at` with any
other time in v0.2, and it accepts multiple countersignatures for one attempt
when their distinct observation times produce distinct IDs. The artifact
narrows T-H2 at the AAR-to-mediator boundary. It does not prove the signer
caused a device effect, that an outcome report is true, or that the signer is
independent. The demo's EP and mediator are same-operator (F22), but use
distinct credentials.

**Why.** The VMS leg already recomputes and compares the canonical-command hash
before dispatch. Signing that observation binds the pre-send AAR attempt to the
mediator boundary without importing D-62's future attestation-vantage model or
changing direct VAPIX bundles.

## D-68 — Credential principal types are checked before content IDs

**Decision.** The credential issuer fixture is a `service` with role
`authority_source`. Verifiers reject an unknown credential principal-type
at step 6 with `schema/enum-unknown`; a non-text value is `schema/bad-type`.
The existing CDDL enum is unchanged.
**Why.** A role is not a principal type. Corrected dependent KATs must be regenerated.

## D-69 — Demo production follows the consumption and anchor schema; `same_operator` is an explicit basis

**Decision.** The scripted demo commits its signed logical request as its one
consumption item, emits no exclusions from its secret-free logical command,
and declares the anchor basis `same_operator`. `independence-declaration.basis`
gains that second value; it declares no independence between anchor targets,
and a verifier records anchor existence/order only for such a plan. The basis
compares anchor targets with each other, not with the producer. Consumption
bounds, exclusion shape, and the basis enum are checked at step 6, even when
no anchor record is carried. These repairs give the demo bundles step-6 wire
shape; they do not by themselves make the demo verifier-conformant. A
`same_operator` anchor still anchors: it MAY support the `externally_anchored`
time class, because time class is an anchoring axis and independence is a
separate axis.
**Why.** A same-operator demo must not carry a true-sounding independence
claim on the wire, and the existing basis must keep its meaning. Making the
limitation an explicit wire value keeps it visible to every verifier.

## D-70 — Evaluation time is explicitly caller-selected

**Decision.** At step 5 the bundle evaluation time must equal the caller's time,
then be at least the trust-store creation time; either failure is
`schema/out-of-range`. Both verdict time fields always record the caller's time,
including on failure. Caller times must be uints no greater than 2^53-1.
**Why.** The producer must not silently choose a different evaluation time.

## D-71 — v0.2 does not establish custody continuity

**Decision.** Every v0.2 verdict emits `custody_continuity="not_established"`.
The verdict schema no longer permits `partially_evidenced`.
**Why.** General conformance, anchoring, and mediator countersignatures do not
constitute a defined custody-lineage verification procedure.

## D-72 — Every conformant v0.2 verdict observes `ingress_completeness_not_established`

**Decision.** A v0.2 verifier emits the `ingress_completeness_not_established`
observation on every conformant verdict, not only when the bundle declares
complete coverage. Both reference implementations emit it last, after any
`producer_declared_complete` observation. A failure verdict carries an empty
`observations` array; observations accumulated before the first failure are
report-layer only.
**Why.** CONFORMANCE.md defines the observation as "no independent
census/reconciliation", which is true of every v0.2 verdict. The harness
verifier already behaved this way; pyref emitted it only for complete coverage,
which broke cross-implementation verdict-byte equality on conformant bundles.
