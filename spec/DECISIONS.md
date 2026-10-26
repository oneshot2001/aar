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

## D-73 — Demo-only divergences: canonical command binding, epoch event pairing, verifier credential, algorithm enum

**Decision.** Four rules the KAT corpus never exercised — three surfaced by
running the reference demo bundles through both verifiers, one (the algorithm
enum) already listed as a known gap in `pyref/DIVERGENCES.md` — ruled
2026-09-09 as the release prerequisite for `v0.2.0`:

1. **Canonical command binding (step 10).** `canonical_command` decodes as
   `canonical-command-payload` (new CDDL production): required `operation`,
   `target`, `parameters_digest`, optional `logical_target` and `parameters`.
   The verifier compares the three required members to the normalized action
   and, when `parameters` is present, requires its deterministic encoding to
   hash to `parameters_digest`. The harness already compared the required
   members; pyref compared only `action_name`/`target_id` on the manifest and
   never decoded the command; the demo emitted `parameters` with no
   `parameters_digest`. Adapters keep executing from `parameters`.
2. **Epoch event pairing (step 14).** A carried manifest with no event group,
   or an event group with no manifest, is `epoch/open-close`. The harness
   already enforced both halves; pyref enforced neither and tolerated an
   event-less closed manifest (the demo shipped exactly that). The open must
   also precede the close in both `event_seq` and `occurred_at` (the harness
   checked time, pyref checked sequence; both now check both). The demo now
   emits signed open and close events.
3. **Verifier credential (step 20).** D-58's rule — the verifier's signing kid
   resolves from bundle credentials, else signed indeterminate
   `key/not-found` — was enforced by the harness only; pyref signed
   regardless. pyref now enforces it with the harness's find-first semantics
   (the first credential carrying the verifier kid must have
   `verifier_signing` usage); the demo credentials the published
   Gate-4 KAT verifier key exactly as the corpus does. This remains the
   published test key, not an operational verifier identity (pyref/README).
   An interoperable external-key input stays a v0.3 candidate (D-58).
4. **Algorithm enum (step 6).** pyref now rejects credential `cose_alg` ≠ -7
   or `curve` ≠ "P-256" (`schema/bad-type` for wrong type, then
   `schema/enum-unknown`), in harness order after `principal_type`.

**Evidence.** Six new negative KATs (`repair-d73-*`), golden demo digests
re-pinned, `canonical-command-payload` wired into the CDDL so the D-74 oracle
validates it, and a new test proving both verifiers emit byte-identical
conformant verdicts for the S1/S3 golden bundles (byte identity there is
under a caller-supplied verifier identity copied from pyref, as in the
cross-implementation gate; it proves rule agreement, not independent
identity). Corpus positive fixtures are unchanged; only the demo bundles
changed bytes. Not fixture-covered: the open-before-close time rule, because a
mutated event breaks the event chain first; parity rests on the aligned code.

**Why.** Same lesson as D-56 and D-60: two implementations agreeing over the
corpus proves unambiguity only where the corpus reaches. The demo is the first
producer outside the harness, and it found three rules the corpus never put
in front of pyref. Ruled by the gate 2026-09-09; the two open items in
`pyref/DIVERGENCES.md` are closed by this entry.

## D-74 — Schema membership is gated by an external CDDL oracle at release, not by runtime validators

**Decision.** CDDL membership of every conformant fixture, the golden demo
bundles, and their signed verdicts is proven at release by
`python3 -B -m pyref.schema_kat`, which feeds exact bytes (including every
`bstr .cbor` payload and protected header) to the Ruby `cddl` gem pinned at
0.12.14, after self-tests prove the engine enforces `.cbor` recursion, closed
maps, enums, `.size`, and occurrence bounds. The verdict CDDL is read from the
normative block in CONFORMANCE.md at run time; there is no second copy. A
missing or mismatched engine fails the gate; it never skips. The runtime
verifiers are unchanged: they keep their focused step-6 checks and their
first-failure ordering, and do not become recursive schema validators.
**Why.** Handwritten payload checks in two verifiers agreeing with each other
does not establish CDDL membership; an independent engine does, at release,
without adding release risk to the runtime path.

## D-75 — A decision record MAY cite zero status snapshots

**Decision.** `decision-record.status_snapshot_ids` is `optional-digest-ids`
(`0*64 digest32`), not `digest-ids` (`1*64`). The `1*64` minimum was never
justified by a decision entry, is not enforced by either runtime verifier, has
no negative KAT, and CONFORMANCE step 8 only resolves the references a record
actually cites. The change is wire-additive: zero verdict-byte change, zero
fixture change. The same-operator demo precedent (D-69) went the other way
because that enum value carried an independence claim the demo had to state
explicitly; an empty snapshot list claims nothing. Proposed by the reviewer
(D5 oracle, headline finding) and accepted by the gate 2026-09-09.

## D-76 — Prior-emission history is committed into the signed verdict

**Decision.** Extend D-51, without replacing its existing preimages, with
`prior_emissions_digest = SHA-256(deterministic-CBOR(["AAR-VERDICT-PRIOR-v1",
prior-emissions-map]))` in `verdict-trust-policy`. Section 5 of CONFORMANCE.md
freezes the closed `{ entries: [...] }` map, entry fields, and strict unique
ordering. An empty or absent `prior_emissions` array in a supplied file binds
the empty entries map; no supplied prior state uses a zero digest. Absence of
prior state uses 32 zero bytes, and duplicate or unsorted supplied entries are
a usage error. The required key raises the verdict version from 2 to 3 and the
declared spec to v0.2.1; the protected v0.2 content type and receipt fixtures
are unchanged.

**Why.** A read-only external review on 2026-09-27 demonstrated that the
issuer-sequence-rollback fixture evaluated with empty prior history and with
unrelated prior history (a different issuer kid) produced byte-identical
signed verdicts. The real rollback history flipped the result while every
trust-policy digest stayed unchanged. `prior_emissions` governs
`identity/reuse`, `identity/issuer-sequence-rollback`, and
`identity/epoch-sequence-rollback`, but D-51's `replay_state_digest` covers only
replay entries. A verdict that flips on an input it does not commit to is not
a complete signed statement of its own evaluation.

## D-77 — Signed objects are bound to their declared signer; root usage, credential validity, and root uniqueness each get one rule

**Decision.** Four verifier rules, each closing a defect found on 2026-10-08
while reviewing the D-58 trust-provisioning proposal
(`docs/verifier-trust-provisioning-design-v0.1.md` §0, X-1 to X-4):

1. **Declared signer (X-1).** An envelope's protected kid MUST equal the
   signer its payload declares: a credential's `issuer_kid` (a self-signed
   root has `issuer_kid == subject_kid ==` protected kid), a status
   snapshot's `issuer_kid`, an anchor record's `target.anchor_kid`, the
   subject kid of the credential a delegation names as
   `issuer_credential_id`, the subject kid of the credential an
   approver-originated presentation names as `presenter_credential_id`, and
   for an EP-authenticated-session presentation the signer of its enclosing
   authorization receipt. The existing epoch-owner and Merkle-signer checks
   are the same rule and move to the same position. Two supporting rules
   keep the binding deterministic. First, when several carried credentials
   share a `subject_kid`, the first in array order is the resolved
   credential (D-73's find-first rule). Second, a credential for a
   trust-store root key MUST have an empty path (`credential/path-invalid`),
   so only the root's self-signed credential can stand in for the root.
   A non-array credential `path` is `schema/bad-type` at step 6. A
   presentation's `presenter_credential_id` MUST equal the decision's
   `approver_credential_id` (`receipt/decision-presentation`, which pyref
   already enforced and the harness did not). A failure is `credential/usage-mismatch` at
   CONFORMANCE step 6.7.5, the code the epoch-owner check already uses, or
   `countersign/credential-invalid` for a countersigned subject.
2. **Root usage (X-2).** At step 8, a credential whose `subject_kid` is the
   protected kid of any envelope verified at step 6 (embedded delegations
   and nested presentation manifests included) MUST carry a `key_usage`
   listed in its root record's `allowed_key_usages`, else
   `credential/root-not-accepted`. A carried credential that signs nothing
   is exempt from the usage clause, not from root acceptance.
3. **Credential validity (X-3).** A resolved signing credential is valid on
   the half-open interval `[valid_from, valid_until)` at the signing time:
   a receipt's `emission.committed_at`, otherwise the evaluation time.
4. **Root uniqueness (X-4).** Trust-store root records MUST NOT share a
   `root_kid`. A repeat is `schema/duplicate-entry` at step 5, before the
   per-root tenant/site check.

Step 6.7 is now an ordered list (key resolution, kid/key match, P-256,
usage, declared signer, tenant/site, validity), and the receipt coordinate
comparison runs after all of it. The two reference implementations had
ordered these differently: pyref checked validity before tenant/site, the
epoch owner after both, and receipt coordinates before key resolution; the
harness had no step-6 tenant/site check and checked the epoch owner before
validity. The declared spec becomes v0.2.2. Wire shape, the verdict version
(3), and its content type are unchanged.

**Why.** (1) Without it the issuer field is decorative. Each credential
envelope was verified with the key its own header named, while path
construction followed the declared `issuer_kid`. Anyone holding a key could
therefore mint a credential claiming issuance by an accepted root, and both
verifiers returned `conformant`. This was reproduced on
`kats/positive/bundle-valid-subset` on 2026-10-08; a self-declared root and a
corrupted signature were still rejected as controls. Status snapshots,
anchor records, delegations, and presentations had the same unbound field.
A producer could sign an anchor record for a target it declared
independent, any authority key could sign a delegation naming another
authority as issuer, and any approver key could sign a presentation naming
another approver. That last one is pinned by
`repair-d77-presentation-signer-forged`, which both pre-D-77 verifiers
accepted as `conformant`. A presentation with an unknown `signer_mode`
escaped the binding entirely, because neither verifier validated that
closed enum (or the presentation `state` enum) as step 6.6 already
requires. Both now do. Attribution, the
product's core claim, rests on this check. (2) and (4) The reference
implementations disagreed (pyref checked usage for signers, the harness
only for mediator credentials; pyref kept the last duplicate root, the
harness accepted any match), and no corpus case exercised the difference,
so the cross-implementation byte gate passed. (3) Half-open matches the
delegation `not_after`, replay `expires_at`, and selector
`committed_until` intervals. Signing time matches the reason-code table's
"signing/use" wording for revocation and compromise. Neither reference
implementation yet judges revocation or compromise at signing time; that
gap is backlogged. It keeps a receipt verifiable after its signing key
expires, for keys that sign only receipts (agent, outcome observer), and
within status freshness. Backdating is bounded by the EP-signed manifest
index, which must commit the same `committed_at`, so a forged early time
needs the EP's key. A receipt's `committed_at` is otherwise only as
trustworthy as its time class, which the verdict's `maximum_time_class`
reports.

**Evidence.** A corpus scan before the change found that all 1,771
credential, 176 status-snapshot, and 128 anchor-record envelopes in `kats/`
satisfy rule 1. So do all 523 delegations and 166 presentations (every
presentation in the corpus is approver-originated). No bundle repeats a
`root_kid` or carries a root-key credential with a non-empty path.
Existing KAT results and reasons are unchanged. pyref's reported step for
`receipt-signer-role-mismatch` moves from 10 to 6, and pyref's mediator
mapping for a non-bytes `public_key` or non-uint validity (unreachable after
schema validation) now matches the harness. New negative KATs cover each rule, including the X-1
forgery. Verdict bytes change only through verifier identity, because the
build preimages move to v0.2.2.

**Alternatives considered.** New reason codes such as
`credential/issuer-mismatch` or `anchor/signer-mismatch`: rejected, because
the epoch-owner precedent already maps a declared-signer mismatch to
`credential/usage-mismatch`, and reason codes are wire surface. Rejecting duplicate `subject_kid`
outright: rejected, because the corpus's `credential/role-key-reuse`
fixture carries one key under two roles and must keep its own step-8 code.
Find-first makes resolution deterministic without taking that code
away. Checking
root usage for every carried credential: rejected, because the corpus
carries a `verifier_signing` credential whose root does not list that
usage, and usage matters only for keys that sign. Evaluation-time validity
for receipts (pyref's prior behavior): rejected, because a key whose
validity ended before the bundle's evaluation time would invalidate every
receipt it signed while valid, which contradicts the signing-time
revocation rule. A closed validity interval: rejected, because it would be
the only closed interval in the wire.

## D-78 — Input origin in an action's ancestry is a producer declaration, relayed as a limit and an observation

**Decision.** Six parts, one wire minor (v0.2.3, verdict `v: 4`).

1. **Closed enum.** `input-origin = "principal" / "operator_system" /
   "device_sensed" / "third_party" / "unknown"`. Classification is by the
   *origin of the content*, never its transport, message role, or current
   custodian: an internal tool that returns text fetched from the web declares
   `third_party`; OCR of a camera frame declares `device_sensed`; the live
   request of a principal who is also the operator is `principal`, while
   independently configured system prompts, policies and internal records are
   `operator_system`. `unknown` means the emitter classifies inputs and could
   not classify this one. It is distinct from absence, which means "not
   declared".
2. **Two optional fields.** `consumption-item.origin: input-origin` (one value;
   an item carrying content of more than one origin declares the least
   trusted present, in the order `third_party`, `device_sensed`, `unknown`,
   `principal`, `operator_system`) and `inference-body.origins: input-origins`,
   a strictly sorted unique set of one to five values in deterministic-CBOR
   encoded-byte order (`unknown`, `principal`, `third_party`, `device_sensed`,
   `operator_system`) summarising the origin classes present across the
   inference's prompt, retrieval and tool inputs. Both are wire-additive: a
   receipt without them is byte-identical to a v0.2.2 receipt.
3. **Step 6 validation.** `origins` that is not an array is `schema/bad-type`;
   empty or longer than five is `schema/out-of-range`; a non-text member is
   `schema/bad-type`; an unlisted member `schema/enum-unknown`; a repeated
   member anywhere in the array `schema/duplicate-entry` (checked before
   order); a member out of encoded-byte order `schema/unsorted-set`. A
   consumption-item `origin` follows the same type and enum rules. A
   consumption-item `disposition` is validated for type and enum at step 6,
   which neither runtime did before; no corpus bundle is affected.
4. **Step 13 tail: input-origin ancestry.** After every dispatch has passed
   step 13, take the set of distinct action attempts those dispatches resolve.
   For each, walk incoming edges transitively, following every edge type
   except `attempted_as` and `observed_outcome`, visiting each receipt once
   and following cross-epoch links already validated at step 12. The walk
   therefore covers observation, inference, authorization and
   outcome_observation ancestors, including the authorization's own
   `requested_by`/`triggered_by`/`supports` parents and an
   outcome_observation's `supports` parents. `supports` is noncausal (D-09):
   the result means an input sat in the action's ancestry, never that it was
   consumed by the agent or caused the action. A *declaration slot* is one
   inference receipt (declared iff `origins` is present) or one consumption
   item with `disposition = "used"` (declared iff `origin` is present); an
   all-`discarded` observation contributes no slot. Over the union of slots
   across all attempts: `limits.input_origin_ancestry` is `not_evaluated` when
   there are no slots, `declared_only` when every slot is declared,
   `not_declared` when none is, otherwise `partially_declared`. The
   observation `untrusted_origin_declared_in_action_ancestry` is recorded iff
   any declared value is `third_party`, `device_sensed` or `unknown`. Signed
   bytes carry only these two aggregates. Verifier tools MUST surface a
   report-layer per-attempt table (dispatch array order, then attempt id;
   declared origin set; undeclared slot count), including attempts that are
   eligible but undispatched, bound to the bundle and verdict identifiers.
5. **Verdict.** `verdict-limits` gains the required key
   `input_origin_ancestry`; the `observations` enum gains
   `untrusted_origin_declared_in_action_ancestry`, emitted after
   `refused_pre_dispatch` and before `membership_only`, with
   `ingress_completeness_not_established` still last (D-72). The required key
   raises the verdict version from 3 to 4 (the D-76 precedent) and the
   declared spec to v0.2.3; the protected v0.2 content type and every
   existing receipt fixture are unchanged. A failure verdict carries
   `input_origin_ancestry: "not_evaluated"` and an empty `observations`
   array.
6. **Claim cap.** A v0.2.3 verifier MUST NOT emit any value stronger than
   `declared_only`. Declarations are relayed, not established: the verifier
   does not and cannot check them against prompt, retrieval or tool manifest
   bytes (D-32), and at `self_asserted` provenance an input omitted from the
   consumption manifest is undetectable (T-P3, RR-8). `declared_only` means
   every declaration slot the specified traversal examined contained an
   emitter-supplied origin label; it establishes neither label accuracy,
   complete capture of inputs, actual consumption, nor causal influence.

**Why.** Primary guidance published 2026-05-01 by the Five Eyes cyber agencies
describes the confused-deputy pattern for agents and observes that executing
an injected instruction "under a trusted agent identity ... produces audit
logs that appear legitimate". Identity, network and endpoint records cannot
distinguish that action from a legitimate one; only the harness that fed the
model knows what untrusted content entered the context first. AAR already
commits the inputs (consumption manifests, D-46; prompt, retrieval and tool
manifests, D-32) and already caps the forensic claim at "the item was
disclosed among captured inputs" (T-P4). What it lacked was a closed place
for the producer to say *where an input came from* and a rule relating the
captured inputs to the dispatched action, so that a third party can see that
an untrusted-origin path was disclosed, or that nothing was declared at all.
D-29 is why the aggregate is a required limit rather than a conditional
observation alone: silence must never read as "no untrusted input". The
Enforcement Point can apply the same declarations at authorization time as a
toxic-combination rule (untrusted origin present and a consequential action
requested); that is an EP policy, and nothing in the signed verdict
establishes that it was applied.

**Alternatives considered.** Observation only, keeping verdict v3: a bundle
with no declarations and one declared all-trusted would produce the same
silent verdict, and an optional limits key would still break closed-map
consumers while weakening D-29. Limit only, folding the finding into the
enum: conflates completeness of declaration with the finding; a partially
declared ancestry with one `third_party` is a real state. A signed
per-attempt table: no precedent in the verdict, unbounded size, and the
report layer already carries it. Encoding origin in existing fields:
`source_device.failure_domain_id` is load-bearing for step-19 observer
independence; a reserved `evaluated_inputs` name is the free vocabulary D-09
forbids and records what the Authority Source evaluated, not what the agent
consumed; presence of a `retrieve` transformation cannot see injected content
arriving through the prompt manifest and fires on every internal retrieval.
Treating `unknown` as trusted: declaring `unknown` would then launder.
Stopping the walk at outcome_observation receipts: `observation -supports->
outcome_observation -supports-> inference` is a legal path and would be a
blind spot. A new step number: every sidecar `expected_step` would churn. A
v0.3 line: nothing is removed or made required on receipts. Proposed by the
2026-10-11 design pass (two independent plans, one arguing against new
fields, converging) and a Codex challenge that corrected the edge set, the
sorted order, the disposition gap, the pyref `state.classes` overwrite, and
the naming; accepted by the gate 2026-10-11.

## D-79 — A delegation names the enforcement point that attempts under it

**Decision.** At step 13, after `decision.delegation_id` equality and before
any scope check, the embedded delegation's `subject_credential_id` MUST
resolve, by find-first over the carried `credentials` array, to a credential
whose `subject_kid` equals the protected kid of the action attempt. No such
credential, or a different kid, is `delegation/scope`. The step-13 order is
normative (D-54): dominance and embedded-delegation identity; subject; action,
target, purpose, profile, tenant, site, invocation (all `delegation/scope`);
`not_before`; `not_after`; `parent_delegations`; then D-66 for that dispatch.
The invocation check applies whenever the delegation carries `invocation_id`,
and a `one_time` delegation without `invocation_id` fails it. No wire change;
no new reason code; the `delegation/scope` row names the subject.

**Why.** `subject_credential_id` was carried and never read, so a delegation
issued to one enforcement point authorized an attempt signed by another.
Every producer in the corpus and the demo issues delegations to the EP
credential (`harness/fixtures.ts`, `demo/ep/wire-builder.ts`), and action
attempts are EP-signed by role (§2 roles), so binding the subject to the
attempt's signer closes the gap without touching bundle bytes. The two
verifiers also disagreed on whether the time window or the scope fails first,
and on when the invocation check applies; one order and one rule end both.

**What this does not establish.** Which *agent* was delegated. A delegation
whose subject is an `agent_signing` credential now fails `delegation/scope`
by rule; agent attribution needs a selection rule over the attempt's ancestry
(request signer, inference signer, human and standing-condition roots) and
stays a DESIGN item in BACKLOG (Codex challenge 2026-10-17, finding 6).

**Alternatives considered.** Bind to the request envelope's `agent_signing`
kid or the nearest inference signer: breaks the base positive, and no rule
picks one ancestor under `human_request` or `standing_condition_trigger`
roots. A usage-keyed rule (an EP subject binds to the attempt, an agent
subject to the inference ancestor): more spec surface for a delegation shape
no producer issues. A new reason code: D-77 reused codes for the same kind of
binding.

## D-80 — A rotation record is signed by the predecessor's issuer and ordered within its tenant and site

**Decision.** Rotation binding at step 8, per record in artifact-array order:
`predecessor_credential_id` and `successor_credential_id` resolve to carried
credentials whose `subject_kid` equal `predecessor_kid` and `successor_kid`;
the record's protected kid equals the predecessor credential's `issuer_kid`
(the predecessor's own key when it is self-signed); the record's `tenant_id`
and `site_id` equal both credentials'. Any failure is
`credential/rotation-invalid`. After every record binds, the ordering pass
groups records by (`tenant_id`, `site_id`), sorts each group by
(`effective_at`, `continuity_sequence`), and fails a record whose
`continuity_sequence` or `effective_at` is not strictly greater than its
predecessor's with `credential/rotation-rollback`; groups are never compared.
A rotation record asserts continuity only: it never makes its successor's root
accepted, and a successor root key is accepted through the trust store like
any other root. The rotation envelope's own signer is subject to the step-8
status checks like every envelope (D-81), so a predecessor issuer revoked or
compromised before evaluation cannot authorize a rotation.

**Why.** Any `credential_issuing` key could sign a rotation asserting
continuity between any two credentials, so a stranger's issuing key could
splice a successor onto a victim's identity. Only the authority that issued
the retiring key can speak for its successor. The namespace question was a
cross-implementation divergence (pyref per tenant/site by `(effective_at,
seq)`, harness global by `seq`): the CDDL carries tenant and site on every
record and names no global allocator, and no producer has asked for one
sequence across sites, so the partition is the rule and the harness changes.
Binding every record before any ordering check keeps the first failure
observable: a binding defect in one record cannot be masked by, or mask, a
rollback between two others.

**Alternatives considered.** Signer must equal both credentials' issuers:
forbids issuer handover, which is what root rotation is. Global sequence
(harness): a new restriction with no producer behind it. Interleaving binding
and ordering per record (harness today): the first-failure code depends on
array position in a way the spec never stated.

## D-81 — Revocation and compromise are judged at use time; every signed object has one signing time

**Decision.** Three parts, one wire-additive field (v0.2.4; verdict `v: 4`,
protected content types unchanged).

1. **`revoked_at`.** A status snapshot gains optional `revoked_at:
   unix-time`. A `revoked` snapshot without `revoked_at`, or a `compromised`
   snapshot without `compromise_at`, is `schema/missing-field` at step 6; a
   present value that is not a `unix-time` is `schema/bad-type`. The instant
   is the status authority's assertion of the effective event and travels
   unchanged through refreshed snapshots; `produced_at` is when the snapshot
   was published and is never the instant.
2. **Signing time per object (6.7.7).** The signing time of an object is the
   time it claims for its own signed act: a receipt's `emission.committed_at`;
   an epoch manifest's `closed_at`; an epoch event's `occurred_at`; an anchor
   record's `accepted_at`; a Merkle batch's `created_at`; a presentation
   manifest's `delivered_at`; a status snapshot's `produced_at`; a request
   envelope's `freshness.issued_at`; a mediator countersignature's
   `mediator_observed_at`. A credential, a delegation, and a rotation record
   carry no time of their own signing; their signing time is the evaluation
   time. The same signing time is the credential validity instant at 6.7.7
   and the key's use time at step 8.
3. **Use-time status (step 8).** For a `revoked` or `compromised` snapshot,
   the named credential's key is used by every envelope verified at step 6
   whose protected kid equals that credential's `subject_kid` (embedded
   delegations and nested presentation manifests included), each at its
   signing time, and by the verifier's own signing credential at the
   evaluation time (step 20). The snapshot fails (`credential/revoked`,
   `credential/compromised`) when any use is at or after its instant, and
   passes when no use is, with the status inputs bound into the verdict. A
   `revoked` or `compromised` snapshot whose `credential_id` names no carried
   credential fails closed as if used at the evaluation time. After every
   snapshot's content passes, a carried snapshot naming no carried credential
   and a decision reference naming no carried snapshot are each
   `credential/status-missing`, in that order (D-52). The freshness boundary
   is half-open: an evaluation time at or after `next_update` is
   `credential/status-stale`.

**Why.** D-15 already decided that a signature before the compromise time
may validate even when evaluated later. Both verifiers nonetheless failed
every `revoked` snapshot unconditionally and judged compromise at the
evaluation time, so a revoked key made every receipt it ever signed
unverifiable, the opposite of what evidence retention needs. Doing it at use
time needs an instant the authority asserts (`compromise_at` existed,
`revoked_at` did not; a snapshot's `produced_at` moves with each refresh) and
a signing time for every object, not only receipts (under the old 6.7.7 a
revoked EP key still failed its manifests and events at step 8). The
verifier's own key is a use at the evaluation time because step 20 is about
to sign with it; without that rule a revoked verifier credential went from
`credential/revoked` to `conformant`. Lifecycle envelopes get the evaluation
time because their `valid_from`, `not_before`, and `effective_at` express
effectiveness, not issuance, and a compromised issuer can backdate them. All
four points come from the Codex challenge of 2026-10-17 (findings 1 to 3 and
8).

**Consequence for producers.** Revoking or marking an issuer key compromised
fails every credential, delegation, and rotation record that key signed, in
any bundle that also carries the snapshot. Re-issue leaf credentials under
the successor before stapling the snapshot; an export built after the fact
can carry the re-issued chain and omit the old one. Receipts signed by a
revoked leaf key before `revoked_at` keep verifying.

**Alternatives considered.** Keep evaluation time and rewrite the rows to
match the code: erases D-15 and makes history after a revocation
unverifiable. `produced_at` as the revocation instant: unstable across
refreshes. `valid_from` / `not_before` / `effective_at` as issuance proxies:
self-asserted by the party whose key is in question. Exempting unresolved
subjects as "unused": lets a dangling `credential_id` downgrade
`credential/revoked` to `credential/status-missing`, the masking D-52
forbids.

## D-82 — Verifier parity: one failure-verdict table, forks reject, nested envelopes travel with their receipt, chains are transitive, the schema table is bounded

**Decision.** Ten parts, no wire change (v0.2.5; verdict `v: 4`; protected
content types unchanged). Each closes a cross-implementation divergence the
2026-10-08 parity audit (`docs/verifier-parity-audit-2026-10-08.md`) or the
2026-10-17 scoping pass found. Every rule is pinned by a fixture in both
verifiers before the audited rows are re-pinned.

1. **Failure-verdict population (§5).** A `nonconformant` or `indeterminate`
   verdict is populated by the §5 table and nothing else: scope,
   `requested_profile` and `selector_commitment` carry decoded bundle values
   once step 3 has succeeded as a whole; the four trust values once step 5
   has; `evaluation_time` is always the caller's; replay and prior digests
   always bind the supplied inputs and are zero only when nothing was
   supplied; `evaluated_profile` is `below_AAR-1`; `technical_integrity` is
   `not_evaluated` for a failure at steps 1 to 5 and `not_satisfied` from
   step 6 on; `discovery_completeness` is `not_established`; every maximum
   class and `input_origin_ancestry` is `not_evaluated`, step-19 aggregates
   discarded on a later failure; `observations` is empty. The shape of
   `trust_inputs` is step-3 bundle schema in both verifiers.
2. **Forks.** A carried `fork_declared` event is `epoch/fork` at step 14: the
   wire's `handling` is `reject_and_surface`, so the verifier rejects the
   epoch and surfaces the declaration in its report. Conflicting event chains
   fail `epoch/event-chain` at chain linkage, before any fork rule; distinct
   manifests for one owner/epoch remain `epoch/fork`. The former positive
   fixture `epoch-event-fork-declared` becomes a negative (`epoch/fork`, step
   14); a branching-chain fixture pins the `epoch/event-chain` precedence.
3. **Ordering at step 3.** Sort order and uniqueness of every artifact array
   are checked at step 3 before step 6 touches any envelope (§2 already said
   so; pyref checked them per category after verifying it). A non-rejecting
   credential index may be built first, because an envelope may reference a
   credential that appears later in array order.
4. **Per-envelope traversal and nested position (step 6).** Each signed object
   completes sub-steps 1 to 9 before the next is decoded; an embedded
   delegation is validated immediately after its enclosing authorization
   receipt, and that receipt's nested presentation manifest immediately after
   the delegation. The harness's parse-everything-first pass is replaced; the
   masking class recorded under D-77, D-78, and D-81 closes.
5. **Outcome subject edge (step 10).** An `outcome_observation` MUST carry
   exactly one `observed_outcome` parent whose receipt id equals the body's
   `subject_id`; zero or several such parents, or a different id, is
   `receipt/outcome-subject-mismatch`.
6. **Evidence-class initialisation (step 19).** Every maximum class starts at
   `not_evaluated` in both verifiers. This changes one successful verdict: an
   observation-only bundle reported `self_asserted` provenance in pyref and
   `not_evaluated` in the harness; `not_evaluated` is the ruled value and the
   pyref bytes change. Observation-only and receipt-free subsets are fixtured.
7. **Late insertion and cross-epoch binding (step 14, §2.1).** A receipt whose
   `late_for_epoch_id` is not lower than its own `epoch_id` is
   `epoch/late-insertion`, manifest carried or not. A cross-epoch link's
   manifest MUST belong to the parent receipt's epoch owner, epoch, tenant,
   and site, and the link's anchor MUST bind that manifest; otherwise
   `graph/cross-epoch-unanchored`. pyref gains both rules; a wrong-number and
   a same-number-different-owner fixture pin them.
8. **Bounded schema table (step 6).** In CDDL field order within each
   production: every closed scalar enum (listed in 6.6), every `unix-time`,
   `sequence`, and `epoch-id` field of every production (nested and array
   members included) for presence then type, and a receipt's `freshness`
   and `binding` sub-maps for presence then type of each member. Three
   pinned precedences stand: credential `principal_type` before fixed-size
   ids; presentation `state` before ids; request coordinate fields judged at
   step 7 as `request/coordinate-mismatch`. An unknown evidence class is
   therefore a step-6 `schema/enum-unknown`; it was an uncaught exception in
   pyref and an unvalidated string copied into the signed verdict by the
   harness. Traversal of every remaining field is a separate ruling
   (BACKLOG).
9. **Delegation chains (step 13).** `parent_delegations` is traversed
   transitively, array order, depth first. Every link MUST resolve to a
   carried top-level delegation; contain the child's window; contain each of
   the child's four scope lists as a subset; share tenant and site; not widen
   `use` (a `one_time` parent forbids a `reusable` child, and a parent
   `invocation_id` MUST equal the child's); and not name a delegation already
   on the path. Any failure is `delegation/chain-invalid`. Both verifiers
   inspected only immediate parents; pyref checked existence only.
10. **Full-corpus gate.** pyref's corpus rows carry `first_failure_step`; the
    harness cross-implementation test compares result, reason, step, and
    verdict bytes on every fixture the Python enumeration lists, with the
    count derived from that enumeration, and is no longer skipped. The
    audited rows are re-pinned once, after every rule above lands, as the
    measured change set (the audit's 39 field-only rows, its one result row,
    and the rows parts 1 and 6 add), never before.

**Why.** Two clean-room verifiers agreeing byte for byte is the whole value of
the corpus gate; a divergence on identical bytes means one implementation is
wrong or the spec was silent, and the audit rightly forbade re-pinning the 40
rows by fiat. Each part says which. Parts 1 and 2 are spec silence resolved;
3, 5, 6, 7, and 9 are pyref or harness defects against text that already
existed; 4 and 8 close the masking class and the crash-or-overclaim class the
builds since D-77 kept logging. The Codex challenge of 2026-10-17 corrected the
first draft on five points: the fork rule had been read backwards (pyref's
`>1` manifest check rejects, it does not license accepting a declaration);
scope containment on chains is four finite subset checks, not a deferral;
pyref's artifact ordering ran after verification; the acceptance table had
to be per field, not "whichever step validated it"; and a universal CDDL
traversal would have reversed three pinned precedences, so the table is
bounded and the precedences are written down.

**Alternatives considered.** Accept a fork declaration as mere surfacing:
contradicts `reject_and_surface` and the `epoch/fork` row. Window-only chain
checks with scope deferred: leaves a normative row unenforced for a cheap
check. Universal field traversal now: reverses pinned precedences and moves
generated malformed-input variants from later steps to step 6 without a
ruling. Keep pyref's `self_asserted` initialisation: a successful verdict
would claim a provenance class for a bundle with no inference. Re-pin the 40
rows first and rule later: launders bugs as identity changes, which the
audit forbids.

**Amendments from the build review (2026-10-18).** The Codex finding pass and
the reviewer agent probed the first build with signed bundles outside the
corpus and found splits and crashes the ten parts left open. Pinned: (a) within
a production the closed-map presence check precedes the field-ordered
traversal, and the request-coordinate precedence applies to present fields;
(b) the step-6 table covers every `unix-time`, `sequence`, and `epoch-id`
field, nested and array members included — the first build had bounded it to
top-level fields, which left a text `wall_time` conformant and a list-typed
event `epoch_id` a pyref crash; (c) step 12 runs each listed check over every
receipt, in artifact order, before the next check (the harness model; the
second build sorted pyref's receipts by `epoch_seq`, which the root and
cross-epoch checks, each with more than one code, made observable); (d) epoch duration is judged
on the manifest pair and on the event pair, one code; (e) the chain traversal
evaluates each carried delegation once (iterative, memoised), because a
path-local cycle check alone let a 1,000-link chain exhaust pyref's recursion
and shared ancestors cost exponential revisits; (f) the loose credential index
of both verifiers takes any artifact entry whose element 0 decodes to a map
(the harness model), so a malformed credential envelope is reported at its own
position; (g) a present `null` nested envelope is a step-6 type failure in
both; (h) step-6 sub-steps 1 to 5 are read literally: a protected bstr holding
an empty map is `cose/alg-missing`, an undecodable protected bstr is
`cose/protected-not-map`, and a 64-byte signature with `r` at or above the
group order and low `s` reaches verification and is `sig/verify-failed`; (i)
selector sets use the same pairwise comparison as artifact arrays; (j) a
missing top-level bundle member is `schema/missing-field` at step 3; (k) every
hand-written nested-map guard uses the text-keyed-map rule; (l) a used
embedded delegation whose `scope` is not a map, or whose lists are not arrays,
is `delegation/scope` at step 13 in both (its shape traversal stays deferred);
(m) a `body.delegation` on a non-authorization receipt is ignored by both
until the body closed-map traversal lands (BACKLOG); (n) the bare bundle-level
productions step 6 never sees, a Merkle membership proof's `leaf` and the
`entry` of every range-proof and boundary proof, have their `unix-time`,
`sequence`, and `epoch-id` members checked for presence then type at step 3
(the second build did this for the Merkle leaf and declared the range entries
deferred; amendment b says every production); (o) the step-13 scope check
reads the attempt's `legal.purpose_id` and the decision's `profile` through a
guard: an absent or wrongly typed value is simply not contained, so the
failure is `delegation/scope`, never a crash (the second build left pyref
raising on a non-map `legal`); (p) the step-12 root-descriptor guard follows
(k): a `root` that is not a text-keyed map is `graph/root-missing`, a map
whose `kind` is absent or unlisted is `graph/root-forbidden`; (q) a reference
whose identifier is not a byte string of its CDDL size (credential `path`
members, rotation `predecessor_credential_id` and `successor_credential_id`,
status `credential_id`, decision `status_snapshot_ids` members, close-event
`manifest_id`, Merkle proof `batch_id`, range and anchor `manifest_id`,
step-19 attestation and anchor ids) resolves to nothing, and the step's
existing code for an unresolved or mismatched reference fires; likewise a
receipt `issuer_role` that is not text matches no role, a close-event
`item_count` that is not a uint matches no span, and an `observer` or
`source_device` that is not a text-keyed map (`null` included) is treated as
absent, so none of these is ever a crash (the third build's bare-read sweep
found pyref raising on each while the harness already emitted the code); (r)
the `receipt/manifest-inconsistent` row covers presentation `artifacts`
ordinals: the harness, which never checked them, now does, and a presentation
whose `artifacts` is not an array of text-keyed maps is the same code at step
10 in both; (s) step 19 judges `independently_sensed` observer independence
against the observations in the outcome receipt's ancestry (the harness
model): pyref had compared against every carried observation, so an unrelated
observation sharing the observer's failure domain flipped a conformant bundle
nonconformant in pyref alone; (t) an anchor whose `manifest_id` does not
resolve is `anchor/target-unplanned`, step 17's first listed check (the
harness order; pyref had said `anchor/manifest-binding`). Fixtures pin each.

**Second build review (2026-10-18, reviewer round 2 and a Codex probe pass
whose final synthesis was filter-blocked; its probe log was recovered).** Both
probed the fifth build with signed bundles and found the residual sentence
wrong (the harness usually emits a verdict where pyref raises), two amendments
contradicted by one verifier, a present-`null` class, and pre-existing
semantic splits outside the ten parts. Pinned: (u) a present `null` is a
present value of the wrong type for every optional member of every
production, never an absent member (extending g; pyref's `is not None` tests
had treated it as absent, so `root: null`, `cross_epoch: null`,
`degraded: null`, `hazard_class: null`, a first event's
`previous_event_digest: null`, a manifest's `predecessor_manifest_digest:
null`, and an anchor's `consistency: null` split the verifiers); (v)
`replay/expired` is judged on `committed_at` only: the freshness window
bounds emission, and a receipt verified after its window has closed is
evidence, not a replay (pyref had also rejected `evaluated_at >= expires_at`,
which would have made every archived receipt unverifiable once its window
closed; the reason-code row is reworded); (w) the carried manifests of one
owner, in `opened_at` order, chain by `predecessor_manifest_digest`; a
predecessor that names no carried manifest is not itself a defect in a
`valid_subset` bundle (pyref's model; the harness had required resolution);
(x) a consistency proof's `new_tree_size` and `new_root` MUST equal the
record's own `anchor_tree_size` and `anchor_root` (the harness check; pyref
had accepted any internally valid proof); (y) the record's head conflicts
with the expected head when their sizes are equal and their roots differ, or
when their sizes differ and their roots are equal (each verifier had one half);
(z) an action flow for invocation-ID consistency is the set of receipts that
share one `correlation_id`, and a receipt with no correlation binding is in
no flow (the harness model; pyref's parent-edge rule would reject an inference
derived from an observation sensed under an earlier invocation); (aa) step
19's `externally_anchored` requires the anchor's manifest to resolve and its
`epoch_owner_kid` to equal the receipt binding's, as the sentence already
said (pyref aligns); (ab) the proof-bearing productions are checked for
presence then type of every member where they are first seen: at step 6 for
an anchor record's `inclusion`, `consistency`, and `head`, a Merkle batch's
members, and every manifest index entry's members; at step 3 for a Merkle
membership proof, a range or boundary `inclusion` proof, and the enclosing
range proof (this closes the "residual" the fifth build declared, which the
probes showed was mostly pyref raising where the harness emitted a code, and
in one case, a missing anchor `head.root`, the harness emitting `conformant`);
(ac) step 7 requires a referenced manifest payload's byte length to equal the
declared `byte_length` (`hash/mismatch`; the harness had not checked), the
commitments recomputed are those at their CDDL positions only (pyref had
walked every nested map for digest-named members), and a presentation whose
`presentation_id` does not recompute is `identity/artifact-id-mismatch` like
every other artifact id; (ad) sequence span and count are judged at step 14
(the open event's `first_epoch_seq` and the close's `last_epoch_seq` equal
the manifest span; the close's `item_count`, the manifest's `item_count`,
and the index's `leaf_count` equal the index length) and the step-15 span is
the minimum and maximum `epoch_seq` over the entries (entries are ordered by
`committed_at` first, so the first and last entries need not carry the
extremes); (ae) step 2 reports `cbor/malformed` for an item that is both
non-canonical and later malformed (well-formedness precedes re-encoding in
the listed order), `cbor/float-forbidden` for any float in both verifiers,
and `cbor/malformed` for an integer whose magnitude exceeds 2^53 − 1; (af)
every lookup of a wire string in a table uses own-property semantics in the
harness (`constructor` and `__proto__` as an `edge_type` or root `kind` had
thrown), and every hand-written map guard in pyref is the text-keyed rule
(an embedded delegation `scope` and a manifest `anchor_plan` with mixed keys
had passed pyref); (ag) amendment (o) read literally: the attempt's
`legal.purpose_id` and the decision's `profile` MUST be text and contained
in the delegation lists; a non-text or absent value is `delegation/scope`
even when the list carries the same malformed value or a `null`; (ah) the
remaining pins from the probes: a reused epoch coordinate naming a different
receipt id is `identity/coordinate-equivocation` and only a decreasing
sequence is rollback; an evidence label on a kind that forbids it is that
class's `evidence/*-class-unsatisfied` at step 10; an ordinal is a uint and a
bool is never one (Python's `False == 0` had admitted a bool ordinal); a text
label `"1"` in the unprotected map is `cose/unprotected-not-empty` (label 1 is
the integer); every artifact array's CDDL occurrence bound that is not a
section 1 limit is `schema/out-of-range` at step 3 in both; the section 1
proof-object limits count each inclusion, consistency, or membership proof
once and never the container that carries it (pyref had counted a range
proof and its entries both); a trust-store `snapshot_id` of 32 zero bytes
is the verdict's not-evaluated sentinel and is `schema/out-of-range` at step
5 (pyref had refused to emit a verdict, the harness had emitted a conformant
one carrying the sentinel); an exact replay supplied in the replay state with
the same `content_digest` is a duplicate, as the step-11 text already said
(pyref had compared the receipt id to the content digest); a credential
`path` beyond its CDDL bound is `schema/out-of-range` at step 6 (the bound
is also a section 1 limit, but the array is schema before it is a resource);
step 18 verifies a present boundary's inclusion proof (the harness had not);
(ai) within a range, step 18 resolves the manifest, matches the selector
commitment, requires contiguous leaf indices, verifies every entry and
boundary proof, and only then judges the temporal slice (pyref's order and the
sentence's: "against the signed manifest index root" comes first; the harness
had judged the slice before the proofs, so a range that both misses its slice
and carries a bad proof split the verifiers); the sixth build also pinned a
present `null` anchor `consistency` as `schema/bad-type` at step 6, since (ab)
types it there and step 6 precedes 17.

**Third review (2026-10-18, reviewer round 3, 54 new probes on the seventh
build).** Pinned: (aj) under `complete`, a carried receipt not reachable from a
selected receipt is judged by its objective index entry, and no entry at all
is `bundle/artifact-out-of-scope` like an entry outside the selector (the
harness had tolerated unindexed extras, pyref had judged them by their own
fields with empty subject and correlation sets); (ak) the CDDL bounds on a
Merkle membership proof (at most 20 siblings) and a batch `tree_size`
(1..1,048,576) are `schema/out-of-range` at steps 3 and 6, and a sibling count
impossible for the tree size is `merkle/path-length` at 16 in both (pyref had
neither bound, the harness had both at 16); (al) the ranges of one manifest
carry strictly increasing leaf indices in array order, judged at the
contiguity position (the row says "overlap another range"; pyref had checked
repeated coordinates inside its proof loop); (am) step 7 visits artifacts in
the step-6 order (the harness had checked every id before any receipt
commitment, pyref every receipt before any presentation); (an) an undecodable
COSE item is `cbor/malformed` at step 6 (the `cose/bad-structure` row says
"well-formed"; the harness had mapped every decode error to it); (ao) the
bound in step 2 is literal: the thirty-third nested container exceeds it, the
thirty-second does not (the top-level item is depth 0; the container at depth 33 exceeds, the one at depth 32 does not), at the top level and inside a COSE payload alike, and
a float is recognised before its bytes are read as an integer (both scanners
had reported a double as `cbor/malformed`; pyref's second-phase decoder had
rejected depth 32); the anchor record's own scalars (`anchor_tree_size`,
`anchor_leaf_index`, `anchor_root`, `manifest_digest`), a manifest index's
`root` and `leaf_count`, and a plan's `independence.groups` members join the
(ab) tables (a `null` in any of them had crashed one verifier while the other
signed a verdict); (u) applies to a parent delegation's `invocation_id` in the
chain link; the 6.6 closed-map-first sentence is scoped to enveloped
productions, and the (ab) productions tolerate unknown members until the body
traversal lands. The builder's structural sweep (every untyped member of every
production mutated to null, list, int, text, and bool, both verifiers) is the
eighth build's gate for this class. The fourth review (20 probes on the
eighth build) added: (ap) a repeated `target_id` in `anchor_plan.targets` is
`schema/duplicate-entry` at step 6 and a repeated `target_id` in
`trust_inputs.expected_anchor_heads` is `schema/duplicate-entry` at step 3,
the D-77 `root_kid` pattern (pyref had taken the last entry, the harness the
first, so a duplicated target or head flipped a CDDL-valid bundle); (aq) a tag
nested inside a COSE item is `cbor/tag-forbidden` at step 6, as the row says
("outside the top level of a serialized COSE bstr"); `cose/tagged` is only the
tag that wraps the COSE_Sign1 (both verifiers had mapped the nested case to
`cose/tagged`).
Fixtures pin each. The parity claim D-82 makes is: every corpus row and every
fixture-pinned shape agree in both verifiers. Shapes no fixture pins are not
claimed; whatever the sixth build's probes leave open is listed in
`BACKLOG.md` with both verdicts, and the differential fuzz tool (Packet D)
is the instrument for the rest.

## D-83 — A relying party supplies its own trust ceiling and verifier identity; the verdict binds the policy and is signed by the policy's leaf

**Decision.** `docs/verifier-trust-provisioning-design-v0.1.md` is ratified
with the corrections below. Release v0.3.0: the verdict becomes `v: 5` under
the protected content type `application/aar-verdict+cbor;v=0.3`; every bundle
artifact keeps its `v=0.2` content type and byte shape; receipt, bundle and
credential bytes do not change. Without a policy, every evaluation outcome is
unchanged and the no-policy verdict differs from v0.2.5 only by the decoded
field delta in part 8.

1. **The policy object.** `relying-party-policy` (`aar-core.cddl`; digest =
   SHA-256 of deterministic CBOR `["AAR-RP-POLICY-v1", policy]`) carries
   `artifact_roots` (1..64 records, strictly sorted, unique by `root_kid`),
   `verifier_root_kid`, and `verifier_credentials` (the leaf plus exactly the
   credentials its path names, 1..9). Each record's `allowed_sites` and
   `allowed_key_usages` are strictly sorted and unique, the bundle's
   `trust-root` rule at step 3 (amendment a, 2026-10-21: the ratified text
   had named only the two array-level uniqueness rules; the build's loaders
   had rejected duplicate usages but not unsorted sites). Q5 ruled: one tenant per `root_kid`,
   mirroring the producer rule. The policy is a configuration object, not a
   bundle artifact: it is never carried in a bundle and never sourced from a
   platform trust store (D-58 policy clauses stand).
2. **Configuration precedes the bundle.** A verifier loads and validates the
   policy and the signing key before it reads a single bundle byte. Validation
   is the policy's closed-map, sort and uniqueness rules; the signer contract
   (exactly one `verifier_credentials` entry has `subject_kid` = SHA-256 of
   the supplied key's SPKI; that entry is the leaf); and the chain algorithm
   of design §3.3 items 1 to 11 at the supplied evaluation time (the leaf has
   `key_usage = "verifier_signing"`, `principal_role = "verifier"`, a
   non-empty path; every other member has `key_usage = "credential_issuing"`;
   the terminal member is self-signed by `verifier_root_kid`; every member's
   protected kid equals its `issuer_kid` and its signature verifies under the
   issuer's carried SPKI; every `tenant_id` and `site_id` is all-zero; no
   `credential_id` or `subject_kid` repeats). The credential checks are the
   same closed-map, type, enum and size checks a verifier applies to a carried
   credential at steps 3 and 6; the release CDDL oracle, not the verifier, is
   the authority for full CDDL membership, and the `rp-*` policy sidecars are
   in its corpus. Any configuration failure is a usage error with no verdict
   (the `--trust-policy` class; exit 2 in pyref). Internal defects stay
   unsigned crashes (D-61).
3. **Key contract.** The signing key is supplied as one file holding 64
   lowercase hexadecimal characters, the P-256 private scalar `d` with
   `1 <= d < n`, optionally followed by one LF or CRLF and nothing else
   (amendment b, 2026-10-21: the build had used each runtime's whitespace
   definition, and a U+0085 or U+FEFF suffix split the two verifiers); the
   verifier derives the SPKI and `kid = SHA-256(SPKI)`.
   Policy and key MUST be supplied together; either alone is a usage error. No
   environment variable, no scalar on a command line. Signing is the existing
   verdict rule: deterministic RFC 6979 ES256, low-S, P1363. (Codex: a
   randomized signing provider would break byte parity; an env var leaks into
   process listings.)
4. **Ceiling, separation, order (steps 5 and 8).** Producer validation is
   unchanged. At step 5, after the per-root tenant/site checks and before the
   evaluation-time checks, a producer root whose `root_kid` is a verifier kid
   (`verifier_root_kid` or any `verifier_credentials[].subject_kid`) is
   `credential/root-not-accepted`. At step 8, inside the root-acceptance loop,
   per carried credential, after role-key separation and path construction
   have passed for it: (a) separation — a carried credential whose
   `subject_kid` is a verifier kid fails; (b) producer acceptance as today;
   (c) policy acceptance — its terminal credential's `subject_kid` equals a
   policy `root_kid` whose `tenant_id` equals the credential's and whose
   `allowed_sites` contains the credential's `site_id`; and, when the
   credential's `subject_kid` is the protected kid of at least one envelope
   verified at step 6 (the D-77 signer set), its `key_usage` is in that
   record's `allowed_key_usages`. One record is checked against one
   credential; sites and usages are never pooled. A failure is
   `credential/root-not-accepted`, or `countersign/credential-invalid` for a
   mediator credential; the result is `nonconformant` (design Q1). No new
   reason code: the bound digest says a policy applied; the report layer says
   which check rejected. A relying party narrows trust and never widens it.
5. **Verifier identity (step 20).** Under a policy, step 20 does not consult
   bundle credentials: the signer is the configured leaf, the protected kid is
   its `subject_kid`, and a bundle-carried `verifier_signing` credential is an
   ordinary carried credential for steps 6 and 8, the ceiling included. D-73's
   find-first rule holds only when no policy is supplied. D-81's use of the
   verifier's own key at the evaluation time is recorded for the configured
   leaf's kid in policy mode and for the corpus verifier's kid otherwise; the
   step-6 signer set is captured before that use is added, so the synthetic
   use never makes a credential a signer for the usage check.
6. **Two authorized policy-mode transitions (correcting design §3.2 and §6
   "a failing bundle can never pass under a policy").** Artifact acceptance
   is monotone: a bundle that fails a producer or artifact check without a
   policy fails it with one. Identity is not: (i) a bundle carrying no
   verifier credential, `key/not-found` at step 20 without a policy, can be
   conformant under one; (ii) a carried corpus-verifier credential named by
   a `revoked` or `compromised` snapshot effective at the evaluation time,
   `credential/revoked` at step 8 without a policy because signing the verdict
   was a use of that key, passes under a policy when that credential signs
   nothing, because D-81 judges revocation at use time and the use moved to
   the leaf. A snapshot that names no carried credential still fails closed
   (D-81). Both transitions are pinned (`rp-*`); no no-policy row moves.
7. **Verdict binding and distinguishability.** `verdict-trust-policy` gains
   the required `relying_party_policy_digest: bstr .size 32`, the policy
   digest whenever a policy was supplied, at every failing step including 1
   to 3, and 32 zero bytes only when none was (the D-51/D-76 absence
   discipline). The configured signer and the digest are unconditional; the
   `--trust-policy` exact pin stays and coexists, and its post-evaluation
   check is unchanged. For a `conformant` verdict only: without a policy the
   protected kid appears among the bundle's credential `subject_kid`s and the
   digest is zero; with one, the kid is the policy leaf, the digest is
   nonzero, and no carried credential has that kid (part 4a). Early failures
   and separation failures carry no such guarantee, which is why the
   statement is scoped. A consumer resolves a policy-mode signer from the
   policy, never from the bundle; the content-type bump names the changed
   signer semantics. The reader's package is bundle + policy + verdict.
8. **Allowed decoded-field delta for the re-pin.** Every corpus verdict is
   re-pinned once, and the audit diffs decoded fields, not bytes: `v`,
   `trust_policy.relying_party_policy_digest`,
   `limits.control_path_completeness` (D-84), `verifier.version` and
   `build_digest`, the protected content type, and the derived `verdict_id`
   and signature. Result, reason and failing step are frozen on every
   no-policy row.
9. **Key hygiene is a named-key exclusion, not secrecy assurance.** A policy
   whose chain contains any kid in the frozen fixture-key set (the published
   Gate 4 scalars, `pyref/crypto.py` `TEST_SCALARS` / `harness/testkeys.ts`,
   enumerated by kid in the configuration module) is a usage error. The
   `rp-*` corpus signs with a separate published relying-party fixture key
   pair (`rp_credential_issuing`, `rp_verifier_signing`), which the exclusion
   does not cover so the corpus stays reproducible; `pyref/README.md` keeps
   the operator-facing sentence, extended to both sets: neither is an
   operational verifier identity and neither signature is third-party
   assurance. No bypass flag exists. Passing the exclusion establishes
   nothing about the operator's key.
10. **Q2 ruled honestly: validity window only.** The relying-party chain is
    valid at the asserted evaluation time; v0.3 provides no revocation and no
    creation-time assurance for it. Because the evaluation time is
    caller-selected (D-70), a short leaf `valid_until` narrows the window a
    compromised key can assert, and nothing more. A status mechanism for the
    relying-party chain is a v0.3.x candidate.
11. **Fixtures.** `kats/relying-party/rp-*`: design §4 items 3 and 4, with
    usage negatives over every D-77 signer category (EP, agent, authority,
    approver, outcome observer, anchor, status issuer, rotation issuer,
    embedded delegation signer, presentation signer, mediator), the two
    part-6 transitions, a dangling snapshot naming an uncarried policy
    credential, and separation fixtures built on the relying-party fixture
    keys. Each row has one `*.inputs.json` sidecar naming policy, key, exact
    pin, replay state, prior state and evaluation time, absent kept distinct
    from empty; `pyref/kat.py`, `harness/crossimpl.test.ts`,
    `harness/kat.test.ts` and `pyref/schema_kat.py` name the directory and
    the sidecar suffixes explicitly. The cross-implementation gate passes the
    same key file to both verifiers and each decodes the policy itself.

**Why.** D-58 deferred an interoperable external-key format until a corpus
could cover it; D-77 fixed the four chain defects a ceiling would have
inherited; D-82 made the two verifiers agree on every corpus row. The design
doc's Comparator analysis (the checking side owns the trust list; the list is
a ceiling; it is bound into the result) carried through two Codex passes in
October and a third on 2026-10-21 that found the monotonicity claim false
(reproduced on `repair-d81-status-verifier-revoked`), the distinguishability
statement overbroad, the harness lacking a configured-pin input the design's
own KAT list needs, and the hygiene rule a named-key exclusion dressed as
secrecy. Each is written down here as it is. Closes the BACKLOG freeze
blocker "Verifier identity / trust provisioning for an unrelated verifier"
and the first half of crosswalk gap G-C; the second half (proof of which
code ran) stays open.

**Alternatives considered.** Replacing or filtering the producer store
(loosens artifact validation); exempting unused credentials from the ceiling
(a self-signed root signs its own envelope; the exemption cannot deliver);
checking the chain at step 20 as a signed `key/not-found` (a verifier that
cannot vouch for its own key must sign nothing); keeping the corpus
verifier's synthetic use in policy mode (a stranger's verdict would then
depend on the producer's verifier credential); an optional verdict key
(D-78 rejected it); new `policy/*` reason codes (no new code surface); a
hygiene set that includes the relying-party fixture keys plus a test bypass
(worse than the honest exclusion); PEM/PKCS#8 key files (a parser in both
languages for no interoperability gain); a status snapshot in the policy now
(Q2; deferred with the limit stated).

## D-84 — The verdict states that control-path completeness is not established

**Decision.** `verdict-limits` gains the required key
`control_path_completeness: "not_established"`, emitted on every result,
pass and failure, by every v0.3 verifier; no other value exists. It rides
the D-83 version bump (`v: 5`) and the single re-pin. CONFORMANCE §5 carries
the MUST; the README does-not-prove table, the admissibility crosswalk limits
table and the RFP prohibited-claim list each gain one row; both CLIs print
every signed limit (no-wire commit before the build).

**Why.** The threat model (`docs/threat-model-v0.1.md`, "the
instrumented-control boundary"; RR-10; T-S4) says actions dispatched around
the EP (a VMS console, a vendor app, physical access) produce no receipts
and are undetectable by AAR alone, and calls that boundary normative context
for every completeness claim. No signed field carried it: `source_authenticity`,
`custody_continuity` and `legal_admissibility` cover other residuals, and
`ingress_completeness` / `discovery_completeness` describe actions that went
through the EP. A conformant `coverage: complete` verdict therefore invited
the reading "every camera move in the window is accounted for", which fails
in the most common physical-security case. D-29's rationale (a limit a
machine cannot check launders) applies exactly as it does to
`source_authenticity`. The name states the property that is not established;
`out_of_band_operation` would read as whether one occurred. Pre-ingress and
post-ingress omission (RR-3, RR-4) and EP bypass (RR-10) are distinct
residuals, so the field is not a reserved value of `ingress_completeness`: an
ingress census does not enumerate other control paths. Origin: the Pipelock
hard-limit-codes pattern (`L-CONTAINMENT-UNPROVEN`), 2026-10-18.

**Alternatives considered.** A `non_claims` registry of stable IDs covering
RR-1, RR-5/6, RR-10, RR-12, RR-13 and verifier drift (a larger surface with
an ordering rule; a docs-only mapping of the existing signed fields to RR-n
can follow); report layer only (D-29 rejected unsigned limits); a reserved
positive value such as `census_supported` (no normative decision licenses
one; add it when an evidence rule exists, the custody pattern); a separate
v0.3.1 at a second full re-pin (a required closed-map key forces a version
bump either way; one re-pin is cheaper and the plan's one-decision-per-release
rule is amended explicitly for this release rather than hidden inside D-83).

## D-85 — What a differential fuzz run means

**Decision (non-normative).** A run of `harness/difffuzz.ts` compares the
TypeScript harness and pyref on mutants of the corpus rows and reports one
line, the run line in `BACKLOG.md`, with every number on it. The line
separates what was planned from what was executed (survival no-ops and
unsupported shapes are counted, not executed); nothing is claimed for a
shape the run did not execute. Two implementations can share a bug, so
agreement is not correctness. The release schema gate (D-74) validates the
artifacts it enumerates — the corpus and the demo — and does not validate
fuzz mutants; the leg oracle is the only check in a run that does not
depend on the two verifiers agreeing: it checks that each
evidence leg a positive row carries is load-bearing against the spec's
allowed-outcome set (corruption of a retained leg rejects; removal of
optional evidence may leave the verdict unchanged; a weakened claim moves
the field that governs it). Rejection-site saturation is a budget rule for
how much of pyref's `_fail` / `CBORError` inventory a run reached; it is not
premise coverage and says nothing about a clause being driven both ways.
A finding is a split between the two verifiers (`bytes`, `classification`,
`crash`, whether a mutant or a leg mutant produced it) or a leg-oracle class
(`corruption-accepted`, `claim-weakening-unmoved`, `removal-accepted`); leg
outcomes outside the allowed set that are not acceptance (`unexpected`), leg
operator errors and CLI-lane disagreements are named on the line as well;
findings are promoted to fixtures by hand, never
auto-promoted to `_fail`. A run that cannot reproduce every pinned corpus row
or fire every control reports nothing else.

**Why.** The corpus gate proves only the rows it carries (D-82's parity
claim is narrowed to "every corpus row and every fixture-pinned shape"). A
fuzz run widens the executed set but inherits the same limit, and the
Packet D challenge (2026-10-21) showed every way a run could overclaim:
a repair erasing the mutation, a masked earlier failure read as coverage, a
dead comparator, a stale import, an absent limit read as a bug. The accept
line is the only form a run result takes so that none of those readings
survives.

**Alternatives considered.** A coverage percentage on the run line
(renamed: line events do not evaluate premises); an expected verdict per
mutant (fabricated; replaced by reachability and the leg table); a sixth
"leg not load-bearing" channel (split into masked / pass / the two finding
classes, because §5 does not give every leg a limit).

## D-86 — Emission identity checks the bundle before history, one class at a time

**Decision.** CONFORMANCE step 9 runs in two phases, and every phase-A
failure outranks every phase-B failure.

0. **History consistency (usage error, no verdict).** Two supplied
   `prior_emissions` entries with the same `receipt_id` and `envelope_digest`
   but different coordinates are a usage error, checked after the entry-shape
   check and the D-76 duplicate/unsorted rule, before evaluation begins
   (step 1). An entry
   whose `receipt_id` and `envelope_digest` equal a carried receipt's but
   whose coordinates (`issuer_kid`, `issuer_seq`, `epoch_owner_kid`,
   `epoch_id`, `epoch_seq`) differ from that receipt's is a usage error,
   checked at step 9 before phase A.
1. **Phase A (always).** Over the carried receipts in canonical artifact
   order: one full pass for `identity/coordinate-equivocation`, the issuer
   coordinate `(signing kid, issuer_seq)` before the epoch coordinate
   `(owner, epoch_id, epoch_seq)` for each receipt. A `receipt_id` repeated
   within the bundle has already failed step 3 (`schema/duplicate-entry`).
2. **Phase B (only with supplied prior state).** Over every carried
   receipt × entry pair: (i) one full pass for `identity/reuse` (same ID,
   different digest); (ii) one full pass for
   `identity/coordinate-equivocation` (same issuer or epoch coordinate,
   different ID); (iii) over the remaining receipts, one full pass for
   `identity/issuer-sequence-rollback` (same signing kid, strictly lower
   `issuer_seq`), then one for `identity/epoch-sequence-rollback` (same owner
   and `epoch_id`, strictly lower `epoch_seq`). A carried receipt equal to an
   entry in ID, digest and coordinates is a duplicate observation
   (`duplicate_exact`, in both verifiers) and is exempt from (iii), never from
   (i) or (ii). The epoch comparison changes from `<=` to `<`; equality with a
   different ID is equivocation under (ii).
3. **Witness order.** Within a class the reported witness is the first
   carried receipt in canonical artifact order, then the first entry in
   committed (sorted) order. The signed verdict carries the class code only,
   so the witness is not observable in it; it shows only as the harness's
   diagnostic failure `path`. Entries that conflict only with each other do
   not fail the bundle.
4. **Unchanged.** `prior_emissions_digest` hashes the supplied history exactly
   as today, never a filtered set; the verdict stays `v: 5`, the bundle wire
   v0.2, every content type as it was, and `stateful_not_evaluated` without
   prior state as before.

The declared spec becomes v0.3.1, a patch release on the D-77 precedent
(acceptance and order fixes, no wire change). Every signed verdict re-pins,
because the verifier version and build identity are signed; the decoded
old/new delta is `docs/verifier-delta-audit-v0.3.1.md`. Nineteen `d86-*`
stateful KATs pin the rule: the six fuzz splits; Q1 to Q3; full-history
re-observation; phase order with and without prior state; phase-B class
order (reuse over rollback, issuer rollback over epoch rollback,
equivocation over rollback); an exact duplicate exempt from neither reuse
nor equivocation; entries that conflict only with each other; and partial
history (an exact copy of only the highest-`epoch_seq` receipt is rollback
for the others). The usage errors and rule 0(b) over a phase-A failure are
unit tests in both verifiers and pyref CLI tests (the harness has no
prior-state CLI flag); the issuer-before-epoch witness is a harness unit test
on its diagnostic `path`.

**Why.** Step 9 named four codes and no precedence, and the two verifiers
filled the gap differently. Six differential-fuzz splits
(`docs/fuzz-runs/2026-10-22/` m-01770, m-01931, m-01969, m-01986;
`docs/fuzz-runs/2026-10-24/` m-01906, m-01946) carried an in-bundle issuer
coordinate collision on a rollback seed: with the seed's history the harness,
which interleaved its checks per receipt, reported a rollback and pyref,
which ran its in-bundle checks first, reported equivocation; without history
the harness also reported equivocation, so its code for the same bytes
depended on the history it held. Three history probes (2026-10-26) found
defects the verifiers shared. Q1: an entry reusing a carried receipt's issuer
coordinate under another ID passed. Q2: an entry reusing its epoch
coordinate was reported as epoch rollback. Q3: an exact re-presentation of a
carried receipt was rejected as epoch rollback, though this step calls exact
repeated bytes a duplicate. The exemption fixes Q3 for the re-presented
receipt itself; every other carried receipt is still judged by the ordinary
rollback rule against the supplied history, so history holding a copy of only
the highest-`epoch_seq` receipt makes the bundle's lower receipts rollback
(`d86-partial-history-epoch-rollback`, unchanged from v0.3.0; whether
`prior_emissions` is a complete record or a high-water mark is open in
`BACKLOG.md`). These are conformance defects, not precedence
choices: D-05 defines duplicate, reuse and equivocation with no bundle
boundary, D-06 makes both sequence domains monotonic and the epoch domain
unique, and D-82 amendment (ah) ("a reused epoch coordinate naming a
different receipt id is `identity/coordinate-equivocation` and only a
decreasing sequence is rollback") is not limited to one bundle. Two phases
keep the code for an intrinsic defect independent of the verifier's history,
so two relying parties holding different histories name the same defect for
the same bytes. Class-wide passes keep serialization order from choosing the
class (pyref looped over history first, the harness over receipts first). The
duplicate exemption is receipt-wide because a per-entry one still rejects a
full re-observation: with exact copies of every carried receipt as history,
the receipt at epoch sequence 8 meets the copy at 9. The usage error exists
because the history tuple is unique only as a whole, so contradictory
records for one receipt were accepted, and a verifier should not sign a
verdict over history it can see is corrupt.

**Alternatives considered.** Global class order across both phases (reuse
anywhere, then equivocation anywhere, then rollback): an intrinsic collision
could not then mask a history reuse in the reported code, but that code
would depend on the history supplied. Both orders reject the same bundles
and differ only in the code; while codes are diagnostic, stability across
verifier histories is worth more (rejected; revisit if a relying party is
expected to act differently on reuse than on equivocation). Per-receipt
interleave (the harness before this decision): receipt or history order
picks the class. Rollback first, as the relying party's stronger evidence:
the same history dependence, and a fork is reported as a rollback. A
per-entry duplicate exemption (fails full re-observation, above). Treating
an entry that contradicts a carried receipt as an ordinary non-duplicate,
checked on its stated coordinates: a signed verdict over corrupt input.
D-52 is not the precedent for phase order: it is an anti-masking rule, not
a general state-independent-first rule; the two-phase choice rests on
verdict stability alone.

**Amended in review (2026-10-26).** Rule 0 is preceded by the prior-state
entry-shape check (CONFORMANCE section 5): the closed seven-key map, three
unsigned integers that are never booleans, four 32-byte values, checked by
the library and the command line alike before evaluation begins. pyref's
library had taken entries unchecked, so `epoch_seq: false` compared equal to
0 and pyref signed a conformant verdict over history the harness refused.
Phase A is one equivocation pass: step 3 rejects any repeated `receipt_id`
in `artifacts.receipts`, equal bytes or not, before step 9 runs, so the
phase-A reuse pass and the coalesced in-bundle duplicate were unreachable in
both verifiers; both are removed and step 3 stays as released.
`duplicate_exact` now means only an exact re-observation of a prior-state
entry (the D-05 duplicate, observed against history).
