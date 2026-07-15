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
trigger. The root descriptor is part of that receipt's signed identity.

**Why.** W-3 explicitly freezes six node types while W-4 requires a root allowlist.
This represents the allowed external origin without silently creating node seven.

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
