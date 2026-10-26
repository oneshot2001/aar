# AAR v0.2 conformance contract — gate-1 candidate

This document is normative for validation behavior. `aar-core.cddl` is normative
for wire shape. RFC 8949, RFC 9052, RFC 9053, and the EdgeProof SDR v1.1 wire
discipline as frozen at repository commit `b9d7bc6` govern where this document is
silent. “Reject” means produce a signed
`nonconformant` or `indeterminate` verdict as specified below; a bare `PASS`, `OK`,
or unsigned success token is never a conformant AAR verdict.

## 1. Fixed verifier limits

These limits are part of the verifier configuration and MUST also be committed in
the verdict's `limits_digest`.

| Resource | Limit |
|---|---:|
| Exact encoded bundle bytes | 16,777,216 bytes |
| CBOR container nesting | 32 |
| Receipt nodes | 10,000 |
| Directed graph edges | 50,000 |
| Parents of one receipt | 64 |
| DAG depth (nodes on longest root-to-node path) | 128 |
| DAG width (nodes at one computed rank) | 4,096 |
| One encoded proof object | 65,536 bytes |
| Aggregate encoded proof objects | 4,194,304 bytes |
| Epoch manifest entries | 10,000 per manifest |
| Merkle batch leaves | 1,048,576 |
| Credential path length | 8 credentials |

The verifier MUST enforce limits while decoding where possible and MUST NOT first
materialize an unbounded object. Once step 7 validates content-derived receipt
IDs, the receipt graph is acyclic by construction: every parent ID is committed
inside the child receipt's ID preimage, so a cycle would require a SHA-256 fixed
point. Implementations MAY defensively bound a graph traversal to one visit per
receipt, but that bound is non-normative and exceeding it is an internal or
cryptographic failure, not a v0.2 conformance rejection. “Width” is computed by
assigning roots rank 0 and every other node one plus the maximum rank of its
parents.

## 2. One normative validation order

First failure wins. Within every artifact array, items are evaluated in encoded
array order. Set-like arrays required by the CDDL comments to be sorted are checked
for sort order and duplicates before their elements are semantically evaluated.
No verifier may continue to a later step and substitute its reason for an earlier
failure. Within a step, checks evaluate in the order this section lists them,
and the first failing check supplies the reason code — intra-step order is as
normative as the step order itself (D-54).

1. **Bundle byte limit.** Reject an input longer than the bundle byte limit before
   CBOR decoding.
2. **Bundle CBOR.** Decode one untagged deterministic-CBOR item with the depth
   bound. Check well-formedness, valid UTF-8, definite lengths, unique keys, no
   tags, no floats, no trailing bytes, and exact deterministic re-encoding, in
   that order; an item that is both non-canonical and later malformed is
   `cbor/malformed`, and an integer whose magnitude exceeds 2^53 − 1 is outside
   the profile and `cbor/malformed` (D-82 amendment ae).
3. **Bundle schema.** Check the closed top-level map, `v`, required fields, field
   types, fixed-size values, enums/ranges, and sorted/unique
   arrays, in that order; the shape of `trust_inputs` (snapshot, root records,
   expected anchor heads) and the sort order and uniqueness of every artifact
   array are checked here, before step 6 touches any envelope (D-82).
   Occurrence ceilings listed as section 1 resource limits
   are deferred to step 4 so their `resource/*` code is reachable. The optional
   `artifacts.mediator_countersignatures` array is closed and sorted by primary
   ID like the other artifact arrays; absence is the pre-D-67 encoding. The
   bare (unsigned) bundle-level productions, a Merkle membership proof's `leaf`
   and the `entry` of every range-proof and boundary proof, are text-keyed maps
   whose `unix-time`, `sequence`, and `epoch-id` members are checked for
   presence then type here, since step 6 never sees them (D-82); likewise every
   member of a Merkle membership proof, of a range or boundary `inclusion`
   proof, and of the enclosing range proof is checked for presence then type
   here (D-82 amendment ab). Every artifact array's CDDL occurrence bound that
   is not a section 1 limit (for example `delegations` and `credentials`,
   `0*1000`) is `schema/out-of-range` here. Check
   `selector_commitment` last within this step.
4. **Static resource counts.** Check artifact counts, parent counts, total edge
   count, individual proof byte lengths, and aggregate proof bytes in that order.
   A proof object is one inclusion, consistency, or membership proof (a range
   entry's or boundary's `inclusion`, an anchor's `inclusion` or
   `consistency`, a Merkle membership proof); each is counted once and the
   container that carries it is not counted (D-82 amendment ah).
5. **Trust-policy input.** Validate the trust-store snapshot digest, root records,
   root-key uniqueness, tenant/site scopes, evaluation time, expected anchor
   heads, and policy digest. No two root records may share a `root_kid`; a
   repeat is `schema/duplicate-entry` (D-77), as is a repeated `target_id`
   among the expected anchor heads (checked at step 3 with the heads' shape,
   D-82 amendment ap). A trust-store `snapshot_id`
   of 32 zero bytes is the verdict's not-evaluated sentinel (section 5) and is
   `schema/out-of-range` at this step (D-82 amendment ah).
   Under a relying-party policy (D-83, section 6), after the per-root
   tenant/site checks and before the evaluation-time check, a root record
   whose `root_kid` is a verifier kid (the policy's `verifier_root_kid` or any
   `verifier_credentials[].subject_kid`) is `credential/root-not-accepted`.
   At the evaluation-time check, require the bundle's `evaluation_time` to
   equal the explicitly supplied verifier evaluation time; then require that
   time to be at least the trust-store snapshot's `created_at`. Either failure
   is `schema/out-of-range` at step 5. Every verdict, including an earlier
   failure verdict, records the caller's time in both `evaluated_at` and
   `trust_policy.evaluation_time`. No wall-clock fallback is permitted.
6. **Envelope mechanics.** For each signed object, in this artifact order —
   credentials, rotation records, status snapshots, request envelopes,
   delegations, epoch events, epoch manifests, anchor records, Merkle batches,
   mediator countersignatures, then receipts (each receipt followed immediately
   by its embedded delegation, then by its nested signed presentation manifest,
   D-82) — perform, completing sub-steps 1 to 9 for one object before decoding
   the next (D-82):

   1. decode the untagged four-element COSE array and require deterministic CBOR;
   2. require protected to be a bstr containing a closed deterministic map;
   3. require protected `alg=-7`, the exact content type for the payload, and a
      32-byte `kid`; for receipts also require all provisional AAR labels;
   4. require the unprotected map to be empty and payload to be `nil`;
   5. classify signature encoding length-first, require 64-byte P1363, nonzero
      `r,s`, and low-S;
   6. decode the detached payload bytes under step 2's CBOR rules, then validate
      its selected closed schema (a credential `path` that is not an array
      is `schema/bad-type`, D-77);
      this includes nested productions and closed scalar enums, including
      a credential's `principal_type`, and its `cose_alg`/`curve` (integer
      `-7` and text `P-256` only; wrong type is `schema/bad-type`, wrong
      value `schema/enum-unknown`, in that order after `principal_type`,
      D-73). Unknown principal-type text is
      `schema/enum-unknown` at step 6, before content-ID validation.
      For an inference body, an `origins` value that is not an array is
      `schema/bad-type`; empty or longer than five entries is
      `schema/out-of-range`; a non-text member is `schema/bad-type`; a member
      outside `input-origin` is `schema/enum-unknown`; a member repeated
      anywhere in the array is `schema/duplicate-entry`, checked before order;
      a member out of deterministic-CBOR encoded-byte order is
      `schema/unsorted-set` (D-78). For an observation body, after the
      consumption cardinality check, each item that decodes as a text-keyed
      map has its `disposition` validated for presence
      (`schema/missing-field`), type (`schema/bad-type`) and closed enum
      (`schema/enum-unknown`), then its optional `origin` for type and enum,
      in item order; an item that is not a text-keyed map is left to step 10
      (D-78). For a status snapshot, after `status` validates as a closed
      enum, a `revoked` snapshot without `revoked_at` or a `compromised`
      snapshot without `compromise_at` is `schema/missing-field`, and a
      present `revoked_at` or `compromise_at` that is not a `unix-time` is
      `schema/bad-type` (D-81). More generally (D-82), in CDDL field order
      within each production, validate every closed scalar enum (credential
      `key_usage` and `principal_role`; delegation `use`; epoch event `event`;
      manifest `close_reason`, `late_arrival_policy`, and `fork_policy`;
      transformation `operation`; `phase`; `format`; `reversibility`; outcome
      `state`; evidence `time.class`, `provenance.class`, and `outcome.level`;
      and every enum D-73, D-77, D-78, and D-81 already name), every
      `unix-time`, `sequence`, and `epoch-id` field of every production,
      nested members and array members included (the receipt bodies'
      `observed_at` and `dispatched_at`, `evidence.time.wall_time`, parent
      edges' `parent_epoch_id`, event detail sequences and times, manifest
      `sequence_span` and index entries, anchor and Merkle batch `epoch_id`s), for
      presence then type, a receipt's `freshness` and `binding` sub-maps
      for presence then type of each member, and the proof-bearing
      productions carried in envelopes (an anchor record's `inclusion`,
      `consistency`, and `head`; a Merkle batch's members; every manifest
      index entry's members) for presence then type of each member (D-82
      amendment ab). Absence is
      `schema/missing-field`, a wrong type `schema/bad-type`, an unlisted
      value `schema/enum-unknown`. A present `null` is a present value of the
      wrong type for every optional member of every production, never an
      absent member (D-82 amendment u, extending g). Within an enveloped production, the closed-map
      presence check of its top-level members precedes the field-ordered
      traversal, so a missing top-level member is reported before any type or
      enum defect of an earlier field. Three pinned precedences stand: a
      credential's `principal_type` enum before its fixed-size ids; a
      presentation's `state` enum before its ids; and a request envelope's
      present coordinate fields (`tenant_id`, `site_id`, `target_ep_kid`,
      `correlation`) are judged at step 7 as `request/coordinate-mismatch`,
      never as a step-6 schema failure (an absent one is the closed-map
      `schema/missing-field`). Traversal of every remaining field is a
      separate ruling.
   7. resolve a P-256 verification key through the accepted credential path
      and check the resolved signer, in this order (D-77):
      1. a carried credential whose `subject_kid` equals the protected kid
         exists, else `key/not-found`; when several carry that kid, the
         first in `credentials` array order is the resolved credential
         (D-73's find-first rule);
      2. `SHA-256(public_key) == subject_kid`, else
         `credential/kid-key-mismatch`; the carried SPKI is the verification
         key;
      3. the key is P-256, else `key/not-p256`;
      4. the credential's key usage (and, for a mediator countersignature,
         its role) authorizes the object; a request envelope requires
         `agent_signing` usage; else `credential/usage-mismatch`
         (`receipt/signer-role-mismatch` for a receipt);
      5. the protected kid equals the signer the payload declares, where it
         declares one: a credential's `issuer_kid` (for an empty path, its
         `issuer_kid` and `subject_kid` both); a status snapshot's
         `issuer_kid`; an anchor record's `target.anchor_kid`; an epoch
         event's, epoch manifest's, or Merkle batch's `epoch_owner_kid`; the
         `subject_kid` of the carried credential named by a delegation's
         `issuer_credential_id` or by an approver-originated presentation's
         `presenter_credential_id` (no such carried credential fails this
         check); for an EP-authenticated-session presentation, the protected
         kid of its enclosing authorization receipt; and a Merkle batch's
         `signer_kid` MUST equal its `epoch_owner_kid`; else
         `credential/usage-mismatch`;
      6. the resolved credential's `tenant_id` and `site_id` equal the
         selector's, else `credential/usage-mismatch`;
      7. the signing time lies in the half-open interval
         `[valid_from, valid_until)`, else `credential/not-yet-valid` or
         `credential/expired`. The signing time of an object is the time it
         claims for its own signed act (D-81): a receipt's
         `emission.committed_at`; an epoch manifest's `closed_at`; an epoch
         event's `occurred_at`; an anchor record's `accepted_at`; a Merkle
         batch's `created_at`; a presentation manifest's `delivered_at`; a
         status snapshot's `produced_at`; a request envelope's
         `freshness.issued_at`; a mediator countersignature's
         `mediator_observed_at`. A credential, a delegation, and a rotation
         record carry no time of their own signing, so their signing time is
         the evaluation time. The same signing time is the use time of the
         signer's key for the step-8 revocation and compromise checks.

      Status-snapshot content (lease, freshness, revocation) is evaluated at
      step 8; status envelopes pass sub-step 7 like every other envelope;
   8. after all of sub-step 7, compare protected receipt coordinates to
      payload coordinates;
   9. reconstruct COSE `Sig_structure` from the received protected and payload
      bytes and verify ES256.

   A mediator countersignature uses content type
   `application/aar-mediator-countersignature+cbor;v=0.2`, requires an
   `outcome_signing` credential whose `principal_role` is `outcome_observer`,
   and verifies with the carried SPKI. A countersignature COSE/profile or
   signature failure is `countersign/invalid`; failure to resolve or accept its
   credential, chain, usage, role, scope, validity, status, or SPKI is
   `countersign/credential-invalid`. More generally, any validation failure of
   a credential that is the subject of a carried countersignature reports
   `countersign/credential-invalid`, including a failure while validating that
   credential's own envelope.

7. **Content commitments and IDs.** Artifacts are visited in the step-6 order
   (each receipt's commitments, then its embedded delegation's and nested
   presentation's ids, before the next artifact; D-82 amendment am). Note (GATE3 F3): artifact IDs bind
   content, not signer — reference-by-ID resolves to the carried artifact,
   whose signature is independently validated at use (the credential check
   re-validates the token's signer for its role); revisit signer-in-preimage
   only if a multi-signer delegation model appears. Recompute every content-derived ID and every
   declared digest whose bytes are present. Recompute `delegation_id`,
   `credential_id`, `snapshot_id`, `rotation_id`, `event_id`, `anchor_id`, and
   `batch_id` from their domain-separated deterministic-CBOR claims with their
   own ID field absent; a mismatch is `identity/artifact-id-mismatch` (a
   presentation's `presentation_id` included). For a
   referenced canonical manifest,
   first require a payload with the declared digest, media type, and byte
   length (a length that disagrees is `hash/mismatch`), then hash it. The
   commitments recomputed are those at their CDDL positions; a digest-named
   member at any other position is a shape matter for the body traversal, not
   a commitment (D-82 amendment ac).
   For every `agent_request` root, resolve exactly one request envelope by
   `request_id` and require the root's `request_commitment` to equal SHA-256 of
   the exact request claims bstr. A missing request envelope is
   `bundle/dependency-missing`; a different digest is
   `request/commitment-mismatch`. Then require the request's declared coordinates
   to agree with what the receipt already asserts: `tenant_id` and `site_id` MUST
   equal the receipt binding's, `target_ep_kid` MUST equal the binding's
   `epoch_owner_kid`, and the request's `correlation.target_ep_kid` MUST equal its
   own top-level `target_ep_kid`. Any disagreement is
   `request/coordinate-mismatch` (D-60): a correct commitment proves only that
   these are the bytes the agent signed, never that the agent signed them for this
   tenant, this site, or this enforcement point. A missing or non-conforming
   coordinate — on either side of any comparison — is treated as disagreement and
   MUST yield the same code, never an implementation error. `human_request` and
   `standing_condition_trigger` roots remain commitment-only. For each mediator
   countersignature, recompute `countersignature_id` from the domain
   `AAR-MEDIATOR-COUNTERSIGNATURE-ID-v1` and its claims with that field absent;
   disagreement is `countersign/digest-mismatch`.
8. **Credential lifecycle.** Enforce role-key separation; path construction;
   tenant-scoped roots; and rotation predecessor/successor continuity and monotonic
   sequence, in this order (D-54): role-key separation; path construction for
   every credential; root acceptance for every credential; rotation binding for
   every rotation record in artifact-array order; the rotation ordering pass;
   then status snapshots. In path construction, a credential whose `subject_kid` equals a
   trust-store `root_kid` MUST have an empty path, else `credential/path-invalid`
   (D-77): only the root's self-signed credential may speak for a root key.
   Root acceptance (D-77) checks every carried credential: its
   terminal credential's `subject_kid` equals a root record's `root_kid`, that
   record's `tenant_id` equals the credential's, and the credential's `site_id`
   is in the record's `allowed_sites`. When the credential's `subject_kid` is
   the protected kid of at least one envelope verified at step 6 (embedded
   delegations and nested presentation manifests included), its `key_usage`
   MUST also be in the record's `allowed_key_usages`. Either failure is
   `credential/root-not-accepted`. Under a relying-party policy (D-83,
   section 6) the per-credential root-acceptance check has three parts in
   this order, each after role-key separation and path construction have
   passed for that credential: separation — a carried credential whose
   `subject_kid` is a verifier kid fails; producer acceptance as above; policy
   acceptance — the terminal credential's `subject_kid` equals a policy
   `root_kid` whose `tenant_id` equals the credential's and whose
   `allowed_sites` contains the credential's `site_id`, and, for a credential
   in the step-6 signer set, its `key_usage` is in that record's
   `allowed_key_usages`. One record is checked against one credential; sites
   and usages are never pooled across records. Every failure is
   `credential/root-not-accepted`, or `countersign/credential-invalid` for a
   mediator credential, with result `nonconformant`. Rotation binding (D-80) checks every
   rotation record, in artifact-array order and in this order per record:
   `predecessor_credential_id` and `successor_credential_id` each resolve to a
   carried credential whose `subject_kid` equals the record's `predecessor_kid`
   or `successor_kid`; the record's protected kid equals the predecessor
   credential's `issuer_kid` (the predecessor's own key when it is
   self-signed); and the record's `tenant_id` and `site_id` equal both
   credentials'. Any failure is `credential/rotation-invalid`. The ordering
   pass then groups records by (`tenant_id`, `site_id`) and sorts each group by
   (`effective_at`, `continuity_sequence`); within a group, a record whose
   `continuity_sequence` or `effective_at` is not strictly greater than its
   predecessor's is `credential/rotation-rollback`. Records in different groups
   are never compared. A rotation record asserts continuity only: it never
   makes its successor's root accepted, and a successor root key is accepted
   through the trust store like any other root.
   Then, for EVERY carried status snapshot — whether or not any decision
   references it — evaluate its content in this order: lease maxima
   (`credential/lease-too-long`), status freshness (`credential/status-stale`:
   the snapshot's age exceeds the profile maximum, or the evaluation time is at
   or after `next_update`), revocation use (`credential/revoked`), compromise
   use (`credential/compromised`), unknown status (`credential/status-unknown`),
   and the lease validity window (`credential/not-yet-valid`,
   `credential/lease-expired`). Revocation and compromise are judged at use
   time, never at the evaluation time alone (D-15, D-81): the named
   credential's key is used by every envelope verified at step 6 whose
   protected kid equals that credential's `subject_kid` (embedded delegations
   and nested presentation manifests included), each at its own signing time
   as 6.7.7 defines it, and by the verifier's own signing credential at the
   evaluation time (step 20). A `revoked` snapshot fails when any such use is
   at or after its `revoked_at`; a `compromised` snapshot fails when any such
   use is at or after its `compromise_at`; a snapshot whose key has no use at
   or after its instant passes, with the status inputs bound into the verdict.
   A `revoked` or `compromised` snapshot whose `credential_id` names no carried
   credential fails closed, as if its key were used at the evaluation time.
   Only after every carried snapshot passes are references resolved: a carried
   snapshot whose `credential_id` names no carried credential, then a decision
   `status_snapshot_ids` entry that names no carried snapshot, are each
   `credential/status-missing`. Content defects MUST
   fire before reference-resolution failures so a producer cannot mask a revoked
   or compromised stapled snapshot behind a dangling reference (D-52). The
   numeric maxima are: AAR-1/AAR-2 status age and lease 86,400 seconds; AAR-2A/
   AAR-3 status age 300 seconds and lease 3,600 seconds. All profiles use a maximum
   86,400-second anchor cadence.
   Lease duration is `status_snapshot.lease_not_after - lease_not_before`; use
   before/after that interval fails even if the credential validity is wider.
9. **Emission identity.** A receipt's issuer coordinate is `(signing kid,
   issuer_seq)` and its epoch coordinate is `(epoch owner kid, epoch_id,
   epoch_seq)`. Exact repeated envelope bytes are one duplicate observation and
   are coalesced with an informational verdict entry. The same `receipt_id` with
   different envelope bytes is identity reuse. One coordinate naming different
   IDs is equivocation (`identity/coordinate-equivocation`, whichever coordinate
   repeats). A strictly decreasing issuer or epoch sequence is rollback. A gap is
   not itself a reject in a `valid_subset` bundle. The checks run in two phases,
   and every phase-A failure outranks every phase-B failure (D-86):
   1. **Phase A (always).** Over the carried receipts in canonical artifact
      order, one full pass for `identity/reuse`, then one full pass for
      `identity/coordinate-equivocation`, checking each receipt's issuer
      coordinate before its epoch coordinate.
   2. **Phase B (only when prior state is supplied).** Over every pair of a
      carried receipt and a `prior_emissions` entry: (i) one full pass for
      `identity/reuse` (same `receipt_id`, different `envelope_digest`); (ii) one
      full pass for `identity/coordinate-equivocation` (same issuer coordinate
      or same epoch coordinate, different `receipt_id`); (iii) over the
      remaining receipts, one full pass for
      `identity/issuer-sequence-rollback` (same signing kid, `issuer_seq`
      strictly lower than the entry's), then one full pass for
      `identity/epoch-sequence-rollback` (same epoch owner kid and `epoch_id`,
      `epoch_seq` strictly lower than the entry's). A carried receipt equal to
      an entry in `receipt_id`, `envelope_digest` and every coordinate is a
      duplicate observation; it is exempt from (iii) but not from (i) or (ii).
      An equal sequence naming a different ID is equivocation under (ii), never
      rollback.

   Within a class the reported witness is the first carried receipt in
   canonical artifact order, then the first entry in committed order. Entries
   that conflict only with each other do not fail the bundle. Before phase A,
   an entry whose `receipt_id` and `envelope_digest` equal a carried receipt's
   but whose coordinates differ from that receipt's is a usage error (section
   5), and no verdict is produced.
10. **Receipt schema semantics.** Require `kind`/body and kind/signer-role
    agreement; required evidence label presence (a label absent from the kind
    that requires it, or present on a kind that forbids it, is that class's
    `evidence/*-class-unsatisfied`); manifest field commitments (an ordinal
    is a uint; a bool is never one);
    resolve every inference `consumption_manifest_id` to either the
    `manifest_digest` of a consumption manifest carried by a `derived_from`
    parent observation or the `digest` of a bundle
    `canonical-manifest-payload`, rejecting an unresolved reference with
    `receipt/consumption-ref-unresolved`;
    decision/presentation conditional fields and presentation signer mode
    (a presentation's `presenter_credential_id` MUST equal the decision's
    `approver_credential_id`, else `receipt/decision-presentation`);
    action-attempt/refusal conditional fields; reject an unknown `hazard_class`
    enum with `schema/enum-unknown`; require every
    `hazard_class="life_safety"` marker's normalized `action_name` to occur in
    the bound trust policy's optional `life_safety_action_names` list, otherwise
    reject with `receipt/hazard-class-unbound`; then degraded-marker constraints;
    normalized action/command agreement (D-73: `canonical_command` MUST decode
    as `canonical-command-payload` whose `operation`, `target`, and
    `parameters_digest` equal the normalized action's `action_name`,
    `target_id`, and `parameters_digest`; an undecodable command is
    disagreement; when `parameters` is present its deterministic encoding MUST
    hash to `parameters_digest`); and dispatch/outcome subject agreement (an
    `outcome_observation` MUST carry exactly one `observed_outcome` parent, and
    that parent's receipt id MUST equal the body's `subject_id`; zero or
    several such parents, or a different id, is
    `receipt/outcome-subject-mismatch`, D-82), in that order. Then evaluate mediator countersignatures in artifact-array
    order: `action_attempt_receipt_digest` MUST equal SHA-256 of exactly one
    carried `action_attempt` receipt-envelope's received deterministic-CBOR
    bytes, and `command_digest` MUST equal that attempt's already-verified
    command digest. Either disagreement, including no or multiple matching
    attempts, is `countersign/digest-mismatch`. Only after every carried
    countersignature passes does the verifier add the signed observation
    `mediator_countersigned`. `mediator_observed_at` is carried and signed but
    is not validated against any other time in v0.2. Duplicate
    countersignatures for one attempt are accepted when distinct
    `mediator_observed_at` values yield distinct `countersignature_id` values.
    The signer check establishes only an accepted in-tenant
    `outcome_observer`/`outcome_signing` credential; v0.2 does not pin its `kid`
    to "the mediator", and mediator-`kid` trust-policy pinning is a v0.3
    question. If no `life_safety_action_names` list is bound, every
    life-safety marker is unbound. `refusal_reason="journal/unavailable"` is valid
    only on a `not_dispatched` attempt. A `degraded` marker is valid only when its
    reason is `journal/unavailable`, the policy-bound normalized action carries
    `hazard_class="life_safety"`, and the attempt remains
    `eligible_for_dispatch`; every other marker combination is
    `receipt/attempt-disposition` (D-54, D-66).
11. **Replay and freshness.** Require `issued_at <= committed_at < expires_at`
    (the freshness window bounds emission, not evaluation: a receipt verified
    after its window has closed is not expired, D-82 amendment v), exact
    intended-parent equality, invocation-ID consistency within an action flow
    (the receipts that share one `correlation_id`; a receipt with no
    correlation binding is in no flow for this check, amendment z), unexpired
    leases, and no prior different use of a one-time
    `(replay_domain, invocation_id)`. An exact replay of identical bytes,
    whether carried in the bundle or supplied in the replay state with the
    same `content_digest`, is a duplicate; changed content under the same
    one-time coordinate is rejected.
12. **Referential closure and graph.** Resolve every parent, require parent metadata
    to equal the resolved parent, enforce the edge matrix and root rules below,
    enforce cross-epoch rules, then enforce depth and width. Each listed check
    runs over every receipt, in artifact order (the `receipts` array order step
    3 requires), before the next check begins (D-54): a dangling parent anywhere
    in the graph is reported before a missing root descriptor anywhere in it,
    and within one check the earlier receipt's defect is reported first. A root
    descriptor that is not a text-keyed map is `graph/root-missing`; one whose
    `kind` is absent or unlisted is `graph/root-forbidden`.
13. **Authorization dominance.** For every dispatch, resolve its single
    `attempted_as` action attempt. The attempt MUST have exactly one
    `authorized_by` authorization ancestor, and that authorization MUST carry
    exactly one valid delegation whose scope contains that attempt's action,
    target, purpose, profile, invocation, tenant, and site. Removing that
    authorization node or its delegation MUST disconnect the dispatch from a
    permitted root. No second authorization or delegation may dominate it.
    The delegation evaluated is the `delegation-envelope` embedded in the
    authorization body — never a top-level artifact selected by position,
    cardinality, or subject heuristics. `decision.delegation_id` MUST equal the
    embedded delegation's `delegation_id`; a mismatch, or any dominating path
    that fails to resolve, is `graph/dominator-missing`. The top-level
    `delegations` array exists to resolve `parent_delegations` references. A
    verifier MUST NOT skip delegation evaluation when a reference fails to
    resolve (D-53). The embedded delegation's `subject_credential_id` MUST
    resolve, by find-first over the carried `credentials` array, to a
    credential whose `subject_kid` equals the protected kid of the action
    attempt (D-79): a delegation names the enforcement point that attempts
    under it. No such credential, or a different kid, is `delegation/scope`.
    The remaining delegation checks run in this order (D-54): subject; then
    action, target, purpose, profile, tenant, site, and invocation, each
    `delegation/scope` (the invocation check applies whenever the delegation
    carries `invocation_id`, and a `one_time` delegation without
    `invocation_id` fails it); then `not_before` (`delegation/not-yet-valid`);
    then `not_after` (`delegation/expired`); then `parent_delegations`
    (`delegation/chain-invalid`), traversed transitively (D-82): every link
    MUST resolve to a carried top-level delegation; contain the child's
    `[not_before, not_after]`; contain each of the child's `actions`,
    `targets`, `purpose_ids`, and `allowed_profiles` as a subset; share the
    child's `tenant_id` and `site_id`; not widen `use` (a `one_time` parent
    forbids a `reusable` child, and a parent `invocation_id` MUST equal the
    child's); and not name a delegation already on the path. Links are
    followed in `parent_delegations` array order, depth first; each carried
    delegation's chain is evaluated at most once per verification, so the
    traversal is bounded by the number of carried delegations whatever the
    sharing of ancestors. For each dispatch in array order, after that dispatch's
    dominance, embedded-delegation, scope, time and parent-delegation checks
    succeed, apply D-66 before moving to the next dispatch (D-54). On an AAR-3
    profile, the linked `action_attempt` is committed
    before the action-bearing send only if (a) its signed binding supplies the
    same epoch owner and epoch as the dispatch, (b) its `epoch_seq` is lower than
    the dispatch's, and (c) its `emission.committed_at` is no later than
    `dispatch.body.dispatched_at`. A dispatch
    without that prior journal commitment is `nonconformant` with
    `journal/uncommitted-dispatch`. The only exception is an action carrying
    policy-bound `hazard_class="life_safety"` and an attempt carrying
    `degraded.reason="journal/unavailable"`; that dispatch remains conformant and
    records `degraded_dispatch`. This exemption comes only from the bound trust
    policy and is never established by an EP assertion alone. Anchoring is
    asynchronous and MUST NOT enter this check. An AAR-3 `not_dispatched` attempt with
    `refusal_reason="journal/unavailable"` and no dispatch naming it records
    `refused_pre_dispatch`.

    **Input-origin ancestry (D-78).** After every dispatch has passed this
    step, take the set of distinct action attempts those dispatches resolve.
    For each attempt, walk incoming edges transitively, following every edge
    type except `attempted_as` and `observed_outcome`, visiting each receipt
    once and following the cross-epoch links already validated at step 12.
    The walk covers observation, inference, authorization and
    outcome_observation ancestors, including an authorization's own
    `requested_by`, `triggered_by` and `supports` parents and an
    outcome_observation's `supports` parents. `supports` is noncausal (D-09):
    a result means an input sat in the action's ancestry, never that the
    agent consumed it or that it caused the action. A *declaration slot* is
    one inference receipt (declared iff `origins` is present) or one
    consumption item with `disposition="used"` (declared iff `origin` is
    present); an observation whose items are all `discarded` contributes no
    slot. Over the union of slots across all attempts, set
    `limits.input_origin_ancestry` to `not_evaluated` when there are no
    slots, `declared_only` when every slot is declared, `not_declared` when
    none is, otherwise `partially_declared`. Record
    `untrusted_origin_declared_in_action_ancestry` iff any declared value is
    `third_party`, `device_sensed` or `unknown`. Only these two aggregates
    enter the signed verdict. Verifier tools MUST surface a report-layer
    per-attempt table in dispatch array order, then attempt id, giving each
    attempt's declared origin set and undeclared slot count, including
    attempts that are eligible but undispatched, bound to the bundle and
    verdict identifiers. This paragraph never rejects.
14. **Epoch state machine.** Validate owner/event chains, monotonic epoch IDs and
    event sequences, predecessor manifest digest, one open and one close, duration,
    sequence span/count, immutable close, late-arrival routing, anchor deadline,
    and fork rules. Two distinct manifests for one owner/epoch are a fork, and a
    carried `fork_declared` event is itself `epoch/fork`: its `handling` is
    `reject_and_surface`, so the verifier rejects the epoch and surfaces the
    declaration in its report; conflicting event chains fail `epoch/event-chain`
    at chain linkage, before any fork rule (D-82). A receipt whose
    `late_for_epoch_id` is not lower than its own `epoch_id` is
    `epoch/late-insertion`, whether or not that epoch's manifest is carried
    (D-82). Duration is judged on both the manifest's `opened_at`/`closed_at`
    and its paired open and close events' `occurred_at`: either pair more than
    86,400 seconds apart is `epoch/duration-exceeded`.
    D-73: a carried manifest whose owner/epoch has no event group, and an
    event group with no carried manifest, are each `epoch/open-close` — a
    closed epoch is the manifest **and** its open/close events.
    `previous_event_digest` is absent only on event sequence zero and otherwise
    MUST equal SHA-256 of the exact preceding epoch-event payload bstr; a mismatch
    is `epoch/event-chain`. A predecessor manifest digest is absent only on the
    first epoch known for that owner; later epochs require it. The carried
    manifests of one owner, in `opened_at` order, chain by it: each later
    manifest's `predecessor_manifest_digest` MUST equal SHA-256 of the
    preceding carried manifest's payload bstr (`epoch/predecessor-mismatch`);
    a predecessor that names no carried manifest is not itself a defect in a
    `valid_subset` bundle (amendment w). Sequence span and count are judged
    here: the open event's `first_epoch_seq` and the close event's
    `last_epoch_seq` MUST equal the manifest's `sequence_span`, and the close
    event's `item_count`, the manifest's `item_count`, and the index's
    `leaf_count` MUST equal the index length (`epoch/span-count-mismatch`,
    amendment ad).
15. **Manifest index.** Require, in this order: sort order
    (`manifest/index-order`), contiguous leaf indices (`manifest/index-gap`),
    unique receipt IDs/epoch sequences (`manifest/index-duplicate`),
    entry-to-receipt equality (`manifest/index-receipt-mismatch`), and equality
    of sequence spans (the span is the minimum and maximum `epoch_seq` over the
    entries; a nil span pairs only with an empty padding index, amendment ad).
    Only after every entry-level requirement holds
    are the entry leaves and root recomputed and compared to the carried root;
    `manifest/index-root-mismatch` fires last (D-54).
16. **Merkle batches.** Recompute domain-separated leaf/node hashes with
    `batch_id` excluded from the leaf preimage; enforce proof batch ID against the
    signed batch's recomputed ID and enforce index, size, signer,
    tenant/site/epoch leaf context, and path length (a sibling count that is
    impossible for the batch's tree size is `merkle/path-length`; the CDDL
    bounds themselves, more than 20 siblings and a `tree_size` outside
    1..1,048,576, are `schema/out-of-range` at steps 3 and 6, D-82 amendment
    ak), then compare the root. Among
    successfully proven leaves carried in this bundle for one signed batch,
    reject two leaves at different indices that share
    `(tenant_id, site_id, epoch_id, item_digest)`. The verifier cannot make that
    duplicate claim about unproven leaves. A successful result is recorded only
    as membership.
17. **Anchors.** Verify target identity and plan membership, inclusion proof,
    optional consistency proof (its `new_tree_size` and `new_root` MUST equal
    the record's `anchor_tree_size` and `anchor_root`, else
    `anchor/consistency-invalid`, amendment x), manifest/epoch binding, and recompute
    `manifest_digest` as SHA-256 of the exact epoch-manifest payload bstr under
    `anchor/manifest-binding`; then verify submission deadline, expected-head
    match/freshness (the record's head conflicts with the expected head when
    their sizes are equal and their roots differ, or when their sizes differ
    and their roots are equal, `anchor/head-mismatch`, amendment y), and
    multi-target independence declaration. An anchor proves
    existence/order by time only.
    The independence basis compares anchor targets with each other; it does
    not assert that an anchor operator differs from the producer. A
    `same_operator` basis declares no independence: the verifier performs no
    pairwise distinctness check and records existence/order only. The basis
    enum is validated at step 6 even when no anchor record is carried, and a
    repeated `target_id` among the plan's targets is `schema/duplicate-entry`
    at step 6 (amendment ap).
    Observation consumption cardinality and command exclusion shape are
    likewise step-6 schema checks; missing exclusion commitments are not
    deferred to command hashing.
18. **Bundle ranges and coverage.** For each range, in this order (D-54, D-82
    amendment ai): resolve its manifest (`bundle/range-manifest-missing`),
    match its selector commitment (`bundle/range-selector-mismatch`), require
    contiguous leaf indices that also lie strictly above the previous range of
    the same manifest in array order (`bundle/range-noncontiguous`, amendment
    al), verify every entry
    proof and every present boundary proof against the signed manifest index
    root (`bundle/range-proof-invalid`), then require correct left/right
    temporal boundaries (`bundle/range-boundary`); then evaluate the selector;
    require every selected entry and its closed
    graph. Under `complete`, a carried receipt that is not reachable from a
    selected receipt is judged by its objective index entry: an entry outside
    the selector, or no entry at all, is `bundle/artifact-out-of-scope`
    (amendment aj). Per D-19, a range's `entries` MUST carry every objective index entry in
    the half-open temporal slice — including entries whose kind, subject, or
    issuer do not match the selector. Selector predicates are applied locally by
    the verifier only after slice completeness is established; a matching-only
    slice fails `bundle/range-boundary` (D-55). `complete` is complete only
    relative to signed producer-declared
    manifest indexes. Ingress completeness remains `not_established` without an
    independently committed census or future R-15 reconciliation result.
    `first_leaf_index` is present iff `entries` is nonempty; an empty temporal
    slice requires valid neighboring boundaries (except at the index ends).
19. **Evidence-class qualification.** Recompute the maximum class declared and
    structurally supported by committed artifacts. Each
    `boot_attestation_id`, `capture_attestation_id`,
    `provider_attestation_id`, and `qualifying_predicate_id` required by the
    declared class MUST resolve to a bundle `canonical-manifest-payload` whose
    `digest` equals the ID; absence is `manifest/payload-missing`. `boot_bound`
    requires the boot artifact. `externally_anchored` additionally requires that
    `anchor_id` resolve to a verified anchor for an earlier epoch under the same
    owner, tenant, and site, with `anchor.accepted_at <= receipt.committed_at`.
    That prior anchor is the lower bound; a separately verified anchor for the
    receipt's own epoch, when present, is the upper bound. `proxy_captured`
    requires the capture artifact; `provider_attested` additionally requires the
    provider artifact; `independently_sensed` requires the qualification artifact
    and an observer whose `failure_domain_id` differs from the
    `source_device.failure_domain_id` of every observation in the outcome
    receipt's ancestry (the observations the reported action derived from; an
    unrelated observation elsewhere in the bundle does not count, D-82). v0.2 carries these bytes
    opaquely and does not cryptographically interpret TPM quotes, provider
    signature formats, predicates, or other attestation content; deep validation
    is a v0.3 or stronger-profile concern. Contradicted and unknown remain honest
    terminal labels, never successful independent sensing. `maximum_outcome_level`
    MUST be a pure function of the multiset of committed receipts' declared
    `evidence.outcome.level` values, independent of receipt-ID sort order:
    `contradicted` if any receipt declares it; else `unknown` if any receipt
    declares it; else the highest-ranked declared level (`independently_sensed` >
    `device_acknowledged` > `dispatched` > `accepted`); else `not_evaluated`.
20. **Verdict.** Construct, deterministically encode, and sign exactly one verdict
    under section 5. The result is `conformant` only if every requested check
    succeeded. Missing external policy, key, expected head, or replay state yields
    `indeterminate`; a malformed or semantically invalid bundle yields
    `nonconformant` with the first reason code. Without a relying-party
    policy, per D-58 the verifier's own signing key resolves from bundle
    credentials: a bundle carrying no `verifier_signing` credential for the
    verifier's kid yields a signed indeterminate `key/not-found` at this step
    (D-73 find-first). Under a relying-party policy (D-83, section 6) this
    step consults no bundle credential: the signer is the configured leaf,
    the protected kid is its `subject_kid`, and a carried `verifier_signing`
    credential is an ordinary carried credential for steps 6 and 8. Signing
    the verdict is a use of the signing key at the evaluation time — the
    configured leaf's kid under a policy, the verifier's corpus kid otherwise:
    a carried `revoked` or `compromised` snapshot that names that credential
    is judged against that use at step 8 (D-81). The step-6 signer set is
    captured before this use is added; it never makes a credential a signer
    for the usage check.

### 2.1 Edge legality and roots

An edge is written on the child and reads `parent -> child`. The following matrix
is closed; every unlisted pair is `graph/edge-illegal`.

| Edge | Allowed parent kinds | Allowed child kinds |
|---|---|---|
| `derived_from` | observation, inference | observation, inference |
| `requested_by` | observation, inference | inference, authorization, action_attempt |
| `authorized_by` | authorization | action_attempt |
| `triggered_by` | observation, inference | authorization, action_attempt |
| `attempted_as` | action_attempt | dispatch |
| `observed_outcome` | action_attempt, dispatch | outcome_observation |
| `supports` | observation, inference, outcome_observation | inference, authorization, outcome_observation |

The `requested_by` edge claims exactly that the child was created in response to
the parent's content; the originating external request is carried by the root
descriptor and request artifact, never by this edge.

Only observation, inference, and authorization receipts may be roots. A root MUST
carry exactly one root descriptor. `agent_request` may root observation or
inference; `human_request` may root observation, inference, or authorization; and
`standing_condition_trigger` may root observation or authorization. A non-root
MUST NOT carry a root descriptor.

Receipt signer roles are also closed: observation permits Agent, EP, or Outcome
Observer; inference permits Agent; authorization, action_attempt, and dispatch
permit EP; outcome_observation permits Outcome Observer. An approver-originated
presentation is signed with `approver_signing`; an EP authenticated-session
presentation is signed with `ep_signing`. A request envelope is signed with
`agent_signing`. Delegations use `authority_signing`;
credentials/rotations use `credential_issuing`; status snapshots use
`status_signing`; epoch events, epoch manifests, and Merkle batches use
`ep_signing`, and their signing kid MUST equal `epoch_owner_kid`. A Merkle batch's
`signer_kid` MUST also equal `epoch_owner_kid` in v0.2; the separate field is a
seam for a future delegated-journal profile. Violations use
`credential/usage-mismatch`. Anchors and verdicts use their correspondingly named
key usage.

Evidence presence is closed by kind. Every receipt carries time evidence.
Inference carries provenance evidence and other kinds omit it. Action attempt,
dispatch, and outcome observation carry outcome evidence; observation, inference,
and authorization omit it. `accepted` is valid on action attempt, `dispatched` on
dispatch, and the remaining outcome labels on outcome observation.

All edges are same tenant/site. They are same epoch unless they carry
`cross_epoch`. Cross-epoch is allowed only for:

- `derived_from` with reason `historical_evidence`;
- `supports` with reason `historical_evidence`;
- `observed_outcome` with reason `long_running_action` or `late_outcome`.

The source epoch MUST be earlier, closed, anchored, and named by the exact source
manifest and anchor: the named manifest MUST belong to the parent receipt's
epoch owner, epoch, tenant, and site, and the named anchor MUST bind that
manifest; otherwise `graph/cross-epoch-unanchored` (D-82). Authorization, request, trigger, and attempt edges never cross
an epoch boundary.

## 3. Closed reason-code table

This table is the complete reason-code vocabulary for W-1 through W-10. Every code
has exactly the trigger written here. Implementations MUST NOT invent synonyms or
emit a code for a different trigger. All entries are verifier rejection reasons
except `journal/unavailable`, which is explicitly the closed operational refusal
reason carried by an `action_attempt` receipt and is never a verdict reason. Where
one input has several defects, section 2 selects the first verifier code.

| Code | Exact trigger |
|---|---|
| `resource/bundle-too-large` | Exact input exceeds 16,777,216 bytes. |
| `resource/cbor-depth` | A syntactically open container would exceed nesting depth 32. |
| `resource/node-count` | Receipt or mediator-countersignature count exceeds 10,000. |
| `resource/edge-count` | Total parent edges exceeds 50,000. |
| `resource/parent-count` | One receipt has more than 64 parents. |
| `resource/dag-depth` | Acyclic graph longest path exceeds 128 nodes. |
| `resource/dag-width` | More than 4,096 nodes have the same computed rank. |
| `resource/proof-too-large` | One encoded proof exceeds 65,536 bytes. |
| `resource/proofs-too-large` | Aggregate encoded proofs exceed 4,194,304 bytes. |
| `cbor/malformed` | Input is not one well-formed CBOR item after earlier resource checks. |
| `cbor/invalid-utf8` | A CBOR text string is not valid UTF-8. |
| `cbor/indefinite-length` | Any indefinite-length string, array, or map occurs. |
| `cbor/duplicate-key` | Any CBOR map repeats a key, including a protected header. |
| `cbor/trailing-bytes` | Bytes follow the one top-level item. |
| `cbor/tag-forbidden` | Any CBOR tag occurs outside the top level of a serialized COSE bstr. |
| `cbor/float-forbidden` | Any float, including NaN, infinity, or negative zero, occurs. |
| `cbor/non-canonical` | A well-formed item violates shortest encoding or deterministic map order, or differs from deterministic re-encoding. |
| `schema/unknown-field` | A closed map contains an unlisted key. |
| `schema/missing-field` | A required key is absent. |
| `schema/bad-type` | A present value has the wrong CBOR major type or container shape. |
| `schema/version-wrong` | `v` is present as uint but is not exactly 2. |
| `schema/enum-unknown` | A text or integer enum value is outside its closed production. |
| `schema/out-of-range` | A correctly typed integer or collection violates its numeric/occurrence range. |
| `schema/string-size` | A tstr violates its stated UTF-8 byte length. |
| `schema/digest-size` | A digest, kid, UUID-like id, or signature-sized bstr has the wrong fixed length. |
| `schema/unsorted-set` | A bundle selector set, bundle artifact array, or inference `origins` set (D-78) is not strictly in its prescribed order. |
| `schema/duplicate-entry` | A bundle selector set, bundle artifact array, or inference `origins` set (D-78) repeats an otherwise valid entry, or two trust-store root records share a `root_kid` (D-77). |
| `cose/tagged` | A CBOR tag wraps a COSE_Sign1. |
| `cose/bad-structure` | A well-formed COSE item is not an untagged four-element array of the required element types. |
| `cose/protected-not-map` | Protected is a bstr but its contents are not one closed CBOR map. |
| `cose/protected-label` | Protected contains a label outside the selected protected-header schema. |
| `cose/alg-missing` | Protected label 1 is absent. |
| `cose/alg-wrong` | Protected label 1 is present but not integer -7. |
| `cose/content-type-missing` | Protected label 3 is absent. |
| `cose/content-type-wrong` | Protected label 3 does not exactly select the detached payload schema. |
| `cose/kid-missing` | Protected label 4 is absent. |
| `cose/receipt-coordinate-missing` | A required AAR receipt protected label -70000 through -70006 is absent. |
| `cose/receipt-coordinate-mismatch` | A protected principal/role/tenant/site/epoch/sequence value differs from the payload. |
| `cose/alg-in-unprotected` | The unprotected map contains label 1. |
| `cose/unprotected-not-empty` | The unprotected map is nonempty and does not contain label 1. |
| `cose/payload-not-detached` | COSE element 2 is not CBOR null. |
| `sig/der-encoding` | Signature length is not 64 and the bytes parse as DER Ecdsa-Sig-Value. |
| `sig/bad-length` | Signature length is not 64 and the bytes do not parse as DER. |
| `sig/zero-rs` | A 64-byte P1363 signature has r=0 or s=0. |
| `sig/high-s` | A 64-byte P1363 signature has s greater than the P-256 half-order. |
| `sig/verify-failed` | ES256 verification over the exact prescribed Sig_structure fails. |
| `key/not-found` | No credential supplies the protected kid and no accepted external key is configured. |
| `key/not-p256` | The selected public key is not an EC P-256 key. |
| `hash/mismatch` | A consumption, decision, presentation, command, structured-claim, normalized-parameter, canonical-manifest-payload, or ID-less trust-store preimage does not hash to its adjacent declared digest/ID. |
| `request/commitment-mismatch` | An `agent_request` root's commitment is not SHA-256 of the exact claims bstr in the request envelope resolved by its request ID. |
| `request/coordinate-mismatch` | An `agent_request` root's resolved request declares a `tenant_id`, `site_id`, or `target_ep_kid` that disagrees with the receipt binding (`epoch_owner_kid` for the EP), or its `correlation.target_ep_kid` disagrees with its own `target_ep_kid`. |
| `manifest/payload-missing` | A referenced canonical manifest payload is absent from the bundle. |
| `manifest/media-type-mismatch` | A manifest reference and supplied payload have different media types. |
| `identity/receipt-id-mismatch` | Recomputed receipt ID differs from `receipt_id`. |
| `identity/artifact-id-mismatch` | Recomputed delegation, credential, status, rotation, epoch-event, anchor, or Merkle-batch ID differs from its declared primary ID. |
| `identity/reuse` | One receipt ID names nonidentical envelope bytes within the bundle (step 9 phase A) or relative to a supplied prior-state entry (phase B). |
| `identity/coordinate-equivocation` | One issuer or epoch coordinate names different receipt IDs within the bundle (phase A) or between a carried receipt and a supplied prior-state entry (phase B); entries that conflict only with each other do not fail the bundle. |
| `identity/issuer-sequence-rollback` | A carried receipt that exactly duplicates no prior-state entry has an `issuer_seq` strictly lower than an entry's for the same signing kid (an equal coordinate naming a different ID is equivocation). |
| `identity/epoch-sequence-rollback` | A carried receipt that exactly duplicates no prior-state entry has an `epoch_seq` strictly lower than an entry's within the same owner/epoch (a reused coordinate naming a different ID is equivocation). |
| `receipt/kind-body-mismatch` | Receipt `kind` does not select the supplied body production. |
| `receipt/signer-role-mismatch` | Receipt kind, protected/payload role, or required credential key usage violates the closed signer matrix. |
| `receipt/manifest-inconsistent` | Consumption, presentation, decision, or command manifest ordinals, counts, or cross-references disagree after direct byte/digest checks. |
| `receipt/consumption-ref-unresolved` | An inference `consumption_manifest_id` resolves to neither a `derived_from` parent observation's consumption-manifest digest nor a carried canonical-manifest-payload digest. |
| `receipt/decision-presentation` | Presentation presence or approver fields disagree with the decision enum. |
| `receipt/attempt-disposition` | `not_dispatched` lacks `refusal_reason`; `eligible_for_dispatch` carries one; `journal/unavailable` appears outside a `not_dispatched` refusal; or a `degraded` marker is not exactly the life-safety exception described at step 10. |
| `receipt/hazard-class-unbound` | A normalized action carries `hazard_class="life_safety"`, but its `action_name` does not occur in the bound trust policy's `life_safety_action_names` list, including when that optional list is absent. |
| `receipt/action-command-mismatch` | Normalized action and command action/target/parameter commitment disagree. |
| `receipt/dispatch-attempt-mismatch` | Dispatch does not name the command and attempt selected by `attempted_as`. |
| `receipt/outcome-subject-mismatch` | Outcome subject is not its `observed_outcome` dispatch/attempt parent, or the outcome carries zero or several `observed_outcome` parents (D-82). |
| `journal/unavailable` | Operational refusal reason: before an AAR-3 non-life-safety action-bearing send, neither the primary nor emergency journal can durably commit the `action_attempt`; the EP emits a `not_dispatched` attempt carrying this exact `refusal_reason`. This code never appears as a verifier verdict reason. |
| `journal/uncommitted-dispatch` | On an AAR-3 profile, a dispatch's linked attempt lacks the prior journal commitment defined at step 13 and is not the marked life-safety exception. |
| `credential/root-not-accepted` | Credential path ends at a root not accepted for the bound tenant/site, or a credential that signs a verified envelope has a key usage its root does not allow (D-77); under a relying-party policy, also a root or credential that is a verifier kid, or a credential outside the policy's root, site or usage ceiling (D-83). |
| `credential/path-invalid` | Path within its schema length is not a contiguous issuer/subject chain or contains a loop. |
| `credential/kid-key-mismatch` | SHA-256 of the credential's carried DER SubjectPublicKeyInfo differs from `subject_kid`. |
| `credential/usage-mismatch` | Credential key usage does not authorize the signed object/role, including an epoch event, epoch manifest, or Merkle batch not signed by its `epoch_owner_kid` with `ep_signing`, or a Merkle batch whose `signer_kid` differs from `epoch_owner_kid`, or an envelope whose protected kid differs from the signer its payload declares, or a signing credential whose tenant/site differs from the selector's (D-77). |
| `credential/not-yet-valid` | Signing time (step 6.7) precedes credential `valid_from`, or use precedes the status lease window (step 8). |
| `credential/expired` | Signing time (step 6.7) is at or after credential `valid_until`. |
| `credential/status-missing` | A required stapled snapshot for the decision/key is absent, or a carried snapshot names a credential the bundle does not carry; both checked only after every snapshot's content (D-52, D-81). |
| `credential/status-stale` | Snapshot age exceeds 86,400 seconds for AAR-1/2 or 300 seconds for AAR-2A/3, or the evaluation time is at or after `next_update`. |
| `credential/revoked` | A use of the named credential's key (a step-6 envelope at its signing time, or the verifier's own key at the evaluation time) is at or after the snapshot's `revoked_at`; or a `revoked` snapshot names no carried credential (D-81). |
| `credential/compromised` | A use of the named credential's key (a step-6 envelope at its signing time, or the verifier's own key at the evaluation time) is at or after the snapshot's `compromise_at`; or a `compromised` snapshot names no carried credential (D-81). |
| `credential/status-unknown` | A required status snapshot says `unknown`. |
| `credential/lease-too-long` | Issued lease exceeds 86,400 seconds for AAR-1/2 or 3,600 seconds for AAR-2A/3. |
| `credential/lease-expired` | Evaluation/use occurs after the lease expiry. |
| `credential/rotation-invalid` | Successor/predecessor ids or kids do not cross-bind, the record is not signed by the predecessor credential's issuer, or the record's tenant/site differs from either credential's (D-80). |
| `credential/rotation-rollback` | Within one tenant and site, rotation continuity sequence or effective time is non-monotonic (D-80). |
| `credential/role-key-reuse` | Agent, EP, or Authority Source resolve to the same signing kid. |
| `replay/not-yet-valid` | Receipt freshness `issued_at` is after its committed time/evaluation window. |
| `replay/expired` | Receipt committed at or after `expires_at`. |
| `replay/parent-binding` | `intended_parents` is not exactly the ordered parent-id list. |
| `replay/invocation-mismatch` | Receipts in one action flow disagree on invocation ID or replay domain. |
| `replay/one-time-reused` | A one-time replay-domain/invocation coordinate was previously used for different content. |
| `delegation/not-yet-valid` | Attempt precedes delegation `not_before`. |
| `delegation/expired` | Attempt is at or after delegation `not_after`. |
| `delegation/scope` | The delegation's subject is not the enforcement point that signed the attempt (D-79), or action, target, purpose, tenant, site, profile, or invocation is outside delegation scope. |
| `delegation/chain-invalid` | A parent delegation on the transitive chain is missing, already on the path, does not contain the child's window or its four scope lists, differs in tenant or site, or widens `use` or `invocation_id` (D-82). |
| `graph/dangling-parent` | A parent id cannot be resolved in the bundle when closure is required. |
| `graph/parent-metadata-mismatch` | Parent kind/tenant/site/epoch metadata differs from the resolved parent. |
| `graph/edge-illegal` | Edge parent-kind/child-kind pair is absent from the closed matrix. |
| `graph/root-missing` | A parentless allowed node lacks a root descriptor. |
| `graph/root-forbidden` | Node kind/root kind pair is unlisted, or a non-root carries `root`. |
| `graph/tenant-site-splice` | Parent and child have different tenant or site. |
| `graph/cross-epoch-forbidden` | Cross-epoch edge type/reason is unlisted or an unequal epoch lacks `cross_epoch`. |
| `graph/cross-epoch-unanchored` | Cross-epoch source is not earlier, closed, and bound to the named valid anchor/manifest; or the named manifest does not belong to the parent's owner/epoch/tenant/site, or the named anchor does not bind that manifest (D-82). |
| `graph/dominator-missing` | Dispatch lacks its one exact dominating authorization/delegation path. |
| `graph/dominator-ambiguous` | More than one authorization or delegation dominates a dispatch. |
| `epoch/event-chain` | Event sequence or previous-event digest does not form one owner/epoch chain. |
| `epoch/id-nonmonotonic` | Epoch ID is not greater than its predecessor epoch ID. |
| `epoch/predecessor-mismatch` | Manifest predecessor digest differs from the prior accepted manifest. |
| `epoch/open-close` | Epoch lacks exactly one valid open followed by one valid close. |
| `epoch/duration-exceeded` | Close is more than 86,400 seconds after open. |
| `epoch/span-count-mismatch` | First/last sequence, item count, manifest count, or empty-padding rules disagree. |
| `epoch/late-insertion` | A receipt is inserted into a closed epoch instead of the next epoch with `late_for_epoch_id`, or its `late_for_epoch_id` is not lower than its own `epoch_id` (D-82). |
| `epoch/anchor-deadline` | Closed event does not set deadline to close+86,400, or its anchor-submitted event occurs after that declared deadline. |
| `epoch/fork` | Distinct manifests exist for one owner/epoch, or a `fork_declared` event is carried; conflicting event chains are `epoch/event-chain` first (D-82). |
| `manifest/index-order` | Objective entries are not strictly ordered by committed time, epoch sequence, receipt ID. |
| `manifest/index-gap` | Leaf indices are not contiguous from zero or epoch sequences have an unexplained gap in a complete manifest. |
| `manifest/index-duplicate` | Index repeats receipt ID or epoch sequence. |
| `manifest/index-receipt-mismatch` | Index metadata differs from its receipt. |
| `manifest/index-root-mismatch` | Recomputed objective index root differs from signed root. |
| `merkle/batch-binding` | Proof batch/tree/index/tenant/site/epoch differs from leaf or signed batch. |
| `merkle/duplicate-leaf` | Two successful membership proofs carried in one bundle for one signed batch have different indices but the same `(tenant_id, site_id, epoch_id, item_digest)`. |
| `merkle/path-length` | Sibling count is impossible for tree size or exceeds 20. |
| `merkle/root-mismatch` | Domain-separated membership recomputation differs from signed batch root. |
| `anchor/target-unplanned` | Anchor target is absent from the signed epoch anchor plan. |
| `anchor/manifest-binding` | Anchor record manifest/tenant/site/epoch differs from the signed manifest. |
| `anchor/inclusion-invalid` | Inclusion path does not compute the signed target root. |
| `anchor/consistency-invalid` | Supplied old/new sizes, roots, or path do not establish consistency. |
| `anchor/submission-late` | Target receipt's `submitted_at` is over 86,400 seconds after epoch close. |
| `anchor/head-missing` | Required expected current head is absent from trust-policy inputs. |
| `anchor/head-mismatch` | Anchor record head conflicts with expected head at the same/later size. |
| `anchor/head-stale` | Trusted evaluation time is over 86,400 seconds after the accepted expected head. |
| `anchor/independence-invalid` | Claimed independent targets share operator or failure-domain id, or declarations disagree. |
| `bundle/selector-commitment` | Recomputed objective selector commitment differs. |
| `bundle/selector-interval` | `committed_from >= committed_until`. |
| `bundle/range-manifest-missing` | A range names no valid signed manifest. |
| `bundle/range-selector-mismatch` | Range selector commitment differs from bundle selector commitment. |
| `bundle/range-noncontiguous` | Range entries/indices are not contiguous or overlap another range. |
| `bundle/range-boundary` | Left/right boundary does not prove the full half-open time interval. |
| `bundle/range-proof-invalid` | An entry or boundary inclusion proof fails against the manifest index root. |
| `bundle/selected-receipt-missing` | A matching objective index entry has no carried receipt under `complete`. |
| `bundle/dependency-missing` | A selected receipt's required request/graph/credential/manifest dependency is absent. |
| `bundle/coverage-overclaim` | `complete` is asserted without complete producer-declared index ranges and closure. |
| `bundle/artifact-out-of-scope` | `complete` bundle carries a receipt outside its selector that is not reachable as a dependency of a selected receipt. |
| `evidence/time-class-unsatisfied` | Declared time class omits its required boot ID or fails the prior-epoch anchor relationship. |
| `evidence/provenance-class-unsatisfied` | Inference lacks provenance evidence, a different kind carries it, or the declared class omits a required capture/provider attestation ID. |
| `evidence/outcome-class-unsatisfied` | Outcome evidence is absent/present on the wrong kind, its label is invalid for that kind, or it omits required dispatch/ack/independent predicate fields. |
| `evidence/observer-not-independent` | `independently_sensed` observer is not in a distinct accepted failure domain. |
| `countersign/invalid` | A carried mediator countersignature has an invalid COSE/profile encoding or signature. |
| `countersign/digest-mismatch` | Its ID, action-attempt receipt-envelope digest, or canonical-command digest does not match the carried bundle. |
| `countersign/credential-invalid` | Its signer credential, chain, SPKI, role, usage, scope, validity, or status is not accepted. |

An unavailable external key, replay database, expected anchor head, or trust-policy
input is not evidence that the bundle is bad. The verdict is `indeterminate` and
uses the same first applicable code (`key/not-found`, `anchor/head-missing`, or the
relevant `schema/missing-field`) so the trigger remains unambiguous.

## 4. Non-reject observations

These are signed verdict observations, not reason codes and never replace the
first-failure reason:

- `duplicate_exact`: identical envelope bytes were observed more than once;
- `valid_prefix`: epochs validate only through the newest fresh expected head;
- `producer_declared_complete`: `complete` holds for selected signed indexes;
- `ingress_completeness_not_established`: no independent census/reconciliation;
- `membership_only`: a Merkle proof establishes no completeness;
- `anchor_existence_order_only`: anchor establishes neither truth nor completeness;
- `refused_pre_dispatch`: an AAR-3 attempt was refused with
  `journal/unavailable` and no dispatch names it;
- `degraded_dispatch`: an AAR-3 action marked `life_safety` proceeded without the
  normal prior journal commitment, was allowed by the bound trust policy, and
  carried the required `degraded` marker;
- `untrusted_origin_declared_in_action_ancestry` (D-78): at least one
  declaration slot in the step-13 ancestry of a dispatched attempt carried a
  producer-declared origin of `third_party`, `device_sensed` or `unknown`,
  which this specification treats as potentially untrusted. The observation
  relays a declaration; it establishes neither that the input was consumed,
  that it influenced the action, nor that any undeclared input was absent.
  Its companion limit `input_origin_ancestry` states how completely the
  ancestry declared itself, so that the absence of this observation on a
  `not_declared` or `partially_declared` verdict is never read as "no
  untrusted input";
- `mediator_countersigned`: every carried D-67 artifact verified and bound an
  exact action-attempt receipt envelope to the canonical-command digest observed
  by an accepted in-tenant `outcome_observer`/`outcome_signing` signer; v0.2
  does not establish that the signer's `kid` is "the mediator";
- `empty_scope` (GATE3 F4): the bundle verified `conformant` over zero receipts
  matching the selector — the verdict asserts nothing about any receipt;
- `stateful_not_evaluated` (GATE3 F6): no prior evaluated state was supplied, so
  cross-evaluation sequence-rollback and one-time-reuse properties were NOT
  evaluated — they did not "pass." The verdict's `replay_state_digest` and
  `prior_emissions_digest` bind which state, if any, was used.

In v0.2, `empty_scope` and `stateful_not_evaluated` are REPORT-LAYER
observations: verifier tools MUST surface them in human/machine reports, but
they do not enter the signed verdict bytes (the D-51 verdict preimages, extended
by D-76, are frozen). Promoting them into the signed verdict is a wire-version decision.

## 5. W-12 signed machine-readable verdict

The verdict is deterministic CBOR in an untagged detached COSE_Sign1 using the same
ES256/P1363/low-S/RFC-6979 rules. Its protected map is exactly `{1:-7,
3:"application/aar-verdict+cbor;v=0.3",4:kid}`. The verifier key MUST have
`verifier_signing` usage; `kid` is the corpus verifier's kid, or the
configured leaf's under a relying-party policy (section 6). The verdict ID is computed like a receipt ID: SHA-256 of
deterministic CBOR `['AAR-VERDICT-ID-v1', exact-protected-bstr,
verdict-id-input]`.

```cddl
verdict-envelope = [
  payload: bstr .cbor verdict,
  signature: bstr .cbor verdict-cose-sign1,
]

verdict-cose-sign1 = [
  protected: bstr .cbor verdict-protected,
  unprotected: {},
  payload: nil,
  signature: bstr .size 64,
]

verdict-protected = {
  1: -7,
  3: "application/aar-verdict+cbor;v=0.3",
  4: bstr .size 32,
}

verdict = {
  verdict_id: bstr .size 32,
  verdict-fields
}

verdict-id-input = { verdict-fields }

verdict-fields = (
  v: 5,
  evaluated_at: uint .le 9007199254740991,
  result: "conformant" / "nonconformant" / "indeterminate",
  ? reason: tstr .size (1..128),
  bundle_digest: bstr .size 32,
  selector_commitment: bstr .size 32,
  verifier: verifier-identity,
  trust_policy: verdict-trust-policy,
  scope: verdict-scope,
  limits: verdict-limits,
  observations: [ 0*64 (
      "duplicate_exact"
    / "valid_prefix"
    / "producer_declared_complete"
    / "ingress_completeness_not_established"
    / "membership_only"
    / "anchor_existence_order_only"
    / "refused_pre_dispatch"
    / "degraded_dispatch"
    / "mediator_countersigned"
    / "untrusted_origin_declared_in_action_ancestry"
  ) ],
)

verifier-identity = {
  product: tstr .size (1..128),
  version: tstr .size (1..64),
  build_digest: bstr .size 32,
  config_digest: bstr .size 32,
  limits_digest: bstr .size 32,
}

verdict-trust-policy = {
  trust_store_snapshot_id: bstr .size 32,
  trust_store_digest: bstr .size 32,
  verifier_policy_digest: bstr .size 32,
  evaluation_time: uint .le 9007199254740991,
  anchor_heads_digest: bstr .size 32,
  replay_state_digest: bstr .size 32,
  prior_emissions_digest: bstr .size 32,
  relying_party_policy_digest: bstr .size 32,
}

verdict-scope = {
  tenant_id: bstr .size 16,
  site_id: bstr .size 16,
  committed_from: uint .le 9007199254740991,
  committed_until: uint .le 9007199254740991,
  receipt_kinds: [ 1*6 (
      "observation" / "inference" / "authorization"
    / "action_attempt" / "dispatch" / "outcome_observation"
  ) ],
  coverage: "valid_subset" / "complete",
  ingress_completeness:
      "not_established" / "census_supported" / "reconciliation_supported",
}

verdict-limits = {
  requested_profile: "AAR-1" / "AAR-2" / "AAR-2A" / "AAR-3",
  evaluated_profile: "AAR-1" / "AAR-2" / "AAR-2A" / "AAR-3" / "below_AAR-1",
  maximum_time_class:
      "asserted" / "boot_bound" / "externally_anchored" / "not_evaluated",
  maximum_provenance_class:
      "self_asserted" / "proxy_captured" / "provider_attested" / "not_evaluated",
  maximum_outcome_level:
      "accepted" / "dispatched" / "device_acknowledged"
    / "independently_sensed" / "contradicted" / "unknown" / "not_evaluated",
  technical_integrity: "satisfied" / "not_satisfied" / "not_evaluated",
  source_authenticity: "not_established",
  custody_continuity: "not_established",
  discovery_completeness: "not_established" / "producer_declared_only",
  legal_admissibility: "not_established",
  input_origin_ancestry:
      "not_evaluated" / "not_declared" / "partially_declared" / "declared_only",
  control_path_completeness: "not_established",
}
```

A v0.2.3 verifier MUST NOT emit an `input_origin_ancestry` value stronger than
`declared_only`. `declared_only` means every declaration slot examined by the
step-13 ancestry traversal contained an emitter-supplied origin label; it
establishes neither label accuracy, complete capture of inputs, actual
consumption, nor causal influence (D-78). Origin declarations are relayed, not
checked against prompt, retrieval or tool manifest bytes (D-32). A failure
verdict carries `not_evaluated`.

A v0.2 verifier MUST emit `custody_continuity="not_established"` for every
result. Receipt signatures, anchors, and mediator countersignatures do not
establish custody continuity. A positive custody value requires a future
normative decision defining custody evidence and its validation.

A v0.2 verifier MUST emit only `not_established` for `ingress_completeness`.
`census_supported` and `reconciliation_supported` are reserved for the later
R-15/census feature and MUST NOT be emitted by a verifier that does not implement
that feature.

A v0.3 verifier MUST emit `control_path_completeness="not_established"` for
every result (D-84). AAR covers only actions that traverse the instrumented
enforcement point; an action dispatched around it (a VMS console, a vendor
application, physical access to the device) produces no receipt, and no
receipt, anchor, census or countersignature establishes that none occurred.
`coverage: complete` and every `ingress_completeness` value describe actions
that went through the enforcement point and say nothing about this field. A
positive value requires a future normative decision defining control-path
evidence and its validation.

The v0.2.1 verdict used `v: 3` because its closed trust-policy map gained a
required key (D-76). The v0.2.3 verdict used `v: 4` because `verdict-limits`
gained the required key `input_origin_ancestry` (D-78). The v0.3.0 verdict
uses `v: 5` because `verdict-trust-policy` gained
`relying_party_policy_digest` (D-83) and `verdict-limits` gained
`control_path_completeness` (D-84); its protected content type names the
v0.3 line because a policy-mode signer cannot be resolved from the bundle
(section 6), while every bundle artifact keeps its v0.2 content type. A v2,
v3 or v4 consumer must not silently accept this verdict. The v0.3.1 verdict
keeps `v: 5` and this content type; v0.3.1 changes only step 9's precedence
and history comparisons (D-86).

`relying_party_policy_digest` is the SHA-256 of deterministic CBOR
`["AAR-RP-POLICY-v1", relying-party-policy]` whenever a relying-party policy
was supplied, at every failing step including steps 1 to 3 (configuration is
complete before the first bundle byte is read), and 32 zero bytes only when
no policy was supplied. No supplied policy uses a zero digest (the D-51
absence discipline).

The verdict digest preimages are frozen as follows:

- `limits_digest = SHA-256(deterministic-CBOR(["AAR-VERDICT-LIMITS-v1",
  limits-map]))`, where `limits-map` is the closed map containing the twelve
  section 1 values under these keys:
  `exact_encoded_bundle_bytes`, `cbor_container_nesting`, `receipt_nodes`,
  `directed_graph_edges`, `parents_per_receipt`, `dag_depth`, `dag_width`,
  `encoded_proof_bytes`, `aggregate_proof_bytes`, `epoch_manifest_entries`,
  `merkle_batch_leaves`, and `credential_path_length`;
- `anchor_heads_digest =
  SHA-256(deterministic-CBOR(["AAR-VERDICT-HEADS-v1",
  expected-anchor-heads]))`, using the exact decoded, already validated and
  canonically ordered expected-head array;
- when replay state is supplied, `replay_state_digest =
  SHA-256(deterministic-CBOR(["AAR-VERDICT-REPLAY-v1", replay-state-map]))`.
  `replay-state-map` is the closed map `{ entries: [...] }`; each entry is the
  closed map `{ replay_domain, invocation_id, content_digest }`, and entries are
  strictly sorted by deterministic CBOR of
  `[replay_domain, invocation_id, content_digest]`. When no replay state was
  supplied, `replay_state_digest` is 32 zero bytes rather than the digest of an
  empty map;
- when prior state is supplied, `prior_emissions_digest =
  SHA-256(deterministic-CBOR(["AAR-VERDICT-PRIOR-v1", prior-emissions-map]))`.
  `prior-emissions-map` is the closed map `{ entries: [...] }`; each entry is
  the closed map `{ issuer_kid: bstr .size 32, issuer_seq: uint,
  epoch_owner_kid: bstr .size 32, epoch_id: uint, epoch_seq: uint,
  receipt_id: bstr .size 32, envelope_digest: bstr .size 32 }`. Entries are
  strictly sorted and unique by deterministic CBOR of `[issuer_kid, issuer_seq,
  epoch_owner_kid, epoch_id, epoch_seq, receipt_id, envelope_digest]`.
  Duplicate or unsorted `prior_emissions` in a supplied prior-state file is a
  usage error, as are two entries with the same `receipt_id` and
  `envelope_digest` but different coordinates and, detected at step 9 before
  phase A, an entry whose `receipt_id` and `envelope_digest` equal a carried
  receipt's but whose coordinates differ from that receipt's (D-86); a usage
  error produces no verdict. The digest always covers the supplied entries
  exactly as given, never a subset step 9 exempts or filters. Supplying a file
  whose `prior_emissions` is empty or absent binds
  the digest of `{ entries: [] }`. When no prior state was supplied,
  `prior_emissions_digest` is 32 zero bytes. No supplied prior state uses a zero
  digest (the D-51 absence discipline, extended by D-76).

`build_digest` and `config_digest` have implementation-defined preimages. An
implementation MUST keep each value stable for one released build or effective
configuration and MUST document its selected preimage; these fields bind verifier
identity and are not interoperability digests.

A `nonconformant` or `indeterminate` verdict is populated by this table and
nothing else (D-82). The normative early-failure sentinel is: every unknown ID,
digest, and numeric scope/trust time all-zero; `receipt_kinds=["observation"]`,
`coverage="valid_subset"`, `ingress_completeness="not_established"`, and the
requested profile `AAR-1`.

| Field | Population on a failure verdict |
|---|---|
| `scope` (`tenant_id`, `site_id`, `committed_from`, `committed_until`, `receipt_kinds`, `coverage`), `limits.requested_profile`, `selector_commitment` | The decoded bundle values once step 3 has succeeded as a whole; else the sentinel. |
| `trust_policy.trust_store_digest`, `trust_store_snapshot_id`, `verifier_policy_digest`, `anchor_heads_digest` | The validated values once step 5 has succeeded as a whole; else the sentinel. |
| `trust_policy.evaluation_time`, `evaluated_at` | Always the caller's explicitly supplied time. |
| `trust_policy.replay_state_digest`, `prior_emissions_digest` | Always the digest of the supplied input (an empty supplied state binds the digest of an empty map); all-zero only when nothing was supplied. |
| `trust_policy.relying_party_policy_digest`, the protected `kid` | Always the supplied policy's digest and the configured leaf's kid when a policy was supplied, at every step; the zero digest and the corpus verifier's kid only when none was (D-83). |
| `limits.control_path_completeness` | `not_established` (D-84). |
| `limits.evaluated_profile` | `below_AAR-1`. |
| `limits.technical_integrity` | `not_evaluated` when the failing step is 1 to 5; `not_satisfied` from step 6 on. |
| `limits.discovery_completeness` | `not_established`. |
| `limits.maximum_time_class`, `maximum_provenance_class`, `maximum_outcome_level`, `input_origin_ancestry` | `not_evaluated`; aggregates computed at step 19 are discarded on a later failure. |
| `observations` | Empty. |

A requested scope, profile, or trust value explicitly configured at the verifier
replaces only its corresponding sentinel. The shape of `trust_inputs` (snapshot,
root records, expected anchor heads) is part of the step-3 bundle schema in both
verifiers; step 5 validates its content.

`reason` MUST be absent for `conformant` and MUST be exactly one section 3 code for
`nonconformant` or `indeterminate`. A `conformant` verdict MUST carry a fully
populated, non-sentinel `scope`, `trust_policy`, and `evaluated_profile`
recomputed from the evaluated bundle; the all-zero early-failure sentinels of
section 5 appear only with a `nonconformant` or `indeterminate` result. A
verifier that cannot populate a real scope MUST NOT return `conformant`.
`conformant` means only that the artifacts in
the signed scope satisfy the stated profile and class limits under the exact bound
build, configuration, trust policy, expected heads, evaluation time, replay state,
and resource limits. Evidence class limits mean declared and structurally
supported, with required opaque bytes committed; they do not claim deep
cryptographic validation of attestation content. A conformant verdict is not a
statement of sensor truth, inference correctness, lawfulness, complete discovery,
custody, admissibility, or control-path completeness.

## 6. Relying-party policy (D-83)

A relying party (the operator of a verifier who is not the producer) MAY
supply one `relying-party-policy` (`aar-core.cddl`) and one signing key out
of band. Neither is ever carried in a bundle, sourced from a platform trust
store, or installed into one (D-58).

**Configuration precedes the bundle.** Before any bundle byte is read, the
verifier MUST validate: the policy's closed map (`v` is the integer 1; a
boolean is not an integer), its strictly sorted and
unique `artifact_roots` (by `root_kid`; one tenant per root) whose every
record has strictly sorted and unique `allowed_sites` and `allowed_key_usages`
of the step-3 `trust-root` shape, and `verifier_credentials` (by
`credential_id`); every `path` element of every configured credential is a
32-byte byte string before it is looked up; the signer contract (the
supplied key's SPKI hashes to exactly one `verifier_credentials[].subject_kid`;
that credential is the leaf); and the leaf's chain at the supplied evaluation
time: each member decodes as deterministic CBOR under the credential
production with protected content type `application/aar-credential+cbor;v=0.2`,
recomputes its `credential_id`, carries a P-256 SPKI hashing to its
`subject_kid`, has all-zero `tenant_id` and `site_id`, and is valid at the
evaluation time under the 6.7.7 boundary rule; the leaf has
`key_usage = "verifier_signing"`, `principal_role = "verifier"` and a
non-empty `path`; the path resolves entry by entry, each entry's
`subject_kid` equalling the previous member's `issuer_kid`, each issuer's own
`path` equalling the remaining suffix, no `credential_id` or `subject_kid`
repeating, at most 8 entries; every member except the leaf has
`key_usage = "credential_issuing"`; every member's protected kid equals its
`issuer_kid` and its signature verifies under the issuer's carried SPKI; the
terminal member is self-signed with `subject_kid`, `issuer_kid` and protected
kid all equal to `verifier_root_kid`; and `verifier_credentials` is exactly
the leaf plus the credentials its path names. The credential checks are the
closed-map, type, enum and size checks of steps 3 and 6 applied to a
configured credential; the release CDDL oracle is the authority for full
membership. Any failure is a usage error with no verdict, never a signed
result.

**Key contract.** The signing key is one file holding 64 lowercase
hexadecimal characters, the P-256 private scalar `d` with `1 <= d < n`,
optionally followed by one LF or CRLF and nothing else (no other whitespace,
no byte-order mark). The
verifier derives the SPKI and `kid = SHA-256(SPKI)`. Policy and key MUST be
supplied together; either alone is a usage error. Signing follows the
verdict rule above (deterministic RFC 6979 ES256, low-S, P1363).

**Key hygiene.** A policy whose chain contains any kid of the published
fixture keys (the frozen set in `pyref/crypto.py` and `harness/testkeys.ts`)
is a usage error. The `rp-*` corpus signs with a separate published
relying-party fixture key pair, which this exclusion does not cover. Neither
set is an operational verifier identity; passing the exclusion establishes
nothing about the operator's key.

**Effect on evaluation.** Steps 5, 8 and 20 above state the separation,
ceiling and signer rules; every other step is unchanged. Artifact acceptance
is monotone (a bundle that fails a producer or artifact check without a
policy fails it with one); identity is not: a bundle with no verifier
credential, and a bundle whose carried corpus-verifier credential is revoked
but signs nothing, can each be `conformant` under a policy (D-83 part 6).

**Distinguishability (conformant verdicts only).** Without a policy the
protected `kid` appears among the bundle's credential `subject_kid`s and
`relying_party_policy_digest` is zero; with one, the `kid` is the policy
leaf's, the digest is nonzero, and no carried credential has that kid. A
consumer resolves a policy-mode signer from the policy, never from the
bundle; the reader's package is bundle + policy + verdict. Early failures and
separation failures carry no such guarantee.

## Appendix A. Informative RATS EAR/AR4SI verdict cross-map

This appendix is informative. It does not add fields, validation steps, reason
codes, or claims to the v0.2 signed verdict. It follows the two-axis vocabulary
in [Hardware-rooted attestation for AI-agent evidence](https://arxiv.org/abs/2608.00801):
authorisation is `Authorised`, `Unauthorised`, or `Indeterminate`, while the
platform appraisal is `Attested`, `Contested`, or `Expired`. It uses
[EAR](https://datatracker.ietf.org/doc/draft-ietf-rats-ear/) as the carrier and
the [AR4SI trustworthiness vector](https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/)
as the platform-appraisal vocabulary. EAR and AR4SI are Internet-Drafts at this
pin, so their field names and tiers may change.

The cross-map applies only to an action-bearing AAR-2A or AAR-3 scope. An AAR
`conformant` result establishes that the carried artifacts satisfy AAR’s
declared profile under the bound verifier policy; it does not itself appraise a
TPM, measured boot, model artifact, or runtime. For `nonconformant`, only an
authorization-specific reason such as `delegation/expired`, `delegation/scope`,
or `graph/dominator-missing` supports `Unauthorised`; other failures leave that
axis `Indeterminate`. `maximum_outcome_level` is likewise not a platform
appraisal. In the table, “Attested” means that a fresh EAR binds the exact AAR
outcome commitment and has all relying-party-required AR4SI facets in the
Affirming range with no disqualifying facet Contraindicated; “Contested” means
a relevant facet is Contraindicated; “Expired” means the nonce, timestamp,
epoch, or EAR expiry fails the relying party’s freshness policy. Missing AR4SI
facets make no claim about those facets.

The two-axis column is the result after the EAR condition in the last column
has been met. Without that separate appraisal, the platform axis is unmapped;
the AAR result and outcome label alone do not produce `Attested`, `Contested`,
or `Expired`.

| AAR signed result | `maximum_outcome_level` | Two-axis result after appraisal | EAR/AR4SI trust vector | What the opaquely carried attestation would need to say to move the cell |
|---|---|---|---|---|
| `conformant` | `accepted` | Authorised × Attested | required facets Affirming; none disqualifying Contraindicated | A fresh EAR would need to bind the accepted action’s exact outcome commitment and appraise the required platform facets as Affirming. |
| `conformant` | `dispatched` | Authorised × Attested | required facets Affirming; none disqualifying Contraindicated | A fresh EAR would need to bind the exact dispatch/outcome commitment, not merely the earlier authorization or request. |
| `conformant` | `device_acknowledged` | Authorised × Attested | required facets Affirming; none disqualifying Contraindicated | A fresh EAR would need to bind the acknowledged outcome hash and identify the appraised platform that produced that acknowledgment. |
| `conformant` | `independently_sensed` | Authorised × Attested | required facets Affirming for each relied-on attester; none disqualifying Contraindicated | A composite or otherwise scoped EAR would need to appraise the runtime and the distinct outcome observer while preserving AAR’s failure-domain separation. |
| `conformant` | `contradicted` | **★ Authorised × Contested** | at least one relevant facet Contraindicated | The cell could move to Attested only through a fresh appraisal that resolves the contradiction under relying-party policy; another opaque success assertion cannot erase the AAR contradiction. |
| `conformant` | `unknown` | Authorised × Expired only when freshness explains `unknown`; otherwise platform axis unmapped | vector not current when freshness fails | The cell could move to Attested only if a fresh nonce-bound EAR binds the outcome commitment and the AAR evidence separately resolves `unknown`. |
| `nonconformant` | `accepted` | (Unauthorised for an authorization-specific reason, otherwise Indeterminate) × Attested | required facets may be Affirming independently of the AAR failure | An EAR could establish platform state, but it would also need distinct valid authorization evidence to move the authorization axis and cannot change the AAR result. |
| `nonconformant` | `dispatched` | (Unauthorised for an authorization-specific reason, otherwise Indeterminate) × Attested | required facets may be Affirming independently of the AAR failure | An EAR could bind the dispatch to an appraised platform, but only repaired AAR authorization evidence could move the first axis. |
| `nonconformant` | `device_acknowledged` | (Unauthorised for an authorization-specific reason, otherwise Indeterminate) × Attested | required facets may be Affirming independently of the AAR failure | An EAR could bind the acknowledgment and appraise its platform, but it cannot convert malformed or unauthorized AAR evidence into a conformant verdict. |
| `nonconformant` | `independently_sensed` | (Unauthorised for an authorization-specific reason, otherwise Indeterminate) × Attested | required facets may be Affirming for each attester independently of the AAR failure | An EAR could appraise both attesters, but the authorization defect and AAR observer-qualification checks would still need independent repair. |
| `nonconformant` | `contradicted` | (Unauthorised for an authorization-specific reason, otherwise Indeterminate) × Contested | at least one relevant facet Contraindicated | A fresh EAR could move only the platform axis by resolving the contradiction; authorization remains Unauthorised or Indeterminate from the AAR reason. |
| `nonconformant` | `unknown` | (Unauthorised for an authorization-specific reason, otherwise Indeterminate) × Expired only when freshness explains `unknown` | vector not current when freshness fails | A fresh EAR could replace an expired platform appraisal, but separate AAR evidence must resolve both `unknown` and the nonconformance. |
| `indeterminate` | `accepted` | Indeterminate × Attested | required facets may be Affirming despite missing AAR trust input | An EAR could establish platform state, but the missing AAR key, head, replay state, or policy input must be supplied before the authorization axis can move. |
| `indeterminate` | `dispatched` | Indeterminate × Attested | required facets may be Affirming despite missing AAR trust input | A fresh EAR would need to bind the exact dispatch, while the missing AAR trust input would still have to be supplied separately. |
| `indeterminate` | `device_acknowledged` | Indeterminate × Attested | required facets may be Affirming despite missing AAR trust input | A fresh EAR would need to bind the device acknowledgment, while AAR’s unresolved external input continues to hold the first axis Indeterminate. |
| `indeterminate` | `independently_sensed` | Indeterminate × Attested | required facets may be Affirming for each attester despite missing AAR trust input | A scoped appraisal of both runtime and observer could move the platform axis, but it cannot supply AAR’s missing trust-policy input by implication. |
| `indeterminate` | `contradicted` | Indeterminate × Contested | at least one relevant facet Contraindicated | The cell could move to Attested only if a fresh appraisal resolves the platform contradiction and the missing AAR trust input is evaluated separately. |
| `indeterminate` | `unknown` | Indeterminate × Expired only when freshness explains `unknown`; otherwise platform axis unmapped | vector not current when freshness fails | A fresh nonce-bound EAR could replace the expired appraisal, but AAR must still resolve `unknown` and the input that made the verdict indeterminate. |

The marked `(Authorised, Contested)` cell is deliberate: valid authority and
a disputed platform or outcome are compatible facts. An implementation must
not collapse that cell into either “authorized, therefore trusted” or
“contested, therefore unauthorized.” Because v0.2 carries attestation bytes
opaquely under D-49, reaching any platform term in this appendix requires a
separate RATS appraisal; the core AAR verifier does not emit it.
