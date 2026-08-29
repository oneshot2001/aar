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
   that order.
3. **Bundle schema.** Check the closed top-level map, `v`, required fields, field
   types, fixed-size values, enums/ranges, and sorted/unique
   arrays, in that order. Occurrence ceilings listed as section 1 resource limits
   are deferred to step 4 so their `resource/*` code is reachable. Check
   `selector_commitment` last within this step.
4. **Static resource counts.** Check artifact counts, parent counts, total edge
   count, individual proof byte lengths, and aggregate proof bytes in that order.
5. **Trust-policy input.** Validate the trust-store snapshot digest, root records,
   tenant/site scopes, evaluation time, expected anchor heads, and policy digest.
6. **Envelope mechanics.** For each signed object, in this artifact order —
   credentials, rotation records, status snapshots, request envelopes,
   delegations, epoch events, epoch manifests, anchor records, Merkle batches,
   then receipts (including any nested signed presentation manifest) — perform:

   1. decode the untagged four-element COSE array and require deterministic CBOR;
   2. require protected to be a bstr containing a closed deterministic map;
   3. require protected `alg=-7`, the exact content type for the payload, and a
      32-byte `kid`; for receipts also require all provisional AAR labels;
   4. require the unprotected map to be empty and payload to be `nil`;
   5. classify signature encoding length-first, require 64-byte P1363, nonzero
      `r,s`, and low-S;
   6. decode the detached payload bytes under step 2's CBOR rules, then validate
      its selected closed schema;
   7. resolve a P-256 verification key through the accepted credential path,
      require `SHA-256(public_key) == subject_kid`, use that carried SPKI for
      verification, and enforce key usage, tenant/site scope, validity, and
      status; a request envelope requires `agent_signing` usage;
   8. compare protected receipt coordinates to payload coordinates;
   9. reconstruct COSE `Sig_structure` from the received protected and payload
      bytes and verify ES256.

7. **Content commitments and IDs.** Note (GATE3 F3): artifact IDs bind
   content, not signer — reference-by-ID resolves to the carried artifact,
   whose signature is independently validated at use (the credential check
   re-validates the token's signer for its role); revisit signer-in-preimage
   only if a multi-signer delegation model appears. Recompute every content-derived ID and every
   declared digest whose bytes are present. Recompute `delegation_id`,
   `credential_id`, `snapshot_id`, `rotation_id`, `event_id`, `anchor_id`, and
   `batch_id` from their domain-separated deterministic-CBOR claims with their
   own ID field absent; a mismatch is `identity/artifact-id-mismatch`. For a
   referenced canonical manifest,
   first require a payload with the declared digest and media type, then hash it.
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
   `standing_condition_trigger` roots remain commitment-only.
8. **Credential lifecycle.** Enforce role-key separation; path construction;
   tenant-scoped roots; and rotation predecessor/successor continuity and monotonic
   sequence. Then, for EVERY carried status snapshot — whether or not any decision
   references it — evaluate its content in this order: lease maxima
   (`credential/lease-too-long`), status freshness (`credential/status-stale`),
   revocation (`credential/revoked`), compromise time (`credential/compromised`),
   unknown status (`credential/status-unknown`), and the lease validity window
   (`credential/not-yet-valid`, `credential/lease-expired`). Only after every
   carried snapshot passes are decision `status_snapshot_ids` references resolved;
   an unresolved reference is `credential/status-missing`. Content defects MUST
   fire before reference-resolution failures so a producer cannot mask a revoked
   or compromised stapled snapshot behind a dangling reference (D-52). The
   numeric maxima are: AAR-1/AAR-2 status age and lease 86,400 seconds; AAR-2A/
   AAR-3 status age 300 seconds and lease 3,600 seconds. All profiles use a maximum
   86,400-second anchor cadence.
   Lease duration is `status_snapshot.lease_not_after - lease_not_before`; use
   before/after that interval fails even if the credential validity is wider.
9. **Emission identity.** Sort observations by `(issuer kid, issuer_seq)` and by
   `(epoch owner kid, epoch_id, epoch_seq)`. Exact repeated envelope bytes are one
   duplicate observation and are coalesced with an informational verdict entry.
   The same `receipt_id` with different envelope bytes is identity reuse. One
   coordinate naming different IDs is equivocation. A decreasing issuer sequence
   or reused epoch sequence is rollback/equivocation. A gap is not itself a reject
   in a `valid_subset` bundle.
10. **Receipt schema semantics.** Require `kind`/body and kind/signer-role
    agreement; required evidence label presence; manifest field commitments;
    resolve every inference `consumption_manifest_id` to either the
    `manifest_digest` of a consumption manifest carried by a `derived_from`
    parent observation or the `digest` of a bundle
    `canonical-manifest-payload`, rejecting an unresolved reference with
    `receipt/consumption-ref-unresolved`;
    decision/presentation conditional fields and presentation signer mode;
    action-attempt/refusal conditional fields; reject an unknown `hazard_class`
    enum with `schema/enum-unknown`; require every
    `hazard_class="life_safety"` marker's normalized `action_name` to occur in
    the bound trust policy's optional `life_safety_action_names` list, otherwise
    reject with `receipt/hazard-class-unbound`; then degraded-marker constraints;
    normalized action/command agreement; and dispatch/outcome subject agreement,
    in that order. If no `life_safety_action_names` list is bound, every
    life-safety marker is unbound. `refusal_reason="journal/unavailable"` is valid
    only on a `not_dispatched` attempt. A `degraded` marker is valid only when its
    reason is `journal/unavailable`, the policy-bound normalized action carries
    `hazard_class="life_safety"`, and the attempt remains
    `eligible_for_dispatch`; every other marker combination is
    `receipt/attempt-disposition` (D-54, D-66).
11. **Replay and freshness.** Require `issued_at <= committed_at < expires_at`,
    exact intended-parent equality, invocation-ID consistency, unexpired leases,
    and no prior different use of a one-time `(replay_domain, invocation_id)`.
    An exact replay of identical bytes is a duplicate; changed content under the
    same one-time coordinate is rejected.
12. **Referential closure and graph.** Resolve every parent, require parent metadata
    to equal the resolved parent, enforce the edge matrix and root rules below,
    enforce cross-epoch rules, then enforce depth and width.
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
    resolve (D-53). For each dispatch in array order, after that dispatch's
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
14. **Epoch state machine.** Validate owner/event chains, monotonic epoch IDs and
    event sequences, predecessor manifest digest, one open and one close, duration,
    sequence span/count, immutable close, late-arrival routing, anchor deadline,
    and fork rules. Two distinct manifests for one owner/epoch are a fork.
    `previous_event_digest` is absent only on event sequence zero and otherwise
    MUST equal SHA-256 of the exact preceding epoch-event payload bstr; a mismatch
    is `epoch/event-chain`. A predecessor manifest digest is absent only on the
    first epoch known for that owner; later epochs require it.
15. **Manifest index.** Require, in this order: sort order
    (`manifest/index-order`), contiguous leaf indices (`manifest/index-gap`),
    unique receipt IDs/epoch sequences (`manifest/index-duplicate`),
    entry-to-receipt equality (`manifest/index-receipt-mismatch`), and equality
    of counts and sequence spans. Only after every entry-level requirement holds
    are the entry leaves and root recomputed and compared to the carried root;
    `manifest/index-root-mismatch` fires last (D-54).
16. **Merkle batches.** Recompute domain-separated leaf/node hashes with
    `batch_id` excluded from the leaf preimage; enforce proof batch ID against the
    signed batch's recomputed ID and enforce index, size, signer,
    tenant/site/epoch leaf context, and path length, then compare the root. Among
    successfully proven leaves carried in this bundle for one signed batch,
    reject two leaves at different indices that share
    `(tenant_id, site_id, epoch_id, item_digest)`. The verifier cannot make that
    duplicate claim about unproven leaves. A successful result is recorded only
    as membership.
17. **Anchors.** Verify target identity and plan membership, inclusion proof,
    optional consistency proof, manifest/epoch binding, and recompute
    `manifest_digest` as SHA-256 of the exact epoch-manifest payload bstr under
    `anchor/manifest-binding`; then verify submission deadline, expected-head
    match/freshness, and multi-target independence declaration. An anchor proves
    existence/order by time only.
18. **Bundle ranges and coverage.** Verify each range against the signed manifest
    index root; require contiguous leaf indices and correct left/right temporal
    boundaries; evaluate the selector; require every selected entry and its closed
    graph. Per D-19, a range's `entries` MUST carry every objective index entry in
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
    and a distinct accepted observer failure domain. v0.2 carries these bytes
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
    `nonconformant` with the first reason code.

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
manifest and anchor. Authorization, request, trigger, and attempt edges never cross
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
| `resource/node-count` | Receipt count exceeds 10,000. |
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
| `schema/unsorted-set` | A bundle selector set or bundle artifact array is not strictly in its prescribed order. |
| `schema/duplicate-entry` | A bundle selector set or bundle artifact array repeats an otherwise valid entry. |
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
| `identity/reuse` | One receipt ID names nonidentical envelope bytes relative to prior evaluated state. |
| `identity/coordinate-equivocation` | One issuer or epoch coordinate names different receipt IDs. |
| `identity/issuer-sequence-rollback` | Issuer sequence decreases relative to a prior committed receipt in evaluated state. |
| `identity/epoch-sequence-rollback` | Epoch sequence decreases or is reused within one owner/epoch. |
| `receipt/kind-body-mismatch` | Receipt `kind` does not select the supplied body production. |
| `receipt/signer-role-mismatch` | Receipt kind, protected/payload role, or required credential key usage violates the closed signer matrix. |
| `receipt/manifest-inconsistent` | Consumption, presentation, decision, or command manifest ordinals, counts, or cross-references disagree after direct byte/digest checks. |
| `receipt/consumption-ref-unresolved` | An inference `consumption_manifest_id` resolves to neither a `derived_from` parent observation's consumption-manifest digest nor a carried canonical-manifest-payload digest. |
| `receipt/decision-presentation` | Presentation presence or approver fields disagree with the decision enum. |
| `receipt/attempt-disposition` | `not_dispatched` lacks `refusal_reason`; `eligible_for_dispatch` carries one; `journal/unavailable` appears outside a `not_dispatched` refusal; or a `degraded` marker is not exactly the life-safety exception described at step 10. |
| `receipt/hazard-class-unbound` | A normalized action carries `hazard_class="life_safety"`, but its `action_name` does not occur in the bound trust policy's `life_safety_action_names` list, including when that optional list is absent. |
| `receipt/action-command-mismatch` | Normalized action and command action/target/parameter commitment disagree. |
| `receipt/dispatch-attempt-mismatch` | Dispatch does not name the command and attempt selected by `attempted_as`. |
| `receipt/outcome-subject-mismatch` | Outcome subject is not its `observed_outcome` dispatch/attempt parent. |
| `journal/unavailable` | Operational refusal reason: before an AAR-3 non-life-safety action-bearing send, neither the primary nor emergency journal can durably commit the `action_attempt`; the EP emits a `not_dispatched` attempt carrying this exact `refusal_reason`. This code never appears as a verifier verdict reason. |
| `journal/uncommitted-dispatch` | On an AAR-3 profile, a dispatch's linked attempt lacks the prior journal commitment defined at step 13 and is not the marked life-safety exception. |
| `credential/root-not-accepted` | Credential path ends at a root not accepted for the bound tenant/site. |
| `credential/path-invalid` | Path within its schema length is not a contiguous issuer/subject chain or contains a loop. |
| `credential/kid-key-mismatch` | SHA-256 of the credential's carried DER SubjectPublicKeyInfo differs from `subject_kid`. |
| `credential/usage-mismatch` | Credential key usage does not authorize the signed object/role, including an epoch event, epoch manifest, or Merkle batch not signed by its `epoch_owner_kid` with `ep_signing`, or a Merkle batch whose `signer_kid` differs from `epoch_owner_kid`. |
| `credential/not-yet-valid` | Evaluation or signing time precedes credential validity. |
| `credential/expired` | Evaluation or signing time is after credential validity. |
| `credential/status-missing` | A required stapled snapshot for the decision/key is absent. |
| `credential/status-stale` | Snapshot age exceeds 86,400 seconds for AAR-1/2 or 300 seconds for AAR-2A/3. |
| `credential/revoked` | Signing/use is at or after an effective revocation. |
| `credential/compromised` | Signing/use is at or after declared compromise time. |
| `credential/status-unknown` | A required status snapshot says `unknown`. |
| `credential/lease-too-long` | Issued lease exceeds 86,400 seconds for AAR-1/2 or 3,600 seconds for AAR-2A/3. |
| `credential/lease-expired` | Evaluation/use occurs after the lease expiry. |
| `credential/rotation-invalid` | Successor/predecessor ids or kids do not cross-bind. |
| `credential/rotation-rollback` | Rotation continuity sequence or effective time is non-monotonic. |
| `credential/role-key-reuse` | Agent, EP, or Authority Source resolve to the same signing kid. |
| `replay/not-yet-valid` | Receipt freshness `issued_at` is after its committed time/evaluation window. |
| `replay/expired` | Receipt committed/evaluated at or after `expires_at`. |
| `replay/parent-binding` | `intended_parents` is not exactly the ordered parent-id list. |
| `replay/invocation-mismatch` | Receipts in one action flow disagree on invocation ID or replay domain. |
| `replay/one-time-reused` | A one-time replay-domain/invocation coordinate was previously used for different content. |
| `delegation/not-yet-valid` | Attempt precedes delegation `not_before`. |
| `delegation/expired` | Attempt is at or after delegation `not_after`. |
| `delegation/scope` | Action, target, purpose, tenant, site, profile, or invocation is outside delegation scope. |
| `delegation/chain-invalid` | Parent delegation is missing, cyclic, expired, or grants less authority than its child. |
| `graph/dangling-parent` | A parent id cannot be resolved in the bundle when closure is required. |
| `graph/parent-metadata-mismatch` | Parent kind/tenant/site/epoch metadata differs from the resolved parent. |
| `graph/edge-illegal` | Edge parent-kind/child-kind pair is absent from the closed matrix. |
| `graph/root-missing` | A parentless allowed node lacks a root descriptor. |
| `graph/root-forbidden` | Node kind/root kind pair is unlisted, or a non-root carries `root`. |
| `graph/tenant-site-splice` | Parent and child have different tenant or site. |
| `graph/cross-epoch-forbidden` | Cross-epoch edge type/reason is unlisted or an unequal epoch lacks `cross_epoch`. |
| `graph/cross-epoch-unanchored` | Cross-epoch source is not earlier, closed, and bound to the named valid anchor/manifest. |
| `graph/dominator-missing` | Dispatch lacks its one exact dominating authorization/delegation path. |
| `graph/dominator-ambiguous` | More than one authorization or delegation dominates a dispatch. |
| `epoch/event-chain` | Event sequence or previous-event digest does not form one owner/epoch chain. |
| `epoch/id-nonmonotonic` | Epoch ID is not greater than its predecessor epoch ID. |
| `epoch/predecessor-mismatch` | Manifest predecessor digest differs from the prior accepted manifest. |
| `epoch/open-close` | Epoch lacks exactly one valid open followed by one valid close. |
| `epoch/duration-exceeded` | Close is more than 86,400 seconds after open. |
| `epoch/span-count-mismatch` | First/last sequence, item count, manifest count, or empty-padding rules disagree. |
| `epoch/late-insertion` | A receipt is inserted into a closed epoch instead of the next epoch with `late_for_epoch_id`. |
| `epoch/anchor-deadline` | Closed event does not set deadline to close+86,400, or its anchor-submitted event occurs after that declared deadline. |
| `epoch/fork` | Conflicting event chains or distinct manifests exist for one owner/epoch. |
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
- `empty_scope` (GATE3 F4): the bundle verified `conformant` over zero receipts
  matching the selector — the verdict asserts nothing about any receipt;
- `stateful_not_evaluated` (GATE3 F6): no prior evaluated state was supplied, so
  cross-evaluation sequence-rollback and one-time-reuse properties were NOT
  evaluated — they did not "pass." The verdict's `replay_state_digest` binds
  which state, if any, was used.

In v0.2, `empty_scope` and `stateful_not_evaluated` are REPORT-LAYER
observations: verifier tools MUST surface them in human/machine reports, but
they do not enter the signed verdict bytes (the D-51 verdict preimages are
frozen). Promoting them into the signed verdict is a wire-version decision.

## 5. W-12 signed machine-readable verdict

The verdict is deterministic CBOR in an untagged detached COSE_Sign1 using the same
ES256/P1363/low-S/RFC-6979 rules. Its protected map is exactly `{1:-7,
3:"application/aar-verdict+cbor;v=0.2",4:kid}`. The verifier key MUST have
`verifier_signing` usage. The verdict ID is computed like a receipt ID: SHA-256 of
deterministic CBOR `['AAR-VERDICT-ID-v1', exact-protected-bstr,
verdict-id-input]`.

```cddl
verdict-envelope = [
  payload: bstr .cbor verdict,
  signature: bstr .cbor verdict-cose-sign1,
]

verdict-cose-sign1 = [
  protected: bstr .cbor {
    1: -7,
    3: "application/aar-verdict+cbor;v=0.2",
    4: bstr .size 32,
  },
  unprotected: {},
  payload: nil,
  signature: bstr .size 64,
]

verdict = {
  verdict_id: bstr .size 32,
  verdict-fields
}

verdict-id-input = { verdict-fields }

verdict-fields = (
  v: 2,
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
  custody_continuity: "not_established" / "partially_evidenced",
  discovery_completeness: "not_established" / "producer_declared_only",
  legal_admissibility: "not_established",
}
```

A v0.2 verifier MUST emit only `not_established` for `ingress_completeness`.
`census_supported` and `reconciliation_supported` are reserved for the later
R-15/census feature and MUST NOT be emitted by a verifier that does not implement
that feature.

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
  empty map.

`build_digest` and `config_digest` have implementation-defined preimages. An
implementation MUST keep each value stable for one released build or effective
configuration and MUST document its selected preimage; these fields bind verifier
identity and are not interoperability digests.

If bundle decoding fails before scope or trust policy is known, the signed verdict
uses the normative early-failure sentinel: every unknown ID, digest, and numeric
scope/trust time is all-zero; `receipt_kinds=["observation"]`,
`coverage="valid_subset"`, `ingress_completeness="not_established"`, and the
requested profile defaults to `AAR-1`. The actual evaluation time remains in both
`evaluated_at` and `trust_policy.evaluation_time`. A requested scope, profile, or
trust value explicitly configured at the verifier replaces only its corresponding
sentinel. A decoded valid requested value is likewise used even when a later step
fails.

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
custody, or admissibility.

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
