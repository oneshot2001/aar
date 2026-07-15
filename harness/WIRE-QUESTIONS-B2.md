# Slice B2 wire questions

## B2-Q1 — `graph/cycle` is unreachable after receipt-ID validation

Step 7 requires every `receipt_id` to hash the receipt fields, including its
parent IDs. Step 12 then asks the verifier to reject cycles. A self-cycle requires
an ID that is a fixed point of its own hash preimage; a multi-node cycle requires
the same circular fixed-point construction across all member IDs. Without a
SHA-256 break, no negative fixture can pass step 7 and reach `graph/cycle`.

**Needed ruling:** either move cycle detection before content-derived receipt-ID
validation, define a non-content-addressed graph reference for this check, or
delete `graph/cycle` as unreachable under the current validation order.

## B2-Q2 — `merkle/duplicate-leaf` conflicts with `leaf_index` in the leaf

The canonical `merkle-leaf` includes `leaf_index`, and step 16 requires the proof
index to equal that leaf index before duplicate detection. Therefore the same
canonical leaf cannot occur at two different valid indices. Changing the index
changes the canonical leaf; retaining it fails `merkle/batch-binding` first.

**Needed ruling:** define duplicate identity over the index-less leaf content
(for example tenant/site/epoch/item digest), remove `leaf_index` from the leaf
hash preimage, or delete `merkle/duplicate-leaf`.

## B2-Q3 — evidence attestation IDs have no verifiable artifact production

`boot_attestation_id`, `capture_attestation_id`,
`provider_attestation_id`, and `qualifying_predicate_id` are digest references,
but `bundle-artifacts` defines no corresponding attestation or qualification
artifact. Step 19 requires a boot attestation, capture attestation, provider
signature, and named qualification predicate, yet a verifier can currently check
only identifier presence (plus the carried observer failure-domain value).

**Needed ruling:** add signed artifact productions and bundle arrays, or state
which existing signed object each ID resolves to and the exact digest/signature
binding. The current harness checks the strongest properties expressible on the
wire but cannot establish the named attestations cryptographically.

## B2-Q4 — a same-epoch `externally_anchored` receipt is self-referential

A receipt commits `evidence.time.anchor_id`; its receipt ID is then included in
the epoch manifest; the anchor ID commits the manifest ID/digest. Setting the
receipt's anchor ID therefore changes the receipt ID, manifest, and anchor ID
again. No finite construction produces the requested same-epoch class-boundary
positive KAT without a cryptographic fixed point.

**Needed ruling:** make the time anchor reference a prior epoch/checkpoint, add a
post-emission qualification artifact, or remove `anchor_id` from the receipt
identity preimage. The `boot_bound -> externally_anchored` lower/failing KAT is
present; the higher/satisfying KAT is withheld rather than using an unrelated
anchor.

## B2-Q5 — verdict digest preimages and pre-decode failure scope are unspecified

Section 5 requires `build_digest`, `config_digest`, `limits_digest`,
`anchor_heads_digest`, and `replay_state_digest` but defines no domain/preimage
for them. It also requires a complete verdict scope and trust-policy block when
steps 1–3 may prevent those inputs from being decoded.

The reference harness uses SHA-256 of deterministic CBOR for limits, expected
heads, and replay state; deterministic test build/config IDs; and valid zero/default
scope and trust values when the bundle cannot supply them. These choices are
deterministic test-harness conventions, not claimed wire rules.

**Needed ruling:** freeze each digest domain/preimage and define whether early
failure verdicts receive verifier-supplied requested scope/trust inputs or a
standard sentinel representation.
