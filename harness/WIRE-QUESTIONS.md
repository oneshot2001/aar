# Gate-2 wire questions

The harness does not change or extend the gate-1 contract. The following points
need an explicit gate disposition before a later semantic verifier can treat the
affected values as content-derived.

1. **No preimage is specified for several primary IDs.** `delegation_id`,
   `credential_id`, `snapshot_id`, `rotation_id`, `event_id`, `anchor_id`, and
   `batch_id` are fixed-size fields and bundle sort keys, but neither
   `aar-core.cddl` nor `CONFORMANCE.md` defines a hash preimage for them. Positive
   KATs therefore use deterministic opaque IDs derived from harness labels. The
   self-check recomputes only IDs and commitments whose normative preimages are
   defined by the contract.

2. **`previous_event_digest` has no byte target.** The epoch chain requires the
   field but does not say whether it hashes the prior event payload bstr, complete
   envelope bytes, event object re-encoding, or `event_id`. The KAT uses SHA-256
   of the exact preceding event payload bstr and records that convention only as
   harness metadata, not as a new wire rule.

3. **`manifest_digest` in an anchor record has no preimage rule.** The manifest
   already has a normative content-derived `manifest_id`; the distinct anchor
   `manifest_digest` is not defined. The KAT uses SHA-256 of the exact epoch
   manifest payload bstr.

4. **Signer key usage is not stated for epoch events, epoch manifests, or Merkle
   batches.** The signer matrix names the other artifact types. The KAT uses the
   EP signing key for these producer journal artifacts.

5. **Credential objects carry no public-key material.** `subject_kid` commits to
   an SPKI, but the SPKI itself is absent. Verification therefore requires an
   out-of-band key registry even when the credential is carried in a bundle. The
   harness descriptor identifies the fixed test key used for each signature.
