# Gate 2, slice A — Claude review + wire-question rulings
2026-07-14. Reviewed: harness/ + kats/positive/ at b72ab49 against the rubric
KAT bar. Verification re-run independently: `bun test harness` 5/5 (166
assertions), `bun run generate` reproduces 33 KATs byte-identically,
`bunx tsc --noEmit` clean. **Slice A ACCEPTED.** The five WIRE-QUESTIONS.md
findings are real contract gaps; rulings below amend the gate-1 wire contract
(pre-freeze, so no version bump). KATs affected by WQ-1/WQ-5 regenerate in the
fix pass.

## Rulings on WIRE-QUESTIONS.md

**WQ-1 — primary-ID preimages: DEFINE ALL SEVEN.** Bundle sort keys must be
content-derived, or ID substitution is undetectable. Extend the receipt-ID
pattern uniformly: for each signed artifact,
`<id> = SHA-256(deterministic-CBOR(["AAR-<TYPE>-ID-v1", claims-without-<id>]))`
over the payload/claims map with its own ID field absent —
`AAR-DELEGATION-ID-v1`, `AAR-CREDENTIAL-ID-v1`, `AAR-STATUS-ID-v1`,
`AAR-ROTATION-ID-v1`, `AAR-EPOCH-EVENT-ID-v1`, `AAR-ANCHOR-ID-v1`,
`AAR-BATCH-ID-v1`. (No protected-bstr term for these — unlike receipts, their
envelopes carry no AAR coordinate labels; the kid inside claims/binding
suffices.) Add `identity/artifact-id-mismatch` reason code + recompute step in
validation order step 7. Harness must COMPUTE these from now on.

**WQ-2 — `previous_event_digest`: ADOPT the harness convention as normative.**
SHA-256 of the exact preceding epoch-event **payload bstr** (the signed
bytes). Add one sentence to CDDL comment + CONFORMANCE step 14 recompute +
reuse `epoch/event-chain` code on mismatch.

**WQ-3 — anchor `manifest_digest`: ADOPT as normative.** SHA-256 of the exact
epoch-manifest **payload bstr**. This deliberately differs from `manifest_id`
(content-derived): the digest pins the exact signed bytes, the id pins the
content. State both sentences; recompute in step 17 under
`anchor/manifest-binding`.

**WQ-4 — journal signer usage: EP signs its journal.** Epoch events, epoch
manifests, and Merkle batches are signed with `ep_signing`, and the signing
kid MUST equal `epoch_owner_kid`. For Merkle batches, which carry both
`epoch_owner_kid` and `signer_kid`, `signer_kid` MUST equal `epoch_owner_kid`
in v0.2 — the separate field stays only as a seam for a future
delegated-journal profile. Extend the
CONFORMANCE §2.1 key-usage paragraph; violations = existing
`receipt/signer-role-mismatch` is receipt-scoped, so add
`credential/usage-mismatch` as the firing code (it already covers "signed
object/role" — extend its trigger text to name journal artifacts explicitly).

**WQ-5 — credentials MUST carry the SPKI: ACCEPT as wire change.** Add
`public_key: bstr .size (1..256)` (DER SubjectPublicKeyInfo) to
`credential-profile-object`. Verifier requires `SHA-256(public_key) ==
subject_kid` (new code `credential/kid-key-mismatch`) and uses this key —
bundles become verifiable fully offline, which is the product premise.
`key/not-found` keeps its trigger for external keys (e.g. trust-root kids
without carried credentials).

## WQ-1 reruling (2026-07-14, after Codex circularity objection — sustained)
As first stated, WQ-1 was circular twice: `batch_id = H(claims incl. root)`
while every Merkle leaf includes `batch_id`; and credential `path` includes
the credential's own ID. Corrected rulings:

- **WQ-1a (Merkle):** the leaf-hash preimage EXCLUDES `batch_id` (keeps
  tenant/site/epoch_id/tree_size/leaf_index/item_digest — context binding
  that blocks cross-epoch/-tenant transplant is preserved). Computation
  order: leaves → root → `batch_id = H(["AAR-BATCH-ID-v1",
  claims-without-batch_id])`. The membership proof still carries `batch_id`;
  the verifier requires proof.batch_id == signed batch's computed batch_id
  AND leaf context fields equal the batch's. Same-root/same-epoch proof
  portability between two batches signed by the same EP is accepted —
  claims are `membership_only`.
- **WQ-1b (credential):** `path` is the ordered ISSUER chain from immediate
  issuer to root, EXCLUDING the subject credential itself.
  `credential_id = H(["AAR-CREDENTIAL-ID-v1", claims-without-credential_id])`
  is then well-defined. A credential issued directly by a trust root has
  path length 1; a self-signed root credential uses an empty path (CDDL
  becomes `0*8`) and is accepted only via the trust store. Pin this rule in
  the CDDL comment.

## Fix-pass scope (slice A.1)
1. Apply WQ-1..WQ-5 to `spec/aar-core.cddl` + `spec/CONFORMANCE.md` (preimage
   comments, two digest sentences, journal-usage paragraph, `public_key`
   field, 2 new reason codes + trigger-text extension, validation-order
   recompute hooks). Record all five as D-37..D-41 in DECISIONS.md.
2. Update harness generators accordingly (compute the seven artifact IDs,
   emit `public_key`, keep WQ-2/WQ-3 conventions now blessed), regenerate
   kats/positive/, keep `bun test` green and extend the self-check to
   recompute the seven artifact IDs.
3. Delete harness/WIRE-QUESTIONS.md content and replace with a pointer to
   this ruling (questions closed).

Slices B (negative fixtures per reason code) and C (class-boundary +
adversarial graph/epoch fixtures) remain queued behind A.1.
