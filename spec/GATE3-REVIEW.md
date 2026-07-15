# Gate 3 — adversarial review of the v0.2 release candidate
2026-07-14, at 1ba28d1. **Reviewer routing note:** the Codex finding pass was
blocked by OpenAI's cybersecurity content filter (reviewing a
signature/receipt security spec tripped the guard; 200k tokens, no report).
Defensive review of an evidence-integrity spec is authorized security work, so
Claude ran the finding pass directly and gates its own findings under the
discipline: **freeze only if every finding is fixed or explicitly deferred
with rationale.** Verified against `docs/spec-v0.1.1-requirements-draft.md`,
`docs/threat-model-v0.1.md`, and the full harness.

## Findings

**F1 — MAJOR (spec-hardening) — `conformant` is not normatively barred from
carrying sentinel scope/trust.** §2 step 20 says `conformant` requires every
check to pass; §5 defines all-zero sentinels for early-failure verdicts. But
no sentence forbids a `conformant` verdict from ALSO carrying sentinel scope,
trust-policy, or `evaluated_profile`. A reader keys off `result`; a
hostile-or-buggy conformant implementation could emit `conformant` + zeroed
scope and be technically schema-valid. **The reference verifier is correct**
(the conformant path `emitVerdict` builds scope from the real decoded bundle;
only `emitFailureVerdict` uses sentinels) — so this is a spec gap, not a code
bug. **Fix:** add a normative sentence to §5: a `conformant` verdict MUST
carry a fully populated, non-sentinel `scope`, `trust_policy`, and
`evaluated_profile`; sentinels appear only with `nonconformant`/
`indeterminate`. **FIXED this pass.**

**F2 — MAJOR (internal contradiction) — Merkle "proof portability" prose
contradicts the enforced `batch_id` equality check.** GATE2-SLICE-A-REVIEW's
WQ-1a text says "same-root, same-epoch proof portability between batches
signed by the same EP is accepted." But CONFORMANCE step 16 and the verifier
require `proof.batch_id == the signed batch's recomputed batch_id`. Two
batches sharing a root but differing in `created_at` have *different*
`batch_id`, so a proof is NOT portable — the prose and the check disagree,
which is exactly the "two conformant implementations diverge" class a freeze
must eliminate. Resolution: portability is NOT intended; the `batch_id` bind
is correct and stays. **Fix:** strike the portability sentence from the review
doc; add a CONFORMANCE clarifying sentence that a membership proof is bound to
exactly one `batch_id`. **FIXED this pass.**

**F3 — MINOR (deferred) — artifact IDs bind content, not signer.** The seven
artifact-ID preimages hash claims *without* the signer kid (unlike
`receipt_id`, which includes the protected bstr). A `decision_record`
references a delegation by `delegation_id` alone; two validly-signed tokens
with identical claims share an ID. Not exploitable — the signature binds
origin, bundle arrays are unique by ID, and the credential check re-validates
the token's signer as `authority_signing` at use. **Defer:** add a v0.2-rc
note that reference-by-ID resolves to the carried artifact whose signature is
independently checked; revisit signer-in-preimage only if a multi-signer
delegation model appears. No freeze blocker.

**F4 — MINOR (deferred) — an all-empty bundle verifies `conformant`.** Empty
artifact arrays + a valid selector → `conformant`/`valid_subset` over zero
receipts. Honest (it asserts nothing false) but waveable as "verified."
**Defer:** add an `empty_scope` verdict observation in the verifier phase so a
reader sees the bundle carried no matching receipts. No freeze blocker.

**F5 — WITHDRAWN — empty `external_aad` is not a weakness.** Cross-type
signature reuse is already blocked: the COSE content-type is in the *protected*
header and therefore signed, so a receipt signature cannot verify as a
delegation (different protected bytes → different Sig_structure). No finding.

**F6 — MINOR (deferred, inherent) — cross-evaluation sequence-rollback checks
are verifier-state-dependent.** `identity/issuer-sequence-rollback` /
`epoch-sequence-rollback` / `identity/reuse` fire only when prior evaluated
state is supplied (the stateful fixtures + `priorEmissions` option). Two
verifiers with different state histories legitimately differ. This is inherent
to stateful detection and already honestly scoped (D-44/D-45). **Defer:** the
verdict's `replay_state_digest` already binds which state was used; state that
absent prior state, the property is "not evaluated," not "passed." No freeze
blocker.

## Cryptographic spot-checks (no findings)
- RFC 6979 deterministic ECDSA + low-S normalization → byte-unique signatures:
  blocks malleability AND is what makes KATs reproducible. Correct.
- Domain-separated ID/leaf/node preimages (distinct `AAR-*-v1` strings) →
  no cross-type preimage collision. Correct.
- Verdict binds `bundle_digest` (SHA-256 of exact deterministic bytes) +
  `selector_commitment`; deterministic CBOR → one canonical byte string →
  a verdict cannot be lifted to a re-encoded equivalent bundle. Correct.
- Dominance rule (step 13) + closed edge matrix + `supports`-is-noncausal →
  no graph-splice path to a permitted root. Correct (R-29 satisfied).
- Cross-epoch edges restricted to historical/late-outcome; authorization/
  request/trigger/attempt never cross → no stale-authorization migration.
  Correct.

## Verdict
Two MAJOR findings, both spec/doc-hardening with a already-correct reference
implementation; three MINOR deferrals with rationale; one withdrawn. F1 and F2
fixed this pass. **RECOMMENDATION: FREEZE as v0.2-rc1** after the F1/F2 edits
re-verify green. The deferred F3/F4/F6 are recorded as rc-phase notes, none a
correctness or interop blocker.
