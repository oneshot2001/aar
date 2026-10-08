# Verifier parity audit 2026-10-08: pre-existing full-corpus byte gaps

Found while building D-77; not caused by it. Tracked as the differential-fuzzing freeze blocker in `BACKLOG.md`. The executable form is the skipped full-corpus test in `harness/crossimpl.test.ts`.

2026-10-08. D-77 implements all 13 requested KATs; each has the expected result/reason and identical signed verdict bytes under a shared verifier identity. The wider 232-fixture audit finds 192 identical verdicts and 40 differences. No existing fixture expectation was edited.

The audit uses the same explicit pyref identity, evaluation time, empty replay state, and per-fixture prior state in both verifiers. Standalone artifacts use `pyref.kat._context_for_standalone` to construct a common bundle, since the harness accepts bundles. The full-corpus test in `harness/crossimpl.test.ts` reproduces these gaps; it is checked in as `test.skip` until they are resolved.

All 219 existing pyref verdict digests reproduce the committed values when only the prior build identity is restored. Comparing the committed harness verifier with this working tree under the same explicit identity also produces identical verdict bytes on all 219 existing fixtures, proving that all 40 cross-implementation gaps predate D-77. The differences below therefore must not be “fixed” by changing fixture expectations or by repinning them as D-77 identity changes.

## Questions for the spec owner

1. What are the exact failure-verdict values for `evaluated_profile`, `technical_integrity`, `discovery_completeness`, and the maximum evidence classes? Section 5 freezes their enums and successful-verdict behavior, but does not give a complete failure-step population rule. For step-19 evidence failures pyref carries the requested evaluated profile while the harness emits `below_AAR-1`.
2. Early failures differ in whether decoded-but-schema-invalid bundle fields and supplied replay state populate the verdict. Section 5 says decoded valid requested values replace their sentinels; this needs a shared field-by-field validity rule rather than choosing one implementation’s behavior.
3. The standalone `epoch-event-fork-declared` fixture, inserted into the common context, yields pyref `conformant` and harness `nonconformant / epoch/fork`. Resolve this existing context/epoch-rule discrepancy in a separate ruled repair; it is not caused by D-77.

## Differing fixtures

Paths below are relative to `kats/`. Except for the last row, results and reasons agree; only signed verdict fields differ. `verdict_id` and signatures consequently differ and are omitted from the field lists.

| Fixture | Differing fields |
|---|---|
| `class-boundary/outcome-device-acknowledged-declared-independently-sensed.cbor` | `limits.evaluated_profile` |
| `class-boundary/provenance-proxy-captured-declared-provider-attested.cbor` | `limits.evaluated_profile` |
| `class-boundary/provenance-self-asserted-declared-proxy-captured.cbor` | `limits.evaluated_profile` |
| `class-boundary/time-asserted-declared-boot-bound.cbor` | `limits.evaluated_profile` |
| `class-boundary/time-boot-bound-declared-externally-anchored.cbor` | `limits.evaluated_profile` |
| `negative/bundle-artifact-out-of-scope.cbor` | `limits.discovery_completeness` |
| `negative/bundle-coverage-overclaim.cbor` | `limits.discovery_completeness` |
| `negative/bundle-range-boundary.cbor` | `limits.discovery_completeness` |
| `negative/bundle-range-manifest-missing.cbor` | `limits.discovery_completeness` |
| `negative/bundle-range-noncontiguous.cbor` | `limits.discovery_completeness` |
| `negative/bundle-range-proof-invalid.cbor` | `limits.discovery_completeness` |
| `negative/bundle-range-selector-mismatch.cbor` | `limits.discovery_completeness` |
| `negative/bundle-selected-receipt-missing.cbor` | `limits.discovery_completeness` |
| `negative/bundle-selector-commitment.cbor` | `scope.site_id`, `scope.tenant_id`, `scope.receipt_kinds`, `scope.committed_from`, `scope.committed_until`, `limits.requested_profile`, `limits.technical_integrity`, `trust_policy.trust_store_digest`, `trust_policy.anchor_heads_digest`, `trust_policy.replay_state_digest`, `trust_policy.verifier_policy_digest`, `trust_policy.trust_store_snapshot_id`, `selector_commitment` |
| `negative/cbor-duplicate-key.cbor` | `limits.technical_integrity`, `trust_policy.replay_state_digest` |
| `negative/cbor-float-forbidden.cbor` | `limits.technical_integrity`, `trust_policy.replay_state_digest` |
| `negative/cbor-indefinite-length.cbor` | `limits.technical_integrity`, `trust_policy.replay_state_digest` |
| `negative/cbor-invalid-utf8.cbor` | `limits.technical_integrity`, `trust_policy.replay_state_digest` |
| `negative/cbor-malformed.cbor` | `limits.technical_integrity`, `trust_policy.replay_state_digest` |
| `negative/cbor-non-canonical.cbor` | `limits.technical_integrity`, `trust_policy.replay_state_digest` |
| `negative/cbor-tag-forbidden.cbor` | `limits.technical_integrity`, `trust_policy.replay_state_digest` |
| `negative/cbor-trailing-bytes.cbor` | `limits.technical_integrity`, `trust_policy.replay_state_digest` |
| `negative/evidence-observer-not-independent.cbor` | `limits.evaluated_profile` |
| `negative/evidence-outcome-class-unsatisfied.cbor` | `limits.evaluated_profile` |
| `negative/evidence-provenance-class-unsatisfied.cbor` | `limits.evaluated_profile` |
| `negative/evidence-time-class-unsatisfied.cbor` | `limits.evaluated_profile` |
| `negative/manifest-payload-missing.cbor` | `limits.evaluated_profile` |
| `negative/resource-bundle-too-large.cbor` | `limits.technical_integrity`, `trust_policy.replay_state_digest` |
| `negative/resource-cbor-depth.cbor` | `limits.technical_integrity`, `trust_policy.replay_state_digest` |
| `negative/schema-bad-type.cbor` | `scope.site_id`, `scope.tenant_id`, `scope.receipt_kinds`, `scope.committed_from`, `scope.committed_until`, `limits.requested_profile`, `limits.technical_integrity`, `trust_policy.trust_store_digest`, `trust_policy.anchor_heads_digest`, `trust_policy.replay_state_digest`, `trust_policy.verifier_policy_digest`, `trust_policy.trust_store_snapshot_id`, `selector_commitment` |
| `negative/schema-digest-size.cbor` | `scope.site_id`, `scope.tenant_id`, `scope.receipt_kinds`, `scope.committed_from`, `scope.committed_until`, `limits.requested_profile`, `limits.technical_integrity`, `trust_policy.trust_store_digest`, `trust_policy.anchor_heads_digest`, `trust_policy.replay_state_digest`, `trust_policy.verifier_policy_digest`, `trust_policy.trust_store_snapshot_id` |
| `negative/schema-duplicate-entry.cbor` | `scope.site_id`, `scope.tenant_id`, `scope.receipt_kinds`, `scope.committed_from`, `scope.committed_until`, `limits.requested_profile`, `limits.technical_integrity`, `trust_policy.trust_store_digest`, `trust_policy.anchor_heads_digest`, `trust_policy.replay_state_digest`, `trust_policy.verifier_policy_digest`, `trust_policy.trust_store_snapshot_id`, `selector_commitment` |
| `negative/schema-enum-unknown.cbor` | `scope.site_id`, `scope.tenant_id`, `scope.receipt_kinds`, `scope.committed_from`, `scope.committed_until`, `limits.technical_integrity`, `trust_policy.trust_store_digest`, `trust_policy.anchor_heads_digest`, `trust_policy.replay_state_digest`, `trust_policy.verifier_policy_digest`, `trust_policy.trust_store_snapshot_id`, `selector_commitment` |
| `negative/schema-missing-field.cbor` | `scope.site_id`, `scope.tenant_id`, `scope.receipt_kinds`, `scope.committed_from`, `scope.committed_until`, `limits.requested_profile`, `limits.technical_integrity`, `trust_policy.trust_store_digest`, `trust_policy.anchor_heads_digest`, `trust_policy.replay_state_digest`, `trust_policy.verifier_policy_digest`, `trust_policy.trust_store_snapshot_id`, `selector_commitment` |
| `negative/schema-out-of-range.cbor` | `scope.site_id`, `scope.tenant_id`, `scope.receipt_kinds`, `scope.committed_from`, `scope.committed_until`, `limits.requested_profile`, `limits.technical_integrity`, `trust_policy.trust_store_digest`, `trust_policy.anchor_heads_digest`, `trust_policy.replay_state_digest`, `trust_policy.verifier_policy_digest`, `trust_policy.trust_store_snapshot_id`, `selector_commitment` |
| `negative/schema-string-size.cbor` | `scope.site_id`, `scope.tenant_id`, `scope.receipt_kinds`, `scope.committed_from`, `scope.committed_until`, `limits.requested_profile`, `limits.technical_integrity`, `trust_policy.trust_store_digest`, `trust_policy.anchor_heads_digest`, `trust_policy.replay_state_digest`, `trust_policy.verifier_policy_digest`, `trust_policy.trust_store_snapshot_id`, `selector_commitment` |
| `negative/schema-unknown-field.cbor` | `scope.site_id`, `scope.tenant_id`, `scope.receipt_kinds`, `scope.committed_from`, `scope.committed_until`, `limits.requested_profile`, `limits.technical_integrity`, `trust_policy.trust_store_digest`, `trust_policy.anchor_heads_digest`, `trust_policy.replay_state_digest`, `trust_policy.verifier_policy_digest`, `trust_policy.trust_store_snapshot_id`, `selector_commitment` |
| `negative/schema-unsorted-set.cbor` | `scope.site_id`, `scope.tenant_id`, `scope.receipt_kinds`, `scope.committed_from`, `scope.committed_until`, `limits.requested_profile`, `limits.technical_integrity`, `trust_policy.trust_store_digest`, `trust_policy.anchor_heads_digest`, `trust_policy.replay_state_digest`, `trust_policy.verifier_policy_digest`, `trust_policy.trust_store_snapshot_id`, `selector_commitment` |
| `negative/schema-version-wrong.cbor` | `scope.site_id`, `scope.tenant_id`, `scope.receipt_kinds`, `scope.committed_from`, `scope.committed_until`, `limits.requested_profile`, `limits.technical_integrity`, `trust_policy.trust_store_digest`, `trust_policy.anchor_heads_digest`, `trust_policy.replay_state_digest`, `trust_policy.verifier_policy_digest`, `trust_policy.trust_store_snapshot_id`, `selector_commitment` |
| `positive/epoch-event-fork-declared.cbor` | `limits.evaluated_profile`, `limits.maximum_time_class`, `limits.technical_integrity`, `limits.maximum_outcome_level`, `limits.maximum_provenance_class`, `result`, `observations`, `reason` |

## Release environment

The separate adapter suite passed 25 tests and failed its local witness-proxy server test. Bun reports `EADDRINUSE` for `listen(0, "127.0.0.1")`; a Python loopback-bind probe reports `PermissionError: [Errno 1] Operation not permitted`. This is a sandbox restriction; no adapter test was disabled or modified.
