# Verifier delta audit — v0.3.1 → v0.4.0 (D-87)

Gate for the v0.4.0 re-pin (D-87; the D-83 part 8 method). Every signed
verdict changes bytes because the verdict version, its content type, two new
required keys, the limits digest and the verifier version and build identity
are signed, so the audit diffs decoded fields, not bytes.

**Method.** pyref at `6ff6b51` (v0.3.1) evaluated every row of its own
`pyref.kat` enumeration (532 rows) with the row's own inputs
(`KAT_EVALUATION_TIME`, the row's prior and replay state, or its
relying-party inputs sidecar); pyref at the D-87 build did the same over its
enumeration (549 rows). Both verdict envelopes were decoded; payload maps were
flattened and diffed field by field, the protected headers compared, and
result, reason and first failing step compared. Rows are paired by path; the
four rows D-87 relocates from `negative/stateful/` to `positive/stateful/`
are paired by name (their bundle and prior bytes are identical). The harness
needs no separate column: the full-corpus gate (`harness/crossimpl.test.ts`)
holds it byte-identical to pyref on every row, before and after (0 splits
over 549 rows at the D-87 build). The 17 rows D-87 adds were also run through
both v0.3.1 verifiers.

## The 532 existing rows

| Measure | Count |
|---|---:|
| Rows evaluated at v0.4.0 (pairs) | 532 |
| Rows whose verdict bytes changed | 532 |
| `v` changed (5 → 6) | 532 |
| Protected content type changed (`application/aar-verdict+cbor;v=0.3` → `;v=0.4`) | 532 |
| `verifier.version` changed (`v0.3.1` → `v0.4.0`) | 532 |
| `verifier.build_digest` changed (the new documented preimages) | 532 |
| `verifier.limits_digest` changed (two section 1 limits added, D-87 rule 6) | 532 |
| `trust_policy.retained_epochs_digest` added at its absent value (32 zero bytes without prior state: 509; the `{ bundles: [] }` digest `829f7eb0…` with prior state and no `retained_epochs`: 23) | 532 |
| `limits.retained_manifest_membership` added as `not_established` | 532 |
| `verdict_id` and signature changed (derived from the fields above) | 532 |
| Identity fields and the two D-87 keys only | **515** |
| Result, reason or first failing step changed | **12** (below) |
| Observations reordered, outcome unchanged | **2** (below) |
| New bundle bytes, outcome unchanged (`bundle_digest`, `anchor_heads_digest`) | **3** (below) |
| Any other payload field changed | **0** |

Every row outside the 17 named below differs only in the identity fields and
the two D-87 keys at their absent values.

### Result, reason or step moved (12)

| Row (v0.3.1 path) | v0.3.1 | v0.4.0 | Rule |
|---|---|---|---|
| `negative/repair-d82-complete-extra-unindexed-receipt` | `bundle/artifact-out-of-scope`@18 | `manifest/receipt-unindexed`@15 | D-87 rule 0: its subject is exactly a receipt its epoch's index omits |
| `negative/stateful/identity-issuer-sequence-rollback` | `identity/issuer-sequence-rollback`@9 | conformant, `sequence_below_observed_history`; now `positive/stateful/` | D-87 rule 2 (rollback retired) |
| `negative/stateful/identity-epoch-sequence-rollback` | `identity/epoch-sequence-rollback`@9 | conformant, `sequence_below_observed_history`; now `positive/stateful/` | D-87 rule 2 |
| `negative/stateful/d86-phase-b-issuer-outranks-epoch-rollback` | `identity/issuer-sequence-rollback`@9 | conformant, `sequence_below_observed_history`; now `positive/stateful/` | D-87 rule 2 |
| `negative/stateful/d86-partial-history-epoch-rollback` | `identity/epoch-sequence-rollback`@9 | conformant, `duplicate_exact`, `sequence_below_observed_history`; now `positive/stateful/` | D-87 rule 2 |
| `negative/stateful/identity-reuse` | `identity/reuse`@9 | `identity/reuse`@20 | D-87 rule 1 (D-86 phase B to the history phase) |
| `negative/stateful/d86-history-issuer-coordinate` | `identity/coordinate-equivocation`@9 | same code @20 | D-87 rule 1 |
| `negative/stateful/d86-history-epoch-coordinate` | `identity/coordinate-equivocation`@9 | same code @20 | D-87 rule 1 |
| `negative/stateful/d86-history-reuse-outranks-rollback` | `identity/reuse`@9 | `identity/reuse`@20 | D-87 rule 1 |
| `negative/stateful/d86-phase-b-equivocation-outranks-rollback` | `identity/coordinate-equivocation`@9 | same code @20 | D-87 rule 1 |
| `negative/stateful/d86-duplicate-not-exempt-from-equivocation` | `identity/coordinate-equivocation`@9 | same code @20 | D-87 rule 1 |
| `negative/stateful/d86-duplicate-not-exempt-from-reuse` | `identity/reuse`@9 | `identity/reuse`@20 | D-87 rule 1 |

The four pass ↔ fail rows also change `result`, `reason`, `limits` and
`observations` as a pass ↔ fail change must (a failure verdict carries the
D-82 failure population). The eight D-86 phase-A rows (six fuzz splits and
both phase-order rows) keep `identity/coordinate-equivocation`@9; their
descriptors now pin `expected_step` 9, and the seven moved negative rows
`expected_step` 20.

### Observations reordered (2)

`positive/stateful/d86-history-exact-represent` and
`positive/stateful/d86-history-full-reobservation`: `duplicate_exact` moves
from first to last (`["duplicate_exact", "membership_only",
"anchor_existence_order_only", "ingress_completeness_not_established"]` →
`["membership_only", "anchor_existence_order_only",
"ingress_completeness_not_established", "duplicate_exact"]`). D-87 rule 1:
the observation is emitted in the step-20 history phase, after every
observation of steps 10 to 19 (D-78 emission order).

### New bundle bytes, outcome unchanged (3)

`positive/d82-chain-shared-ancestors`, `positive/d82-chain-two-levels`,
`positive/d82-parent-delegation-invocation-absent`. Their builders re-sign
the embedded delegation, which re-identifies the authorization and its
descendants while the carried manifest still indexed the old IDs (five
receipts in each row, D-87 spec P2-5). Rule 0 rejects that
(`manifest/receipt-unindexed`@15), so the generator now reindexes the
manifest (`harness/mutate-graph.ts` `reindexCarried`: each stale entry
points at the carried receipt holding its `epoch_seq`, then re-sort, re-leaf,
re-root, events and anchor rebound). They stay conformant on the same
subject; `bundle_digest` and `anchor_heads_digest` (the expected head follows
the rebound anchor) change with the bytes. Every other generated row is
byte-identical (the helper is a no-op when no entry is stale).

## The 17 rows D-87 adds

Old codes are what each v0.3.1 verifier returns for the same bytes and prior.

| Row | v0.3.1 harness | v0.3.1 pyref | v0.4.0 (both) |
|---|---|---|---|
| `negative/stateful/d87-receipt-unindexed-in-bundle` (no prior) | conformant | conformant | `manifest/receipt-unindexed`@15 |
| `negative/stateful/d87-history-independence-dangling-parent` | `identity/reuse`@9 | `identity/reuse`@9 | `graph/dangling-parent`@12, as without history |
| `negative/stateful/d87-retained-forged-insertion` | usage error (`prior-state: unknown retained_epochs`) | usage error (same) | `manifest/receipt-unindexed`@20 |
| `negative/stateful/d87-retained-competing-manifest` | usage error | usage error | `epoch/fork`@20 |
| `negative/stateful/d87-retained-conflicting-event` | usage error | usage error | `epoch/fork`@20 |
| `positive/stateful/d87-retained-superset` | usage error | usage error | conformant, `all_receipts_listed` |
| `positive/stateful/d87-retained-unretained-epoch` | usage error | usage error | conformant, `not_established` |
| `positive/stateful/d87-retained-zero-receipts` | usage error | usage error | conformant, `not_established` |
| `negative/stateful/d87-retained-index-mismatch` (fix round 1) | usage error | usage error | `manifest/index-receipt-mismatch`@20 |
| `negative/stateful/d87-history-independence-equivocation-membership` (fix round 1) | usage error | usage error | `graph/dangling-parent`@12 |
| `negative/stateful/d87-history-independence-fork` (fix round 1) | usage error | usage error | `graph/dangling-parent`@12 |
| `negative/stateful/d87-history-after-key-not-found` (fix round 1) | `identity/reuse`@9 | `identity/reuse`@9 | indeterminate `key/not-found`@20, as without history |
| `positive/stateful/d87-late-for-epoch-not-selecting` (fix round 1, no prior) | conformant | conformant | conformant, `not_established` |
| `relying-party/rp-replay-two-entries` (fix round 1) | conformant (compared only the last entry) | `replay/one-time-reused`@11 | `replay/one-time-reused`@20 |
| `relying-party/rp-history-independence-replay` (fix round 1) | `replay/one-time-reused`@11 | `replay/one-time-reused`@11 | `graph/root-missing`@12 |
| `relying-party/rp-retained-under-policy` (fix round 1) | usage error | usage error | conformant, `all_receipts_listed` |
| `negative/stateful/d87-history-early-failure` (fix round 2) | `hash/mismatch`@7 | `hash/mismatch`@7 | `hash/mismatch`@7, unchanged: a contradicting history is refused only once step 9's coordinate type checks pass, so a step-7 failure is signed with it bound |

The v0.3.1 pyref column for the two replay rows decodes the replay sidecar
by hand: v0.3.1's KAT adapter passed the hex strings through undecoded (the
BACKLOG replay-sidecar item, fixed with these rows).
`d87-history-after-key-not-found` is the one corpus row whose outcome D-87
moves by ordering alone: a bundle whose verifier key does not resolve now
reports `key/not-found` even when the supplied history shows reuse (D-87
residuals).

`d87-receipt-unindexed-in-bundle` is byte-identical to the v0.3.1
`kats/positive/d82-chain-two-levels.cbor` (SHA-256 `09a17bd2…`; the
generator builds it with `buildD82PositiveFixtures(false)`, the pre-D-87
build, and a test asserts the identity). `d87-history-independence-dangling-parent`
is byte-identical to `kats/negative/graph-dangling-parent.cbor`; its prior
holds one entry reusing a carried receipt ID.

Corpus after re-pin: 549 rows (`pyref/results-c2.json`), 549 matched, 549
deterministic, 0 divergences (454 nonconformant, 90 conformant, 5
indeterminate). The 532 existing rows' classes above are unchanged by fix
round 1 (re-run: 515 / 12 / 2 / 3 / 0).
