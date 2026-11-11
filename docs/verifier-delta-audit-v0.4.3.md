# Verifier delta audit — v0.4.2 → v0.4.3 (D-90)

Gate for the v0.4.3 re-pin (D-90; the D-83 part 8 method). Every signed
verdict changes bytes because the verifier version and build identity are
signed, so the audit diffs decoded fields, not bytes.

**Method.** pyref at `170ac37` (v0.4.2) evaluated every row of its own
`pyref.kat` enumeration (570 rows) with the row's own inputs
(`KAT_EVALUATION_TIME`, the row's prior and replay state, or its
relying-party inputs sidecar); pyref at the D-90 build did the same over its
enumeration (594 rows). Both verdict payloads were decoded, flattened and
diffed field by field, and result, reason and first failing step compared.
Rows are paired by path. The harness needs no separate column for the
existing rows: the full-corpus gate (`harness/crossimpl.test.ts`) holds it
byte-identical to pyref on every row, before and after. The 24 rows v0.4.3
adds were also run through both v0.4.2 verifiers.

## The 570 existing rows

| Measure | Count |
|---|---:|
| Rows evaluated (475 nonconformant, 90 conformant, 5 indeterminate) | 570 |
| `verifier.version` changed (`v0.4.2` → `v0.4.3`) | 570 |
| `verifier.build_digest` changed (the new documented preimage) | 570 |
| `verdict_id` changed (derived from the fields above) | 570 |
| Result, reason or first failing step changed | **0** |
| Bundle bytes changed | 30 |
| `bundle_digest` changed | 30 (exactly the rows whose bytes changed) |
| `trust_policy.anchor_heads_digest` changed | 6 (all among those 30) |
| Any other payload field changed | **0** |

Rows by directory: `negative` 437 (`negative/stateful` included),
`positive` 63 (`positive/stateful` included), `relying-party` 38,
`class-boundary` 19, `evidence-commit` 6, `countersign` 4, `terminal-state` 3.

**Why 30 rows changed bytes.** Their generators edited a decision record and
recomputed the authorization's `decision_commitment`, but left the citing
attempt's copy stale. Under D-90 a stale copy is `graph/dominator-missing`, so
the shared cascades (`rewriteD78Receipts` and `mutateEmbeddedDelegation`, now
both in `harness/mutate-graph.ts`) and one class-boundary builder carry the
recomputed commitment into the attempts that cite it. Each row keeps its
planted fault and its outcome:

- 3 conformant `positive/d82-chain-*` / `d82-parent-delegation-invocation-absent`;
- 1 conformant `class-boundary/origin-no-input-ancestor`;
- 26 negatives: the `delegation-*`, `repair-d79-delegation-*` and
  `repair-d82-*` delegation rows, three `d88-*` rows, one status row, and
  `negative/stateful/d87-receipt-unindexed-in-bundle`. That last one's
  deliberately stale index is preserved.

A corpus scan of the new tree finds no bundle, outside the D-90 rows that
plant one, in which an attempt that a dispatch names carries a commitment
other than its authorization's.

## The 24 rows v0.4.3 adds

Old codes are what each v0.4.2 verifier returns for the same bytes (no prior
or replay state; evaluation time `1735689800`). Both v0.4.2 verifiers agree on
every row. Every row starts from `bundle-valid-subset` and is re-indexed, so
outside the `d90-order-*` rows the D-90 fault is the only one.

| Row | v0.4.2 (both) | v0.4.3 (both) |
|---|---|---|
| `negative/d90-dispatch-refused-attempt` | conformant | `graph/dominator-missing`@13 |
| `negative/d90-dispatch-under-deny` (the oneshot2001/aar#1 held-state probe) | conformant | `graph/dominator-missing`@13 |
| `negative/d90-attempt-commitment-other` / `-missing` / `-null` / `-int` | conformant | `graph/dominator-missing`@13 |
| `negative/d90-commitment-not-recomputed` (decision lacks `policy_set_root`; step 7 skips) | conformant | `graph/dominator-missing`@13 |
| `negative/d90-undispatched-eligible-under-deny` | conformant | `graph/dominator-missing`@13 |
| `negative/d90-life-safety-degraded-under-deny` (AAR-3) | conformant | `graph/dominator-missing`@13 |
| `negative/d90-one-time-two-attempts` | conformant | `delegation/scope`@13 |
| `negative/d90-one-time-one-attempt-two-dispatches` | conformant | `delegation/scope`@13 |
| `negative/d90-one-time-parent-two-children` | conformant | `delegation/scope`@13 |
| `negative/d90-one-time-parent-then-child` | conformant | `delegation/scope`@13 |
| `negative/d90-decision-hold` | conformant | `schema/enum-unknown`@6 |
| `negative/d90-decision-missing` | conformant | `schema/missing-field`@6 |
| `negative/d90-decision-null` / `-int` | conformant | `schema/bad-type`@6 |
| `negative/d90-disposition-held` | conformant | `schema/enum-unknown`@6 |
| `negative/d90-disposition-missing` | `receipt/kind-body-mismatch`@10 | `schema/missing-field`@6 |
| `negative/d90-disposition-null` | conformant | `schema/bad-type`@6 |
| `negative/d90-order-action-name-before-disposition` | `schema/enum-unknown`@6 | `schema/enum-unknown`@6 |
| `negative/d90-order-deny-before-scope` | `delegation/scope`@13 | `graph/dominator-missing`@13 |
| `negative/d90-order-journal-before-later-refused-dispatch` (AAR-3) | `journal/uncommitted-dispatch`@13 | `journal/uncommitted-dispatch`@13 |
| `positive/d90-deny-refusal-no-dispatch` | conformant | conformant |

Corpus after re-pin: 594 rows (`pyref/results-c2.json`), 594 matched, 594
deterministic, 0 divergences.
