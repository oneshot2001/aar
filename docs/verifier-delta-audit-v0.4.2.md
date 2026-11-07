# Verifier delta audit — v0.4.1 → v0.4.2 (D-89)

Gate for the v0.4.2 re-pin (D-89; the D-83 part 8 method). Every signed
verdict changes bytes because the verifier version and build identity are
signed, so the audit diffs decoded fields, not bytes.

**Method.** pyref at `8a6eb98` (v0.4.1) evaluated every row of its own
`pyref.kat` enumeration (565 rows) with the row's own inputs
(`KAT_EVALUATION_TIME`, the row's prior and replay state, or its
relying-party inputs sidecar); pyref at the D-89 build did the same over its
enumeration (570 rows). Both verdict envelopes were decoded; payload maps were
flattened and diffed field by field, the protected headers and signatures
compared, and result, reason and first failing step compared. Rows are paired
by path. The harness needs no separate column for the existing rows: the
full-corpus gate (`harness/crossimpl.test.ts`) holds it byte-identical to
pyref on every row, before and after. The 5 rows v0.4.2 adds were also run
through both v0.4.1 verifiers.

## The 565 existing rows

| Measure | Count |
|---|---:|
| Rows evaluated (470 nonconformant, 90 conformant, 5 indeterminate) | 565 |
| Rows whose verdict bytes changed | 565 |
| `verifier.version` changed (`v0.4.1` → `v0.4.2`) | 565 |
| `verifier.build_digest` changed (`c66c8973…` → `810c3755…`, the new documented preimage) | 565 |
| `verdict_id` changed (derived from the fields above) | 565 |
| Signature changed (over the new payload) | 565 |
| Result, reason or first failing step changed | **0** |
| Any other payload field changed (`v`, `config_digest`, `limits_digest`, every `trust_policy` digest, `limits`, `scope`, `observations`, …) | **0** |
| Protected header changed (content type stays `application/aar-verdict+cbor;v=0.4`) | **0** |
| Bundle bytes changed (every existing row regenerates byte-identical) | **0** |

Rows by directory: `negative` 432 (`negative/stateful` included),
`positive` 63 (`positive/stateful` included), `relying-party` 38,
`class-boundary` 19, `evidence-commit` 6, `countersign` 4, `terminal-state` 3.
No existing row carries a presentation state other than `human_approved` that
reaches step 10 (`repair-d77-presentation-state-unknown` carries `bogus_state`
and fails at step 6 first), as D-89 states.

## The 5 rows v0.4.2 adds

Old codes are what each v0.4.1 verifier returns for the same bytes (no prior
or replay state; evaluation time `1735689800`). Every row starts from
`bundle-valid-subset` and changes the approval authorization's nested
presentation: `presentation_id` recomputed, the presentation re-signed by its
signer, the enclosing receipt re-signed and re-indexed. Outside the
`d89-order-*` row the state is the only planted fault.

| Row | v0.4.1 harness | v0.4.1 pyref | v0.4.2 (both) |
|---|---|---|---|
| `negative/d89-pwa-state-assembled` | conformant | conformant | `receipt/decision-presentation`@10 |
| `negative/d89-pwa-state-delivered` (the oneshot2001/aar#1 item 2 probe) | conformant | conformant | `receipt/decision-presentation`@10 |
| `negative/d89-pwa-state-rendered` | conformant | conformant | `receipt/decision-presentation`@10 |
| `negative/d89-pwa-state-delivered-ep-session` (EP-authenticated-session presentation, signed by the EP key) | conformant | conformant | `receipt/decision-presentation`@10 |
| `negative/d89-order-state-before-ordinals` (and artifact ordinals `[1, 0]`) | `receipt/manifest-inconsistent`@10 | same | `receipt/decision-presentation`@10 |

The same recipe with the state left at `human_approved`, in either signer
mode, is conformant in both verifiers before and after; it is a probe, not a
corpus row.

Corpus after re-pin: 570 rows (`pyref/results-c2.json`), 570 matched, 570
deterministic, 0 divergences (475 nonconformant, 90 conformant, 5
indeterminate).
