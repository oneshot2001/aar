# Verifier delta audit — v0.4.0 → v0.4.1 (D-88)

Gate for the v0.4.1 re-pin (D-88; the D-83 part 8 method). Every signed
verdict changes bytes because the verifier version and build identity are
signed, so the audit diffs decoded fields, not bytes.

**Method.** pyref at `073afcd` (v0.4.0) evaluated every row of its own
`pyref.kat` enumeration (550 rows) with the row's own inputs
(`KAT_EVALUATION_TIME`, the row's prior and replay state, or its
relying-party inputs sidecar); pyref at the D-88 build did the same over its
enumeration (564 rows). Both verdict envelopes were decoded; payload maps were
flattened and diffed field by field, the protected headers and signatures
compared, and result, reason and first failing step compared. Rows are paired
by path. The harness needs no separate column for the existing rows: the
full-corpus gate (`harness/crossimpl.test.ts`) holds it byte-identical to
pyref on every row, before and after. The 14 rows v0.4.1 adds, and the one
probe it pins outside the corpus, were also run through both v0.4.0 verifiers.

## The 550 existing rows

| Measure | Count |
|---|---:|
| Rows evaluated (455 nonconformant, 90 conformant, 5 indeterminate) | 550 |
| Rows whose verdict bytes changed | 550 |
| `verifier.version` changed (`v0.4.0` → `v0.4.1`) | 550 |
| `verifier.build_digest` changed (`2b70d745…` → `c66c8973…`, the new documented preimage) | 550 |
| `verdict_id` changed (derived from the fields above) | 550 |
| Signature changed (over the new payload) | 550 |
| Result, reason or first failing step changed | **0** |
| Any other payload field changed (`v`, `config_digest`, `limits_digest`, every `trust_policy` digest, `limits`, `scope`, `observations`, …) | **0** |
| Protected header changed (content type stays `application/aar-verdict+cbor;v=0.4`) | **0** |
| Bundle bytes changed (every existing row regenerates byte-identical) | **0** |

Rows by directory: `negative` 417 (`negative/stateful` included),
`positive` 63 (`positive/stateful` included), `relying-party` 38,
`class-boundary` 19, `evidence-commit` 6, `countersign` 4, `terminal-state` 3.
No existing row carries a missing, mistyped or unlisted action name at the
three D-88 sites, as D-88 states.

## The 14 rows v0.4.1 adds, and one probe

Old codes are what each v0.4.0 verifier returns for the same bytes (no prior
or replay state; evaluation time `1735689800`). Every row starts from
`bundle-valid-subset`; a changed command manifest has its `command_id`
recomputed and every re-identified receipt is re-indexed, so in the rows
that are not `d88-order-*` the action name is the only planted fault. On
v0.4.0 it surfaces through its consequences: changing one of the three
name sites gives `receipt/action-command-mismatch`@10, and the embedded
scope row, whose delegation no longer lists the dispatched action, gives
`delegation/scope`@13. Each `d88-order-*` row carries a second fault on
purpose, to pin which check fires first.

| Row | v0.4.0 harness | v0.4.0 pyref | v0.4.1 (both) |
|---|---|---|---|
| `negative/d88-action-name-missing` | `receipt/action-command-mismatch`@10 | same | `schema/missing-field`@6 |
| `negative/d88-action-name-int` | `receipt/action-command-mismatch`@10 | same | `schema/bad-type`@6 |
| `negative/d88-action-name-export-clip` | `receipt/action-command-mismatch`@10 | same | `schema/enum-unknown`@6 |
| `negative/d88-command-action-name-missing` | `receipt/action-command-mismatch`@10 | same | `schema/missing-field`@6 |
| `negative/d88-command-action-name-unknown` | `receipt/action-command-mismatch`@10 | same | `schema/enum-unknown`@6 |
| `negative/d88-scope-embedded-unknown` (the permit's embedded delegation, used) | `delegation/scope`@13 | same | `schema/enum-unknown`@6 |
| `negative/d88-scope-non-text-member` (the approval's embedded delegation, unused) | conformant | conformant | `schema/bad-type`@6 |
| `negative/d88-scope-unused-top-level-unknown` | conformant | conformant | `schema/enum-unknown`@6 |
| `negative/d88-scope-mixed-array` (`["camera.stream.view", "camera.export_clip", 7]`) | conformant | conformant | `schema/enum-unknown`@6 (array order) |
| `negative/d88-order-scope-before-not-before` (and `not_before` text) | `schema/bad-type`@6 | same | `schema/enum-unknown`@6 |
| `negative/d88-order-closed-map-first` (and no `not_before`) | `schema/missing-field`@6 | same | `schema/missing-field`@6, unchanged |
| `negative/d88-order-reversibility-before-command` (`partially`, and no command `action_name`) | `schema/enum-unknown`@6 | same | `schema/enum-unknown`@6, unchanged (the reversibility failure) |
| `negative/d88-order-command-before-excluded` (and no `excluded_fields`) | `schema/missing-field`@6 | same | `schema/enum-unknown`@6 |
| `negative/d88-refusal-export-clip-consistent` | conformant | conformant | `schema/enum-unknown`@6 |
| probe `d88-non-authorization-delegation-ignored` (`harness/crossimpl.test.ts`) | conformant | conformant | conformant, unchanged (amendment m) |

`d88-refusal-export-clip-consistent` is the oneshot2001/aar#1 item 3 shape:
`camera.export_clip` in the permit's embedded delegation scope (beside
`camera.stream.view`, which the dispatched attempt still uses), the refused
attempt's normalized action, its command manifest and its canonical command,
with `command_digest` and `command_id` recomputed. The outside emitter's own
probe bundle gives the same result through both CLIs at its own evaluation
time (`nonconformant`, step 06 `schema/enum-unknown`, first at the top-level
delegation's `scope.actions[0]`; both said `conformant` at v0.4.0).

The probe gives the refused attempt's body a re-identified, re-signed copy of
the permit's embedded delegation with `scope.actions` `["camera.export_clip"]`.
D-88 leaves a `body.delegation` on a non-authorization receipt ignored
(amendment m), so both verifiers still sign it conformant, byte-identically.
It is a cross-implementation probe, not a corpus row, because the CDDL oracle
(`pyref.schema_kat`) requires every conformant corpus row to be CDDL-valid and
the extra body member is not; closing it stays with the BACKLOG step-6
traversal item.

Corpus after re-pin: 564 rows (`pyref/results-c2.json`), 564 matched, 564
deterministic, 0 divergences (469 nonconformant, 90 conformant, 5
indeterminate); C1 84 fixtures, unchanged.
