# Verifier delta audit — v0.3.0 → v0.3.1 (D-86)

Gate for the v0.3.1 re-pin (D-86; the D-83 part 8 method). Every signed
verdict changes bytes because the verifier version and build identity are
signed, so the audit diffs decoded fields, not bytes.

**Method.** pyref at `a840688` (v0.3.0) and pyref at the D-86 build each
evaluated every corpus row its own `pyref.kat` enumeration lists, with the
row's own inputs (`KAT_EVALUATION_TIME`, the row's prior and replay state, or
its relying-party inputs sidecar). Both verdict envelopes were decoded;
payload maps were diffed field by field, the protected headers compared, and
result, reason and first failing step compared. The harness needs no
separate column for these rows: the full-corpus gate
(`harness/crossimpl.test.ts`) holds it byte-identical to pyref on every row,
before and after. The 13 rows D-86 adds were also run through both v0.3.0
verifiers.

## The 513 existing rows

| Measure | Count |
|---|---:|
| Rows evaluated (431 nonconformant, 78 conformant, 4 indeterminate) | 513 |
| Rows whose verdict bytes changed | 513 |
| `verifier.version` changed (`v0.3.0` → `v0.3.1`) | 513 |
| `verifier.build_digest` changed (`7ee8238e…` → `f5418f98…`, the new documented preimage) | 513 |
| `verdict_id` changed (derived from the fields above) | 513 |
| Signature changed (over the new payload) | 513 |
| Result, reason or first failing step changed | **0** |
| Any other payload field changed (`v`, `config_digest`, `limits_digest`, every `trust_policy` digest, `limits`, `scope`, `observations`, …) | **0** |
| Protected header changed (content type stays `application/aar-verdict+cbor;v=0.3`) | **0** |

Rows by directory: `negative` 391, `positive` 52, `relying-party` 35,
`class-boundary` 19, `evidence-commit` 6, `countersign` 4,
`negative/stateful` 3, `terminal-state` 3. No existing row's code is changed
by the rule; the three pre-D-86 stateful rows keep `identity/reuse`,
`identity/issuer-sequence-rollback` and `identity/epoch-sequence-rollback`
(their priors are strictly greater than every carried sequence, so `<=` and
`<` agree).

## The 13 rows D-86 adds

Old codes are what each v0.3.0 verifier returns for the same bytes and prior.

| Row | v0.3.0 harness | v0.3.0 pyref | v0.3.1 (both) |
|---|---|---|---|
| `negative/stateful/d86-fuzz-m-01770` | issuer-sequence-rollback | coordinate-equivocation | coordinate-equivocation |
| `negative/stateful/d86-fuzz-m-01931` | issuer-sequence-rollback | coordinate-equivocation | coordinate-equivocation |
| `negative/stateful/d86-fuzz-m-01969` | issuer-sequence-rollback | coordinate-equivocation | coordinate-equivocation |
| `negative/stateful/d86-fuzz-m-01986` | epoch-sequence-rollback | coordinate-equivocation | coordinate-equivocation |
| `negative/stateful/d86-fuzz-m-01906` | issuer-sequence-rollback | coordinate-equivocation | coordinate-equivocation |
| `negative/stateful/d86-fuzz-m-01946` | issuer-sequence-rollback | coordinate-equivocation | coordinate-equivocation |
| `negative/stateful/d86-history-issuer-coordinate` (Q1) | conformant | conformant | coordinate-equivocation |
| `negative/stateful/d86-history-epoch-coordinate` (Q2) | epoch-sequence-rollback | epoch-sequence-rollback | coordinate-equivocation |
| `negative/stateful/d86-history-reuse-outranks-rollback` | reuse | epoch-sequence-rollback | reuse |
| `negative/stateful/d86-phase-order-with-prior` | issuer-sequence-rollback | coordinate-equivocation | coordinate-equivocation |
| `negative/stateful/d86-phase-order-without-prior` | coordinate-equivocation | coordinate-equivocation | coordinate-equivocation |
| `positive/stateful/d86-history-exact-represent` (Q3) | epoch-sequence-rollback | epoch-sequence-rollback | conformant, `duplicate_exact` |
| `positive/stateful/d86-history-full-reobservation` | epoch-sequence-rollback | epoch-sequence-rollback | conformant, `duplicate_exact` |

Against v0.3.0 pyref, the rows whose code is unchanged differ in the same
three identity fields as the existing rows. Q1, Q3 and full re-observation
also change result, `limits` and `observations`, as a pass ↔ fail change
must (a failure verdict carries the D-82 failure population). The m-01931
and m-01906 rows have identical bytes and prior (the same mutation recurred
in both fuzz runs) and are kept as two rows, one per recorded finding.

Corpus after re-pin: 526 rows (`pyref/results-c2.json`), 526 matched, 526
deterministic, 0 divergences.

## Round 2: review fixes (2026-10-26)

The review round moved prior-state shape validation into both libraries,
removed the unreachable phase-A reuse pass, and added six rows. v0.3.1 is
unreleased, and its version string and build preimages did not change, so no
verdict re-pins: the 526 rows above are byte-identical to `a6200ea`. Under
`kats/`, the only changes are the 18 files of the six new rows. Every
round-1 entry in `pyref/results-c2.json` is unchanged: result, code, step,
observations, `stateful_properties` and `verdict_sha256`.

The six rows through both v0.3.0 verifiers (`a840688`) and v0.3.1:

| Row | v0.3.0 harness | v0.3.0 pyref | v0.3.1 (both) |
|---|---|---|---|
| `negative/stateful/d86-phase-b-issuer-outranks-epoch-rollback` | epoch-sequence-rollback | epoch-sequence-rollback | issuer-sequence-rollback |
| `negative/stateful/d86-phase-b-equivocation-outranks-rollback` | epoch-sequence-rollback | epoch-sequence-rollback | coordinate-equivocation |
| `negative/stateful/d86-duplicate-not-exempt-from-equivocation` | epoch-sequence-rollback | epoch-sequence-rollback | coordinate-equivocation |
| `negative/stateful/d86-duplicate-not-exempt-from-reuse` | reuse | reuse | reuse |
| `positive/stateful/d86-history-only-conflict` | conformant | conformant | conformant, no `duplicate_exact` |
| `negative/stateful/d86-partial-history-epoch-rollback` | epoch-sequence-rollback | epoch-sequence-rollback | epoch-sequence-rollback |

On the first three rows, v0.3.0 interleaved its checks per receipt and
compared epoch sequences with `<=`, so it reported the first epoch rollback it
met. The last row records unchanged behaviour (`BACKLOG.md`, prior-state
contract).

Corpus after round 2: 532 rows (`pyref/results-c2.json`), 532 matched, 532
deterministic, 0 divergences.

## Round 3: prior-state boundary (2026-10-26)

No row moved. `kats/` and `pyref/results-c2.json` are byte-identical to
`37b6a43` (532 rows), and no row was added. The round closed four ways a
prior state one verifier refuses could still be hashed or signed by the
other:

- The harness typed boundary (`verifyBundle`) and every verdict digest,
  `emitFailureVerdict` included, now refuse malformed history. A typed extra
  field or a hex-string byte field had signed conformant, and the failure
  signer hashed `epoch_seq: false`.
- Uint fields compare by numeric value: pyref reads JSON `1.0`, `1e0` and
  `-0.0` as integers, as `JSON.parse` does for the harness. pyref had refused
  `1.0`, which the harness accepted.
- The library top level is closed to `prior_emissions` and `entries`.
- The pyref CLI reports container and top-level errors with the libraries'
  messages.

Every refusal is a usage error with one message in the harness, the pyref
library and the pyref CLI.
