# Contributing

## Size ratchet

`harness/size-ratchet.test.ts` keeps every `*.ts` and `*.py` under `harness/`, `pyref/`, `demo/`, `adapters/` and `scripts/` (tests included; `node_modules`, anything under `kats/`, generated files and `*.d.ts` excluded) at or under 20,000 bytes. Files that were already over the line are pinned in `harness/size-baseline.json` at their exact byte size and may not grow past it.

When a change would push a file over its limit, split it instead: extract a cohesive responsibility behind a narrow interface, mirror it in the other implementation, preserve behaviour, update imports, run the cross-implementation suites, and lower the baseline.

Baseline upkeep: an entry only moves down, in the same commit that shrinks the file (the test fails on a pinned file that is smaller than its entry). Never raise an entry or add one.

Module shape between the TypeScript harness and the Python reference is reviewed, not enforced: the ratchet measures bytes; whether a split mirrors cleanly across the two implementations is a review question.

## Regenerating fixtures

Order matters: `bun run harness/generate.ts` (clears `kats/positive/`), then `bun run harness/generate-negative.ts` (writes the negative set and the D-77/80/82 repair positives back), then `bun run harness/generate-relying-party.ts`; then `python3 -B -m pyref.kat --slice all` to re-pin. Running `generate-negative.ts` before `generate.ts` loses 20 positive rows.

## Differential fuzz

`bun run harness/difffuzz.ts --seed N --mutants N --out DIR [--chunk 250] [--lanes 3] [--premises] [--legs] [--cli-lane N]`
runs every corpus row through both verifiers first (the baseline must reproduce `pyref/results-c2.json` and the
harness must agree byte for byte), fires eight controls, then mutates seeds with the step-targeted operators in
`harness/difffuzz-operators*.ts`. `--legs` runs the leg oracle over every positive row; `--premises` records which
pyref rejection sites fired (`pyref/batch.py --premises`, inventory from `pyref/premises.py`) and writes
`saturation.json`; `--cli-lane N` sends N sampled mutants plus the relying-party rows through both CLIs.
Findings land under `DIR/<id>/` (`bundle.cbor`, every file input copied under its sha256 name, `inputs.json`, `both.json`);
`DIR/legs.json` breaks `unsupported` (and every other leg outcome) out per leg and per leg/class; `DIR/report.json`
carries the run line, whose one shape is
`run: seed S, planned N / executed E / no-op O / unsupported U mutants, bytes/classification/crash = a/b/c, controls 8/8, baseline 513/513, legs pass/masked/finding/unexpected/unsupported/operator-error = p/m/f/x/u/e, cli disagreements = d of n (or "cli not run"), saturation X % of Y sites (Z excluded), hash-seed-sensitive = h`
(`BACKLOG.md` fuzz item). `harness/difffuzz-out/` is git-ignored; nothing under `kats/` is written by the tool.

Promotion: a finding becomes a fixture by hand — a `bundleFixture` row in `harness/generate-negative.ts`'s
builders (`negative-fixtures.ts`), then the regeneration order above, then `python3 -B -m pyref.kat --slice all`
to re-pin. A re-pin is a version bump; a run result is only ever reported as its run line.
