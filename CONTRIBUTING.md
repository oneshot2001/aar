# Contributing

## Size ratchet

`harness/size-ratchet.test.ts` keeps every `*.ts` and `*.py` under `harness/`, `pyref/`, `demo/`, `adapters/` and `scripts/` (tests included; `node_modules`, anything under `kats/`, generated files and `*.d.ts` excluded) at or under 20,000 bytes. Files that were already over the line are pinned in `harness/size-baseline.json` at their exact byte size and may not grow past it.

When a change would push a file over its limit, split it instead: extract a cohesive responsibility behind a narrow interface, mirror it in the other implementation, preserve behaviour, update imports, run the cross-implementation suites, and lower the baseline.

Baseline upkeep: an entry only moves down, in the same commit that shrinks the file (the test fails on a pinned file that is smaller than its entry). Never raise an entry or add one.

Module shape between the TypeScript harness and the Python reference is reviewed, not enforced: the ratchet measures bytes; whether a split mirrors cleanly across the two implementations is a review question.
