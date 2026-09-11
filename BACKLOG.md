# BACKLOG — nightly Astra loop input (Claude writes, Matthew edits)

Rules: loop takes the TOP Ready item only. No `accept:` line → loop does not fire.
Branch `night/YYYY-MM-DD` off `main`. Never push. Never touch `spec/` normative text or `kats/` fixtures.

## Ready
- [ ] Wire the L2 emitter tests into the repo test run: `package.json` `test` becomes `bun test harness emitter`; fix anything in `emitter/l2-claude-code/` the run surfaces (tests may use `AAR_L2_DIR` under a tmp dir; no writes outside it) — accept: `bun test harness emitter` exits 0; no changes under `spec/`, `kats/`, `harness/`.
- [ ] `emitter/l2-claude-code/verify.ts`: add `--json` flag printing `{ok, receipts, chain_checks:[{name,pass}], close_present}` to stdout, exit code unchanged — accept: `bun test harness emitter` exits 0 with a new test covering `--json` on an intact chain and on a forked chain.

## Blocked / needs Matthew

## Done
