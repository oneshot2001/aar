# BACKLOG — nightly Astra loop input (Claude writes, Matthew edits)

Rules: loop takes the TOP Ready item only. No `accept:` line → loop does not fire.
Branch `night/YYYY-MM-DD` off `main`. Never push. Never touch `spec/` normative text or `kats/` fixtures.

## Ready
- [ ] `emitter/l2-claude-code/verify.ts`: add `--json` flag printing `{ok, receipts, chain_checks:[{name,pass}], close_present}` to stdout, exit code unchanged — accept: `bun test harness emitter` exits 0 with a new test covering `--json` on an intact chain and on a forked chain.

## Blocked / needs Matthew
- [ ] DESIGN (no accept line, do not loop): "authority crossing" — bind each consequential action to authorizing principal + permitted scope (already partly in the authorization binding), and make the verifier *flag* an action whose parameters exceed the cited authorization's scope, with a negative KAT that demonstrates the flag. Driver: FBI Cyber Strategy 2026 §4.4 ("human review and legal controls" with no mechanism). Needs Claude spec pass on `spec/` first; then split into night-loop items.

## Done
- [x] Wire the L2 emitter tests into the repo test run: `package.json` `test` becomes `bun test harness emitter`; fix anything in `emitter/l2-claude-code/` the run surfaces (tests may use `AAR_L2_DIR` under a tmp dir; no writes outside it) — accept: `bun test harness emitter` exits 0; no changes under `spec/`, `kats/`, `harness/`.
