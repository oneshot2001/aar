# BACKLOG — nightly Astra loop input (Claude writes, Matthew edits)

Rules: loop takes the TOP Ready item only. No `accept:` line → loop does not fire.
Branch `night/YYYY-MM-DD` off `main`. Never push. Never touch `spec/` normative text or `kats/` fixtures.

## Ready

## Strategy (2026-09-27, Codex-pair settled, Matthew accepted)
v0.2 stays experimental. No v1.0 freeze until the blockers below clear AND one independent
integrator (VMS/export tool + evidence recipient) is working one workflow against the spec.
No Rust core, no Go port, no extra bindings until a named integrator asks; then ship exactly
the artifact they ask for. Derivation Record stays a sibling in the SDR family, not an AAR
profile. Venue work item: position against IETF SCITT (RFC 9943/9942) and the two individual
drafts on the same square — draft-mih-scitt-agent-action-capsule, draft-noa-scitt-ai-agent-receipt.

## v1.0 freeze blockers (DESIGN — spec/ + kats/ changes, Claude spec pass first; never night-loop)
- [ ] **Rollback history not committed to the verdict.** `replay_state_digest` preimage is `{entries:[...]}` only (CONFORMANCE.md:718); `prior_emissions` drives `identity/*-rollback` (pyref/verifier.py:1069) but is not hashed into `trust_policy` (verifier.py:2038). Empty vs. unrelated prior state → byte-identical signed verdicts. Choice: add `prior_state_digest` (32 zero bytes when absent, mirroring replay) rather than widening the replay preimage — keeps the two inputs separately auditable. Alternative: fold `prior_emissions` into the replay map. Verdict shape changes → v0.2.1 wire + regenerate verdict KATs.
- [ ] Verifier identity / trust provisioning for an unrelated verifier (CONFORMANCE.md:322, D-58) — define how a stranger's verifier supplies identity + trust policy without producer cooperation.
- [ ] Normative dependency "EdgeProof SDR v1.1 @ b9d7bc6" (CONFORMANCE.md:3) — vendor the governing text or cite an immutable retrievable document.
- [ ] Closed action schema (view + PTZ presets; no parameter constraints in delegation scope — aar-core.cddl:659) vs. "general gateway core" claim — pick narrow v1 explicitly and write extension/version rules.
- [ ] Mandatory RFC 6979 deterministic signing (aar-core.cddl:12, D-02) — test against a non-exportable-key signer before it's a MUST; separate deterministic payloads/KATs from production signature-byte identity.
- [ ] D-73 open-before-close rule unexercised (DECISIONS.md:1206) — mutate + re-sign a coherent event chain so the check is actually reached.
- [ ] Gateway contract under-specified for a profile: admission boundary, durable commitment, retries, duplicate execution, crash-after-dispatch, uncertain outcome, evidence-store exhaustion; reconcile D-66 life-safety exception with "fail-closed" language (docs/gateway-hook-mapping-v0.1.md:92).

## Blocked / needs Matthew
- [ ] DESIGN (no accept line, do not loop): "authority crossing" — bind each consequential action to authorizing principal + permitted scope (already partly in the authorization binding), and make the verifier *flag* an action whose parameters exceed the cited authorization's scope, with a negative KAT that demonstrates the flag. Driver: FBI Cyber Strategy 2026 §4.4 ("human review and legal controls" with no mechanism). Needs Claude spec pass on `spec/` first; then split into night-loop items.

## Done
- [x] `emitter/l2-claude-code/verify.ts`: add `--json` flag printing `{ok, receipts, chain_checks:[{name,pass}], close_present}` to stdout, exit code unchanged — accept: `bun test harness emitter` exits 0 with a new test covering `--json` on an intact chain and on a forked chain.
- [x] Wire the L2 emitter tests into the repo test run: `package.json` `test` becomes `bun test harness emitter`; fix anything in `emitter/l2-claude-code/` the run surfaces (tests may use `AAR_L2_DIR` under a tmp dir; no writes outside it) — accept: `bun test harness emitter` exits 0; no changes under `spec/`, `kats/`, `harness/`.
