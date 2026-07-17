# Gate 5 slice D2a review — VAPIX adapter, offline (ACCEPTED)

2026-07-16. Claude gate. Builder: Codex (three passes: build, D-57 fix,
review fix). Slice defined by `spec/GATE5-D2-SLICES.md` (D2a/D2b split ruled
by Matthew on resume; F17 stands — D2 closes only at D2b live-lab).

## What shipped

`adapters/vapix/` — RFC 7616 digest client (SHA-256/MD5, `stale=true`
re-auth witnessed within the same attempt, multi-scheme challenges,
challenge acquisition via harmless position-query endpoint only), command
translation per DEMO-CONTRACT, F19 PTZ safety protocol as code (baseline
capture, restore+verify, poll-to-tolerance with total deadline, zero
reconciliation redispatch, exclusive-control assertion), effect oracle with
sanitized evidence. Separate mock backend mirroring real endpoints (digest
flow, settling, rejection, application-error-in-2xx, after-send timeout,
nonce rotation) so D2b swaps only base URL + `cred get` credentials +
FILL-AT-D2 config. S1–S6 green offline through EP → transport witness →
adapter → mock → online oracle → pyref, content assertions, prior-state
advanced, hygiene sweep clean with transformed canaries.

## Gate cycle

1. **Build pass** verified independently (46/46, tsc, 43/43 + 188/188,
   scenario table, hygiene). Codex findings G5-D2a-005/006 sustained;
   G5-D2a-007 escalated: not a mere pyref crash — a spec under-determination
   in the signed verdict field `maximum_outcome_level` where the two frozen
   implementations diverged (harness last-wins order-dependence; pyref
   KeyError on wire-valid conformant input). Phase-stopped per exit bar #5
   → **D-57** (order-independent, terminal-dominates, contradicted >
   unknown). Codex's nonce-grinding workaround rejected and removed; 3
   terminal-state fixtures added (corpus 188 → 191) with the crash-triggering
   sort order asserted in the KAT test; all 188 pre-existing verdict byte
   sequences proven unchanged (per-verdict SHA-256, before/after).
2. **Independent adversarial review** (reviewer agent, full diff): verdict
   FIX-FIRST. 2 blockers ruled into **G5-D2a-008**: (a) failed post-dispatch
   poll un-declared a physically dispatched action (`dispatched` now latches
   at action-bearing send — F15); (b) rejection mapped to `contradicted`
   with no position observation (now: readback within deadline, never
   redispatching; `contradicted` only on positively observed out-of-tolerance
   position). 5 P2s sustained and fixed (action-URL digest discovery, stale
   nonce, witness body-digest binding restored + VAPIX request-line shape
   assertion, pre-transport refusal → S3-style `not_dispatched` bundle with
   journal intent-close, honesty-trail). One reviewer claim OVERRULED as
   false positive: `pyref/DIVERGENCES.md` was never modified (git-verified).
   Review-clean dimensions: secret hygiene end-to-end, F19 semantics, F15
   challenge accounting, S5 crash-cut single-goto proof, mock fidelity.
3. **Final bar** (gate re-ran everything): bun 54/54 (1,271 assertions),
   tsc clean, pyref C1 46/46, C2 191/191, determinism 191/191, zero
   divergences, S1–S6 green, hygiene 0 hits, no fixture regeneration in the
   fix pass.

## Residue to D2b

FILL-AT-D2 values (safe-preset number, tolerances, settling deadline, stream
profile + minimum payload rule) — Matthew's lab; exclusive-control window —
Matthew's call; real anchor timing (G5-D1-003); live re-runs S1 + S3 by the
gate (exit bar #8); sanitized artifact corpus for D4. Known residuals:
self-asserted adapter identity (rubric F20); lab cameras must have anonymous
viewer/PTZ disabled and Basic auth off (digest discovery hardening assumes
401-first, multi-scheme handled but untested against real firmware).
