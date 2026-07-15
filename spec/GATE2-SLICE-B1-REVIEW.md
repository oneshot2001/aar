# Gate 2, slice B1 — Claude review + rulings
2026-07-14. Reviewed at working tree post-e03bf2b. Independently verified:
`bun test` 10/10 (740 assertions), `bunx tsc -p harness --noEmit` clean,
89 negative fixtures across 15 families, each asserted to its exact
first-failure code; slice-A positive bundle passes steps 1–11.
**Slice B1 ACCEPTED**, with five rulings on WIRE-QUESTIONS-B1.md:

**B1-Q1 — consumption edge: the sentence is authoritative; fix the fixture.**
An inference that consumed an observation's content links it `derived_from`
(consumption IS derivation); `requested_by` claims response-to, not
consumption (per the G1-2 sentence). CONFORMANCE step 10 stands as written.
Fix: the slice-A `receipt-inference-requested` fixture gains a `derived_from`
edge to the observation whose consumption manifest it references (it may keep
`requested_by` alongside); the B1 verifier tightens to `derived_from`-only
resolution. (D-46)

**B1-Q2 — `cose/kid-mismatch`: DELETE the code.** Selection is by kid; the
trigger space is fully covered by `key/not-found`,
`credential/kid-key-mismatch`, and `sig/verify-failed`. Remove from §3 and
from the step-6.7 sentence. Pre-freeze deletion is clean. (D-42)

**B1-Q3 — `credential/algorithm-mismatch`: DELETE the code.** The credential
schema pins `cose_alg=-7`/`curve="P-256"`, so any other value is
`schema/enum-unknown` first. Remove from §3. (D-43)

**B1-Q4 — `identity/reuse`: KEEP, rescope to prior evaluated state.** Within
one bundle it is shadowed by `schema/duplicate-entry`; across evaluations it
is reachable via replay/prior-emission state. Amend the trigger: "One receipt
ID names nonidentical envelope bytes relative to prior evaluated state."
(D-44)

**B1-Q5 — stateful fixtures: ACCEPT a paired format.** Codes requiring prior
evaluated state (`identity/reuse`, `identity/issuer-sequence-rollback`,
`identity/epoch-sequence-rollback`, `replay/one-time-reused` where
applicable) get `kats/negative/stateful/` fixtures: `{name}.bundle.cbor` +
`{name}.prior.json` + descriptor with expected code. Built in B2. (D-45)

## Slice B2 scope (next)
1. Apply B1-Q1..Q5 (spec code deletions + trigger amendment as D-42..D-46;
   fixture + verifier fix; stateful fixture format).
2. Verifier steps 12–19 (graph, epoch state machine, manifest index, Merkle,
   anchors, bundle ranges/coverage, evidence-class qualification) + step 20
   verdict emission per CONFORMANCE §5 (signed verdict envelope, observations,
   limits block).
3. Negative fixtures for every DEFERRED-B2.md code, including the adversarial
   graph set the rubric requires (splice, dangling parent, duplicate identity,
   wrong-attempt authorization, cross-epoch replay, dominator violation) and
   epoch/equivocation set (fork, ID reuse, rollback, two-manifests-one-epoch,
   late insertion).
4. Class-boundary KATs (rubric bar #3): per evidence-class boundary, an
   artifact set satisfying the lower class and failing the higher.
After B2: Claude runs the gate-2 coverage audit against the full rubric KAT
bar; any residue becomes slice C.
