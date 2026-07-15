# Gate 4 slice C2 review — verifier equivalence + divergence adjudication

2026-07-15. Builder: Codex (clean-room per GATE4-RUBRIC). Gate: Claude.

## Result: ACCEPTED WITH RULINGS — 20 divergences adjudicated, fix passes ordered

Corpus: 188 fixtures. Agreement: 168 full / 172 on result+reason. 20 recorded
divergences, zero silent fudging (verified: pyref exits nonzero while
divergences stand). Verdict determinism 188/188 byte-identical. Stateful 3/3.
Positives 33/33 conformant. C1 regression 43/43. Clean-room held (no
`harness/` reads; the gate did read `harness/` — the gate is not clean-room
bound, and fixture-generator source is what settles construction intent).

**This slice did exactly what the phase exists for.** The 20 divergences
decompose into six families; adjudication of each against spec text, fixture
construction (`negative-fixtures.ts`), and the reference verifier found: two
genuine spec gaps, one reference-implementation defect with a fail-open path,
one locked decision the reference implementation violates (pyref was RIGHT),
and two pyref bugs. Rulings are now normative as CONFORMANCE errata + D-52..D-55.

## Rulings

**R1 — class-boundary reporting (#1–4): pyref bug.** Verdict result/reason
agree on all four; only pyref's boundary-class *reporting* dimension is wrong
(self-diagnosed by the builder). Fix pyref's reporter. No spec change.

**R2 — credential status family (#6–11): spec gap → D-52.** Fixtures mutate
and re-identify the stapled snapshot, leaving the decision's
`status_snapshot_ids` dangling — two defects coexist. Pyref's reference-first
reading (`status-missing`) was textually defensible; the reference
implementation's content-first order is ADVERSARIALLY correct (reference-first
lets a producer mask `compromised` behind `status-missing`). Content-before-
reference is now normative (step 8 rewritten). Fix pyref.

**R3 — delegation family (#12–15): spec gap + reference-implementation
DEFECT → D-53.** Fixtures mutate the top-level delegation; the authorization's
embedded copy stays valid. The reference verifier only reaches the expected
codes via an unspecified fallback — "if the decision reference fails and
exactly one delegation is carried, evaluate that one" — and silently SKIPS
delegation evaluation when the heuristic fails (fail-open,
`verifier.ts` step-11 region). Ruling: the embedded delegation is the one
evaluated; `decision.delegation_id` must equal it; no heuristics; never skip.
Consequence: the reference verifier is fixed, and the four fixtures are
REBUILT to mutate the embedded delegation with full cascade (delegation_id →
decision → decision_commitment → authorization re-sign → receipt_id) so the
expected codes are reachable under D-53. Pyref then implements D-53.

**R4 — epoch/late-insertion (#16): pyref bug.** `rebuildManifest` calls
`rebuildEventChain`, so the fixture's close event and manifest agree on the
deadline; per the reason-code table, `epoch/anchor-deadline` must not fire.
Fix pyref's anchor-deadline predicate. Intra-step order is now normative
(D-54) for all such multi-defect cases.

**R5 — manifest-index family (#17–20): spec gap → D-54.** Fixtures mutate
entries without recomputing the root, so a root mismatch genuinely coexists
with each specific defect; the spec never ordered the root comparison. Ruling:
entry-level requirements in listed order, root comparison LAST (matches the
reference implementation; keeps specific diagnostics reachable; fixtures stay
as-is). Step 15 rewritten. Fix pyref.

**R6 — bundle/artifact-out-of-scope (#5): PYREF CORRECT → D-55.** D-19 locked
"range proofs carry every objective index entry in the selected time slice,
including nonmatching kinds/subjects." The reference implementation's step-18
check compares entries against selector-MATCHING entries only, and its fixture
generator (`makeCompleteRange`) filters the slice the same way — both violate
D-19. Pyref enforced the locked decision and correctly failed the fixture's
matching-only range with `bundle/range-boundary`. Consequence: fix the
reference verifier's step 18, fix `makeCompleteRange`, regenerate affected
fixtures (the out-of-scope fixture then fails with its intended code in both
implementations). This is the flagship gate-4 catch: the second implementation
caught the FIRST one violating a locked decision — the exact failure class
residue #6 exists to flush out.

**Entry-point convention (builder finding): ACCEPTED.** For standalone
`aar-wire-object` fixtures, the C2 runner verdicts them in the published
positive bundle's trust/scope context with `bundle_digest` bound to the exact
standalone fixture bytes. Recorded here as the KAT-harness convention;
non-normative for production verifiers (which verify bundles).

## Fix passes ordered (sequence is deliberate)

1. **Errata (this commit, Claude):** CONFORMANCE §2 preamble, steps 8/13/15/18;
   DECISIONS D-52..D-55.
2. **Run A (Codex, harness side — no pyref access):** reference verifier fixes
   (D-53 delegation selection + fail-open removal; D-55 step-18 full-slice
   check; D-54 intra-step order audit), `makeCompleteRange` fix, delegation
   fixture family rebuilt with cascade, corpus regenerated, 16/16 tests green.
   Claude gates.
3. **Run B (Codex, pyref side — clean-room, no harness reads):** pyref fixes
   per R1/R2/R4/R5 + D-53/D-55 alignment, re-run against the regenerated
   corpus. Bar: 188/188 result+reason agreement, zero divergences. Claude
   gates → GATE4-CLOSE for the verifier-equivalence bar.

Residue #6 closes only after Run B gates clean. Then slice C3 (public CLI
packaging) proceeds per the rubric.

## Run A gate result (2026-07-15): ACCEPTED

Codex implemented A1–A6. Gate verified independently: `bun test` 16/16
(1,152 assertions), `bunx tsc -p harness/tsconfig.json --noEmit` clean, the
cardinality-fallback/fail-open code is gone (D-53 selection now: embedded
delegation per authorization, `decision.delegation_id` equality,
`graph/dominator-missing` on mismatch; delegation lifecycle codes now fire
from step 13, their natural home), step 18 checks the full half-open temporal
slice with selector predicates applied locally (D-55), `makeCompleteRange`
builds full-slice ranges, and the four delegation fixtures mutate the embedded
delegation with full cascade. Changed fixture bytes are exactly the five
expected (`bundle-artifact-out-of-scope` +4 KB from the full slice; the four
delegation fixtures same-size). Run A also found and fixed three FURTHER
intra-step order deviations under D-54 (step 5 root-records-before-time,
step 14 monotonicity/late-insertion/deadline/fork order, step 15 uniqueness-
before-equality) — evidence the D-54 pin was needed beyond the observed
divergences. Corpus regenerated; positives byte-stable.
