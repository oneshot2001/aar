# Gate 5 close — two-adapter live-lab demo (2026-07-18)

Gate: Claude (author ≠ certifier held throughout: builds were reviewer-gated;
Codex was content-filter-blocked twice on this security spec, per the gate-3
precedent, so Claude built under the same rules with the `reviewer` agent as
the independent certifier on every slice).

## Slice trail

| Slice | Result | Record |
|-------|--------|--------|
| D1 shared demo kit | ACCEPTED; flagship catch = D-56 uint32 encoder defect → `v0.2-rc3` | GATE5-RUBRIC.md, adapters/FINDINGS.md G5-D1-* |
| D2a VAPIX offline | ACCEPTED; D-57 verdict-order ruling → 191 fixtures | GATE5-D2A-REVIEW.md |
| D2b VAPIX live | CLOSED on real hardware (F17) → `v0.2-rc5` | GATE5-D2B-PLAN.md / GATE5-D2B-REVIEW.md |
| D3 Vigil VMS leg | CLOSED live; VMS-mediated + 2nd independent impl claim | GATE5-D3-PLAN.md / GATE5-D3-SPIKE.md / GATE5-D3-REVIEW.md |
| D4 packaging | SHIPPED reviewer-gated (`688dedc`) | demo/README.md, demo/results/run-manifest.json |

## Exit bar — gate re-ran everything (2026-07-18, this close)

1. **Scenarios green on both legs, with content assertions (F5):** gate
   re-ran the FULL live suites (not just the S1+S3 minimum) inside an
   operator-authorized exclusive-control window (`AAR_LIVE_WINDOW=1`, F19).
   VAPIX: S1–S5 + S6-rejection + S6-after-send-timeout. VMS (vigil-control →
   VigilCore VAPIXClient → real cameras): S1–S4 + S6 both variants. Every
   verification/outcome/application_status identical to the committed D2b/D3
   evidence records. S5 crash-cut via EP+VAPIX (Q5-2).
2. **Online oracle PASS** per scenario per adapter.
3. **R-1 (S3):** zero invocation-attributable dispatch on both legs, by
   instrumentation + transport witness.
4. **Hygiene:** canary-credential sweep 0 hits on both re-runs, transformed
   variants + hashOnlyRoots scoping (G5-D2b-011) in effect.
5. **Diff-clean:** no changes under `spec/` wire text, `harness/`, or
   `pyref/` since `v0.2-rc6`; D4 was docs-only.
6. **Suites:** full Bun+TS 68/68 (this session); pyref 46/46 + 191/191 + 0
   divergences (per rc6 record; pyref untouched since).
7. **Prior-state discipline:** prior state supplied on every gated run; zero
   `stateful_not_evaluated` occurrences in either re-run's artifacts.
8. **Live re-runs by the gate:** satisfied above — real Q6358-LE (PTZ) and
   Q6325-LE (stream), AXIS OS 12.9.57, via both the direct VAPIX adapter and
   the actual Vigil backend. Cameras rest at park.

## Claim of record

The demo proves the AAR v0.2 receipt/verdict chain end-to-end on real
hardware through two independent implementations (TypeScript direct-VAPIX;
Swift Vigil-mediated). The VMS leg is **VMS-mediated + second independent
implementation — NOT second-protocol or cross-vendor** (GATE5-D3-REVIEW.md).
Anchoring is same-operator demo anchoring (F22). Known residuals:
demo/results/run-manifest.json `known_residuals`.

## Open items leaving the gate

- Model RFP language (phase 5) — next.
- ONVIF second-protocol leg stays available as a later additive claim.
- Noticed-not-fixed: GATE5-D2B-REVIEW.md:93 "two-protocol/same-vendor"
  wording reads as a typo for one-protocol/two-target — rename wording is
  Matthew's call.

**GATE 5 CLOSED.**
