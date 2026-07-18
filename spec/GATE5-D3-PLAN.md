# Gate 5 — D3 Vigil VMS leg build plan (Matthew chose Option A)

2026-07-18. Spike succeeded (spec/GATE5-D3-SPIKE.md); Matthew ruled **Option A
— Vigil VMS leg**. This plan locks the architecture (the witness-boundary
question the spike left for build) and the honest claim boundary.

## Claim boundary (on the record, per Matthew's ruling)

D3 demonstrates **VMS-mediated dispatch** + a **second independent adapter
implementation** (Swift `VigilCore.VAPIXClient` vs D2b's TypeScript
`DigestHttpClient`). It does **NOT** claim a second wire protocol or
cross-vendor — Vigil speaks VAPIX to the same Axis devices. GATE5-CLOSE must
say this in those words. ONVIF (a genuine second protocol) stays available as
a later additive leg if the RFP needs that specific claim.

## Architecture (resolved)

```
AAR EP/producer (TS) ── abstract command
  └─> transport witness (HTTP proxy)         [observes the AAR→mediator boundary]
        └─> vigil-control (Swift HTTP service, wraps VigilCore.VAPIXClient)
              └─> Axis camera (VAPIX wire)   [the mediator's internal business]
```

**Why the witness sits at the AAR→mediator boundary, not device-facing:** for
a VMS-mediated architecture the meaningful, independently-observable fact is
whether the EP handed a dispatch command to the VMS at all. That is exactly
what S3's zero-attributable-dispatch proof needs (the refusal happens before
the VMS is ever asked to act), and it matches the rubric's own F16 note that
ambient VMS↔device chatter is excluded. The device-facing VAPIX is the
mediator's internal effect channel, reported as effect evidence (readback /
media validation), not as the attribution witness. This also keeps **Vigil
source unmodified** — no URLSession-proxy or per-request-header changes to
`VAPIXClient` are needed.

**vigil-control** (new, lives in the AAR repo at `adapters/vms/vigil-control/`
as a SwiftPM executable with a path dependency on `~/Projects/vigil/VigilCore`;
Vigil untouched):
- HTTP service (swift-nio, already a VigilCore dep) on loopback.
- Accepts the AAR abstract command as JSON: `camera.ptz.preset` (preset name)
  and `camera.stream.view` (profile), plus a position-readback query.
- Resolves camera credentials itself via `cred get <reference>` (no shell,
  secret never crosses argv/stdin — mirrors D2b's CredStoreProvider).
- Executes via `VigilCore.AxisEngine.VAPIXClient`
  (`ptzGotoPreset` / `ptzGetPosition` / `getSnapshot` or `getStreamProfiles`).
- Returns the DEMO-CONTRACT `EffectOracle` shape with VMS-adapter evidence
  keys (`http_status` analog, `application_status`, sanitized
  position/tolerance or stream/profile validation). Adapter identity = `vms`.

**AAR TS side** — a `VmsAdapter` in `adapters/vms/` implementing the same
`DemoAdapter` interface as `VapixAdapter`, dispatching by calling
vigil-control through the transport witness (the TS adapter sets the x-aar-*
instrumentation headers exactly as D2b does). F19 PTZ safety
(baseline-capture / restore-verify / poll-to-tolerance / no-redispatch /
exclusive-control) stays orchestrated in the TS adapter layer, issuing
baseline+restore as separate mediated commands — same discipline as D2b, so
the crash-cut (S5) and reconciliation semantics carry unchanged.

## Scenarios (rubric D3: S1–S4 + S6 + outcome_unknown encoding)

Same abstract commands as VAPIX. S5 crash-cut runs ONCE via EP+VAPIX (Q5-2) —
the VMS leg only has to demonstrate it can ENCODE `outcome_unknown` (S6-timeout
covers that), it does not re-run the physical crash. S1 authorized-PTZ, S2
stream-view, S3 expired-delegation refusal (zero mediated dispatch, witnessed),
S4 shared tamper (pinned, reused), S6 rejection + after-send timeout.

## Build constraints (carried)

- No changes under `spec/` wire text, `harness/` verdict logic, `pyref/`, or
  the Vigil repo. New surface = `adapters/vms/` (TS) + `adapters/vms/vigil-control/`
  (Swift, path-dep on VigilCore).
- Everything offline-testable: a mock vigil-control (or a VigilCore stub
  transport) stands in so `bun test` stays hermetic; the live leg swaps in the
  real service + real cameras.
- Verification unchanged: `python -m pyref verify`, pinned `--at`, prior-state
  advanced, content assertions, no `stateful_not_evaluated`.
- Adversarial reviewer gate before any live run (Codex still content-blocked
  on this spec); Claude commits.
- Demo-env assumption documented in DEMO-CONTRACT: vigil-control requires the
  Vigil repo checked out at the path dependency location.

## Steps

1. Scaffold `adapters/vms/vigil-control/` — SwiftPM executable, path-dep on
   VigilCore, HTTP service driving VAPIXClient; prove it builds and drives the
   real camera (readback + a witnessed goto) headlessly.
2. TS `VmsAdapter` implementing `DemoAdapter`, dispatching through the witness
   to vigil-control; F19 orchestration mirrored from `VapixAdapter`.
3. Offline harness (mock vigil-control) — S1–S4 + S6 green through pyref.
4. Reviewer gate → live run (S1–S4 + S6 vs cameras) → pyref → hygiene.
5. GATE5-D3-REVIEW.md close with the explicit claim-boundary sentence.
