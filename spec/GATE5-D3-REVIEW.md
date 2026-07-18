# Gate 5 — D3 Vigil VMS leg: review + close

2026-07-18. Plan: spec/GATE5-D3-PLAN.md. Spike: spec/GATE5-D3-SPIKE.md.
Commits: `eaa512e` (step 1 mediator) → `6c600b9` (step 2+3 adapter + offline
suite) → `71ee00d` (round-1 review fixes) → this close.

## Claim boundary (the sentence of record)

**D3 demonstrates VMS-mediated dispatch and a second independent adapter
implementation (Swift `VigilCore.VAPIXClient` vs D2b's TypeScript
`DigestHttpClient`). It does NOT claim a second wire protocol or cross-vendor
support — Vigil speaks VAPIX to the same Axis devices.** ONVIF remains
available as a later additive second-protocol leg if an RFP needs that claim.

## What was proven

Topology: EP (TS) → transport witness → vigil-control (Swift, loopback,
wraps `VigilCore.AxisEngine.VAPIXClient`; Vigil source unmodified) → owned
cameras (Q6358-LE .33 PTZ / Q6325-LE .32 stream, both AXIS OS 12.9.57).
The witness sits at the AAR→mediator boundary; the device-facing VAPIX wire
is the mediator's internal effect channel (F16: ambient VMS↔device chatter
excluded). The action-bearing dispatch POST body is the canonical command
CBOR (witnessed `request_body_sha256` == committed command digest), and
vigil-control independently refuses `sha256(body) != digest`.

Adversarial gate (Codex content-blocked on this spec — 3rd time — so the
reviewer agent gated; author≠certifier held): round-1 FIX-FIRST with 2 P1
(G5-D3-001 fabricated all-zeros position on error-in-200; G5-D3-002 stream
contradicted-without-observation), 4 P2, 7 P3 → all fixed or ruled →
round-2 verified fixes independently → SHIP.

## Live result (2026-07-18, two independent full runs, identical verdicts)

- S1 conformant · device_acknowledged · position_within_tolerance (real
  park→Home via mediator, poll to 0.5°/100u tolerance, F19 restore verified,
  exactly one unbound restore dispatch witnessed)
- S2 conformant · device_acknowledged · media_payload_valid (real JPEG via
  the VMS snapshot seam, ≥4 KB, mediator-validated SOI/EOI)
- S3 conformant · not_dispatched (delegation-expired refusal; zero
  invocation-attributable mediated dispatch, witnessed)
- S4 nonconformant · first failure sig/verify-failed (pinned tamper, F21)
- S6-rejection conformant · contradicted · position_outside_tolerance
  (absent backend preset = error-in-200 the VMS seam reports "ok" —
  G5-D3-003 — so the positive contrary evidence is the readback: the camera
  demonstrably did not move to gate5-safe)
- S6-after-send-timeout conformant · unknown · transport_timeout_after_send
  (witness withheld only the command-bound dispatch; the real move happened,
  F19 restore still completed and verified)

Every run: EP → witness → vigil-control → camera → online oracle (shared +
`adapters/vms/oracle.ts` mediation/restore discipline, per round-2
checkpoint) → `python -m pyref verify` (pinned --at, trust policy,
prior-state advanced). Preflight through the witnessed mediator channel:
device identity (model/serial) + firmware READBACK via new `/device/info` op
(G5-D2b-007 parity), park-position readback = the G5-D3-001 zero-sentinel
sanity check. Hygiene sweep 0 hits both runs (full transforms over artifact
tree, hash-only over committed tree). Camera rests at operator park.
Artifacts: ~/.aar-demo/d3-*; sanitized manifest adapters/vms/live/evidence/.

## Deltas ruled this gate

G5-D3-001 (zero-sentinel vs fabricated position; residual: non-zero
fabrication passes, mitigated by preflight park readback), G5-D3-002 (stream
outcome calibration: contradicted only on positively observed contrary
result), G5-D3-003 (stream profile echo-only through the VMS seam; live
S6-rejection signal is position-based, not http_rejected_N). Ledger with
closed verification_gap: adapters/FINDINGS.md.

## Status

**D3 CLOSED.** Remaining in Gate 5: D4 packaging (run manifest + evidence
index for RFP language). S5 crash-cut ran once on the EP+VAPIX leg (Q5-2);
the VMS leg encodes outcome_unknown via S6-after-send-timeout, as ruled.
