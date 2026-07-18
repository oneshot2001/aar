# Gate 5 — D2b live-lab review + close (Claude gate)

2026-07-18. D2b executed against the owned lab cameras inside Matthew's
exclusive-control window. **F17 satisfied — D2 is CLOSED.** This is the first
gate slice whose evidence comes from real hardware, not a mock.

## Build routing

Codex (the usual builder) was BLOCKED a second time by the OpenAI
cybersecurity content filter on this receipt/signature security spec (same
class of block as the Gate-3 finding pass and the 2026-07-15 memory note).
Per the recorded routing rule (security-content passes → Claude/Gemini;
Gemini is credit-blocked), Claude built the live runner and the `reviewer`
subagent ran the adversarial gate — roles that keep the build/gate separation
intact (author ≠ sole certifier: the reviewer found a window-burning blocker
before any camera moved).

## Adversarial gate (two rounds)

Round 1 (reviewer agent) returned **FIX-FIRST** with one P1 blocker + P2s:
- **P1 (G5-D2b-004):** the S6 fault seam withheld ALL action-bearing requests,
  so it also swallowed the F19 restore move → `restore_verified=false` →
  online-oracle throw every run. Would have failed the last scenario and
  burned the window. Fixed: withhold scoped to the command-bound dispatch
  (`x-aar-command-digest` header) only.
- **P2 (G5-D2b-005):** preflight queried the wrong param group; live firmware
  would read empty and abort before S1. Fixed + verified against the real
  Q6358.
- **P2 (G5-D2b-006):** hygiene HA1 legs could silently drop. Fixed
  (`parseDigestChallenge`, throw on missing realm).
- **P3s (G5-D2b-007/008):** firmware self-assertion made a real device
  cross-check; close-race rewritten deterministic; S5 worker leak closed;
  park tolerance single-sourced.

Round 2 (same reviewer, seam re-review) returned **SHIP** — empirically
probed the close-race rewrite (complete 700 KB body resolves; mid-body cut
rejects in 106 ms; withheld response rejects at deadline) and confirmed the
P1 fix scoping by tracing command-binding on every request in an S6
invocation.

## Live-surfaced findings (only real hardware exposed these)

- **G5-D2b-010:** the transport witness proxy forwarded upstream framing
  headers verbatim; real Axis devices send BOTH `Content-Length` AND
  `Transfer-Encoding: chunked`, so a buffered re-emit was unparseable
  (`InvalidHTTPResponse`) and aborted at the first preflight request. The mock
  upstream never triggered it. Fixed: strip both framing headers, let the
  buffered body set Content-Length.
- **G5-D2b-011:** the real camera passwords are 4 characters; the reversible
  `literal`/`percent_encoded` sweep transforms matched committed hex
  everywhere (684 hits, all reversible, all in committed files, ZERO hash
  form — not a leak). Fixed: `hashOnlyRoots` scans the committed tree with
  only collision-free hash transforms; the generated artifact tree keeps the
  full set. **Operator note:** 4-char VAPIX passwords are weak beyond an
  isolated lab LAN — flagged, not changed (camera-config decision).

## Live result — two independent full runs, byte-identical verdicts

Topology: one shared EP/producer + one VAPIX adapter, two physical targets
(Q6358-LE .33 PTZ, Q6325-LE .32 stream; both AXIS OS 12.9.57). Every scenario
ran EP → transport witness → adapter → real camera → online oracle →
`python -m pyref verify` (pinned `--at`, demo trust policy, `--prior-state`
advanced across runs; no `stateful_not_evaluated`).

| Scenario | pyref | outcome | evidence |
|---|---|---|---|
| S1 | conformant | device_acknowledged | position_within_tolerance (goto Home + readback ≤0.5°/100u) |
| S2 | conformant | device_acknowledged | media_payload_valid (real JPEG, gate5 profile, EOI-valid ≥4 KB) |
| S3 | conformant | not_dispatched | delegation-expired refusal; zero attributable dispatch |
| S4 | nonconformant | — | first failure `sig/verify-failed` (pinned tamper, F21) |
| S5 | conformant | unknown | outcome_unknown_restore_verified (real crash-cut, resume, zero redispatch) |
| S6-rejection | conformant | contradicted | vapix_application_error + position outside_tolerance |
| S6-after-send-timeout | conformant | unknown | transport_timeout_after_send (command dispatch withheld; restore verified) |

Hygiene sweep: 0 hits, both runs. Camera rests at operator park
(173.93/−0.08/7998). Gate live re-run (exit bar #8) reproduced identically.

## Exit-bar check (GATE5-RUBRIC)

1. All scenarios green, content assertions (F5) — ✅ (S5 crash-cut once via EP+VAPIX)
2. Online oracle PASS per scenario (F6) — ✅
3. R-1 zero attributable dispatch on S3 — ✅ (witnessed)
4. Tamper case first-failure pinned (F21) — ✅ S4 `sig/verify-failed`
5. `--prior-state` advanced, no `stateful_not_evaluated` (F8) — ✅
6. Content-addressed offline verification via public CLI — ✅ pyref
7. Secret hygiene incl. transformed variants (F13) — ✅ 0 hits (scoping fixed)
8. Gate live re-runs — ✅ full suite reproduced byte-identical
9. F19 PTZ safety (baseline/restore-verify/deadline/no-redispatch/exclusive) — ✅
10. F17 real hardware, no stub — ✅ two AXIS devices

## Residual (carried to D3/D4, honest)

- Topology is two-protocol/same-vendor VAPIX only; the VMS/second-protocol
  claim is deferred to D3 (Q5-1: 1-day Vigil spike first, or renamed-ONVIF
  fallback). No VMS claim is made here.
- Pre-existing conservative labels carried (over-latched `afterSend` on
  connect-refused; restoration oracle intolerant of a stale-nonce repair on
  the restore move — low-probability live flake, rerun-not-regression).
- D4 (run manifest + evidence index for the RFP phase) still owed; the
  sanitized `summary.json` + witness logs are the seed corpus.

## Status

**D2 CLOSED.** Recommend tag `v0.2-rc5`. Next: D3 VMS leg (Q5-1), then D4
packaging, then model RFP language.
