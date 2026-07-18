# Gate 5 — D2b live-lab plan (Claude-authored, pre-build)

2026-07-18. Operator window OPEN (Matthew, exclusive control confirmed).
This doc locks the FILL-AT-D2 values, records the target substitution
ruling, fixes the live S5/S6 fault-induction approach, and carries the
build constraints for the D2b live runner. Exit bar unchanged from
GATE5-RUBRIC (F17: D2 closes only on live-lab evidence; gate live re-runs
S1 + S3 per exit bar #8).

## Ruling G5-D2b-001 — stream target substituted P3285-LVE → Q6325-LE

The rubric named P3285-LVE (.19) for the stream leg. Preflight 2026-07-18
found it HTTPS-only (port 80 closed — its documented long-standing config),
while the transport witness is HTTP-only upstream by recorded design
(`demo/witness/proxy.ts` rejects non-HTTP targets; TLS interception 501).
Options considered: (a) enable HTTP on the P3285 for the window, (b) teach
the witness upstream TLS, (c) substitute the Q6325-LE (.32), which serves
HTTP. **Operator ruling (Matthew, 2026-07-18): use Q6358-LE + Q6325-LE.**
(b) was rejected — it would mutate the gated demo kit and contradict its
recorded no-TLS-interception decision. Consequence honestly stated: both
lab targets are PTZ-class cameras; the stream leg exercises only
`camera.stream.view` against the Q6325 and makes no fixed-camera claim.
The P3285 remains available for the D3 leg. Two distinct physical devices
are still exercised (topology: one EP/producer + one VAPIX adapter, two
targets, per the frozen topology's VAPIX leg).

## Locked FILL-AT-D2 values

| Placeholder | Value |
|---|---|
| ptz-base-url (`ptz-primary`) | `http://192.168.1.33` (AXIS Q6358-LE, fw 12.9.57) |
| stream-base-url (`fixed-primary`) | `http://192.168.1.32` (AXIS Q6325-LE, fw 12.9.57) |
| digest-username | `root` (both targets) |
| credential-reference | `cam-q6358-vapix` / `cam-q6325-vapix` — resolved at runtime via `cred get` (no shell, secret never on argv/disk/env-file) |
| safe-preset (backend name for `gate5-safe`) | `Home` (preset 1, the camera's only preset; dispatch via `gotoserverpresetname=Home`) |
| safe-preset-position | pan `0.00`, tilt `-44.99`, zoom `1` — **measured** 2026-07-18 by commanding Home and reading back (the earlier parked position 173.94/-0.08/7998 is NOT Home) |
| pan/tilt tolerance | `0.5` degrees each |
| zoom tolerance | `100` units |
| poll-interval-ms | `500` |
| settling-deadline-ms | `15000` (Home settle observed ≤3 s from a 174° swing) |
| request-timeout-ms | `10000` (live; offline 300 ms does not carry) |
| stream-profile | logical `gate5-live` → backend profile `gate5` (created on the Q6325 2026-07-18: `videocodec=jpeg&resolution=1920x1080`; verified `/axis-cgi/jpg/image.cgi?streamprofile=gate5` → 200 `image/jpeg`, 626 KB) |
| stream-minimum-payload-bytes | `4096` |
| exclusiveControl | `true` — operator-set for this window |

**Pre-run park (baseline) position:** pan `173.94`, tilt `-0.08`, zoom
`7998` — the camera's operator park. Runs start here so the S1 move, the
poll-to-tolerance, and the F19 baseline restore are all real observable
motion, and so S6-rejection's position readback is genuinely off-tolerance
from the safe target (see below).

## Camera prep record (2026-07-18) + revert list

Applied by the gate operator inside the window; every item reversible:

| Device | Change | Before | Revert |
|---|---|---|---|
| .33 | `System.BoaProtViewer` | `anonymous` | restore `anonymous` (operator's call — digest-only may be kept) |
| .33 | `PTZ.BoaProtPTZOperator` | `anonymous` | same |
| .32 | `System.BoaProtViewer` | `anonymous` | same |
| .32 | `PTZ.BoaProtPTZOperator` | `anonymous` | same |
| .32 | stream profile `gate5` created | none existed | delete via streamprofile.cgi `remove` |
| .33 | PTZ moved to Home during prep verification | parked 173.94/-0.08/7998 | return to park after window |

Verified post-prep: anonymous `param.cgi` and `ptz.cgi` both 401 on both
devices (fresh connections); digest 200; **Basic auth rejected** (401 with
`--basic`) under `AuthenticationPolicy=recommended` — the "Basic off"
prep requirement holds without a policy change.

## Live S5/S6 fault induction

- **S5 (crash-cut, once, EP+VAPIX):** same mechanics as offline — worker
  process killed at the dispatch-cut marker after the action-bearing send
  to the REAL camera; durable recovery record on disk; resumed EP verifies
  restore against the real device; zero redispatch, transport-witnessed.
  Safe because the dispatched action is `goto Home` (the designated safe
  preset) — an orphaned dispatch leaves the camera at safe.
- **S6-rejection:** induced by a gate-controlled run config whose
  `gate5-safe` backend mapping names a preset absent on the device
  (e.g. `aar-gate5-absent`); the camera rejects, position readback (from
  park, 174° off the safe target) is positively observed off-tolerance →
  `contradicted`. The mock's literal `http_rejected_503` does NOT carry:
  live assertions key on the adapter's evidence semantics
  (`http_rejected_<status>` + `position_observation=outside_tolerance`),
  with the actual VAPIX rejection status recorded as evidence, not
  assumed. Builder surfaces the observed status in FINDINGS if it differs
  in kind (application error inside 2xx vs HTTP error).
- **S6-after-send-timeout:** induced at the WITNESS layer — a
  gate-controlled fault flag on the live witness proxy that forwards the
  upstream request (real dispatch reaches the camera) then withholds the
  response past the request timeout. The dispatch latches (F15), outcome
  is honest `unknown`, and the action is benign (goto safe). This flag is
  demo-kit surface (permitted build surface), clearly labeled, default
  off, and witnessed in the log as an injected fault.

## Build constraints (carried + D2b-specific)

1. No changes under `spec/` wire text, `harness/` verdict logic, or
   `pyref/`. Witness fault flag + live runner are demo/adapters surface.
2. Live entry `adapters/vapix/live/` mirrors `offline/run.ts` shape:
   real witness proxy process (HTTP), `DigestHttpClient` over real
   sockets, cred-get-backed `CredentialProvider` (spawn without shell,
   never print/persist the secret), real `param.cgi` preflight
   (GET only — `basicdeviceinfo.cgi` is a known 401-loop on the Q6325),
   real anchor timing per G5-D1-003.
3. All new logic testable offline: transports/credentials injectable;
   tests run against the existing mock; the live wiring is config.
4. Hygiene sweep runs with the RUNTIME-fetched real secrets as canaries
   (plus transformed variants) across repo + artifact root — zero hits.
   Secrets never appear in fixtures, logs, witness entries, or bundles.
5. Under-determinations → `adapters/FINDINGS.md` (G5-D2b-00x), Claude
   rules. Claude commits on Codex's behalf.
6. Verification unchanged: `python -m pyref verify` with pinned `--at`,
   demo trust policy, `--prior-state` advanced across runs; content
   assertions per exit bar #1; `stateful_not_evaluated` fails the gate.
