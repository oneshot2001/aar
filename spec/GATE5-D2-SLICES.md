# Gate 5 — D2 sub-slicing (D2a offline / D2b live)

2026-07-16. Matthew's ruling on resume: build the VAPIX adapter offline now
against a mock backend; run the live-lab leg when he opens an
exclusive-control window on the cameras. This file records the split so the
gate trail stays auditable. It does not alter the rubric's exit bar: **F17
stands — a stub or replay server cannot satisfy the gate.** D2a acceptance is
a build gate only; D2 closes at D2b.

## D2a — VAPIX adapter, offline (build + gate now)

Deliverables (Codex builds, Claude gates):

1. **`adapters/vapix/`** — real adapter code, no stub logic inside it:
   - RFC 7616 digest-auth HTTP client. F15 discipline: challenge traffic is
     never dispatch; every action-bearing attempt recorded; consequential
     auto-retries disabled; VAPIX application errors inside HTTP 2xx parsed.
   - Command translation per DEMO-CONTRACT: `camera.ptz.preset` →
     `com/ptz.cgi` goto-preset + position readback poll; `camera.stream.view`
     → one explicitly requested stream response with syntactic media-payload
     validation.
   - F19 PTZ safety protocol implemented as code: baseline position capture
     before any move, restore + verify after every run, poll-to-tolerance
     with hard deadline, zero redispatch during reconciliation,
     exclusive-control window asserted via config flag the live operator
     sets.
   - Effect oracle returning the DEMO-CONTRACT `EffectOracle` shape with
     VAPIX evidence keys (`http_status`, `application_status`, sanitized
     position/tolerance or stream/profile validation values).
2. **Mock VAPIX backend** (test double, lives under `adapters/vapix/mock/` or
   demo test support — clearly labeled): mirrors the real endpoints (digest
   challenge flow, goto-preset, position readback with settling behavior,
   stream payload, rejection + after-send timeout modes for S6) so that
   D2b swaps ONLY base URL + `cred get` credentials + FILL-AT-D2 config.
3. **S1–S6 green offline** through the full path: EP/producer → transport
   witness → VAPIX adapter → mock backend → online oracle → `python -m pyref
   verify` with `--at`, trust policy, `--prior-state` advanced across runs.
   Content assertions per exit bar #1; no `stateful_not_evaluated`.
4. **FILL-AT-D2 values** stay parameterized in config with named
   placeholders; mock supplies mock values. Real preset number, tolerances,
   settling deadline, stream profile land at D2b with Matthew's lab input.
5. Canary-credential hygiene sweep (incl. transformed variants) run against
   the offline corpus — zero hits.

Constraints carried: build on `harness/` (D-56 fixed — real Unix timestamps
now permitted); no changes under `spec/` wire text, `harness/` verdict logic,
or `pyref/`; under-determinations → `adapters/FINDINGS.md`; Claude commits on
Codex's behalf.

## D2b — VAPIX live-lab (needs Matthew's window)

Q6358-LE (.33) PTZ + P3285-LVE (.19) stream; credentials via `cred get` at
runtime; fill FILL-AT-D2 (safe-preset number Matthew designates, tolerances,
settling deadline, stream profile + minimum payload rule); real green
preflight; S1–S6 against the cameras; real anchor timing per G5-D1-003; gate
live re-runs S1 + S3 (exit bar #8); sanitized artifact corpus captured for
D4.
