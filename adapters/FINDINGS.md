# Gate 5 findings

## G5-D1-001 — no exported harness receipt/bundle builder API

- Status: RULED (Claude gate, 2026-07-15): D1 reading sustained — demo builders
  reuse harness primitives and follow the preimages; do not export or import
  fixture builders. Documentation gap only, non-wire.
- Was: open; documentation/producer API question, non-wire.
- Contract relied on: “receipt DAG construction ... via harness builders” and
  “build on `harness/` (deterministic CBOR encoder, COSE, Merkle).”
- Finding: `harness/fixtures.ts` contains the only receipt/bundle builders, but
  they are private functions coupled to published KAT keys and fixed KAT
  coordinates. D1 cannot use them with distinct demo keys without modifying
  `harness/`, which the slice forbids.
- D1 reading: implement demo producer builders that import and reuse the
  harness CBOR, hashing, and Merkle primitives, and follow the fixture builder
  preimages exactly. Do not import fixture builders or KAT private keys.

## G5-D1-002 — refusal DAG termination

- Status: RULED (Claude gate, 2026-07-15): sustained — a refusal terminates at
  `action_attempt` (`not_dispatched`); fabricating dispatch/outcome receipts
  for an action that never dispatched would itself violate honesty calibration.
- Was: open; demo-content question, non-wire.
- Contract relied on: S3 requires “refusal receipted as `action_attempt` +
  `not_dispatched`” and zero invocation-attributable dispatch, while the D1
  topology lists the general DAG through dispatch and outcome observation.
- Finding: the rubric does not say whether a refusal should fabricate later
  receipt kinds.
- D1 reading: S3 terminates at the `action_attempt`. It emits neither dispatch
  nor outcome-observation receipts because no dispatch/effect exists.

## G5-D1-003 — local log integration before live anchor timing exists

- Status: RULED (Claude gate, 2026-07-15): sustained — no manufactured wire
  anchor record in D1; add at D2 with real submitted/accepted timing.
- Was: open; demo-content question, non-wire.
- Contract relied on: D1 requires a minimal local RFC 6962 v1 log and describes
  same-operator demo anchoring, but D2 owns the real transport/effect timing.
- Finding: the rubric does not pin whether D1 synthetic bundles must carry a
  wire anchor record or only exercise the local log.
- D1 reading: append the signed epoch-manifest payload digest to the local log
  and pin that head in trust inputs. Do not manufacture a wire anchor record in
  D1; add it once D2 can commit real submitted/accepted timing and target data.

## G5-D1-004 — harness encoder loses the high byte of uint32 values

- Status: ADJUDICATED → **D-56** (spec/DECISIONS.md): reference-encoder defect,
  non-wire. Encoder fixed, boundary KATs added, corpus regenerated with the
  intended lab-era times, five corruption-era constants restored, two-impl bar
  re-met (harness 30/30; pyref 43/43 + 188/188, 0 divergences). `v0.2-rc3`.
  D2 may use real Unix timestamps; the D1 sub-2^24 workaround is obsolete.
- Was: open; build-on implementation blocker for lab-era Unix time,
  non-wire if corrected in the harness implementation.
- Contract relied on: “MUST build on `harness/` (deterministic CBOR encoder,
  COSE, Merkle)” and D1’s prohibition on modifying `harness/`.
- Finding: `harness/cbor.ts` encodes the first payload byte of a four-byte
  unsigned integer as `value / 2^32` rather than the high uint32 byte. For
  example, `1800000000` encodes as `1a0049d200` and decodes as `4837888`.
  The committed positive KAT likewise carries `7636552` rather than its source
  builder's `1735689800`. A Gate 5 run using a current Unix timestamp therefore
  fails pyref step 5 because carried `evaluation_time` differs from `--at`.
- D1 reading: do not fork the frozen harness or silently introduce a second
  CBOR stack. Synthetic tests use a gate-pinned time below `2^24`. D2 needs an
  adjudicated harness implementation fix (with regenerated KAT impact audited)
  or an explicit ruling that Gate 5 evaluation times remain below this bound.

## G5-D2a-005 — S4 pinned tamper byte and reason are not supplied

- Status: RULED (Claude gate, 2026-07-16): D2a reading sustained — the pin
  (`artifacts.requests[0]` COSE signature byte 0 XOR `0x01`, expected first
  failure `sig/verify-failed`, exit 1) is now the F21 scenario spec of record;
  D2b live runs reuse it unchanged. Non-wire.
- Was: OPEN; D2a scenario-definition question, non-wire.
- Contract relied on: “One shared tamper case (F21): pinned byte in a pinned S1
  artifact, expected first-failure reason code pinned in the scenario spec.”
- Finding: neither the rubric nor the D2a slice contains the referenced scenario
  spec, byte location, or expected reason code.
- D2a reading: pin `artifacts.requests[0]` COSE signature byte 0, XOR it with
  `0x01`, and require pyref exit 1 with first failure `sig/verify-failed` at
  step 6. The untampered produced bundle still receives the S1 content and
  online-oracle assertions.

## G5-D2a-006 — designated-preset position source is not defined

- Status: RULED (Claude gate, 2026-07-16): D2a reading sustained —
  `presetPositions["gate5-safe"]` is a runtime configuration value supplied
  outside the repository; D2b records the owned camera's designated
  safe-preset position at lab configuration (FILL-AT-D2). Non-wire.
- Was: OPEN; D2a configuration question, non-wire.
- Contract relied on: “The oracle compares device-reported pan/tilt/zoom to the
  designated preset.”
- Finding: the contract names the preset mapping and tolerances but does not say
  how the numeric designated-preset position reaches the adapter/oracle.
- D2a reading: require a named `presetPositions["gate5-safe"]` runtime value.
  The mock supplies its test value; D2b records the owned camera's designated
  safe-preset position during lab configuration and supplies it outside the
  repository.

## G5-D2a-007 — pyref terminal-outcome artifact-order crash

- Status: ADJUDICATED → **D-57** (spec/DECISIONS.md): NOT merely a pyref
  implementation defect — a spec under-determination in a **signed verdict
  field** (`maximum_outcome_level`), where the two implementations improvised
  divergently (harness: last-wins order-dependence; pyref: KeyError crash on
  wire-valid conformant input). Phase-stopped per exit bar #5 protocol.
  Aggregation pinned order-independent, terminal-dominates (contradicted >
  unknown > ranked levels); both implementations corrected; the D2a
  nonce-grinding workaround removed; ranked-after-terminal and dual-terminal
  fixture coverage added; existing corpus verdict bytes shown unchanged;
  two-impl bar re-met.
- Was: OPEN; reference-verifier implementation defect, non-wire.
- Contract relied on: “Verification always goes through the other stack:
  `python -m pyref verify`” and the DEMO-CONTRACT downgrade to “`unknown` or
  `contradicted`.”
- Finding: artifact arrays must sort receipts by receipt ID. In pyref's step-19
  evidence loop, an ID-sorted `unknown` or `contradicted` outcome observation
  encountered before the `accepted` or `dispatched` receipt sets the running
  maximum to a terminal label; the later rank lookup then raises `KeyError`
  instead of returning a verdict. The TS verifier uses a guarded lookup.
- D2a reading: do not modify pyref or the wire. For terminal outcomes, the demo
  producer deterministically varies the outcome receipt's valid freshness nonce
  until its receipt ID sorts after the action-attempt and dispatch receipt. The
  carried wire level remains the frozen `unknown`/`contradicted` value.

## G5-D2a-008 — rejection mapped to `contradicted` without positive contrary observation

- Status: RULED (Claude gate, 2026-07-16, from the independent adversarial
  review of the D2a diff): demo bug, non-wire — the DEMO-CONTRACT downgrade
  table was already correct and the adapter deviated from it. An HTTP
  rejection or VAPIX application error observes nothing about position;
  D-57's own rationale defines `contradicted` as a positive observation of
  contradiction, not absence of evidence. Fix: on PTZ rejection/application
  error the adapter MUST attempt a position readback within the settling
  deadline (never redispatching the move); report `contradicted` ONLY when an
  out-of-tolerance position is positively observed; otherwise `unknown`.
  S6-rejection may legitimately remain `contradicted` iff the readback
  positively observes the camera off-preset. The stream-side
  `media_payload_invalid` mapping on HTTP 200 stands — there the observed
  response IS the effect channel.
- Contract relied on: DEMO-CONTRACT outcome table — "`unknown` or
  `contradicted` when contrary position is positively observed."
- Companion review blocker: a failed post-dispatch position poll must never
  un-declare a dispatch that left the transport (`dispatched` latches true
  once the action-bearing request resolves or fails after send); a false
  non-dispatch claim orphans a physically dispatched action (F15).

## G5-D2b-002 — Bun HTTP client emits only "close" (not "error") when the request is destroyed

- Status: RULED (Claude, 2026-07-18, during D2b live-runner build).
- Context: the DigestHttpClient (`adapters/vapix/digest.ts`) settled its
  request promise only on the `response` callback or an `error` event. Under
  Bun 1.3.x, a client request destroyed by a deadline timer — or by an
  after-send fault where the upstream never replies — emits `close` with no
  `error`. The promise never rejected, so the S6-after-send-timeout path (and
  any real socket-death after send) would hang instead of surfacing an honest
  `transport_timeout_after_send`.
- Fix: added a `close` handler that rejects with a DigestTransportError
  carrying `afterSend = sent`, preserving the F15 dispatch-latch semantics
  (a close after the bytes left the socket is an after-send fault → dispatch
  latches, outcome is honest `unknown`). Because `close` also fires just
  before a normal response's `end`, the close-rejection is deferred one
  macrotask and gated by the same `finish()` latch, so a completed response
  always wins. Verified by event-ordering probe (response → data → req-close
  → res-end) and by the live-runner test suite.
- Scope: transport-settling robustness only. No wire, verdict, or pyref
  change; `harness/` and `pyref/` untouched.

## G5-D2b-003 — witness after-send fault seam is demo-kit surface, not a wire change

- Status: RULED (Claude, 2026-07-18). The S6-after-send-timeout scenario needs
  a real dispatch that the client never hears back from. Implemented as an
  optional `WitnessFaultInjection` on the transport witness proxy
  (`demo/witness/proxy.ts`): when set AND the request is action-bearing, the
  proxy forwards upstream (the dispatch is genuinely delivered), records the
  exchange with an `INJECTED_FAULT_WITHHELD_RESPONSE` response line, and does
  not reply — the client hits its own deadline.
- Why acceptable: the witness proxy is demo-kit surface (GATE5-D2-SLICES.md
  permits demo/adapters changes); the flag is default-off, applies only to
  action-bearing traffic, and the injected fault is itself witnessed (it does
  not hide a dispatch — it records one whose outcome the caller cannot
  observe, which is exactly the honest state S6 must produce). Non-action
  traffic (challenge discovery, readbacks) is never affected, so preflight
  and restoration still complete.
- Scope: demo transport only. No wire/verdict/pyref change.

> Note: G5-D2b-003 below is SUPERSEDED by G5-D2b-004 — its sentences
> "applies only to action-bearing traffic … restoration still complete" were
> the exact defect 004 fixes; the seam is now scoped to command-bound traffic.

## G5-D2b-004 — S6 fault seam must withhold ONLY the command dispatch, not the F19 restore (P1 blocker)

- Status: RULED + FIXED (adversarial reviewer P1, 2026-07-18; fix re-verified).
- Finding (reviewer): the seam withheld ALL action-bearing requests. The F19
  restore move (`adapter.ts` `restoreAndVerify`) is action-bearing, so it was
  withheld too → `restore_verified=false` → `assertOnlineOracle`
  ("PTZ restoration evidence") throws every run; the recovery record never
  unlinks and leaks into the D4 corpus; F19's restore+verify bar is not met.
  Passed offline only because the D2a mock fault is one-shot.
- Fix: the withhold now additionally requires an `x-aar-command-digest` header
  (present only on the command dispatch via `bindCommand=true`; the restore is
  command-unbound). The dispatch is withheld (honest after-send `unknown`); the
  restore forwards, completes, verifies, and the recovery record unlinks.
  Test now asserts the command-unbound action passes through while the
  command-bound dispatch is withheld.

## G5-D2b-005 — live preflight firmware group (P2)

- Status: RULED + FIXED. Preflight queried `Properties.System` but read
  `Properties.Firmware.Version`, a sibling group not returned by that list;
  live firmware would be "" and preflight would abort before S1. Verified
  against the real Q6358 (`Properties.Firmware` is its own group). Added
  `Properties.Firmware` to the query group.

## G5-D2b-006 — hygiene realm extraction must fail loud (P2)

- Status: RULED + FIXED. HA1 canary transforms were dropped silently if a
  first-`realm=` regex missed (or a Basic scheme poisoned it), reporting
  "0 hits" without ever testing the transformed-variant bar. Now parses the
  Digest challenge via `parseDigestChallenge` and throws if the realm is
  unrecoverable.

## G5-D2b-007 — firmware self-assertion made a real cross-check (P3)

- Status: FIXED. `source_device.firmware` was a hardcoded "12.9.57" compared
  against itself. Now sourced from the live preflight readback per leg, so the
  content assertion cross-checks the device.

## G5-D2b-008 — close-rejection race hardened; S5 worker leak closed (P3)

- Status: FIXED. The G5-D2b-002 close handler no longer relies on close-vs-end
  timing: it rejects on request `close` only when no response ever started;
  a started response settles via its own end/error/close handlers
  (deterministic for the 626 KB S2 body). The S5 crash worker is now killed
  and awaited if any `waitFor` times out (no leaked credentialed process), and
  its stdout/stderr pipes are drained. Park verification references the config
  tolerance (single source of truth).

## Reviewer items acknowledged, not gate-blocking (2026-07-18)

- Pre-existing `sent=true` before connect means a connection-refused failure
  reports `transport_timeout_after_send` and latches dispatch — over-latching
  is the F15-safe direction (never un-declares a real send); evidence label is
  conservative. Carried, not changed in D2b.
- Restoration exactly-one oracle count doesn't tolerate a stale-nonce repair on
  the restore move (only command attempts have repair tolerance). Low-probability
  live flake; carried.
- Honesty ledger for this handoff — changed: witness seam scoping, preflight
  group, hygiene realm, firmware sourcing, close-rejection, worker lifecycle;
  related-untouched: spec/harness/pyref (no wire/verdict change);
  noticed-not-fixed: the two pre-existing items above; residual-uncertainty:
  live behavior of the 626 KB stream body under the close race;
  **verification_gap: the live suite has NOT been executed against the cameras
  yet — all evidence to this point is offline-mock + real read-only probes.**

## G5-D2b-009 — client-deadline destroy mid-body resolves truncated (P3, fail-closed)

- Status: NOTED (re-review empirical probe, Bun 1.3.5). A client-deadline
  `request.destroy()` that fires mid-body resolves with the partial bytes
  (status 200, truncated) rather than rejecting. Live exposure: only S2's JPEG
  is large enough to dribble past the 10 s deadline, and the adapter's EOI
  media-unit check (`adapter.ts` dispatchStream) rejects a truncated JPEG →
  `media_payload_invalid` → loud failure. Never manufactured success; no fix
  taken. Recorded for trail completeness.
- Pre-window checklist (carried): the restoration exactly-one oracle count is
  intolerant of a stale-nonce repair on the restore move (repair tolerance is
  wired only for command attempts). If S1/S4/S6 fails with "PTZ restoration
  evidence" AND the witness shows a repaired 401 pair on the pan/tilt/zoom
  line, that is the known low-probability flake — rerun, not a regression.

## G5-D2b-010 — witness proxy forwarded framing headers, breaking against real cameras (live)

- Status: RULED + FIXED (live run, 2026-07-18). The transport witness proxy
  buffers the full upstream body but re-emitted the upstream response headers
  verbatim. Real Axis devices (Q6358/Q6325, AXIS OS 12.9.57) return BOTH
  `Content-Length` AND `Transfer-Encoding: chunked`; forwarding either
  alongside a fixed buffered body produced an unparseable response
  (Bun: `InvalidHTTPResponse`), aborting at the very first preflight request.
  The unit tests never caught it — the mock upstream set clean single-framing
  headers. Fix: strip `transfer-encoding` and `content-length` from the
  forwarded headers and let the response derive Content-Length from the
  buffer. Demo-kit surface; no wire/verdict change. First live gate-run then
  reached all scenarios.

## G5-D2b-011 — hygiene sweep false-positives on short secrets via reversible substring match (live)

- Status: RULED + FIXED (live run, 2026-07-18). The real camera passwords are
  4 characters; the `literal` and `percent_encoded` transforms are 4-char
  needles that match arbitrary committed hex/text as substrings — the first
  live sweep reported 684 hits, ALL `literal`/`percent_encoded` in committed
  spec/test files (which by definition cannot contain a runtime-fetched
  secret), ZERO in any hash form. No actual leak. Fix: `sweepCanary` now takes
  `hashOnlyRoots` — roots scanned with only the collision-free irreversible
  (md5/sha256/HA1) transforms. The generated artifact tree gets the full
  transform set (any occurrence there IS a leak); the committed source tree
  gets hash-only. Live re-run: 0 hits, HA1 legs still covered.
- OPERATOR NOTE (non-code): the lab cameras use 4-character VAPIX passwords.
  That is weak for anything beyond an isolated lab LAN. Flagged for Matthew;
  not changed here (camera-config decision, and out of scope for the gate).

## D2b LIVE RESULT — 2026-07-18 (F17 satisfied; D2 CLOSED)

Two independent full runs against the owned cameras (Q6358-LE .33 PTZ /
Q6325-LE .32 stream, both AXIS OS 12.9.57), byte-identical scenario verdicts:
- S1 conformant · device_acknowledged · position_within_tolerance (real goto
  Home + readback poll to 0.5°/100u tolerance)
- S2 conformant · device_acknowledged · media_payload_valid (real JPEG,
  gate5 profile, EOI-validated, ≥4 KB)
- S3 conformant · not_dispatched (delegation-expired refusal; zero
  invocation-attributable dispatch, transport-witnessed)
- S4 nonconformant · first failure sig/verify-failed (pinned tamper, F21)
- S5 conformant · unknown · outcome_unknown_restore_verified (real EP
  crash-cut after send, resume w/ zero redispatch, F19 restore verified)
- S6-rejection conformant · contradicted · vapix_application_error +
  position_observation outside_tolerance (absent-preset, positive contrary
  readback)
- S6-after-send-timeout conformant · unknown · transport_timeout_after_send
  (witness-layer withhold of the command dispatch only; F19 restore still
  completed and verified)
- Hygiene sweep 0 hits both runs. Camera rests at operator park.
Every run through EP → transport witness → VAPIX adapter → real camera →
online oracle → `python -m pyref verify` (pinned --at, trust policy,
--prior-state advanced across runs). Gate live re-run (exit bar #8)
reproduced identically. Artifacts under ~/.aar-demo/d2b-*.
