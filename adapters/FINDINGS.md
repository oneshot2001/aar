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

## G5-D3-001 — vigil-control fabricated all-zeros position on error-in-200 (P1, FIXED)

- Status: RULED + FIXED (D3 step 2+3 reviewer gate, 2026-07-18).
  `VigilCore.PTZPosition.parse` never fails: any 2xx body (VAPIX `Error:`
  text, HTML error page, empty) parses to defaulted zeros, and this class is
  proven reachable live (D2b S6-rejection produced exactly an error body in
  HTTP 2xx). The mediator would report a fabricated position as a positive
  observation — worst case the F19 baseline is captured as 0/0/0 and the
  camera is later physically "restored" there with `restore_verified: true`.
  Fix: vigil-control refuses all-zeros readbacks (`position_unavailable`) —
  a true 0/0/0 cannot occur on real Axis PTZ (zoom is 1-based, 1..9999).
  Vigil stays unmodified (`VAPIXClient.request` is private, the raw body is
  unreachable); the sentinel is the strongest mediator-side guard available.
  Residual: a fabricated readback with any non-zero field would still pass —
  accepted; the live preflight should sanity-check the park position.

## G5-D3-002 — VMS stream catch-all reported contradicted without observation (P1, FIXED)

- Status: RULED + FIXED. The stream outcome's else-branch bucketed
  mediator-internal failures (`transport_error`, `routing_error`,
  `mediator_http_N`, unparseable effect) into `contradicted` with zero device
  observation — camera unplugged during live S2 would have produced a
  contradicted receipt. Now `contradicted` requires a positively observed
  contrary result (`http_rejected_N`, observed invalid/undersized media);
  mediator-internal failures are `unknown`. Unit-tested both directions.

## G5-D3-003 — stream profile is echo-only through the VMS seam (P2, DOCUMENTED)

- Status: RULED. `VigilCore.getSnapshot()` has no profile parameter; the
  mediator echoes the logical profile and fetches via the VMS's own snapshot
  seam. The mock originally rejected profile mismatches — faking a check the
  live leg does not perform (dangerous-direction fidelity gap). Mock relaxed
  to mirror reality; README states the claim as "one validated media unit via
  the VMS control seam", NOT "media from the mapped profile". Related: a live
  S6-rejection induced via unknown preset surfaces as position-based
  contradiction, not `http_rejected_N` (error-in-200 on ptz.cgi) — the live
  runner must induce S6-rejection accordingly (readback provides the positive
  contrary evidence, as in D2b).

## D3 step 2+3 Honesty Ledger (offline build, pre-live)

- Changed: vigil-control contract v2 (body-digest binding, query routing,
  zero-sentinel, exact-path routing, CredError mapping); TS VmsAdapter +
  witnessed mediator client + mock + offline S1–S4/S6 suite; VMS oracle
  checks factored to `adapters/vms/oracle.ts` for offline+live reuse (P2-2).
- Related-untouched: spec/ wire text, harness/, pyref/, Vigil repo, D2b
  VAPIX adapter and its suite (cross-imports only).
- Noticed-not-fixed: `sent=true` over-latching carry (D2b P3); reconcile()
  mirrored but unexercised on this leg (S5 runs once on EP+VAPIX per Q5-2);
  `cred get` fork/exec per mediator request (tune poll interval live).
- Residual-uncertainty: live behavior of the real vigil-control under the
  witness proxy (framing headers — D2b hit G5-D2b-010 there); space-in-value
  encoding mismatch is fail-closed.
- **verification_gap: the contract-v2 action-bearing surface (digest refusal,
  ptz.goto_preset, ptz.goto restore, stream.view via real vigil-control +
  cameras) has NOT been live-exercised — only GET /ptz/position and /healthz
  were live-proven. The live leg is D3 step 4, after this gate.**

## D3 LIVE RESULT — 2026-07-18 (D3 CLOSED)

Two independent full runs, EP → transport witness → REAL vigil-control
(VigilCore.VAPIXClient, own process, `cred get` in-process) → owned cameras
(Q6358-LE .33 PTZ / Q6325-LE .32 stream, AXIS OS 12.9.57), identical
scenario verdicts both runs:
- S1 conformant · device_acknowledged · position_within_tolerance
- S2 conformant · device_acknowledged · media_payload_valid
- S3 conformant · not_dispatched (zero attributable mediated dispatch)
- S4 nonconformant · sig/verify-failed (pinned tamper)
- S6-rejection conformant · contradicted · position_outside_tolerance
  (absent preset = error-in-200, contrary readback is the evidence — as
  G5-D3-003 predicted)
- S6-after-send-timeout conformant · unknown · transport_timeout_after_send
  (real move, withheld reply, F19 restore verified)
Hygiene 0 hits both runs; camera rests at operator park. New `/device/info`
mediator op gives preflight identity+firmware readback (G5-D2b-007 parity).
The D3 step 2+3 ledger's **verification_gap is CLOSED**: the full contract-v2
action-bearing surface (digest-bound goto_preset, unbound goto restore,
stream.view, plus refusal paths) is now live-exercised. Round-2 checkpoint
held: the live runner imports both adapters/vms/oracle.ts checks.
Gate trail: spec/GATE5-D3-PLAN.md + GATE5-D3-REVIEW.md; evidence
adapters/vms/live/evidence/.

## D4 packaging Honesty Ledger (2026-07-18)

- Built: demo/README.md + demo/results/run-manifest.json (F20 run manifest +
  evidence index). Docs-only slice: no changes under spec/, harness/, pyref/,
  adapters/ code (exit bar #5 trivially clean).
- Reviewer gate round 1 = FIX-FIRST: P1-1 stale pyref counts (43/188 era ->
  46/46 + 191/191 post D-57) and P1-2 misattributed 60/60-to-harness/ (60/60 is
  the FULL Bun+TS suite at v0.2-rc5; harness/ core = 31/31) — both were
  transcribed from older gate docs without re-verification; fixed. P2s fixed:
  full 5-bullet verbatim claim boundary, "byte-identical scenario verdicts"
  wording, this ledger, pyref synopsis alignment, role-scoped preflight note.
- Verified: reviewer executed both offline one-command entrypoints as
  documented (VAPIX S1–S6, VMS S1–S4+S6, hygiene 0 hits); scenario tables,
  devices, tags/commits, finding-ID citations, F20 field coverage, claim
  boundary, and secrets hygiene all checked clean.
- verification_gap: the two LIVE entrypoints (adapters/*/live/run.ts) were not
  re-executed for D4 — requires a camera exclusive-control window; their
  results are cited from the D2b/D3 gate records, not re-run.
- noticed_not_fixed: pre-existing wording in spec/GATE5-D2B-REVIEW.md:93
  ("two-protocol/same-vendor VAPIX only") reads as a typo for one-protocol/
  two-target; committed gate doc, left untouched (rename wording = Matthew's
  call per rubric).
- residual_uncertainty: none beyond the named verification_gap.

## Phase-5 RFP-language Honesty Ledger (2026-07-18)

- Built: docs/rfp-language-v0.2.md (model solicitation clauses). Docs-only.
- Reviewer gate round 1 = FIX-FIRST. 2 P1: (1) "reference toolchain satisfies
  this clause today" contradicted repo record — repo PRIVATE, license TBD, no
  LICENSE file; rewritten as designed-to-satisfy + explicit release
  precondition (publish pyref under OSI license before live use); (2) Clause 1
  mandated AAR-2A receipts for dispositions the v0.2-rc7 wire cannot express
  (closed two-action ontology; alert.suppress experimental, access control out
  of v0) — SHALL scoped to the pinned ontology + issuer guidance added. P2s
  fixed: guarantee wording de-staled per E-1 (anchored epoch manifests, not
  "anchored completeness"); "PTZ and fixed cameras" corrected (both PTZ
  hardware); Q5-2 single-run S5 parenthetical; this ledger. P3s folded:
  R-31-deferred crash-durability caveat; "verified" bar tightened to
  ontology-observer rule + same-API read-back exclusion.
- verification_gap: availability claim was drafted without checking repo
  licensing (the P1-1 root cause — same transcribed-not-verified class as D4
  round 1); no legal review of clause enforceability — model text, not
  counsel-reviewed solicitation language.
- noticed_not_fixed: none. residual_uncertainty: whether procurement offices
  accept rc-pinned conformance language at all — untested with a real agency.
- related_untouched: spec/, harness/, pyref/, adapters code — untouched.

## D-66 Packet A Honesty Ledger (2026-08-28)

- changed: D-66 normative decision, CDDL policy-bound life-safety/degraded
  markers, conformance reasons/observations/per-dispatch order, five
  evidence-commit KATs, both verifier implementations, and the shared EP
  pre-send receipt commit. The review-found self-asserted life-safety hole is
  closed by requiring `action_name` membership in the bound trust policy's
  optional `life_safety_action_names`; an absent list binds no exemptions.
  VAPIX and VMS offline/live runners now include S7, and
  `demo/run-scenario.ts` supplies the S7 content/online oracle; offline proves
  zero attributable dispatch and unchanged camera position.
- packet_deviation: packet section 4 proposed injecting the journal failure
  through the S6 witness seam. Packet A instead added
  `JournalFaultOptions.failActionAttemptCommitForCommandDigest` in
  `demo/ep/journal.ts`, scoped to the exact command digest, because the S6 seam
  runs after the journal gate and therefore cannot exercise the pre-send
  commitment failure.
- related_untouched: anchoring remains asynchronous and does not gate dispatch;
  S5 post-send crash/reconciliation semantics and S6 after-send response
  withholding remain unchanged; countersign and multi-step ontology remain out
  of scope.
- noticed_not_fixed: the packet names 191 frozen fixtures, while this branch's
  pre-change C2 corpus contains 192 because D-60 added
  `request/coordinate-mismatch`; preservation is therefore measured over all
  192, not silently reported as 191. The supplied base was `4635d88`, while the
  requested branch was already at `8f8d74c` (two later documentation commits,
  with `4635d88` still an ancestor); the branch was not rewound.
- residual_uncertainty: policy binding fixes the EP-self-asserted exemption, but
  the offline verifier still cannot detect a compromised EP that omits the
  life-safety marker and lies about `committed_at`, or bypasses the mediated
  adapter path; those remain inside the trusted-EP/clock boundary.
- verification_gap: S7 is green offline through pyref for both adapters, but the
  live VAPIX and VMS S7 legs were not executed in this packet. They remain gated
  for the next owned-camera exclusive-control window with
  `AAR_LIVE_WINDOW=1`. On 2026-08-28 the builder's sandboxed `bun test` run
  reported 86 pass / 1 fail (the live-proxy test could not bind a loopback port
  in that sandbox, `EADDRINUSE`); the gate's two unsandboxed re-runs the same
  day reported 87 pass / 0 fail, 1,496 assertions — the failure was
  environmental, not a property of the branch.
  `python3 -m pyref.kat --slice all` completed C1 51/51 in every
  recomputation category and C2 197/197, with zero mismatches or divergences and
  deterministic verdicts 197/197. All 192 pre-packet C2 verdict digests remain
  byte-identical; the results diff contains only the five added D-66 rows and
  aggregate count updates.

## D-67 Packet B Honesty Ledger (2026-08-28)

- changed: ratified D-67 alone as an optional v0.2 standalone artifact using
  the existing `outcome_observer` role and `outcome_signing` usage; added the
  signed receipt-envelope digest, mediator-verified canonical-command digest,
  and mediator observation time; added step-3/6/7/8/10 validation, the three
  closed countersign reasons, and signed `mediator_countersigned` observation
  in both independent verifiers. `vigil-control` now owns a P-256 key, returns
  the COSE countersignature plus carried credential, and fails closed before
  backend dispatch if an offered `attempt_digest` cannot be countersigned. The
  original offline runner and countersign KATs incorrectly reused the EP's
  outcome key; both now use a distinct mediator credential and `kid`. The TS
  VMS adapter transports the artifact; four KATs cover valid, signed digest
  mismatch, expired mediator credential, and absence. Contract v3 keeps
  `attempt_digest` additive: absence dispatches with the pre-D-67 status and no
  artifact, while presence countersigns or fails closed; the oracle accepts
  both witnessed line shapes. The production release binary does not expose
  `--sign-test`: that end-to-end Swift/TypeScript interoperability hook is
  compiled only under Swift's `DEBUG` build flag. `adapter.test.ts` now covers
  malformed offered artifacts and the absent/present contract-v3 behavior.
- related_untouched: D-62, D-63, D-64, and D-65 remain candidate text only;
  no direct VAPIX file changed and absent artifacts preserve its wire path.
  `/Users/matthewvisher/Projects/vigil` is unmodified: `git status --short`
  returned empty and `git diff --quiet` returned 0. No commit was created.
- noticed_not_fixed: the packet names base `4635d88`, but the supplied checkout
  was already at `25fd549` with the five D-66 fixtures present; it was not
  rewound. Compatibility was therefore checked over all 197 pre-D-67 C2
  verdicts, a strict superset of the requested 192, and all 197 remained
  byte-identical.
- residual_uncertainty: v0.2 checks only that an in-tenant
  `outcome_observer`/`outcome_signing` credential signed the two bound digests
  and a carried time. It does not pin the signer's `kid` to "the mediator";
  mediator-`kid` trust-policy pinning is a v0.3 question. It does not compare
  `mediator_observed_at` with another time, and accepts multiple artifacts for
  one attempt when distinct observation times yield distinct IDs. It proves
  neither device actuation nor outcome truth. The demo EP and mediator use
  distinct credentials but remain same-operator (F22), so this narrows T-H2
  without establishing an independent vantage point.
- verification_gap: the live owned-camera leg was not run outside its next
  exclusive-control window. Offline VMS S1, S2, S4, and S6-rejection carried
  countersignatures and verified; no artifact is available to the caller when
  S6-after-send-timeout deliberately withholds the response, while S3/S7 never
  dispatch. The D-67 plus adapter-focused run was 20/20 (351 assertions), and
  the complete VMS adapter slice was 10/10 (39 assertions). Pyref was C1 55/55
  in all three categories and C2 201/201, with zero mismatches/divergences and
  determinism 201/201. Builder's sandbox run 89/90 (loopback bind), gate's
  unsandboxed runs 90/90 — environmental. This fix pass adds
  one adapter test; its current sandbox run was 90/91 (1,518 assertions), with
  the same sole loopback-bind failure.
