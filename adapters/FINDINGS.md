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
