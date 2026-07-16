# Gate 5 rubric — challenge pass rulings

2026-07-15. Challenger: Codex (read-only, no content-filter block this time).
Gate: Claude. Input: GATE5-RUBRIC.md at `344bf4b`. 22 findings: 3 BLOCKER,
13 MAJOR, 2 MINOR, 4 question-answers. **All 22 SUSTAINED** (two with
calibration noted below). None require wire changes; the one branch that
would (F7's "verdict proves reconciliation") is REJECTED — rc2 stays frozen.
Rubric v1.1 (same file) folds every ruling.

## Question rulings

- **Q5-1 (VMS leg):** Codex sustained with modification. ONVIF against the
  same AXIS cameras is protocol diversity, NOT a VMS and NOT R-12
  cross-vendor evidence. Ruling: time-boxed Vigil spike (1 day) stands —
  note Vigil has no `IntentInvocationRecord` in code today, so the spike
  must first prove a headless control seam is reachable. If the spike
  fails: fall back to ONVIF but the phase result is RENAMED
  "two-protocol / same-vendor demo," the VMS + cross-vendor claim is
  explicitly deferred, and GATE5-CLOSE says so. No silent substitution.
  ⚠️ Flagged to Matthew: the rename affects external claim wording.
- **Q5-2 (crash test on both adapters):** Codex sustained. Rubric's R-16
  citation was WRONG — crash durability/idempotency is R-31, explicitly
  deferred at the wire freeze. Recast: both adapters must be able to encode
  an honest `outcome_unknown`; exactly ONE real crash-cut runs, through the
  shared EP + VAPIX path; the demo explicitly claims NOT to be R-31
  conformance.
- **Q5-3 (scripted agent):** Agreed, with Codex's hardening: the scripted
  agent issues a FRESH signed request per run with gate-supplied
  invocation/correlation values — it may not call fixture builders or
  replay canned requests.
- **Q5-4 (repo):** Agreed: demo code lives in this repo. Lab configuration,
  credentials, raw traces, and private keys stay OUTSIDE the repo; the demo
  produces a sanitized, publishable artifact corpus from inception.

## Blocker rulings

- **F5 (vacuous conformant) SUSTAINED:** exit bar gains content assertions —
  no `empty_scope`, evaluated profile AAR-3 (S1) / correct profile per
  scenario, expected receipt kinds/action/target/adapter identity/outcome
  level present, scope `complete`, and gate-supplied fresh invocation IDs
  found in the bundle.
- **F6 (no effect oracle) SUSTAINED:** a demo-layer **online oracle** binds
  gate request → observed backend traffic (independent transport witness) →
  command manifest → dispatch receipt → observed effect, per adapter. Lives
  entirely outside the frozen verifier (this IS the R-13 offline/online
  split); pyref remains the only wire authority.
- **F7 (S5 overclaims reconciliation) SUSTAINED:** S5 recast as an
  externally observed fault test: deterministic cut point, durable pre-kill
  evidence on disk, same invocation resumed after restart, zero redispatch
  (transport-witnessed). The wire is NOT asked to prove recovery; any need
  for verifier-visible reconciliation semantics is future work and would
  stop the phase (exit bar #4).

## Major/minor rulings (all sustained; dispositions folded into rubric v1.1)

F8 prior-state supplied + advanced every run, `stateful_not_evaluated` fails
the gate · F9 gate supplies unlabelled expired + valid tokens and asserts
token times, refusal output, zero attributable dispatch independently ·
F10 topology frozen: ONE shared EP/producer (authorize, journal, sign,
recover) + two backend-specific translation/dispatch adapters · F11 expected
outcome-evidence level pinned per action/backend with normative downgrade
conditions · F12 versioned non-wire DEMO-CONTRACT.md (logical targets,
preset mapping, stream-success definition, PTZ tolerance/settling, effect
oracles) · F13 secret hygiene v2: manifests built from a secret-free logical
request before auth injection; credential-derived commitments prohibited;
canary-credential audit over argv/env/logs/temp/pcap incl. transformed
variants (HA1, base64, percent-encoded) · F14 new S6: gate-controlled
backend rejection / after-send timeout per transport → honest
dispatched/unknown or contradicted result · F15 digest-auth convention:
challenge traffic ≠ dispatch; every action-bearing attempt recorded;
consequential auto-retries disabled; VAPIX application errors inside 2xx
parsed · F16 R-1 assertion narrowed to zero invocation-attributable command
dispatch, proven by instrumentation + independent transport witness ·
F17 gate independently reruns PTZ + stream-view + refusal on the VMS leg
too · F18 read-only identity/capability preflight gates S1 · F19 PTZ safety
protocol: designated safe preset, baseline capture/restore, exclusive
control window, poll-to-tolerance with hard deadline, no redispatch during
reconciliation · F20 D4 emits a sanitized machine-readable run manifest +
evidence index (adapter commit, firmware, gate inputs, command/effect
mapping, transport observations, downgrade rationale, known residuals) ·
F21 tamper test collapsed to ONE shared deterministic case with pinned byte
+ expected first-failure code · F22 local anchor labeled "same-operator demo
anchoring"; RFP text must not imply independent timestamping or
withholding-resistance.

## Pipeline note

The challenge caught Claude citing R-16 where R-31 was correct (Q5-2) and
an exit bar that a stub could pass (F5/F6/F17) — third instance of the
two-model pipeline catching gate-author error (rubric '5 outcome' typo,
WQ-1 circular preimage, now this).
