# Gate 5 — two-adapter demonstration (VAPIX + one VMS) — v1.1

2026-07-15, from `v0.2-rc2` (`19fa57b`). The last residue named at every gate
close: "real adapter validation." Claude authored this rubric and gates every
slice. v1.1 folds the Codex challenge pass (22 findings, all sustained —
rulings in `spec/GATE5-CHALLENGE.md`).

## Why this phase exists

Gates 1–4 proved the wire is unambiguous (two clean-room implementations,
byte-identical). Nothing yet proves a *producer* can emit conformant bundles
from a **real system under real conditions** — digest-auth round trips,
device latency, ambiguous outcomes, secrets that must never enter a command
manifest. The demo is also the first artifact a skeptical integrator or RFP
author can run: an agent acts on a camera, receipts come out, the free public
verifier says `conformant` — or provably refuses.

What this phase does NOT do: extend the ontology, touch verdict bytes, add
wire fields, claim adapter *effect* equivalence across backends (R-12), or
claim R-31 crash-protocol conformance (deferred at the wire freeze).

## Topology (frozen — F10)

ONE shared **EP/producer** (`demo/ep/`) owns authorization evaluation,
journaling, signing, and recovery. TWO backend-specific **adapters** own only
translation + dispatch + effect observation:

1. **`adapters/vapix/`** — direct-to-camera over VAPIX HTTP (digest auth).
   Live-lab mandatory: Matthew's personally-owned cameras only (AXIS
   Q6358-LE for PTZ; P3285-LVE for fixed stream-view). No AV customer
   systems, no AV data — ever.
2. **`adapters/vms/`** — VMS-mediated. **Q5-1 ruling:** 1-day time-boxed
   Vigil spike first — Vigil has no `IntentInvocationRecord` in code today,
   so the spike must first prove a headless control seam is reachable. If
   the spike fails: ONVIF fallback is pre-authorized BUT the phase result is
   renamed "two-protocol / same-vendor demo," the VMS + cross-vendor claim
   is explicitly deferred, and GATE5-CLOSE says so. No silent substitution.

The **agent is scripted** (Q5-3): fixed intent, but it issues a FRESH signed
request per run carrying gate-supplied invocation/correlation values. It may
not call fixture builders or replay canned requests.

Both adapters consume the same abstract commands, defined in a versioned
non-wire **`adapters/shared/DEMO-CONTRACT.md`** (F12): logical target names,
preset mapping, what "stream view succeeded" means per backend, PTZ position
tolerance + settling deadline, and each adapter's effect oracle. No claim of
semantic effect equivalence (R-12).

## Build-on rule (NOT clean-room)

The EP/adapters are producers, not implementations-under-test. They MUST
build on `harness/` (deterministic CBOR encoder, COSE, Merkle). Verification
always goes through the *other* stack: `python -m pyref verify`. TS produces,
Python verifies — a standing cross-implementation check on every run.

## Online oracle (F6 — the demo-layer truth check)

The frozen verifier proves wire conformance only; a producer could self-sign
fiction and still verify. The demo therefore includes an **online oracle**,
entirely outside `pyref/`: for each scenario it binds (a) the gate-supplied
request, (b) backend traffic observed by an **independent transport witness**
(logging proxy on the command path), (c) the command manifest in the
receipts, (d) the dispatch receipt, (e) the observed effect per the
DEMO-CONTRACT oracle. This is the R-13 offline/online split made concrete.
pyref remains the only wire authority.

## Demo scenarios

| # | Scenario | Expected result |
|---|---|---|
| S1 | Authorized `camera.ptz.preset` — valid delegation, dispatch, outcome at the **pinned** evidence level (device position readback; `verified` barred — same-device, not independent) | `conformant` + content assertions + online oracle PASS |
| S2 | Authorized `camera.stream.view` — read-only, resource side effects noted, stream success per DEMO-CONTRACT | `conformant` + content assertions + oracle PASS |
| S3 | **Expired delegation** → refusal receipted as `action_attempt` + `not_dispatched`. Gate supplies an UNLABELLED expired token and a neighboring valid token (F9); assertion = zero **invocation-attributable** command dispatch, proven by EP instrumentation AND the transport witness (F16 — ambient VMS keepalives excluded) | `conformant` bundle + independent token-time/refusal/zero-dispatch assertions |
| S4 | **One shared tamper case** (F21): pinned byte in a pinned S1 artifact, expected first-failure reason code pinned in the scenario spec | `nonconformant` (exit 1), exact code |
| S5 | **Fault test, externally observed** (F7 recast): deterministic cut point between dispatch and outcome observation, kill the EP, durable pre-kill evidence on disk, restart resumes the SAME invocation, zero redispatch (transport-witnessed), emits honest `outcome_unknown`. Runs ONCE, through EP+VAPIX (Q5-2). Both adapters must separately demonstrate they can encode `outcome_unknown`. Explicitly NOT R-31 conformance. | `conformant`; report shows declared outcome level |
| S6 | **Backend fault under valid delegation** (F14): gate-controlled rejection and after-send timeout, one per transport. Digest-auth convention per F15: challenge traffic ≠ dispatch, every action-bearing attempt recorded, consequential auto-retries disabled, VAPIX application errors inside HTTP 2xx parsed | honest `dispatched`/`outcome_unknown` or contradicted result — never manufactured success |

Every verification run supplies `--at` (pinned, never wall-clock), the demo
trust policy, AND `--prior-state`, advanced across runs; a verdict carrying
`stateful_not_evaluated` fails the gate (F8).

## Honesty constraints (carried from spec §5)

- **Outcome evidence levels pinned per action/backend** (F11) in
  DEMO-CONTRACT.md, with normative downgrade conditions (timeout, rejection,
  VMS queue-acceptance vs device readback). PTZ readback is same-device:
  `verified` is barred and the README says so plainly.
- **Provenance strength:** demo agent inferences are `self-asserted` and say so.
- **Completeness:** producer-declared `complete` with the mandatory
  `ingress_completeness_not_established` observation (Q6 ruling).
- **Anchoring:** minimal local RFC 6962 v1 log, same code path as harness,
  demo keys distinct from KAT keys (public keys only in repo). Labeled
  **"same-operator demo anchoring"** (F22) — RFP text must not imply
  independent timestamping or withholding-resistance.

## Secret hygiene v2 (F13)

- Command manifests are built from a **secret-free logical request BEFORE
  auth injection**; the auth layer is applied only at transport.
- Credential-derived commitments prohibited (no HA1, no `Authorization`
  header material, hashed or otherwise, anywhere in a receipt — the
  excluded-field commitment must never cover low-entropy credentials).
- Gate audit uses a **canary credential**: plant it, run everything, then
  sweep repo + receipts + argv/env captures + logs + temp files + any
  pcap/HAR for the canary AND transformed variants (HA1, base64,
  percent-encoded). Zero hits.
- Real camera creds come from the local `cred` store at runtime; lab config,
  raw traces, and private keys stay OUTSIDE the repo (Q5-4). The demo
  produces a sanitized, publishable artifact corpus from inception.

## Slices

- **D1 — shared demo kit:** DEMO-CONTRACT.md, EP/producer skeleton, demo
  trust policy + key generation, local anchor log, transport witness,
  scenario runner, read-only **preflight** (F18: device identity,
  model/firmware, preset existence, stream profile, credential access,
  backend mapping — S1 refuses to run without a green preflight).
- **D2 — VAPIX adapter:** live-lab against Q6358-LE (.33) / P3285-LVE (.19),
  digest auth via `cred get`, S1–S6 green. **PTZ safety protocol** (F19):
  designated safe preset, baseline capture before + restore/verify after
  every run, exclusive-control window (no guard tours/autotracking during
  runs), poll-to-tolerance with hard deadline, no redispatch during
  reconciliation.
- **D3 — VMS leg:** per Q5-1 ruling (Vigil spike → build, or renamed ONVIF
  fallback); S1–S4 + S6 + `outcome_unknown` encoding green from the SAME
  abstract commands.
- **D4 — demo packaging:** `demo/README.md` (one-command scenario run per
  adapter; what a verdict proves and — verbatim from pyref README — what it
  does NOT prove) PLUS a sanitized machine-readable **run manifest +
  evidence index** (F20): adapter commit, device/VMS firmware, gate-supplied
  inputs, command/effect mapping, transport observations, outcome downgrade
  rationale, known residuals (incl. self-asserted adapter identity).

## Exit bar (gate re-runs everything)

1. All scenarios green on both legs (S5 crash-cut once via EP+VAPIX), via
   the public CLI, **with content assertions** (F5): no `empty_scope`,
   correct evaluated profile (AAR-3 for S1), expected receipt kinds /
   action / target / adapter identity / outcome level present, scope
   `complete`, gate-supplied fresh invocation IDs found in the bundle.
2. Online oracle PASS per scenario per adapter (F6).
3. R-1 assertion holds (S3): zero invocation-attributable dispatch, by
   instrumentation + transport witness, on gate-supplied unlabelled tokens.
4. Canary-credential sweep clean, incl. transformed variants (F13).
5. No changes under `spec/` wire text, `harness/` verdict logic, or
   `pyref/` — if the demo *needs* a wire change, that is a FINDING that
   stops the phase (rc3 territory, not a patch).
6. Full existing suites still green: harness 16/16, pyref 43/43 + 188/188.
7. Prior-state discipline: no `stateful_not_evaluated` in any gated verdict.
8. Live re-runs by the gate: S1 + S3 on the VAPIX leg against the real
   camera, AND authorized-PTZ + stream-view + refusal on the actual VMS
   backend (F17 — a stub or replay server cannot satisfy the gate).

## Divergence / finding protocol

Same as gate 4: any point where the spec text under-determines what a real
producer must do is a FINDING recorded in `adapters/FINDINGS.md` with the
spec sentence relied on. Claude adjudicates: spec erratum, demo bug, or
documentation gap. Wire-affecting rulings stop the phase (exit bar #5).

## Gate roles

- Builder: Codex (systems lane; live-lab runs on the local LAN are in scope
  for `codex exec`). Content-filter fallback per gate-3/4 precedent: Claude
  builds under the same rules.
- Gate: Claude — re-runs per exit bar #8, audits the canary sweep, audits
  FINDINGS.md, checks exit bar #5 diff-clean, writes `spec/GATE5-CLOSE.md`.
- Matthew: rules on the Q5-1 rename wording if the Vigil spike fails
  (external-claim language), and physically owns the lab (preset choice,
  exclusive-control windows).
