# Gate 5 — two-adapter demonstration (VAPIX + one VMS)

2026-07-15, from `v0.2-rc2` (`19fa57b`). The last residue named at every gate
close: "real adapter validation." Claude authored this rubric and gates every
slice; Codex builds (systems lane). This rubric goes through a Codex challenge
pass before any build starts.

## Why this phase exists

Gates 1–4 proved the wire is unambiguous (two clean-room implementations,
byte-identical). Nothing yet proves a *producer* can emit conformant bundles
from a **real system under real conditions** — digest-auth round trips,
device latency, ambiguous outcomes, secrets that must never enter a command
manifest. The demo is also the first artifact a skeptical integrator or RFP
author can run: an agent acts on a camera, receipts come out, the free public
verifier says `conformant` — or provably refuses.

What this phase does NOT do: extend the ontology, touch verdict bytes, add
wire fields, or claim adapter *effect* equivalence across backends (R-12:
shared abstract commands, adapter-specific effects, no false parity).

## Scope

Two adapters, each an **enforcement point (EP)** producing v0.2 bundles for
the two v0 actions (`camera.stream.view`, `camera.ptz.preset`):

1. **`adapters/vapix/`** — direct-to-camera over VAPIX HTTP (digest auth).
   Live-lab mandatory: runs against Matthew's personally-owned cameras only
   (AXIS Q6358-LE for PTZ; P3285-LVE for fixed stream-view). No AV customer
   systems, no AV data — ever.
2. **`adapters/vms/`** — VMS-mediated. **Proposed: Vigil** (independent-IP
   native-Mac VMS; its `IntentInvocationRecord` seam is already flagged as
   the AAR-3 EP prototype). Alternative if Vigil's control path isn't
   drivable headless within a day's spike: a generic ONVIF adapter against
   the same cameras (different protocol + command model = still a genuinely
   second backend). **Open question Q5-1 for the challenge pass.**

Both adapters consume the same **abstract command fixtures**
(`adapters/shared/commands.json`) per R-12, and translate to
backend-specific command manifests.

## Build-on rule (NOT clean-room)

Adapters are producers, not implementations-under-test. They MUST build on
`harness/` (deterministic CBOR encoder, COSE, Merkle, fixture builders) —
re-implementing the encoder would add a third implementation to maintain
with zero evidentiary value. Verification always goes through the *other*
stack: `python -m pyref verify` (public CLI). TS produces, Python verifies —
a standing cross-implementation check on every demo run.

## Demo scenarios (the exit bar is these five, both adapters)

| # | Scenario | Expected verdict |
|---|---|---|
| S1 | Authorized `camera.ptz.preset` — valid delegation, dispatch, outcome observation at an honestly-declared evidence level | `conformant` (exit 0) |
| S2 | Authorized `camera.stream.view` — read-only path, resource side effects noted | `conformant` (exit 0) |
| S3 | **Expired delegation** → refusal receipted as `action_attempt` + `not_dispatched`; the instrumented dispatch log proves **zero backend traffic** (R-1: tested against the adapter's dispatch instrumentation, not final device state) | `conformant` bundle (a receipted refusal is conformant behavior) + dispatch-log assertion |
| S4 | Tamper: flip one byte in any S1 artifact post-emission | `nonconformant` (exit 1) with the correct reason code |
| S5 | **Crash / outcome-unknown**: kill the adapter between dispatch and outcome observation; recovery emits reconciliation with `outcome_unknown` — certainty is never manufactured | `conformant` (exit 0); verdict report shows the declared outcome level |

Every scenario's bundle is verified by `python -m pyref verify` with
`--at` pinned (never wall-clock) and a demo trust-policy file. S1–S3 run
LIVE on the lab cameras for the VAPIX leg; the VMS leg may drive its
backend headless. S4–S5 may replay captured S1 traffic.

## Honesty constraints (carried from spec §5 — these are the demo's point)

- **Outcome evidence level:** PTZ position readback comes from the *same
  device* that executed the command — it is NOT an independent observer.
  The receipt MUST declare the honest level; `verified` is barred. The demo
  README states this plainly rather than hiding it.
- **Provenance strength:** the demo agent's inference receipts are
  `self-asserted` (no proxy, no provider attestation in the demo) and say so.
- **Completeness:** bundles carry producer-declared `complete` with the
  mandatory `ingress_completeness_not_established` observation (Q6 ruling).
- **Command manifest hygiene (finding 17):** secrets and volatile headers
  excluded. Gate audit: grep the entire receipt corpus + repo for the lab
  credential material → zero hits. Camera credentials come from the local
  `cred` store at runtime; they never appear in the repo, fixtures, config
  committed to git, or any receipt.

## Anchoring

A minimal local anchor log (RFC 6962 v1, same code path as the harness) is
sufficient — the demo proves the wire against real actions, not anchor-
service operations. The anchor's keys are demo keys, distinct from the KAT
test keys, generated at demo setup and committed only as public keys.

## Slices

- **D1 — shared demo kit:** abstract command fixtures, demo trust policy,
  demo key generation, local anchor log, scenario runner skeleton
  (`adapters/shared/`), instrumented-dispatch logging contract.
- **D2 — VAPIX adapter:** live-lab against Q6358-LE (.33) / P3285-LVE (.19),
  digest auth via `cred get`, all five scenarios green.
- **D3 — VMS adapter:** per Q5-1 ruling; all five scenarios green against
  the second backend from the SAME abstract commands.
- **D4 — demo packaging:** `demo/README.md` — one-command scenario run per
  adapter, what each verdict proves and (verbatim from pyref README) what it
  does NOT prove; this is the artifact the RFP-language phase quotes.

## Exit bar (gate re-runs everything)

1. 5/5 scenarios × 2 adapters, verdicts as specified, via the public CLI.
2. R-1 dispatch-log assertion holds (S3: zero backend traffic on refusal).
3. Secret-hygiene grep clean over repo + all emitted receipts.
4. No changes under `spec/` wire text, `harness/` verdict logic, or
   `pyref/` — if the demo *needs* a wire change, that is a FINDING that
   stops the phase and goes to adjudication (rc3 territory, not a patch).
5. Full existing suites still green: harness 16/16, pyref 43/43 + 188/188.
6. Live-lab evidence: the gate independently re-runs at least S1+S3 on the
   VAPIX leg against the real camera.

## Open questions for the challenge pass

- **Q5-1:** VMS leg = Vigil vs generic ONVIF (see Scope §2). Recommend:
  1-day Vigil spike first; ONVIF fallback pre-authorized.
- **Q5-2:** Should S5 (crash/reconciliation) be required on BOTH adapters or
  VAPIX-only for v0.2 demo? Recommend both — R-16/finding 16 is
  load-bearing for the market claim.
- **Q5-3:** Does the demo agent need a real LLM in the loop, or is a
  scripted "agent" (fixed intent → action request) sufficient? Recommend
  scripted — the spec governs the boundary, not the model; a live model
  adds nondeterminism with zero wire coverage.
- **Q5-4:** Where does the demo live — this repo (`adapters/`, `demo/`) or
  a separate repo? Recommend this repo, private, until RFP phase decides
  what goes public.

## Divergence / finding protocol

Same as gate 4: any point where the spec text under-determines what a real
producer must do is a FINDING recorded in `adapters/FINDINGS.md` with the
spec sentence relied on. Claude adjudicates: spec erratum, demo bug, or
documentation gap. Wire-affecting rulings stop the phase (exit bar #4).

## Gate roles

- Builder: Codex (systems lane; live-lab runs on the local LAN are in
  scope for `codex exec`). Content-filter fallback per gate-3/4 precedent:
  Claude builds under the same rules.
- Gate: Claude — re-runs scenarios (incl. live S1+S3), audits secret
  hygiene, audits FINDINGS.md, checks exit bar #4 diff-clean, writes
  `spec/GATE5-CLOSE.md`.
