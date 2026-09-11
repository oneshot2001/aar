<div align="center">

# Agent Action Receipts (AAR)

<img src="docs/banner.png" alt="AAR — evidence-grade receipts for AI agents acting on physical-security systems" width="100%">

### Vendor-neutral, evidence-grade conformance profiles for AI agents acting on physical-security systems.

<p>
  <a href="LICENSE"><img src="https://img.shields.io/badge/code-Apache--2.0-blue.svg" alt="Code: Apache-2.0"></a>
  <a href="LICENSE-SPEC"><img src="https://img.shields.io/badge/spec-CC%20BY%204.0-blue.svg" alt="Spec: CC BY 4.0"></a>
  <a href="spec/aar-core.cddl"><img src="https://img.shields.io/badge/wire-v0.2.0-3ec9a7.svg" alt="Wire: v0.2.0"></a>
  <a href="pyref/"><img src="https://img.shields.io/badge/verifier-offline%20%C2%B7%20stdlib--only-3ec9a7.svg" alt="Verifier: offline, stdlib-only"></a>
  <a href="kats/"><img src="https://img.shields.io/badge/KATs-byte--pinned-1d3648.svg" alt="KATs: byte-pinned"></a>
  <a href="#status"><img src="https://img.shields.io/badge/status-stable%20experimental%20spec-d98e3b.svg" alt="Status: stable experimental spec"></a>
</p>

<a href="spec/aar-core.cddl">Normative CDDL</a> ·
<a href="docs/threat-model-v0.1.md">Threat model</a> ·
<a href="docs/related-work-addendum-2026-08-28.md">Related work</a> ·
<a href="pyref/">Offline verifier</a> ·
<a href="docs/rfp-language-v0.2.md">RFP language</a> ·
<a href="https://github.com/oneshot2001/onvif-mcp">Reference producer</a> ·
<a href="https://github.com/oneshot2001/aar/issues">Report an issue</a>

</div>

---

## What this is, in one paragraph

An AI agent that can view a camera stream or move a PTZ camera leaves a
signed, linked record of what it observed, what it inferred, what it was
authorized to do, what it attempted, whether the command was dispatched, and
what an observer saw happen. Anyone holding that bundle can check it offline,
with no vendor service, account, or network, and get a signed verdict. AAR is
the wire format, the conformance rules, and a free verifier for that record.
It is a **stable experimental spec** (`v0.2.0`), implemented twice by one
operator, run against real cameras, and not yet adopted by anyone else.

## Verify a receipt bundle in 60 seconds

```console
git clone https://github.com/oneshot2001/aar && cd aar
python3 -B -m pyref verify kats/positive/bundle-valid-subset.cbor --at 1735689800
```

Python 3.11+, standard library only. The verifier never reads the wall clock:
you supply the evaluation time. Output is a 20-step report and a signed
verdict; `Result: conformant` means every requested check passed for the
receipts in scope. Change one byte of the bundle and run it again.

## What a conformant verdict proves, and what it does not

| Proves | Does not prove |
|---|---|
| Every artifact was signed by the key its credential names, and nothing was altered after emission | That a signer told the truth before signing (no compromised-signer immunity) |
| The action the agent attempted is bound to the authorization it cites, and refusals are affirmative evidence | That any inference was correct |
| The epoch's manifest, events, and anchor agree; a producer-declared epoch has not been truncated after the fact | That every action that happened was recorded (completeness is census-conditional, see D-72) |
| Outcome claims carry their evidence grade; `verified` is barred without a named independent observer | That a `device_acknowledged` outcome was independently sensed (all live runs so far are device-acknowledged) |
| The verdict bytes are reproducible by a second, clean-room implementation | Custody continuity or legal admissibility (D-71) |

"Evidence-grade" in this repo means exactly the left column: attribution,
post-emission tamper evidence, and anchored completeness over declared
contents. Two further limits of the reference toolchain: the reference
verdict is signed with a **published test key** so its bytes are reproducible
(not an operational verifier identity), and the demo anchor log is
**same-operator** (it demonstrates mechanics, not independent timestamping).

## Supported actions

The `v0.2.0` ontology is closed to two camera actions: `camera.stream.view`
and `camera.ptz.preset`, on VAPIX and via one VMS control path. Alert
disposition is specified but experimental; access control and data-access
actions (ALPR queries, video export) are not in this wire. That is a scoping
choice, stated so nobody has to discover it.

## Status

| Artifact | State |
|---|---|
| Wire | **v0.2.0** — normative CDDL at `spec/aar-core.cddl`; five rc gates closed, exit bar re-run live against real cameras; delta since rc7 in `spec/AUDIT-rc7-to-v0.2.0.md` |
| Offline verifier | **pyref** — clean-room, Python stdlib only, no network, no wall clock |
| Second implementation | TypeScript harness (`harness/`) — generates the KAT corpus; byte-identical verdicts with pyref over 218 fixtures and the demo bundles |
| Conformance KATs | byte-pinned positive / negative / class-boundary / terminal-state fixtures in `kats/` |
| Threat model | **v0.1** — `docs/threat-model-v0.1.md` (30-finding adversarially challenged, gated) |
| Adapters | VAPIX live leg + one VMS control leg exercised at gate 5 (`adapters/`) |
| Reference producer | [onvif-mcp](https://github.com/oneshot2001/onvif-mcp) — governed MCP server for cameras; AAR-vocabulary receipts today, wire conformance in progress |

Two clean-room codebases, one operator. Nobody outside this repo has run an
emitter yet; that is the next thing this project needs, and the wire may still
change in response to it.

Why the demand side is moving: the FBI Cyber Strategy (September 2026,
Objective 4.4) commits the Bureau to "rapidly adopt agentic AI" and to
"detect, divert, and deceive threat actors," with governance stated only as
"human review and legal controls." An agent acting under legal authority needs
a record that binds each consequential action to the person who authorized it
and the scope they permitted, checkable by someone who does not trust the
operator. That is the record this profile is for.

## Integrate

An emitter sits at the enforcement point between the agent and the device. It
commits an attempt before dispatch, journals durably, and exports bundles.
Start with `demo/ep/README.md` (the reference enforcement point and its
contract), then `adapters/vapix/README.md` or `adapters/vms/README.md` for a
translation leg. Procurement text that pins this version is in
`docs/rfp-language-v0.2.md`.

## Guarantees, in the threat model's words

AAR provides **attribution**, **post-emission tamper evidence**, and **tamper
evidence over producer-declared epoch contents** (completeness is
census/reconciliation-conditional). It does **not** stop a compromised signer
lying before emission, prove any inference correct, or establish legal
compliance — see the threat model's residual-risk register for the complete
honest list.

## Layout

- `docs/` — governing documents (spec, threat model, wire rubric, RFP model language, related work)
- `spec/` — normative CDDL + prose, gate records (v0.2 work product)
- `kats/` — byte-pinned known-answer tests + negative fixtures
- `harness/` — KAT generator + cross-verification harness (TypeScript)
- `pyref/` — free offline verifier (Python 3.11+, stdlib only)
- `adapters/` — VAPIX + VMS reference legs
- `demo/` — sanitized end-to-end run evidence

## Release gate

Every tag runs, and must pass, `scripts/release-check.sh`:

```console
bunx tsc --noEmit -p tsconfig.json         # strict types across harness, demo, adapters
bun test harness                           # KATs, verifier, cross-impl bytes
python3 -B -m pyref.kat --slice all        # pyref C1/C2 clean-room KATs
python3 -B -m pyref.schema_kat             # CDDL oracle (Ruby cddl gem, pinned in pyref/README.md)
bun test demo/ep/wire-builder.golden.test.ts   # demo bundles: pinned digests + two-verifier byte identity
bun test adapters                          # offline VAPIX + VMS legs through pyref
```

The same script runs on every push and pull request (`.github/workflows/release-check.yml`).

## Process and name

Built with a two-model pipeline (one model plans and gates, another builds and
challenges); the gate records are published in `spec/` deliberately, because
scrutiny is the hardening. Wire discipline: deterministic CBOR, closed
schemas, COSE_Sign1 ES256, strict first-failure, externally generated KATs.
The most useful things in `spec/DECISIONS.md` are the mistakes: D-56, D-60,
and D-73 each record a rule two implementations agreed on until an input the
corpus never covered showed the rule was incomplete.

"Receipt" is the field's term for this object (Notarized Agents, PCAA,
AgentBound; see `docs/related-work-addendum-2026-08-28.md`). The acronym
collides with "after-action report"; the name stays.

## License

- **Code** (`pyref/`, `harness/`, `kats/`, `adapters/`, `demo/`): Apache License 2.0 — see `LICENSE`.
- **Specification text** (`spec/`, `docs/` prose and CDDL): CC BY 4.0 — see `LICENSE-SPEC`.

Verifying receipts is free, forever, offline, with no account and no license
from anyone. That property is load-bearing: an evidence format you cannot
independently check is not an evidence format.
