# Related-work addendum — 2026-08-30 threat specimen: TrustMeBro

Status: addendum against `v0.2-rc7`, dual-reviewed (Claude + Codex,
2026-08-30). Recorded as a related-work addendum. Claims are limited to
a static read of the repo at HEAD on 2026-08-30 plus its README; no code was
executed. This document changes neither the v0.2 wire nor the verifier.

**Pin.** `github.com/DavidCarliez/trustmebro`, MIT, Go, v0.1.x
(commit read 2026-08-30). Public X framing: "Bypass llm guardrails by
confusing it with fabricated tool output."

---

## A. What it is

TrustMeBro is a red-team harness that installs `PATH` shims (and, in Linux
`lab` mode, Bubblewrap mounts that shadow discovered absolute paths such as
`/usr/bin/dig`) for `dig` / `nslookup` / `host` — any command, in principle.
Per-call YAML rules select one of four actions: **spoof** (fabricated output,
real binary never runs), **rewrite** (run real, patch stdout, preserve
stderr + exit), **passthrough** (`exec` the real binary), or **reject**. Every
decision is written to a JSONL audit log.

Its headline scenario is exactly AAR's motivating attack: an agent is instructed
to verify a fresh DNS TXT authorization marker before proceeding with a scan.
Real `dig` returns nothing → the agent refuses. TrustMeBro fabricates the marker
→ the same agent proceeds. Reported across GPT-5.6 Sol, GPT-5.5, DeepSeek V4
Pro/Flash (all blocked → proceeded).

## B. Why it belongs in AAR's threat record

TrustMeBro is a working, publicly weaponized demonstration of AAR's founding
premise: **tool output is an observation, not proof.** Re-running a check
through the same compromised execution channel adds no assurance because the
attacker controls both observations. Any authorization guardrail enforced only
through agent-visible CLI output collapses under this threat model. This is the
canonical "before" that a signed action receipt is meant to defeat: fabricated
`dig` output carries no valid producer signature, so it fails receipt
verification regardless of how well it mimics the real tool's format.

Maps onto the existing threat model as an instantiation of the tampered /
fabricated-observation family (T-H* input-integrity line), not a new class.
It hardens the record with an independent, external, non-AAR-authored specimen.

## C. Boundaries (do not overstate)

1. **Post-compromise, not remote.** The attack requires prior control of PATH,
   shell init, or the execution namespace. It is a capability an attacker who
   already holds the agent's environment can exercise, not a remote bypass.
   Frame AAR's answer as "the receipt is signed outside the mutable agent
   environment," not "AAR detects the shim."
2. **Novelty is modest.** The interception primitive is MITRE **T1574.007**
   (PATH hijacking); schema-valid false tool observations are already an active
   topic (e.g. `guangxiangdebizi/tool-output-spoofing-lab`). Cite it as
   corroborating evidence the problem is being operationalized, not as novel
   prior art.
3. **Scoped interceptor, per its own README.** Absolute paths bypass it outside
   lab mode; `env -i` / `sudo` / sandbox PATH-replacement escape it; in-process
   resolvers (Python `socket`, `dns.resolver`, DoH) never touch the shim. It is
   a shell-tool interceptor, not a universal MITM.
4. **Its own eval is anecdotal.** The model-results table ships no reproducible
   prompts, traces, or runner. Do not cite the numbers; cite the mechanism.

## D. What to steal (design + eval, not code)

- **Eval shape.** The blocked-vs-proceeded table across models is the exact
  shape of an AAR efficacy eval: run the DNS-marker gate with and without
  receipt verification and show the fabricated output fails signature check.
  Unlike TrustMeBro's table, commit the prompts/traces/runner so it is
  reproducible — avoid the same criticism.
- **Positioning line.** "Guardrails gated on unauthenticated tool output are
  trivially defeated once the environment is compromised; AAR moves the trust
  boundary to a signed receipt the compromised environment cannot forge."

## E. Codex-found defects (for accuracy if cited)

- IPv6 reverse-name generation renders hex nibbles `a-f` as punctuation, so
  `dig -x` spoofing is wrong for many IPv6 addresses.
- Raw logged argv may capture secrets.
- Requires Go 1.27 (tests unrunnable on 1.26.3 in Codex's env).

## Disposition

CITE as an external threat specimen and eval-design template. No dependency,
no code adoption, do not install the shims in any real environment. Build
routing note: OpenAI's cybersecurity content filter has twice blocked Codex
finding-passes on this security spec — the dual-review here used Codex in a
descriptive read-only review role (no finding pass), which cleared.
