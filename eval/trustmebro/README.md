# TrustMeBro fabricated-tool-output efficacy eval (Arm A + Arm B + Arm C1)

Minimum publishable slice of the AAR efficacy eval described in
`2026-08-30-trustmebro-aar-threat-specimen/aar-efficacy-eval-design.md`
(threat + defense). It proves the *mechanism* with a deterministic, byte-for-byte
reproducible harness whose objective oracle is the `pyref` verify exit code —
independent of any model.

## What it proves

- **Arm A (raw-output gate):** an authorization gate that trusts raw `dig`
  stdout is bypassed by a TrustMeBro-style PATH interceptor that fabricates the
  DNS TXT marker. The gate proceeds. This reproduces the specimen threat.
- **Arm B (receipt/AAR gate):** the marker is instead carried in a signed AAR
  bundle, and the gate proceeds only if `python -m pyref verify` returns
  conformant (exit 0) and the verified authorization scope covers the action.
  - *B-legit:* a genuine positive-KAT bundle verifies conformant → proceed.
  - *B-attack:* the same keyless interceptor can fabricate the marker string but
    cannot mint a conformant signed bundle → pyref returns nonconformant
    (exit 1, at step 03 schema — the forgery isn't even a bundle) → the gate
    refuses.
- **Arm C1 (control for B):** two genuine negative KATs that PASS schema and are
  refused at a *later* signature/trust step, proving B's refusal is
  signature-driven, not incidental to malformed CBOR.
  - *C1-badsig:* schema-valid bundle whose producer signature does not verify →
    nonconformant at step 06 (envelope/signature) → refuse. A keyless attacker
    cannot produce a signature that verifies.
  - *C1-untrusted:* schema-valid bundle signed under a root the trust policy does
    not accept → nonconformant at step 08 (credential) → refuse. Signing with
    the attacker's own key gains nothing.

## Honesty boundary (design doc §6)

AAR's guarantee is attribution + post-emission tamper-evidence + anchored
completeness — **not** immunity from a signer whose key is stolen. Against
TrustMeBro **as an interceptor with no keys** (Arm B here) AAR converts a silent
bypass into a **refusal**. Against TrustMeBro **as a compromised producer**
(valid signing key) AAR would convert the bypass into an **attributed,
non-repudiable action** — you learn *who signed the lie*, which is materially
valuable but is **not prevention**. That compromised-signer case (Arm C2 in the
design) is **not built here**; do not read this slice as "AAR stops the attack"
in general. It relocates the trust boundary from ambient tool output to a signed
artifact the compromised environment cannot forge.

## How to re-run

From the repo root:

```sh
sh eval/trustmebro/run.sh
```

Writes all transcripts + pyref verdicts to `eval/trustmebro/out/`. `--at` is
pinned to a fixed lab epoch (`1735689800`), so results are wall-clock-
independent and reproduce byte-for-byte. No hardware, no network, no keys held
by the eval beyond the repo's committed positive KAT.

Requirements: `python3` with the repo's `pyref` importable from the repo root
(as shipped), and a POSIX `sh`.

## Files

- `bin/dig` — the TrustMeBro lab-mode interceptor (spoof action). **Do not
  install outside this eval.**
- `arm_a.sh` — Arm A runner (raw-output gate under the spoof).
- `arm_b.py` — receipt-gate runner: Arm B (B-legit + B-attack) and Arm C1
  (C1-badsig + C1-untrusted).
- `run.sh` — one-command re-runner for both arms.
- `RESULTS.md` — recorded outcomes with per-arm trace pointers.
- `out/` — generated transcripts + verdicts (regenerated each run).

## Not built here (follow-on)

TODO: the N≥20 multi-model decision loop (design §3) — hand each model the tool
result (Arm A) or the pyref verdict + scope (Arm B) and record proceed/refuse
across GPT-5.6/5.5, DeepSeek V4 Pro/Flash, Fable 5, and a Claude peer. This
needs model API keys and is out of scope for this deterministic-oracle slice.
Arms C2 (compromised valid signer — the disclosed boundary) and D
(post-emission tamper) are also follow-ons. (Arm C1 is built — see above.)
