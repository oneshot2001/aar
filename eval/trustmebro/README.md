# TrustMeBro fabricated-tool-output efficacy eval (Arms A, B, C1, C2, D)

The deterministic-oracle slice of the AAR efficacy eval described in
`2026-08-30-trustmebro-aar-threat-specimen/aar-efficacy-eval-design.md` (threat +
defense + the disclosed boundary). It proves the *mechanism* with a deterministic,
byte-for-byte reproducible harness whose objective oracle is the `pyref` verify
exit code — independent of any model. All five arms of the design's single-model
matrix are built; only the multi-model decision loop (§3) remains, blocked on
provider API keys.

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
- **Arm C2 (the disclosed boundary):** attacker holds a producer signing key the
  trust policy accepts (a fully compromised producer). pyref returns conformant
  and the gate **proceeds** — AAR gives *no* immunity here. What it provides is
  attribution: the action is non-repudiably bound to the signer's kid
  (`dc0ce6…b534ba`, the `authorization` receipt's signer). The eval surfaces this
  openly rather than counting C2 as a defeated attack.
- **Arm D (tamper-evidence):** the genuine positive KAT with one byte of a signed
  `authorization` receipt flipped after emission → nonconformant at step 06
  (`sig/verify-failed`) → refuse. A signed receipt cannot be silently edited.

## Honesty boundary (design doc §6) — now measured, not just stated

AAR's guarantee is attribution + post-emission tamper-evidence + anchored
completeness — **not** immunity from a signer whose key is stolen. Against
TrustMeBro **as an interceptor with no keys** (Arms B/C1/D) AAR converts a silent
bypass into a **refusal**. Against TrustMeBro **as a compromised producer** with a
valid signing key (Arm C2) AAR converts the bypass into an **attributed,
non-repudiable action** — you learn *who signed the lie*, which is materially
valuable but is **not prevention**. Arm C2 makes that line reproducible (exit 0,
attributed kid recorded); do not read the refusing arms as "AAR stops the attack"
in general. AAR relocates the trust boundary from ambient tool output onto a
signing key the compromised environment must *also* steal.

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
- `arm_cd.py` — Arm C2 (compromised valid signer — conformant + attributed) and
  Arm D (post-emission one-byte tamper — nonconformant).
- `run.sh` — one-command re-runner for all arms.
- `RESULTS.md` — recorded outcomes with per-arm trace pointers.
- `out/` — generated transcripts + verdicts (regenerated each run).

## Not built here (follow-on)

TODO: the N≥20 multi-model decision loop (design §3) — hand each model the tool
result (Arm A) or the pyref verdict + scope (Arms B–D) and record proceed/refuse
across GPT-5.6/5.5, DeepSeek V4 Pro/Flash, Fable 5, and a Claude peer. This needs
model API keys plus a thin agent-glue runner and is out of scope for this
deterministic-oracle slice. All five single-model arms (A, B, C1, C2, D) are
built — see above.
