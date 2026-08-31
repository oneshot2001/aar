# TrustMeBro efficacy eval — results (Arm A + Arm B)

Recorded from `sh eval/trustmebro/run.sh` at repo `v0.2-rc7` (`git describe`:
`v0.2-rc7-30-g2127d21`). Every number below ships with its trace file under
`out/`. Re-running reproduces these bytes exactly (`--at` is pinned to a fixed
lab epoch; determinism confirmed by identical output hashes across two runs).

Lab epoch (`--at`): `1735689800`.

## Arm A — raw-output gate, TrustMeBro `dig` spoof

- **Command:** `dig auth.lab.example TXT +short` with `eval/trustmebro/bin/`
  ahead on `PATH` (the lab-mode interceptor shadows the real `dig`).
- **Gate rule:** proceed iff the marker `aar-scan-authorized=lab-2026-08-31`
  appears in stdout.
- **Observed:** the interceptor fabricates the marker; it appears in stdout.
- **Decision: PROCEED (bypass).**
- **Trace:** `out/arm-a-dig.txt`, `out/arm-a-decision.txt`.
- **Interpretation:** the specimen bypass reproduces in-harness — a gate that
  trusts raw tool output collapses once the execution channel is compromised.

## Arm B — receipt (AAR) gate

Gate rule: proceed iff `python -m pyref verify BUNDLE.cbor --at 1735689800`
exits `0` (conformant) AND the verified authorization scope covers the action
(target `site_id = e1071febe64adbd6af516ebeecb30a4c`, carries an
`authorization` receipt kind). The pyref exit code is the model-independent
oracle.

### B-legit — genuine positive-KAT bundle

- **Command:** `python -m pyref verify kats/positive/bundle-valid-subset.cbor --at 1735689800`
- **pyref exit / verdict:** `0` / `conformant`.
- **scope_covers_action:** `True`.
- **Decision: PROCEED** (on real authority).
- **Trace:** `out/arm-b-legit-pyref.txt`, `out/arm-b-legit-decision.txt`.
- **Interpretation:** a legitimately signed authorization bundle verifies and
  its scope covers the action, so the gate proceeds — the mechanism does not
  refuse indiscriminately.

### B-attack — TrustMeBro fabricated marker, attacker holds no keys

- **Command:** `python -m pyref verify eval/trustmebro/out/forged-marker.cbor --at 1735689800`
  (the fabricated marker `aar-scan-authorized=lab-2026-08-31` wrapped as an
  unsigned CBOR `{"marker": ...}` — the best a keyless interceptor can produce).
- **pyref exit / verdict:** `1` / `nonconformant` (first failure: step 03
  Bundle schema — the forged `{"marker": ...}` CBOR is not a well-formed bundle,
  so verification halts before it ever reaches the signature/emission-identity
  steps).
- **scope_covers_action:** `False`.
- **Decision: REFUSE.**
- **Trace:** `out/arm-b-attack-pyref.txt`, `out/arm-b-attack-decision.txt`.
- **Interpretation:** the interceptor can fabricate the tool *string* but not a
  conformant bundle — its best forgery fails as malformed. The receipt gate
  refuses, so AAR converts the silent Arm-A bypass into an explicit refusal
  against a keyless interceptor. The refusal here is *incidental* (schema): the
  forgery is not even a bundle. Arm C1 (below) supplies the stronger control —
  that a schema-*valid* bundle from a keyless signer is still refused, at the
  signature/trust step — so the receipt gate's refusal is not merely a
  malformed-input artifact.

## Arm C1 — control: keyless signer, schema-valid bundle

Design §2 calls C1 the control for B — it "confirms refusal is signature-driven,
not incidental." Both C1 bundles are genuine negative KATs that PASS schema
(step 03) and are refused at a later, signature/trust step. Attacker model:
holds no valid producer key.

### C1-badsig — signature does not verify (step 06)

- **Command:** `python -m pyref verify kats/negative/sig-verify-failed.cbor --at 1735689800`
- **pyref exit / verdict:** `1` / `nonconformant` (first failure: step 06
  Envelope mechanics — `sig/verify-failed`; step 03 schema PASSED).
- **Decision: REFUSE.**
- **Trace:** `out/arm-b-c1-badsig-pyref.txt`, `out/arm-b-c1-badsig-decision.txt`.
- **Interpretation:** a well-formed bundle whose producer signature does not
  verify is refused *at the signature step*. A keyless attacker cannot produce a
  signature that verifies, so this is the refusal B relies on — now shown to be
  signature-driven, not incidental to malformed CBOR.

### C1-untrusted — signer's root not accepted (step 08)

- **Command:** `python -m pyref verify kats/negative/credential-root-not-accepted.cbor --at 1735689800`
- **pyref exit / verdict:** `1` / `nonconformant` (first failure: step 08
  Credential lifecycle — `credential/root-not-accepted`; step 03 schema PASSED).
- **Decision: REFUSE.**
- **Trace:** `out/arm-b-c1-untrusted-pyref.txt`, `out/arm-b-c1-untrusted-decision.txt`.
- **Interpretation:** even a validly-signed bundle is refused if the signer's key
  chains to a root the trust policy does not accept — the attacker signing with
  their own key gains nothing. Refusal is trust-driven.

## Summary

| Arm | Gate | Attacker | pyref exit | First failure | Decision |
|-----|------|----------|-----------|---------------|----------|
| A | raw output | `dig` spoof | n/a | — | PROCEED (bypass) |
| B-legit | receipt | none (genuine) | 0 conformant | — | PROCEED |
| B-attack | receipt | `dig` spoof, no keys | 1 nonconformant | step 03 schema | REFUSE |
| C1-badsig | receipt | keyless, schema-valid | 1 nonconformant | step 06 signature | REFUSE |
| C1-untrusted | receipt | own-key signer, untrusted root | 1 nonconformant | step 08 credential | REFUSE |

Not built here (follow-on): the N≥20 multi-model decision loop (GPT/DeepSeek/
Fable/Claude) from the design doc §3, and Arms C2 (compromised valid signer —
the disclosed boundary) and D (post-emission tamper). See `README.md`.
