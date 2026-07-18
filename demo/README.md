# AAR v0.2 demo — two-leg live-lab evidence package (Gate 5 / D4)

This directory is the shared demo kit for the Gate 5 two-adapter demonstration:
one Evidence Producer (EP) and two independent translation/dispatch legs driven
by the SAME abstract commands (`camera.ptz.preset`, `camera.stream.view`)
against real, operator-owned AXIS cameras.

- **VAPIX leg (D2)** — TypeScript adapter speaking RFC 7616 Digest VAPIX
  directly to the devices. Closed live 2026-07-18, tag `v0.2-rc5`.
- **VMS leg (D3)** — TypeScript adapter dispatching abstract operations to a
  loopback `vigil-control` mediator (Swift, wrapping `VigilCore.AxisEngine.VAPIXClient`);
  the device credential is resolved by the mediator's own `cred get`, never by
  the TS process. Closed live 2026-07-18, tag `v0.2-rc6`.

**Claim boundary of the two-leg demo:** the VMS leg is *VMS-mediated* and a
*second independent implementation* (Swift vs TypeScript). It is **not** a
second-protocol or cross-vendor claim — Vigil speaks VAPIX under the hood.
Claim sentence of record: `spec/GATE5-D3-REVIEW.md`.

## One-command scenario runs

Offline (no hardware; separate mock backends, real pyref verification):

```sh
bun run adapters/vapix/offline/run.ts   # VAPIX leg, S1–S6
bun run adapters/vms/offline/run.ts     # VMS leg, S1–S4 + S6 (mock mediator)
```

Live (operator lab only — requires green preflight, `cred get` access, the
designated safe preset, and an exclusive-control window per the F19 PTZ safety
protocol; refuses to run otherwise):

```sh
bun run adapters/vapix/live/run.ts      # D2b leg
bun run adapters/vms/live/run.ts        # D3 leg (starts/uses vigil-control)
```

Every scenario emits a deterministic bundle that is verified by the public
offline CLI:

```sh
python -m pyref verify BUNDLE.cbor --at UNIX_SECONDS [--trust-policy POLICY.json] [--prior-state PRIOR.json]
```

## Scenarios

| ID | Question it answers |
|----|---------------------|
| S1 | Authorized PTZ preset dispatch, effect confirmed by tolerance readback |
| S2 | Authorized stream view, media payload independently validated |
| S3 | Unauthorized request → refusal receipt, **zero attributable dispatch** (R-1, by instrumentation + transport witness) |
| S4 | Pinned single-byte tamper → `nonconformant` with the expected first-failure code (F21) |
| S5 | Producer crash-cut after send → resume without redispatch, `outcome_unknown` + verified restore (EP+VAPIX leg once, per Q5-2) |
| S6 | Backend fault under a valid delegation: application rejection → `contradicted` only on a positively observed off-tolerance readback; after-send timeout → `unknown` |

## What a verdict proves — and does not

A conformant verdict proves that the carried artifacts in the signed scope
satisfied AAR v0.2's structural, cryptographic, graph, policy, freshness,
coverage, and declared evidence-class checks under the exact inputs and fixed
limits named by that verdict.

It does **not** prove sensor truth, inference correctness, lawfulness, custody,
legal admissibility, or complete discovery. In particular:

- `complete` is only producer-declared completeness relative to signed manifest
  indexes; ingress completeness remains `not_established` without an independent
  census or reconciliation artifact.
- A successful Merkle proof is membership-only. It proves neither that other
  leaves are absent nor that a set is complete.
- v0.2 commits required attestation bytes but does not deeply interpret every
  TPM, provider, or predicate format.
- `empty_scope` means a conformant evaluation matched zero receipts, so the
  verdict asserts nothing about any receipt.
- `stateful_not_evaluated` means no prior state was supplied, so sequence
  rollback and cross-evaluation one-time reuse were not evaluated.

(Verbatim from `pyref/README.md` — the free offline verifier. Gated demo runs
exclude both of the last two conditions: content assertions forbid
`empty_scope`, and prior state was supplied on every gated run.)

Additional demo-scope limits (F22 and adapter identity):

- Anchoring in this demo is **same-operator demo anchoring**: the RFC 6962 log
  is operated by the same party as the producer. It demonstrates the anchor
  mechanics; it does NOT provide independent timestamping or
  withholding-resistance. RFP language must not imply otherwise.
- Adapter and mediator identity (model/firmware strings, mediator name) are
  **self-asserted** by the producing side; preflight cross-checks them against
  device readback, but no third party attests them.

## Machine-readable evidence

`demo/results/run-manifest.json` is the sanitized F20 run manifest + evidence
index for both live legs: adapter commits/tags, device models and firmware,
gate-supplied input shape, command→effect mapping, transport-observation
summary, outcome-downgrade rationale per scenario, and known residuals. The
underlying per-leg artifacts live in `adapters/*/live/evidence/`; gate trail in
`spec/GATE5-*.md`; divergences and rulings in `adapters/FINDINGS.md`.

Secrets hygiene: every run ends with a canary-credential sweep (planted
credential plus HA1/base64/percent-encoded/reversible variants, hash-only-root
scoping per G5-D2b-011) over repo, receipts, logs, and captures — zero hits is
part of the exit bar. Real credentials come from the local `cred` store at
runtime; lab config, raw traces, and private keys stay outside the repo.
