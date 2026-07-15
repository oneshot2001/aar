# Agent Action Receipts (AAR)

**Vendor-neutral, evidence-grade conformance profiles for AI agents acting on
physical-security systems.**

> PRIVATE during drafting. Public at launch per the standard-author plan
> (spec + free verifier + conformance suite + RFP language).

## The question AAR answers

*What must be independently provable about what an agent saw, inferred, was
authorized to do, and actually did — before its output triggers physical-world
action or becomes evidence?*

## Status

| Artifact | State |
|---|---|
| Requirements draft | **v0.1.1** — `docs/spec-v0.1.1-requirements-draft.md` (not a conformance spec until the wire freeze) |
| Threat model | **v0.1** — `docs/threat-model-v0.1.md` (30-finding adversarially challenged, gated) |
| v0.2 wire freeze | **IN PROGRESS** — rubric at `docs/v02-wire-rubric.md`; CDDL + KATs under the rc-gate process |
| Reference Verifier | not started (post-freeze) |
| Adapters (VAPIX + one VMS) | not started |

## Guarantees (and honest non-guarantees)

AAR provides **attribution**, **post-emission tamper evidence**, and **tamper
evidence over producer-declared epoch contents** (completeness is
census/reconciliation-conditional). It does **not** stop a compromised signer
lying before emission, prove any inference correct, or establish legal
compliance — see the threat model's residual-risk register for the complete
honest list.

## Layout

- `docs/` — governing documents (spec, threat model, wire rubric)
- `spec/` — normative CDDL + prose (v0.2 work product)
- `kats/` — byte-pinned known-answer tests + negative fixtures
- `harness/` — KAT generator + verifier skeleton

## Process

Two-model pipeline: Claude plans and gates (3 gates: CDDL review → KAT
coverage audit → adversarial rc review); Codex builds. Wire discipline
inherited from edgeproof-sdr v1.1 (deterministic CBOR, closed schemas,
COSE_Sign1 ES256, strict first-failure, externally generated KATs).

## License

TBD at launch (spec text expected open; see rubric).
