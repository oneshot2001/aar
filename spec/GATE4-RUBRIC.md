# Gate 4 — second independent implementation + public verifier packaging

2026-07-15, from `v0.2-rc1` (`2281719`). Closes gate-2 carried residue #6
("two independent encoders byte-identical") and produces the free public
verifier the strategy calls for. Claude authored this rubric and gates every
slice; the builder works clean-room.

## Why this phase exists

One implementation exists (Bun+TS, `harness/`). Self-determinism holds
(double-generation corpus hash stable), but a single implementation cannot
distinguish "the spec is unambiguous" from "the spec means whatever the
implementation does." rc1 is explicitly NOT a ratified conformance spec until
a second implementation, built from the spec text alone, reproduces the wire
bytes and every verdict.

## Clean-room rule (hard constraint)

The builder MUST NOT read, grep, or otherwise consult anything under
`harness/` while building. Permitted inputs, exhaustively:

- `spec/aar-core.cddl` — the wire schema
- `spec/CONFORMANCE.md` — validation steps, reason codes, digest preimages
- `spec/DECISIONS.md` — D-01..D-51 rulings
- `kats/**` — the fixture corpus (CBOR bytes + JSON sidecars). Fixtures are
  DATA, not implementation; decoding them is permitted and required.
- The test-key table below.
- `docs/` background (requirements draft, threat model) — optional context.

Any question the permitted inputs cannot answer is a FINDING, not a reason to
peek: record it in `pyref/DIVERGENCES.md` (see protocol) and continue with the
most defensible spec-text reading.

## Test keys (published, KAT-only)

P-256 private scalars, hex, deliberately trivial. NEVER for use outside KATs.
`kid` = SHA-256 of the DER SubjectPublicKeyInfo of the uncompressed public key.

| role | scalar |
|---|---|
| agent_signing | 0x…01 |
| ep_signing | 0x…02 |
| authority_signing | 0x…03 |
| approver_signing | 0x…04 |
| outcome_signing | 0x…05 |
| anchor_signing | 0x…06 |
| verifier_signing | 0x…07 |
| credential_issuing | 0x…08 |
| status_signing | 0x…09 |
| agent_signing_successor | 0x…0a |

(Each scalar is the 32-byte big-endian value of the small integer shown.)

## Deliverable shape

`pyref/` — Python ≥3.11. Dependency budget: stdlib + at most one small
signature library IF it provides RFC 6979 deterministic ECDSA (e.g. `ecdsa`);
hand-rolling RFC 6979 over stdlib `hashlib` is equally acceptable.
**No CBOR library** — deterministic CBOR encoding/decoding is the property
under test and MUST be implemented from the spec.

Signatures MUST be RFC 6979 deterministic ES256 with low-S normalization —
this is what makes byte-comparison against the corpus meaningful.

## Slice C1 — encoder equivalence

For EVERY `.cbor` under `kats/positive/` and `kats/class-boundary/`:

1. **Round-trip:** decode to an abstract model, re-encode with the pyref
   deterministic encoder → output bytes MUST equal the fixture bytes exactly.
2. **ID/digest recomputation:** independently recompute every value in the
   fixture's JSON sidecar (`computed_ids`, digests, roots) from the decoded
   content using the spec's domain-separated preimages → MUST match.
3. **Signature recomputation:** for every COSE signature in the fixture,
   rebuild the Sig_structure from spec, re-sign with the corresponding test
   scalar (RFC 6979 + low-S) → signature bytes MUST match the fixture.

Exit bar: all three checks pass for 100% of positive + class-boundary
fixtures, reported as a machine-readable results file
(`pyref/results-c1.json`) plus `python -m pyref.kat` runnable by the gate.

## Slice C2 — verifier equivalence

Implement the full 20-step validation pipeline from `spec/CONFORMANCE.md`,
including signed verdicts (verifier_signing key), sentinel rules for
early-failure verdicts (GATE3 F1: `conformant` MUST carry non-sentinel
scope/trust_policy/evaluated_profile), and the stateful checks fed by the
`*.prior.json` files under `kats/negative/stateful/`.

For EVERY fixture in the corpus (positive, class-boundary, negative,
stateful):

- Evaluate → the verdict `result` and reason code(s) MUST match the sidecar's
  expectations (`expected_code` for negatives; conformant for positives unless
  the sidecar says otherwise).
- Verdict determinism: re-run → byte-identical signed verdict (given the same
  supplied state and a fixed evaluation-time input; evaluation time is an
  explicit CLI/API input, never wall-clock, so KAT verdicts are reproducible).

Exit bar: 100% verdict + reason-code agreement, `pyref/results-c2.json`,
runnable end-to-end by the gate.

## Slice C3 — public verifier packaging (after C1+C2 gate PASS)

Minimal offline CLI: `python -m pyref verify <bundle.cbor> [--trust-policy
<file>] [--prior-state <file>] [--at <timestamp>]` → prints the signed verdict
+ human-readable step report, exit code 0 only on `conformant`. No network.
Also implement the GATE3 F4 deferral here: when a bundle verifies conformant
over zero matching receipts, the verdict output includes an `empty_scope`
observation (presentation-layer note, not a wire change).

## Divergence protocol

On ANY mismatch (byte, ID, signature, verdict, reason code):

1. STOP work on that fixture. Do not reverse-engineer the expected bytes into
   the code by trial mutation.
2. Record in `pyref/DIVERGENCES.md`: fixture name, expected vs produced,
   the spec sentence(s) relied on, and the ambiguity hypothesis.
3. Continue with remaining fixtures; ship the slice with divergences listed.
4. Claude adjudicates each divergence against spec text: spec bug (→ erratum,
   possibly rc2), fixture bug, or pyref bug. Only Claude's ruling unblocks a
   change.

A divergence is a SUCCESS of this phase, not a failure — finding spec
ambiguity is the point. Overclaiming "all pass" with silent fudging is the
only unacceptable outcome.

## Gate roles

- Builder: Codex (clean-room; systems lane). If the OpenAI content filter
  blocks the build (gate-3 precedent), Claude builds under the same
  clean-room + divergence rules.
- Gate: Claude — re-runs both result suites independently, spot-decodes
  fixtures, audits `DIVERGENCES.md` adjudications, checks the clean-room rule
  was observed (no `harness/` reads in the transcript), then writes
  `spec/GATE4-CLOSE.md`. Residue #6 closes ONLY on a clean gate.
- rc-notes carried into this phase: F3 (reference-by-ID note), F4
  (`empty_scope` observation — C3), F6 (absent prior state = "not evaluated",
  not "passed") — Claude folds F3/F6 prose into CONFORMANCE.md at gate close.
