# Gate 2 — coverage audit and close
2026-07-14, at 1ba28d1. Audit against the rubric KAT bar (docs/v02-wire-rubric.md):

| # | Bar | Status |
|---|---|---|
| 1 | Positive KAT per node type, edge type, epoch transition, anchor proof, Merkle proof, bundle | ✅ 33 positive KATs; all six node kinds (incl. per-root variants), all four epoch events, RFC 6962 inclusion+consistency, batch membership, valid_subset bundle |
| 2 | Negative fixture per reason code, each triggering it and only it | ✅ **144/144** — mechanically reconciled table↔fixtures (145th grep hit was the §2.1 edge-matrix row, not a code); first-failure asserted exactly per fixture; 3 stateful codes use the paired prior-state format (D-45) |
| 3 | Class-boundary KATs per evidence-class transition | ✅ 10 — time (2 boundaries), provenance (2), outcome (1), each with fail-higher AND pass-higher |
| 4 | Adversarial graph fixtures, each failing with its own code | ✅ 11 (splice, dangling parent, duplicate identity, wrong-attempt authorization, cross-epoch replay, dominator missing/ambiguous, …) |
| 5 | Epoch/equivocation fixtures | ✅ 9 (fork, event-chain break, ID reuse, two-manifests-one-epoch, late insertion, duration, anchor deadline, …) |
| 6 | Two independent encoders byte-identical | ⚠️ **CARRIED RESIDUE** — one implementation exists; self-determinism holds (double-generation corpus hash stable). The second independent implementation IS the reference-Verifier deliverable (next phase); this bar closes there, before any conformance claim ships. |
| 7 | edgeproof-sdr v1 bytes undisturbed | ✅ trivially — no shared tooling was used; aar is standalone |

Totals: 188 CBOR fixtures (33 positive / 142 stateless negative / 3 stateful /
10 class-boundary), verifier implements all 20 validation steps with signed
verdicts, `bun test` 16/16 (1,152 assertions), tsc clean.

Wire-contract deltas produced by this gate (all Codex-found, Claude-ruled):
D-37..D-51 — seven artifact-ID preimages, credential SPKI carry, EP journal
signing, event-chain + anchor manifest digests, three deleted-as-unreachable
codes (`cose/kid-mismatch`, `credential/algorithm-mismatch`, `graph/cycle` —
the last because content-addressing makes the DAG acyclic by construction),
`identity/reuse` + `merkle/duplicate-leaf` rescoped, prior-epoch anchor
sandwich for `externally_anchored` time, attestations carried opaquely,
verdict digest preimages + early-failure sentinels.

**GATE 2 CLOSED** with residue #6 assigned to the reference-Verifier phase.
Next: gate 3 — adversarial review of the full release candidate (Codex
finding pass in read-only mode, Claude gates) → v0.2-rc tag.
