# Gate 4 CLOSED — two independent implementations agree byte-for-byte

2026-07-15. Builder: Codex (clean-room). Gate: Claude. Tag: `v0.2-rc2`.

## The bar, and the result

Gate-2 carried residue #6: "two independent encoders byte-identical" — one
implementation existed and self-determinism is not spec unambiguity. This gate
built a second implementation (`pyref/`, Python ≥3.11, zero dependencies,
hand-rolled deterministic CBOR + RFC 6979 P-256 + RFC 6962 Merkle) CLEAN-ROOM
from `spec/aar-core.cddl` + `spec/CONFORMANCE.md` + `spec/DECISIONS.md` + the
KAT corpus, with `harness/` off-limits throughout (transcript-audited on every
run).

Final state, gate-verified by independent re-runs:

| Bar | Result |
|---|---|
| Encoder round-trip byte-identity (positive + class-boundary) | 43/43 |
| ID/digest commitments recomputed | 548/548 |
| COSE signatures re-signed byte-identical (RFC 6979 + low-S) | 247/247 |
| Verifier result + reason-code agreement (full corpus) | 188/188 |
| Signed-verdict determinism | 188/188 byte-identical |
| Open divergences | 0 |
| Reference (TS) suite after fixes | 16/16, 1,152 assertions, tsc clean |

**Residue #6 is closed.** The v0.2 wire format is now evidenced by two
implementations in different languages with independent crypto stacks
producing identical bytes and identical verdicts from the spec text.

## What the exercise caught (the point of the phase)

The first C2 pass produced 20 divergences; adjudication
(GATE4-SLICE-C2-REVIEW.md) found the spec, the reference implementation, and
the fixtures each guilty of something:

- **D-55 — pyref caught the reference implementation violating locked D-19**
  (range slices filtered to selector-matching entries; membership-only proofs
  cannot prove non-omission). Reference verifier + fixture generator fixed.
- **D-53 — fail-open defect in the reference verifier**: delegation selected
  by a cardinality heuristic, evaluation silently skipped when it failed.
  Selection is now pinned to the embedded delegation; four fixtures rebuilt.
- **D-52 — adversarial-masking spec gap**: status-snapshot content checks now
  normatively precede reference resolution, so `compromised` cannot be
  downgraded to `status-missing` by breaking the reference.
- **D-54 — intra-step check order is now normative**; Run A found three
  further order deviations beyond the observed divergences.
- Two pyref bugs (boundary-class reporting; anchor-deadline predicate), fixed
  under ruling, not by peeking.

## rc status

`v0.2-rc2` = rc1 + D-52..D-55 errata + five regenerated fixtures + the
two-implementation bar met. Remaining before any ratified-conformance claim:
slice C3 (public offline verifier CLI packaging, incl. the GATE3 F4
`empty_scope` observation and F3/F6 rc-notes), then real adapter validation
(two-adapter demo: VAPIX + one VMS).
