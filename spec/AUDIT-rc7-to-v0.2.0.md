# Gate-provenance audit — `v0.2-rc7..HEAD` (pre-`v0.2.0` tag)

Date: 2026-09-01 · Auditor: Claude (read-only diff audit, 30 min) · Range: `v0.2-rc7` (`31b7ac0`) → `9fb8a70`, 33 commits.

Question: does every change to a normative surface (`spec/aar-core.cddl`, `spec/CONFORMANCE.md`, `spec/DECISIONS.md`, `harness/`, `pyref/`, fixtures) carry a two-round adversarial gate trail?

## Normative commits and their trail

| Commit | Change | Gate trail | Verdict |
|---|---|---|---|
| `6e1c38c`, `083feea`, `65bdf8c` | D-58 filed → amended → RATIFIED; D-59 filed → recast → RATIFIED; D-61 filed → RATIFIED | Adversarial review recorded in commit bodies + DECISIONS entries; operator ratification 2026-08-15 | gated |
| `12e47af`, `47cd93c`, `6437ca0`, `52268c8` | D-60 request/coordinate-mismatch: candidate → dependency note → hardening (2 P1 fixed, round-2 CONFIRMED) → RATIFIED | Independent adversarial review, 2 rounds, 7 cross-impl variants + pyref CLI test; operator ratification 2026-08-15 | gated |
| `1b6f014` | Hardening: signed verdicts on all malformed-input classes, wall-clock removed | Reviewer-gated 2 rounds (FIX-FIRST → SHIP); 75/75, pyref 0 divergences, zero fixture/verdict-byte changes | gated |
| `25fd549` | D-66: AAR-3 commits action_attempt before dispatch; fails closed on journal unavailable. **Touches CDDL + both verifiers + KATs** | Reviewer-gated 2 rounds (r1 FIX-FIRST 3 P2, r2 SHIP); harness + pyref clean-room; 5 KATs | gated |
| `d786ad7` | D-67: optional mediator countersignature. **Touches CDDL + both verifiers + KATs** | Reviewer-gated 2 rounds (r1 FIX-FIRST 4 P2, r2 SHIP); 4 KATs incl. expired mediator credential | gated |
| `e7d6f07` | CONFORMANCE.md +59 lines | Informative Appendix A (RATS EAR/AR4SI cross-map) only; explicitly no wire/harness/pyref/fixture change | non-normative |

All other commits in range are docs, drafts, eval (`eval/trustmebro/`), emitter (`emitter/l2-claude-code/`, candidate wire `;v=0.3-draft`, not v0.2), or README. `91bf4ff` fixes tsc errors in mediator envelope encoding (type-level, no byte change claimed; covered by D-67's suite).

## Findings

1. **No ungated normative change found.** Every normative commit carries a two-round trail. No third adversarial review is required before tagging.
2. **`v0.2.0` is NOT byte-identical to rc7 on the wire.** D-66 and D-67 added CDDL (additive: action-attempt evidence commitment; optional mediator countersignature). Pre-existing fixture and verdict bytes are stated unchanged in both commits. The release notes MUST list D-58..D-61, D-66, D-67 as the delta and state that rc7 bundles remain valid.
3. **Gate trails live in commit bodies and DECISIONS entries, not in `spec/GATE*.md` files** as gates 1–5 did. Adequate for provenance; the `v0.2.0` release note should link this audit so a standards reader has one place to look.
4. Candidates still open and explicitly NOT part of `v0.2.0`: D-62..D-65, D-68 (`docs/attestation-spec-deltas.md`); `AAR-EP-BIND/1` profile (`docs/aar-ep-bind-v1.md`, draft, PROPOSED codes).

## Disposition

Proceed to public-face repair → release-check + CI → tag `v0.2.0`. No live-camera rerun required (transport unchanged; wire additions are fixture-covered in both implementations).
