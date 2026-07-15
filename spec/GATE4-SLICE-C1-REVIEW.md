# Gate 4 slice C1 review — encoder equivalence

2026-07-15. Builder: Codex (clean-room per GATE4-RUBRIC). Gate: Claude.

## Result: ACCEPTED

43/43 fixtures (33 positive + 10 class-boundary): round-trip byte-identity,
548 ID/digest commitments recomputed, 247 COSE signatures re-signed
byte-identical (hand-rolled RFC 6979 + low-S over stdlib, zero dependencies,
no CBOR library). Zero divergences. Gate re-ran `python -m pyref.kat`
independently — same result, exit 0.

## Gate checks performed

1. **Independent re-run** — suite re-executed by the gate, results match the
   builder's report exactly.
2. **Clean-room audit** — full builder transcript grepped for `harness/`
   access: all 7 mentions are rubric/prompt echoes or the builder's own
   compliance statements; zero reads. Rule observed.
3. **Anti-fudge code review** — `pyref/cbor.py` is a genuine independent
   deterministic-profile codec; notably it enforces the profile on DECODE
   (shortest-form arguments, canonical map-key ordering, duplicate-key
   rejection, no tags/floats/indefinite), which makes `dumps∘loads` an
   identity on accepted inputs — so nested bstr-wrapped payloads are
   canonicality-proven even where the outer round-trip carries them opaquely.
   Envelope recursion (`_signed_envelopes`) descends into payloads;
   Sig_structure is rebuilt from spec and re-signed with the published test
   scalars, not copied.
4. **Crypto review** — RFC 6979 implementation includes the bits2octets
   mod-N reduction; low-S normalization present. 247/247 byte matches against
   the noble-curves-based impl #1 output is the cross-family confirmation.

## Significance

This is the first independent-implementation evidence for the v0.2 wire
format: a second encoder, built from `aar-core.cddl` + `CONFORMANCE.md` +
`DECISIONS.md` alone in a different language with independent crypto,
reproduces every positive wire byte. Gate-2 residue #6 is HALF closed —
the verifier half (slice C2: 20 steps, all 188 fixtures, verdict + reason-code
agreement) remains before the residue clears.

Next: slice C2.
