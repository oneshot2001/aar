# AAR-EP-BIND/1 — Binding EdgeProof SDR signed frames to AAR observations

Status: **draft**, against AAR `v0.2-rc7` and EdgeProof SDR wire format **v1.1
(FROZEN)** as pinned by `spec/CONFORMANCE.md` (repository commit `b9d7bc6`). This is a
**profile/convention document**: it defines no new CDDL and changes no wire bytes on
either side. All maps in `aar-core.cddl` are closed; everything here rides existing
fields. Conformance codes marked PROPOSED are not yet part of `spec/CONFORMANCE.md`
and go through the normal gate pipeline.

## 1. Purpose

A machine-derived description of video (caption, entity, event) is only evidence if it
is bound to the exact pixels it describes. This profile specifies how an AAR
`observation` references frames signed under EdgeProof SDR v1.1 so that an offline
verifier can prove, from the bundle alone:

1. the referenced frame bytes are the ones the sensor-side signer committed to, and
2. any downstream `inference` (via `derived_from` + `consumption_manifest_id`
   resolution, `CONFORMANCE.md` step for `receipt/consumption-ref-unresolved`)
   describes exactly those frames and no others.

Granularity is deliberately **frame-set**: SDR v1.1 signs single frames
(`src_frame_sha256`); a frame-set is therefore the maximal claim the frozen wire
supports. Dense-video / time-range binding is deferred to a future EdgeProof segment
object (Merkle root over frame digests) and will arrive as `AAR-EP-BIND/2` without
changing the verifier procedure below — only what `content_commitment` commits to.

## 2. Binding construction (producer requirements)

An observation claiming this profile:

**2.1 Consumption items — one per described frame.**
- `media_type` SHALL be the convention string `image/x-edgeproof-frame`.
- `content_commitment` SHALL be the SHA-256 of the source frame bytes,
  **byte-identical to the `src_frame_sha256` of an SDR detection record carried in
  the same bundle**. This equality is the binding.
- Any preprocessing the inference runtime applied (decode, crop, normalize, redact)
  SHALL appear in the item's `transformations` chain with the first entry's
  `input_digest` equal to `content_commitment`. The commitment is always to the
  *signed* bytes, never to a derived tensor.
- Frames consulted but not described SHALL carry `disposition: "discarded"`
  (outcome-honesty: the description's evidentiary scope is the `"used"` set).

**2.2 Native attestation — the SDR record itself.**
One `native-attestation` per contributing SDR record:
- `format` SHALL be `"other"` (the closed enum's extension value; `"axis_signed_video"`
  denotes Axis's SEI scheme, which SDR is not).
- `assertion_digest` SHALL be the SHA-256 of the SDR record's exact signed bytes.
- `pointer` SHALL begin `edgeproof-sdr/1.1:` followed by a bundle-resolvable locator.
  Per D-32 (hash-only references prevent offline verification) and the D-49
  opaque-bytes-plus-digest discipline, the record bytes SHALL be carried in the
  bundle; a pointer that leaves the bundle is nonconformant *for this profile*.

**2.3 Time bounds are derived, never asserted.**
The interval a bound description covers is `[min, max]` of the `ts` fields (strict
RFC3339 UTC, signed) of the bound frames' SDR records. Producers SHALL NOT carry a separate unsigned
time-range claim; verifiers derive it. (This is what frame-set granularity buys:
time is signed data, not annotation.)

**2.4 Key deployment (normative for this profile).**
The `agent_signing` key used on the observation/inference is held and applied by the
**inference runtime/harness**, injected at process level. Model output never contains,
transits, or triggers use of key material. Rationale: a model's account of its own
identity and actions is testimony, not a record — self-reports are unreliable in the
honest case (Lindsey 2026, arXiv 2601.01828, ~20% peak introspective detection) and
adversarial under goal conflict (Anthropic Frontier Red Team, *Patterns and problems
in emerging multiagent systems*, 2026-08-13: agents forging identity in status
checks). The receipt is generated below the agent, by the machinery around it. This
composes with, and does not relax, the core signer matrix (`CONFORMANCE.md`
"Signer legality") and `credential/role-key-reuse`.

## 3. Verifier procedure (offline, bundle-only)

In addition to core AAR verification, a verifier evaluating an AAR-EP-BIND/1 claim
SHALL:

1. Resolve each `native-attestation` with an `edgeproof-sdr/1.1:` pointer to bytes in
   the bundle; check `assertion_digest`.
2. Verify each resolved SDR record's signature per EdgeProof SDR v1.1 (detached
   signature, `kid = SHA-256(SPKI)`), against credentials carried in-bundle — never
   an OS trust store (same rule as core key resolution).
3. Check that every `image/x-edgeproof-frame` item's `content_commitment` equals a
   `src_frame_sha256` of a record verified in step 2.
4. Derive the covered interval per §2.3.
5. Emit a signed verdict as always: never a bare PASS token.

Note this profile makes deep validation of one attestation format **normative**,
which core v0.2 deliberately does not (D-49: "a v0.3 or stronger-profile concern").
AAR-EP-BIND/1 is that stronger profile, for exactly one format.

## 4. Failure semantics (PROPOSED conformance codes)

Consistent with the core philosophy that missing external inputs are `indeterminate`
and contradicted commitments are `nonconformant`
(`CONFORMANCE.md` external-inputs rule):

| Condition | Code | Verdict |
|---|---|---|
| Attestation bytes present, `assertion_digest` mismatch | `attestation/digest-mismatch` | nonconformant |
| Attestation referenced, bytes absent from bundle | `attestation/payload-missing` | indeterminate |
| SDR record signature fails SDR v1.1 verification | `attestation/native-invalid` | nonconformant |
| An `image/x-edgeproof-frame` `content_commitment` matches no verified record | `binding/commitment-unmatched` | nonconformant |

Background: core CONFORMANCE step 19 does not currently require `native_attestations`
to resolve at all — a dangling pointer triggers no rule. The first two codes above are
proposed for core (post-rc7 minor); the last two are profile-specific. A semantic
description whose frame references do not verify is **unverifiable, never silently
"best effort."**

## 5. Non-goals

- **Correctness of the description.** The chain proves attribution and
  tamper-evidence, not that the model described the frames accurately. Hallucination
  is bounded by the reproducibility fields on the inference and by core
  outcome-honesty rules, not by this binding.
- **Dense-video / GOP / segment claims.** Frozen SDR v1.1 has no segment object;
  claims over ranges larger than the bound frame set are out of scope until
  AAR-EP-BIND/2.
- **Compromised-signer immunity** (core's settled guarantee boundary).
- **Whole-clip binding.** The SDR companion clip record (`clip_uri`/`clip_sha256`) is
  unexercised and cannot localize a description in time; it is not used by this
  profile.
