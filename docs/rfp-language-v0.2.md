# Model RFP language — AAR v0.2 (phase 5)

Status: draft against `v0.2-rc7`. AAR v0.2 is a **release candidate**, not a
ratified standard. Any RFP using this text MUST pin the exact version it
requires ("AAR v0.2-rc7" or a later ratified release) — conformance claims are
version-specific.

How to use: each clause below is written to be pasted into a solicitation's
technical-requirements section. `[BRACKETED]` values are the issuing agency's
choices. The clauses deliberately track what AAR can actually prove; the
"Prohibited vendor claims" section exists so evaluators can strike overclaim
during proposal review.

## Definitions (for the solicitation's definitions section)

- **AI agent action**: any machine-initiated observation, inference,
  recommendation, disposition (including alert suppression, downgrade,
  deduplication, or auto-close), or command affecting a physical-security
  system (camera, VMS, access point, sensor) or its records. The receipting
  obligation attaches only to actions within the pinned AAR version's
  ontology (see Clause 1 guidance).
- **Receipt bundle**: the deterministic, signed, offline-verifiable evidence
  artifact defined by AAR v0.2 (`spec/aar-core.cddl`), covering what the agent
  saw, inferred, was authorized to do, and actually did, with typed links
  among observation, inference, authorization, action attempt, dispatch, and
  outcome observation.
- **Offline verifier**: software that evaluates a receipt bundle using only
  the bundle, an operator-controlled trust policy, an explicit evaluation
  time, and optional prior state — with no network access and no reliance on
  the producing vendor's services.

## Clause 1 — Conformance profile

> The Offeror's system SHALL produce AAR v0.2 receipt bundles at profile
> [AAR-1 / AAR-2 / AAR-3] for all AI agent actions within [SCOPE OF SYSTEMS]
> that fall within the pinned AAR version's action ontology. Where the
> pinned version's ontology includes automated dispositions of alerts or
> events — suppression, downgrade, deduplication, or auto-closure — those
> actions SHALL carry the AAR-2A automation subprofile, which imposes AAR-3
> authorization requirements (delegation, evidence-producer decision record,
> fail-closed behavior, revocation checking, completeness anchoring) even
> where no physical actuation occurs.

Guidance for the issuer: AAR-1 (Observe) is the read-only on-ramp; AAR-2
(Advise) adds recommendation receipts; AAR-3 (Act) covers physical actuation.
Profiles are cumulative. **Ontology scoping is version-critical:** under
v0.2-rc7 the wire's action ontology is closed to two camera actions
(`camera.stream.view`, `camera.ptz.preset`); alert disposition
(`alert.suppress`) is specified but experimental — not implementable on the
v0.2-rc7 wire — and access control is out of v0 entirely. Draw [SCOPE OF
SYSTEMS] to the pinned ontology, and reserve the disposition sentence above
for a version whose ontology includes those actions. The principle stands:
the decision *not* to act is a use of authority; the suppressed alarm is what
opposing counsel subpoenas — when disposition receipting lands, do not leave
it outside the required profile.

## Clause 2 — Independent offline verifiability

> Receipt bundles SHALL be verifiable by an offline verifier that (a) is
> available to the Agency without charge and without a license from the
> Offeror, (b) runs from a bundle file, an Agency-controlled trust-policy
> file, and an explicit evaluation time, (c) performs no network access and
> reads no wall clock during verification, and (d) emits a deterministic,
> signed, machine-readable verdict. Verification SHALL NOT require any
> Offeror-operated service, account, or connectivity, at proposal time or at
> any point during the period of performance.

The AAR reference toolchain is designed to satisfy this clause: `python -m
pyref verify BUNDLE.cbor --at UNIX_SECONDS --trust-policy POLICY.json
[--prior-state PRIOR.json]` (Python standard library only; no network, no
wall clock), plus a second independent implementation used for
cross-verification during conformance testing. **Availability caveat:** as
of v0.2-rc7 the AAR repository is private and its license is TBD at launch.
This clause MUST NOT be issued against a version whose verifier is not yet
public under an open license — publishing pyref under an OSI-approved
license is a release precondition for using this model text in a live
solicitation.

## Clause 3 — Refusal and zero-dispatch

> For any request the system refuses or that fails authorization, the system
> SHALL emit a refusal receipt and SHALL demonstrate zero
> invocation-attributable dispatch to the target device or VMS, observable by
> instrumentation and by an independent transport witness positioned at the
> dispatch boundary.

## Clause 4 — Outcome honesty

> Receipts SHALL record action outcomes using AAR v0.2's calibrated outcome
> levels. The system SHALL be capable of, and SHALL be evaluated on, honestly
> encoding degraded results: `unknown` where the effect was unobservable at
> the deadline (including transport timeout after an action-bearing send and
> producer crash-and-resume without redispatch), and `contradicted` only upon
> a positively observed contrary effect. A claimed outcome of "verified"
> SHALL be treated as nonconformant unless the action's ontology entry
> defines a qualifying independent observer and such an observation is
> carried; read-back through the same API as the dispatch is
> device-acknowledged, never independently-sensed.

Note for the issuer: the crash-and-resume behavior above is evaluated as an
externally observed fault test (honest encoding under a real fault); AAR
v0.2 does not certify crash-durability of the producer itself (R-31 was
deferred at the wire freeze).

## Clause 5 — Evidence handling, retention, and deletion

> Receipt bundles SHALL be retained per [AGENCY RETENTION SCHEDULE] and
> SHALL remain verifiable offline for the full retention period using
> Agency-held trust material. Where records are deleted or redacted under
> policy, the system SHALL produce derivation receipts such that the deletion
> or redaction is attributably recorded. Cross-evaluation replay and sequence
> state SHALL be supplied to the verifier for any evaluation offered as
> evidence; a verdict evaluated without prior state SHALL be identified as
> such and SHALL NOT be represented as covering replay or rollback
> properties.

Note for the issuer: AAR records deletion attributably; it does not and
cannot make a deletion "not spoliation" — that is a legal conclusion outside
any technical standard.

## Clause 6 — Anchoring class disclosure

> The Offeror SHALL disclose the anchoring class of its receipt logs:
> whether anchor logs are operated by the Offeror or system operator
> ("same-operator anchoring") or by an independent third party. Same-operator
> anchoring SHALL NOT be represented as providing independent timestamping or
> resistance to record withholding. If the Agency requires independent
> anchoring, it SHALL state so here: [REQUIRED / NOT REQUIRED].

## Clause 7 — Completeness declaration

> The Offeror SHALL declare the completeness basis of its receipt streams.
> Producer-declared completeness (signed manifest indexes) SHALL be
> distinguished from established ingress completeness, which requires an
> independent census or cross-stream reconciliation artifact. Proposals SHALL
> NOT represent producer-declared completeness as proof that no action went
> unrecorded.

## Clause 8 — Demonstration and acceptance test

> Prior to award [or: prior to acceptance], the Offeror SHALL demonstrate, on
> [AGENCY-DESIGNATED / OFFEROR-PROVIDED] hardware, with Agency-supplied fresh
> invocation identifiers, at minimum: (a) an authorized actuation with effect
> confirmed by tolerance readback; (b) an authorized media retrieval with
> payload independently validated; (c) a refusal with zero attributable
> dispatch per Clause 3; (d) detection of a single-byte tamper of a receipt
> bundle, failing verification with a specific machine-readable reason code;
> (e) honest `unknown` encoding under an injected post-send fault; and (f) a
> backend rejection under valid authorization encoded per Clause 4. All
> resulting bundles SHALL verify per Clause 2 using an Agency-held trust
> policy. A credential-hygiene sweep of all produced artifacts SHALL show no
> credential material, including transformed forms.

This mirrors the AAR Gate 5 scenario set (S1–S6), which has been executed
end-to-end on real cameras (PTZ actuation and stream-view targets) through
two independent adapter implementations (the crash-resume scenario runs once
through the shared producer, per the Q5-2 gate ruling); the sanitized
evidence package is `demo/results/run-manifest.json`.

## Prohibited vendor claims (evaluator's strike list)

A proposal SHOULD be marked deficient if it claims AAR conformance provides:

- proof of sensor truth, inference correctness, or lawfulness of an action;
- legal admissibility or a chain-of-custody determination (admissibility is a
  judicial determination; AAR supplies technical foundation, not the ruling);
- immunity to a compromised signer (the guarantee is attribution,
  post-emission tamper evidence, and tamper-evident anchored epoch manifests
  — completeness per Clause 7 — not compromised-key immunity);
- completeness of discovery ("no actions went unrecorded") from
  producer-declared manifests alone (Clause 7);
- independent timestamping from same-operator anchoring (Clause 6);
- process honesty from artifact conformance (a verifier confirms artifacts
  satisfy their declared class; it does not certify the producing process);
- override of life-safety system design (AAR never supersedes fail-safe
  behavior; degraded-mode handling is action-specific).

## Version and change control

> The Offeror SHALL identify the exact AAR version implemented and SHALL
> notify the Agency of any change to receipt wire format, verifier behavior,
> or reason-code semantics, which SHALL require re-acceptance under Clause 8.
