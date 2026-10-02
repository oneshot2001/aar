# Admissibility crosswalk — AAR v0.2 against the Federal Rules of Evidence (draft v0.1)

Status: **draft, unreviewed by counsel, not legal advice.** Written against
wire `v0.2.1` (verdict v3, D-76) on `main` and the Federal Rules of Evidence as amended through December 1,
2024 (the 2023 Rule 702 amendment and the 2024 Rule 1006 / new Rule 107
amendments). State rules differ; the state notes below are marked for
verification. This document does not claim that any AAR artifact is
admissible anywhere. It answers a narrower question: **for each rule a
proponent would have to satisfy, what does the bundle and verdict already
supply, what does it not, and which human has to supply the rest.**

Spec section numbers (§3.2, §5.1, §8, §10 …) refer to
`docs/spec-v0.1.1-requirements-draft.md`, the requirements text; they
describe intended behavior and are distinguished below from what the v0.2
wire and verifier implement (`spec/aar-core.cddl`, `spec/CONFORMANCE.md`).

Companion: `rfp-language-v0.2.md` ("Prohibited vendor claims"),
`threat-model-v0.1.md` T-J1 (evidence-chain and admissibility attacks),
`spec/DECISIONS.md` D-29 (verdicts enumerate claim limits, including negative
limits), `spec/CONFORMANCE.md` §5 limits block.

## 0. The bundle this crosswalk was written against

One real bundle, one real verdict, run offline:

```console
$ python -m pyref verify kats/positive/bundle-valid-subset.cbor --at 1735689800
Result: conformant
Trust policy: producer-declared only
  verdict_id:        064431204fe224ef1c6f1aee22773eb80f40a99e87bf430afd018a517bc1da5b
  bundle_digest:     9571233e3ea5f08ff9cea1e81fa8394b669c135ac113f68c41b0ef59916a5b75
  requested_profile: AAR-2A   evaluated_profile: AAR-2A   coverage: valid_subset
  signed_observations: membership_only, anchor_existence_order_only,
                       ingress_completeness_not_established
```

The verdict carries a signed `limits` map (`spec/CONFORMANCE.md:688-692`)
and a signed `scope` map. For this bundle they read:

| field | map | value emitted | meaning |
|---|---|---|---|
| `technical_integrity` | limits | `satisfied` | bytes, signatures, graph, epochs, anchors check out |
| `source_authenticity` | limits | `not_established` | a valid signature says a key signed, not that the key's holder is who the bundle says |
| `custody_continuity` | limits | `not_established` | v0.2 MUST emit this for every result (`:696-699`) |
| `discovery_completeness` | limits | `not_established` | nobody checked that this is everything the producer holds |
| `legal_admissibility` | limits | `not_established` | the only value the field can take |
| `ingress_completeness` | scope | `not_established` | v0.2 MUST emit only this (`:701`); no census exists |

Two facts about the verifier itself matter for every rule below and are
disclosed in `pyref/README.md:158-165`: the verdict is signed with the
**published Gate 4 KAT test key**, which "is not an operational verifier
identity," and `build_digest` / `config_digest` are **stable constant
preimages**, not a measurement of the code that ran. A verdict therefore
records which check was requested and what conclusion was reported;
independent evidence must establish that the claimed verifier actually
executed it, and the constant digests do not prove deployed-code identity.
That is freeze blocker D-58 (`spec/DECISIONS.md`) seen from the witness
stand.

Everything below is a map from those fields onto the rules. The short
version: **AAR supplies `technical_integrity`; every other row is a human's
job, and the verdict says so in signed bytes.**

## 1. Rule-by-rule crosswalk

Columns: what the rule requires → what the bundle / verdict supplies today
(file reference) → **GAP** (what it does not supply) → who supplies it.

### FRE 901(a) — authentication generally

- **Requires:** evidence sufficient to support a finding that the item is what
  the proponent claims it is.
- **Supplies:** deterministic CBOR bundle bytes committed by `bundle_digest`;
  a signed verdict naming that digest, a verifier build identifier
  (`build_digest`), its configuration (`config_digest`) and its resource
  limits (`limits_digest`) (`spec/CONFORMANCE.md` step 20; D-29).
- **GAP:** 901 asks what the item *is*; the verdict reports conformance and
  scoped consistency with the signatures and commitments supplied to it,
  not historical byte continuity since emission. It does not prove the
  emitting system was the one the agency says it deployed, that the keys
  belonged to it (`source_authenticity: not_established`), or — given the
  published test key and constant preimages above — that the verifier run
  was the one claimed. Independent deployment and build evidence is needed
  for both ends.
- **Who:** a witness with knowledge (901(b)(1)) or a 902(13) certifier,
  speaking to deployment and key custody, not to the spec.

### FRE 901(b)(9) — process or system

- **Requires:** evidence describing a process or system and showing that it
  produces an accurate result.
- **Supplies:** the normative 20-step verifier (`spec/CONFORMANCE.md`), the
  known-answer corpus (`kats/`: positive, negative, class-boundary,
  terminal-state, evidence-commit, countersign), a clean-room second
  implementation (`pyref/`) with its divergence log (`pyref/DIVERGENCES.md`),
  and cross-implementation results (`pyref/results-c1.json`,
  `results-c2.json`). This describes the **verification** process and shows
  it produces a reproducible result, which supports authenticating verifier
  output.
- **GAP:** authenticating the upstream receipts under 901(b)(9) requires an
  additional foundation about the *emitting* process: that a given agent,
  EP, or outcome observer, as deployed, produces accurate records. Nothing
  in the repo measures field accuracy; the KATs test the verifier, not
  emission.
- **Who:** the operator (deployment records, conformance test run on the
  deployed build, change log) plus a witness or certifier who can say the
  deployed build matches the tested one.

### FRE 902(13) — certified records generated by an electronic process or system

- **Requires:** a record generated by an electronic process or system that
  produces an accurate result, **as shown by a certification of a qualified
  person** that complies with the certification requirements of 902(11) or
  902(12); the proponent must give an adverse party **reasonable written
  notice** before the trial or hearing and make the record and certification
  available for inspection.
- **Supplies:** the material a qualified person would rely on: the verdict
  (signed, deterministic, build- and config-pinned as described in §0), the
  bundle, the KAT run, the spec version. Time evidence classes (`asserted` →
  `boot-bound` → `externally-anchored`, spec §5.1) let the certifier say
  *which* kind of timestamp the record carries instead of guessing.
- **GAP:** the certification is made **by a person, not by software.** A
  verifier report is not a 902(13) certification and must never be
  presented as one. The qualified person must be able to attest, from
  knowledge, to how the system works in that deployment and that it produces
  accurate results. The notice obligation is procedural and entirely outside
  the artifact. 902(13) goes to authenticity only; it does not resolve
  hearsay (803(6) below), relevance, reliability, or confrontation (§2).
- **Who:** a qualified person at the producing agency or vendor (records
  custodian, system administrator, or the integrator's engineer), and counsel
  for the notice.

### FRE 902(14) — certified data copied from an electronic device, storage medium, or file

- **Requires:** data copied from a device, medium, or file, authenticated by
  a process of digital identification (the committee note names hash values),
  as shown by a certification of a qualified person under the 902(11)/(12)
  requirements; same notice rule as 902(13).
- **Supplies:** the best fit in the rule set. The bundle is deterministic
  bytes; `bundle_digest` is a SHA-256 commitment; the verdict re-derives it
  and signs it. A copy whose digest matches is the copy the rule describes.
  (Mediator countersignatures, `kats/countersign/`, bind an
  `action_attempt` receipt digest and its command digest —
  `spec/CONFORMANCE.md:186-198` — not the whole bundle; they are evidence
  about one attempt, not a second signature over the copy.)
- **GAP:** the person still certifies. And 902(14) covers the copy, not the
  *original's* provenance: a perfect copy of a bundle produced by a
  compromised EP is still a perfect copy. Media and payloads referenced by
  commitment (spec §8) are not inside the bundle; the digest proves the
  bundle, not the footage it points at.
- **Who:** a qualified person who can attest to the copy process (which
  need not be the operator who ran it); the referenced-media chain is a
  separate 902(14) or 901(b)(1) showing.

### FRE 803(6) — records of a regularly conducted activity (hearsay exception)

- **Requires:** made at or near the time by, or from information transmitted
  by, someone with knowledge; kept in the course of a regularly conducted
  activity; making the record was a regular practice; all shown by the
  testimony of the custodian or another qualified witness, **or by a
  certification that complies with 902(11) or 902(12) or with a statute
  permitting certification** (803(6)(D)); the opponent may show that the
  source or circumstances indicate a lack of trustworthiness.
- **Supplies:** time evidence per receipt (spec §5.1) supports "at or near
  the time"; the epoch state machine and Merkle batches (`CONFORMANCE.md`
  steps 14–16) support "kept in the course of"; purpose-of-use,
  jurisdiction, retention-class, and legal-hold identifiers (spec §8, as
  carried in the wire) support the "regular practice" showing.
- **GAP, and the one that needs a lawyer first:** whether, and which,
  receipts are hearsay. Pure machine output with no human declarant is
  generally treated as lacking a hearsay declarant, though it still must
  be authenticated and still faces relevance, reliability, and the other
  admissibility requirements. Human assertions embedded in a receipt (an
  approver's note, an operator's request text) need their own hearsay
  analysis. An **inference receipt** records an LLM's "structured conclusion
  + declared uncertainty" (spec §3.2). AAR's position is that the receipt
  proves *the agent claimed X*, never *that X is true* (spec §10: "no
  correctness claims for inference"). Offered for that purpose the
  conclusion is not offered for its truth; offered to prove X, its
  treatment is unsettled and this document takes no position. "Regular
  practice" is an organizational fact AAR records as identifiers and
  cannot establish.
- **Who:** counsel, to pick the purpose; a custodian, qualified witness, or
  902(11)/(12) certifier for the foundation.

### FRE 803(8) — public records (note only)

If a law-enforcement agency is the producer, 803(8)(A)(ii) excludes, in a
criminal case, "a matter observed by law-enforcement personnel." Whether an
agent's observation receipt is such a matter is an open question. Flagged;
not analyzed.

### FRE 1001–1003 — originals and duplicates

- **Requires:** for electronically stored information, an "original" is any
  printout or other output readable by sight if it accurately reflects the
  information (1001(d)); a duplicate is a counterpart produced by a process
  that accurately reproduces the original (1001(e)); a duplicate is
  admissible to the same extent as the original unless a genuine question is
  raised about the original's authenticity **or the circumstances make it
  unfair to admit the duplicate** (1003).
- **Supplies:** deterministic encoding makes every byte-identical copy a
  candidate duplicate under 1001(e), subject to showing the copy process
  reproduces the bytes (the digest check does that). The pyref
  human-readable report is a candidate 1001(d) output of the verdict, and
  it labels what it does not sign ("report layer; not signed").
- **GAP:** readability is not enough; the proponent must show the rendering
  *accurately reflects* the verdict before it is an "original." The report
  renders the verdict, not the receipts' payloads; footage or detection
  media behind a commitment is a separate original with its own showing.
- **Who:** counsel decides which rendering to offer; a witness or certifier
  for rendering accuracy if challenged.

### FRE 1006 — summaries (as amended December 1, 2024)

- **Requires:** a summary, chart, or calculation offered to prove the
  content of **voluminous admissible** writings, recordings, or photographs
  that cannot be conveniently examined in court; the underlying materials
  must be made available to the other parties at a reasonable time and
  place. Illustrative aids that are not evidence fall under new Rule 107.
- **Supplies:** a verifier report over a bundle of thousands of receipts has
  the shape of a 1006 summary; the bundle is the underlying material.
- **GAP:** 1006 is a foundation, not an automatic qualification. The
  underlying receipts must themselves be admissible (every gap above
  applies first), the volume must be genuine, the summary must be shown to
  be accurate, and access must be timely. A report shown to the jury only
  to explain the bundle is a Rule 107 illustrative aid, not evidence.
- **Who:** counsel; a witness for summary accuracy.

### FRE 702 and *Daubert* — if the method itself is challenged

Rule 702 as amended December 1, 2023 requires the proponent to show it is
**more likely than not** that the witness is qualified by knowledge, skill,
experience, training, or education; that the testimony will help the trier
of fact; that it rests on sufficient facts or data and reliable principles
and methods; and that the opinion reflects a reliable application of those
methods to the facts. The *Daubert* factors are flexible considerations a
court may weigh against the particular opinion offered, not thresholds; the
table shows what exists for each so counsel can judge the particular
opinion, not the spec in the abstract.

| Factor | What exists | What is missing |
|---|---|---|
| Testability | Normative verifier, KAT corpus, clean-room second implementation, divergence log | Tests the verifier, not field emission |
| Peer review and publication | Open spec and decisions log; related-work corpus (`related-work-v0.2.md` and addenda) | AAR itself has had design challenges, not independent peer review or publication |
| Known or potential error rate | None measured | No error rate for emission or for an observation method |
| Standards controlling the technique's operation | `spec/CONFORMANCE.md`, closed enums, prohibited-claims language | Experimental, not a ratified standard; version-pinned conformance only |
| General acceptance | None | No adopter or integrator workflow (BACKLOG.md strategy 9/27) |

- **Who:** a qualified expert who did not write the spec, or the spec
  author with the bias disclosed. The missing rows weaken a 702 showing
  without barring it; which rows matter depends on the opinion offered.

### FRE 901 chain of custody (common-law showing)

- **Supplies:** scoped tamper checks on the *record*: epochs, Merkle
  batches, anchors (`CONFORMANCE.md` steps 14–17), and mediator
  countersignatures over individual attempts. A verifier can say the bytes
  it was given match what was committed and anchored.
- **GAP:** where the artifacts were, who held them, and what happened
  between emission and verification are **not established**;
  `custody_continuity: not_established` is mandatory in v0.2 and
  `CONFORMANCE.md:696-699` says expressly that signatures, anchors, and
  countersignatures do not establish custody continuity. Access, export,
  and transformation lineage receipts (R-35) are planned, not shipped. The
  custody of referenced media is outside the bundle entirely.
- **Who:** the agency's DEMS / RMS records chain the bundle attaches to.

## 2. Confrontation Clause (criminal cases)

Under *Crawford*, *Melendez-Diaz*, and *Bullcoming*, a certificate that
reports a substantive forensic result prepared for use at trial is
testimonial, and the analyst who made it must testify unless unavailable
and previously cross-examined. The 902(13)/(14) committee notes say those
certifications serve authentication only and leave confrontation questions
unaffected; a certificate that only authenticates a record is not
necessarily testimonial, and raw machine output with no human declarant is
generally not. A human certification that goes further — for instance an
expert's reconciliation opinion comparing a receipt to an independent
observation — may be. **Open legal question; counsel decides per case.** AAR
does not implement any human-certification object; a separate human
certification may reference the bundle and verdict by digest, and its form
must satisfy the applicable certification requirements. Keeping the two
apart lets a court consider the machine record and the human attestation
separately.

## 3. Discovery, *Brady*, and retention

- **Supplies:** spec §8 calls for purpose-of-use, jurisdiction,
  data-classification, retention-class, and legal-hold identifiers on
  receipts, with deletion attributably recorded by derivation receipts and
  redaction and export as receipted actions. In the v0.2 wire, `redact` is
  one permitted `transformation.operation` inside a consumption manifest
  (`spec/aar-core.cddl:334`) — a recorded transformation step, not a
  standalone redaction receipt or action kind; referenced canonical
  manifests must be carried in the bundle and hashed by the verifier
  (`spec/CONFORMANCE.md:122-123`), so manifest contents the producer chose
  to include are available to the recipient.
- **GAP:** the full §8 lineage set — derivation receipts for deletion,
  export and access lineage — is R-35, **planned, not shipped**; treat it
  as a gap, not a feature. `discovery_completeness: not_established` means
  the bundle cannot prove exculpatory receipts were not omitted before
  export (threat model T-J1 "omitted exculpatory material"). When
  derivation receipts do ship, a derivation receipt is "a signed deletion
  *assertion*" (spec §8, erratum E-3): it will not establish that replicas
  and backups were erased, that legal hold was honored, or that the deletion
  was not spoliation. For inference receipts, the prompt, retrieval-context,
  and tool-transcript manifests the producer bundled are present; their
  **completeness**, and the retention of anything they reference
  externally, require audit.
- **Who:** the agency's records and legal-hold process; counsel for *Brady*
  review. **Action item (from the 2026-10-02 pair review):** audit what the
  §3.2 manifests contain and reference, and how long the referenced
  material is kept, before anyone proposes a new "context manifest" record.

## 4. Foundation questions counsel may ask a qualified person

Not a form and not mandatory; the rules differ in what each needs. Grouped
by rule so the declaration can be drafted narrowly.

**For any authentication certification (902(13) or 902(14)):**
1. Identity and role (why they are qualified for this system).
2. The AAR version pinned, the producing components (agent, EP, outcome
   observer, anchor service), and deployed build identifiers.
3. The verdict: `verdict_id`, `result`, the evaluation time used, trust
   policy source (producer-declared or operator-pinned via
   `--trust-policy`), and that the signed `limits` and `scope` maps were
   read and are attached unaltered.
4. That the certification addresses authenticity only, and that
   `source_authenticity`, `custody_continuity`, `discovery_completeness`,
   and `legal_admissibility` are, in the verdict's own words, not
   established by it.

**902(13) specifically:** how the process or system works in this
deployment and the basis for saying it produces an accurate result,
including that the deployed verifier build corresponds to a tested build
(the constant `build_digest` preimage does not show this on its own).

**902(14) specifically:** the copy process and the digest computed before
and after (`bundle_digest`).

**803(6), if the business-records route is used (a separate 902(11)/(12)
certification or custodian testimony):** that receipts are generated
automatically at or near the time of the recorded events, kept in the
course of a regularly conducted activity, as a regular practice, and the
retention schedule they live under.

## 5. Prohibited claims (extends `rfp-language-v0.2.md`)

No AAR documentation, verifier output, vendor collateral, or testimony
prepared from this crosswalk may say:

- "AAR-conformant, therefore admissible" (D-29; verdict laundering, T-J1).
- "The verifier report is the 902(13) certification."
- "Verified" for any outcome below `independently-sensed` (spec §5.2), and
  never for the inference's correctness.
- "Chain of custody established" while `custody_continuity` reads
  `not_established`.
- "Complete record" while `discovery_completeness` or
  `ingress_completeness` is not established.
- "Independently verified" while the verifier identity is the published test
  key (D-58).
- "Nobody else does this" — say "not found in the related-work corpus."

## 6. Consolidated gaps, with an owner

| # | Gap | Owner | Bears on |
|---|---|---|---|
| G-A | Certification by a qualified person; notice to adverse party | agency / counsel | 902(13), 902(14), 803(6) |
| G-B | Field accuracy of emission (vs. verifier conformance) | operator deployment records | 901(b)(9), 702 |
| G-C | Verifier identity: neither reference implementation supports external-key provisioning (D-58 permits implementation-defined support; an interoperable format is a v0.3 candidate), and constant build/config preimages do not prove deployed-code identity | spec, v0.3 candidate | 901(a), any "independent verification" testimony |
| G-D | Error rate — none measured for emission or observation | spec + a study | 702 |
| G-E | General acceptance — no integrator workflow | adoption (BACKLOG strategy 9/27) | 702 |
| G-F | Custody, export, access lineage receipts (R-35) | spec, planned | 901 custody, §3 discovery |
| G-G | Hearsay status of inference receipts and embedded human assertions | counsel | 803(6) |
| G-H | Completeness and retention of material behind §3.2 manifests | operator audit | *Brady* |
| G-I | State-rule variance (e.g. whether a given state has adopted 902(13)/(14) analogs) | counsel, per venue | all |

## 7. Questions for the first lawyer read

1. For an inference receipt offered only to prove what the agent claimed, is
   the hearsay analysis in §1 (803(6)) right, and does it change when the
   claim triggered a physical action?
2. Is a reconciliation verdict comparing an AAR receipt to an independent
   observer's record (the planned witness path) testimonial under
   *Melendez-Diaz* if an expert signs it?
3. Which of G-A through G-I would a defense attorney reach for first against
   an RTCC that auto-suppresses alerts under AAR-2A?
4. Does 803(8)(A)(ii) reach an agent's observation receipt produced inside a
   police agency?
5. Is anything in §5 (prohibited claims) too cautious to be useful?

## Change log

- v0.1 (2026-10-02): first draft from the chain-of-custody next-link review.
  Bounded to a crosswalk with marked gaps against one KAT bundle; no
  templates; no admissibility promised. Revised the same day after a
  Codex finding pass (15 findings: 803(6)(D) certification route, 1003
  unfairness clause, 1006 as amended 2024, 702 elements, confrontation
  scope, limits-vs-scope field placement, countersign scope, custody
  wording, R-35 planned status, verifier test key and constant preimages)
  and a fresh re-grade (4 further fixes: verdict proves a reported
  conclusion, not execution or byte continuity; D-58 permits
  implementation-defined external keys; `redact` is a transformation
  operation, not a receipt). Line references and the `verdict_id` were
  re-taken on `main` after D-76 (verdict v3) landed.
