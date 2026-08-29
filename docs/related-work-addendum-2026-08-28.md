# Related-work addendum — 2026-08-28 corpus reads

Status: round-0 synthesis against `v0.2-rc7`, from the 30-paper corpus
manifest and its per-paper summaries. The arXiv identifiers below were checked
against the supplied manifest on 2026-08-28. Claims are limited to those summaries;
the benchmark reported by PCAA is deliberately not repeated.

This addendum records the papers given a STEAL or CITE disposition in the
corpus review. “STEAL” means a mechanism is a candidate for later design work,
not that this document changes the v0.2 wire or verifier. AAR’s existing
[Notarized Agents citation](related-work-addendum-2026-08-19.md) is extended
below rather than restated.

---

## A. Notarized Agents — extension to the existing citation

**Pin.** [arXiv:2606.04193](https://arxiv.org/abs/2606.04193), as listed in
the corpus manifest.

The earlier addendum cites Notarized Agents for receiver-attested receipts and
a witness-cosigned Merkle log. Two further points belong in AAR’s record. First,
the paper states a per-receipt guarantee, not set completeness; its §6
suppression problem and heartbeat anchor-set sketch are direct inputs to an
eventual ingress-census design. Second, its use of COSE receipts with a
Rekor/SCITT path makes an “AAR anchor as SCITT transparency receipt” profile a
concrete docs-only v0.3 question. Neither point changes the RFC 6962 base
profile in v0.2.

**Disposition.** Extend the existing citation for the completeness boundary,
the heartbeat partial mechanism, receiver-side signing, and SCITT alignment.
Do not describe the heartbeat sketch as an omission proof.

## B. Bounded Agents

**Pin.** [arXiv:2608.15888](https://arxiv.org/abs/2608.15888), as listed in
the corpus manifest.

Bounded Agents commits evidence before execution and fails closed when the
evidence sink is unavailable. That supplies a prior mechanism for a
future action-class rule at AAR’s dispatch boundary: refuse AAR-3 work when the
journal cannot accept the pre-execution commitment, while preserving R-16’s
separate treatment of life-safety behavior. The paper also says tail
truncation remains undetectable from the chain alone, so the mechanism does
not close G3.

**Disposition.** STEAL the commit-before-execute ordering for v0.3 design;
CITE the tail-truncation limit in the G3 residual.

## C. CommitGuard

**Pin.** [arXiv:2607.10487](https://arxiv.org/abs/2607.10487), as listed in
the corpus manifest.

CommitGuard requires every commit-time witness to be Fresh, Causal, Bound, and
Eligible, and treats missing evidence as non-observable rather than safe. This
converges with AAR’s lease, status-snapshot, replay, and command-binding checks,
but it asks the question again at the durable-effect boundary. A v0.3
multi-step note should therefore distinguish authorization when the request
was formed from authorization still current at the irreversible commit.

**Disposition.** STEAL the commit-moment freshness witness as a v0.3 design
input. It is not a claim that the unsigned CommitGuard trace supplies AAR’s
third-party verification properties.

## D. Governing Actions, Not Agents

**Pin.** [arXiv:2606.26298](https://arxiv.org/abs/2606.26298), as listed in
the corpus manifest.

Its hub intent identifier binds the governed action and its expiry bounds the
authorization-to-execution interval. That is the same general shape as AAR’s
authorization artifact, action/command binding, and bounded credential state,
even though the two object models differ. The paper also names CT, in-toto,
and SCITT as publication paths.

**Disposition.** CITE for independent convergence on intent binding, expiry,
and standards-based receipt publication.

## E. Auditable Agents

**Pin.** [arXiv:2604.05485](https://arxiv.org/abs/2604.05485), as listed in
the corpus manifest.

Auditable Agents defines IS Level 3 as evidence that a third party can verify
without the original system. That is the assurance target AAR’s offline
verifier and carried SPKI serve. Its Auditability Card is also a useful buyer
checklist pattern beside `docs/rfp-language-v0.2.md`. The paper’s log presence
completeness gap (LPC) cannot distinguish an event that did not occur from one
that occurred but was not recorded.

**Disposition.** CITE IS Level 3 for the offline-verification target and LPC
for the G3 residual. Do not turn the level name into an AAR conformance label.

## F. Certified Traces

**Pin.** [arXiv:2605.24462](https://arxiv.org/abs/2605.24462), as listed in
the corpus manifest.

Table 2 names four failure modes. Mapping those names to the current closed
AAR reason-code vocabulary gives this audit:

| Certified Traces failure mode | Current AAR coverage | Result |
|---|---|---|
| stale approval | `credential/expired`, `credential/status-stale`, `delegation/expired`, and `replay/expired` cover stale credentials, delegations, and replay windows, but the presentation/approval object has no approval-expiry reason code | **Finding: no exact map** |
| tool deviation | `receipt/action-command-mismatch` and `receipt/dispatch-attempt-mismatch` | mapped |
| certificate laundering | Dominance, scope, and one-time-use checks can reject several laundering paths (`graph/dominator-missing`, `delegation/scope`, `replay/one-time-reused`), but no code names reuse of an otherwise valid certificate outside the certified trace | **Finding: no exact map** |
| fake certificate | `sig/verify-failed`, `key/not-found`, and `credential/root-not-accepted`, selected by the normative first-failure order | mapped |

The two findings are vocabulary/design findings for later review, not new
v0.2 reason codes; this packet is informative and does not alter the closed
table.

**Disposition.** CITE the failure-mode taxonomy and carry the two unmapped
modes into v0.3 reason-code review.

## G. Proof-Carrying Agent Actions (PCAA)

**Pin.** [arXiv:2606.04104](https://arxiv.org/abs/2606.04104), as listed in
the corpus manifest.

PCAA’s enforceability classes describe where control sits, while AAR profiles
describe what evidence and authorization a deployment must produce. The
classes do not map one-to-one:

| AAR profile | Nearest PCAA enforceability class |
|---|---|
| AAR-1 | `observe_only` |
| AAR-2 | `observe_only`; a human, not the runtime, executes |
| AAR-2A | `pre_execution_gate`, or `delegated_runtime_control` where the runtime owns the bounded automated disposition |
| AAR-3 | `pre_execution_gate`, `delegated_runtime_control`, or `runtime_controlled`, depending on where the EP and actuator control actually reside |

**Disposition.** CITE for vocabulary alignment and keep both axes visible.
The paper’s benchmark is withheld, so its reported numerical results are not
cited here.

## H. Governing Dynamic Capabilities

**Pin.** [arXiv:2603.14332](https://arxiv.org/abs/2603.14332), as listed in
the corpus manifest.

The paper’s capability-violation depth and capability-accountability depth
(CVD/CAD) locate the first hop whose required record is missing. That metric
could make an AAR ingress-census failure more precise than a single incomplete
flag. It is still a partial mechanism: the paper assumes honest operator
inclusion and does not prevent operator omission.

**Disposition.** CITE CVD/CAD as an ingress-census design input and the
operator-omission assumption in G3. The bilateral signatures are also relevant
to the deferred receiver-countersign question.

## I. Context Lineage Assurance

**Pin.** [arXiv:2509.18415](https://arxiv.org/abs/2509.18415), as listed in
the corpus manifest.

Context Lineage maps its evidence functions to FedRAMP/NIST SP 800-53 controls,
including AU-2, AU-6, AU-10, and CA-2. AAR can reuse the mapping pattern: state
the precise technical claim first, then map that claim
to a control objective without presenting the mapping as certification.

**Disposition.** CITE as the pattern for a later AAR CJIS/GovRAMP control map;
keep that work separate from any Alpha Vision material.

## J. Proof-or-Stop

**Pin.** [arXiv:2607.14890](https://arxiv.org/abs/2607.14890), as listed in
the corpus manifest.

Proof-or-Stop uses an independent-verdict quorum whose members differ by host,
session, and key, and it degrades explicitly when that independence is absent.
This supplies precedent for AAR’s future witness profile. Its metadata-spoofing
class is already represented in the threat model by T-P1 (a signer fabricates
claims within its authority) and, for adapter identity/version, T-D1
(adapter/runtime substitution); neither row is fully countered at base tier.

**Disposition.** CITE the quorum and honest-degradation pattern. The threat
matrix check is confirmed; no new threat row is needed from the summary alone.

## K. Context-to-Execution Integrity (CXI)

**Pin.** [arXiv:2607.06000](https://arxiv.org/abs/2607.06000), as listed in
the corpus manifest.

CXI binds a single-use capability and lease to an exact-effect action
manifest. AAR’s two-action ontology does not need CXI’s full machinery today,
but the construction is relevant to the AAR-3 automation subprofile as its
ontology and multi-step effects grow.

**Disposition.** CITE for manifest-bound, single-use authorization and lease
design; do not import the larger capability system into v0.2.

## L. Cryptographically Verifiable Authorization (CVA)

**Pin.** [arXiv:2607.21325](https://arxiv.org/abs/2607.21325), as listed in
the corpus manifest.

CVA’s Eq. 42 separates “authorized” from “executed.” That distinction motivates
AAR’s R-13 split between offline bundle verification and online
producer/adapter conformance, and supports retaining
post-dispatch outcome levels rather than treating an authorization proof as an
execution receipt.

**Disposition.** CITE Eq. 42 as motivation for R-13 and the outcome-calibration
layer. The paper supplies authorization proof, not outcome evidence.

## M. Human Delegation Protocol (HDP)

**Pin.** [arXiv:2604.04522](https://arxiv.org/abs/2604.04522), as listed in
the corpus manifest.

HDP v0.1 has the issuer sign every delegation hop. A hop therefore establishes
that it was recorded at the issuer, not that the named agent produced it. This
is close to GATE3 F3’s caution: AAR artifact identifiers bind content rather
than signer, while the carried artifact signature is checked independently at
use.

**Disposition.** CITE as a caution in the GATE3 rc-note lineage; do not imply
that HDP and F3 have identical wire behavior.

## N. aiAuthZ

**Pin.** [arXiv:2607.05518](https://arxiv.org/abs/2607.05518), as listed in
the corpus manifest.

aiAuthZ uses gateway HMAC receipts. Verification therefore requires the
symmetric key and does not provide third-party non-repudiation. AAR’s carried
SubjectPublicKeyInfo and offline ES256 verification deliberately exclude that
class.

**Disposition.** CITE as one example of the symmetric-key receipt class ruled
out by the D-4x credential decisions.

## O. NabaOS

**Pin.** [arXiv:2603.10060](https://arxiv.org/abs/2603.10060), as listed in
the corpus manifest.

NabaOS likewise uses runtime HMAC receipts. Its ledger can flag unreferenced
receipts, but an outside verifier still needs the shared secret, so the object
does not meet AAR’s public-key, third-party offline-verification premise.

**Disposition.** CITE separately from aiAuthZ because it reaches the same
excluded class through a runtime receipt design.

## P. AgentBound

**Pin.** [arXiv:2606.30970](https://arxiv.org/abs/2606.30970), as listed in
the corpus manifest.

AgentBound has the agent sign and the receiving service countersign. Along
with Notarized Agents and Dynamic Capabilities, it is prior art for the
deferred question of a second signer on AAR’s VMS leg. A service-side signer
could leave the VMS product unmodified, but this addendum does not choose that
topology.

**Disposition.** CITE for ordered receiver countersigning and for naming; any
implementation decision remains outside this docs-only packet.

## Q. Hardware-rooted attestation for AI-agent evidence

**Pin.** [arXiv:2608.00801](https://arxiv.org/abs/2608.00801), as listed in
the corpus manifest.

The paper folds an AEP outcome hash and fresh nonce into a TPM quote and
measures the model artifact into a PCR. Its two-axis vocabulary separates
authorisation (`Authorised`, `Unauthorised`, `Indeterminate`) from platform
appraisal (`Attested`, `Contested`, `Expired`). For AAR, the separation matters
because a valid authorization and a disputed platform/outcome can coexist:
the `(Authorised, Contested)` cell is exactly what a receipt-only design tends
to hide. The paper’s outcome is still runtime-reported; the quote binds the
report to a platform, not to an independent observation of the physical world.

**Disposition.** STEAL the vocabulary cross-map, published informatively in
`spec/CONFORMANCE.md`. CITE the hardware binding as a future deep-attestation
profile input, without changing D-49’s v0.2 opaque-carry rule.

---

## Corpus boundary

The papers above support narrower statements than “AAR proves execution.”
Across the corpus, signed action records usually stop at authorization or
dispatch. Proof-or-Stop and the hardware-rooted AEP record a post-dispatch
result, but take the runtime’s report as the outcome. AAR’s distinct claim is
the typed outcome level and, where present, an observer outside that runtime.
Set completeness remains open on both sides.
