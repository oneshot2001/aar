# Related work — AAR v0.2

Status: draft against `v0.2-rc7`. This document records prior art that bears on
AAR's design claims. It exists so that ratification review, the related-work
section of any published spec, and RFP framing can cite convergent or
competing designs precisely rather than by reputation.

Citation discipline: every external artifact cited here is pinned to a commit,
tag, or retrieval date, and every internal cross-reference is resolved against
the file it names. Specifications marked `draft` upstream may change; a claim
in this document is only as current as its pin. Re-verify before quoting any of
it externally.

Verification state: revised after a round-1 adversarial review (2026-07-29)
that found four factual errors, all in internal cross-references asserted
without being resolved. Those are corrected below. Two claims remain marked
UNVERIFIED in place. Do not add a cross-reference to this document without
opening the file it cites.

## Scope of this document

This document **does** record: what an external design specifies, where it
converges with AAR, where it differs structurally, and what AAR should cite it
for.

This document **does not**: rank products, assess the security of any external
system as deployed, or claim that a difference from AAR is a defect in the
other design. Most systems surveyed here answer a different question than AAR
does, and are evaluated on that basis.

---

## 1. Buzz NIP-OA — Owner Attestation (Block, Inc.)

**Pin.** `docs/nips/NIP-OA.md` in `github.com/block/buzz`, at commit
`e0fdeb2ff5ec959432dd247119b7f80862b6ef14` (authored 2026-05-01T15:58:06Z).
Retrieved 2026-07-29. Marked `draft` `optional` upstream. Apache-2.0. That
commit is the only one in the file's path history, so the specification has
been stable since May and is not a moving target, unlike the surrounding
repository. It predates the platform's public launch — dated 2026-07-21 by
[TechCrunch](https://techcrunch.com/2026/07/21/jack-dorsey-is-taking-on-slack-with-buzz-a-group-chat-platform-for-teams-and-their-ai-agents/)
— by roughly three months.

**Why it is relevant.** Buzz is a team-collaboration platform in which AI
agents hold their own keypairs and sign their own work, with a second signature
binding the agent to a responsible human. That is the same primitive AAR uses
to separate an acting agent from the principal accountable for it. It is the
only shipped, publicly-specified instance of that primitive found so far
outside AAR — a claim bounded by §3, which names five unsurveyed bodies of
prior art, at least two of which may bear on it.

**Its own ancestor.** NIP-OA builds on NIP-26 (Nostr delegated event signing)
for credential format and signing flow, while explicitly declining NIP-26's
semantics. NIP-26 is prior art *for NIP-OA*; it is not cited anywhere in AAR's
`spec/`, and this document does not claim otherwise.

### 1.1 What it specifies

An optional Nostr event tag with exactly four elements:

```json
["auth", "<owner-pubkey-hex>", "<conditions>", "<sig-hex>"]
```

- The owner produces a BIP-340 Schnorr signature over
  `SHA256("nostr:agent-auth:" || event.pubkey || ":" || <conditions>)`.
- `<conditions>` is an ASCII string of zero or more `&`-separated clauses. The
  entire clause grammar is three forms: `kind=<decimal>`, `created_at<t>`,
  `created_at>t`. Verifiers MUST evaluate every clause.
- Self-attestation is rejected: an `auth` tag whose owner pubkey equals
  `event.pubkey` MUST be rejected.
- The tag is explicitly a **reusable capability** — the spec states the same
  tag MAY appear on multiple events by the same agent key provided each event
  satisfies the conditions.
- Relays require no changes, MAY index and forward the tag, MUST NOT rewrite
  authorship on the basis of it, and **MUST NOT be required to verify it**.
- The spec ships valid and invalid test vectors.

### 1.2 What it gets right

Three points worth crediting, because AAR makes the same calls and should say
so rather than claim novelty it does not have:

1. **Authorship is separated from authorization, explicitly and normatively.**
   NIP-OA declines to reuse NIP-26 delegation semantics on the grounds that
   NIP-26 assigns the event to the delegator, and that "MUST NOT be reused for
   agent provenance." `event.pubkey` remains the sole author key; clients MUST
   NOT merge attested events into owner-authored timelines or pubkey-filtered
   results, and any provenance display MUST be "clearly distinguished from
   authorship." This is the same separation AAR encodes structurally in
   `principal-role` (`agent`, `approver`, `enforcement_point`, … —
   `spec/aar-core.cddl`), and NIP-OA states it more concisely than AAR does
   anywhere in prose.

2. **Key independence is a stated security property.** Compromise of the agent
   secret key does not imply compromise of the owner secret key, and permits
   only signatures by the compromised agent key. This matches AAR's guarantee
   framing, which explicitly excludes compromised-signer immunity.

3. **Deployability.** Four tag elements, zero relay changes, no new
   infrastructure. AAR has no comparable adoption story and should not pretend
   otherwise: AAR v0.2 is a release candidate in a private repository with a
   two-action ontology, requiring a conformant offline verifier. Where NIP-OA
   is weaker, it is weaker partly because it bought deployability with it.

### 1.3 Layer relationship

The two designs answer different questions. NIP-OA asks whether an agent key
may speak under an owner's authority. AAR asks what is independently provable
about what an agent observed, inferred, was authorized to do, and actually did.

| Property | NIP-OA | AAR v0.2 |
|---|---|---|
| Owner signature covers | agent pubkey + conditions string | full `delegation-claims`, content-addressed as `delegation_id` |
| Binds a specific action | no | yes — `authorization_id` + `decision_commitment` in `action-attempt-body`; `parameters_digest` in `normalized-action` |
| Scope expression | `kind=<n>` only | `delegation-scope`: `actions`, `targets`, `purpose_ids`, `allowed_profiles`. Tenancy is bound separately, in `delegation-claims` (`tenant_id`, `site_id`) |
| Replay defense | none | `use: "one_time" / "reusable"`, `replay_domain`, optional `invocation_id` |
| Validity window | `created_at` clauses evaluated against the event's self-declared time (§1.4.2) | `not_before` / `not_after` evaluated against verifier-supplied time |
| Revocation | issue no further tags | credential status snapshots, `status_snapshot_ids`, profile-dependent `status_max_age_s` (86400 s at AAR-1/2; **300 s at AAR-2A/3**), D-52 anti-masking, credential path ≤ 8 |
| Outcome of the act | not modelled | `outcome-observation-body`: independent `observer` device identity, `state: consistent / contradicted / unknown` |
| Verification obligation | optional; relays not required, clients SHOULD | signed verdict over one normative validation order; a bare `PASS` is never a conformant verdict (`spec/CONFORMANCE.md`) |
| Independent implementations | not specified | two independent, one of them clean-room; 20 divergences from the first cross-check plus further order deviations found under D-54, all adjudicated to 0 open (`spec/GATE4-CLOSE.md`) |

### 1.4 Structural differences

#### 1.4.1 The attestation binds the agent, not the act

The signing preimage covers the agent pubkey and the conditions string. It does
not cover the event id, content, or tags. The owner therefore attests to *an
agent*, not to *anything that agent did*. The spec is direct that this makes the
tag a reusable bearer capability.

Consequence: a valid `auth` tag lifted from one event verifies on any other
event by the same agent key that satisfies the same conditions. AAR's
`replay_domain`, `use: "one_time"`, and `invocation_id` exist specifically to
close this class, and AAR's action binding runs deeper still — the attempt
commits `parameters_digest` and a command manifest, dispatch commits
`command_id`, and every hop is content-addressed into its parent.

This is the single largest difference between the two designs, and the reason
NIP-OA cannot be characterised as a lightweight AAR.

#### 1.4.2 No enforceable expiry — disclosed upstream

NIP-OA's only expiry mechanism constrains `event.created_at`. The spec states
the consequence itself, in the three consecutive sentences that open its
expiry disclosure, quoted here verbatim because the disclosure is
a point in the spec's favour:

> A `created_at<...` or `created_at>...` clause constrains the event's
> self-declared `created_at` field, which the agent controls.
> These clauses do not enforce wall-clock expiry; a misbehaving agent can
> backdate `event.created_at` to satisfy an expired window.
> Relays or clients that require wall-clock freshness MUST enforce it
> independently of this NIP.

The bound is set by the party it constrains, and the mitigation is pushed out
of scope. AAR places delegation validity in signed claims (`not_before` /
`not_after`) evaluated against an explicit verifier-supplied evaluation time,
with time classes ranked by provenance strength and `externally_anchored`
defined as a prior-epoch anchor sandwich.

Note for citation: this is a **disclosed limitation**, not a discovered flaw.
Any AAR material citing it must present it as such.

#### 1.4.3 Revocation is non-renewal

NIP-OA offers one normative mitigation for revocation latency and one
revocation mechanism, in that order:

> Owners SHOULD bound authorization lifetime with a `created_at<...` clause
> when revocation latency matters.
> Owners MAY revoke future authorization by refusing to issue new `auth` tags.

The mitigation is defeated by §1.4.2 — the clause it recommends binds a field
the agent controls. What remains is non-renewal. Combined with §1.4.1,
previously issued reusable capabilities remain verifiable; there is no status
channel, compromise signal, or path constraint.

AAR carries credential status as first-class evidence, bounds its age by
profile — 300 s at AAR-2A/AAR-3, of which AAR-3 is the profile under which
AAR's actuation scenario was evaluated (`spec/GATE5-RUBRIC.md`) — and under
D-52 evaluates status content before resolving references, so that a
`compromised` status cannot be downgraded to `status-missing` by withholding
the reference.

Composed, §1.4.1–§1.4.3 mean a leaked agent key yields an attacker an
action-unbound, unrevocable, effectively unexpiring owner attestation.

How much that matters is set by the deploying application, not by the NIP.
NIP-OA names no application domain: it admits any event kind in `0`–`65535` and
says nothing about chat, workspaces, or any other use. In Buzz's deployment the
blast radius is workspace events, which is a bounded harm — but that bound
comes from Buzz, and nothing in the NIP establishes it. A general-purpose
authorization tag adopted at an actuation boundary would carry the same
properties with none of the containment.

For the boundary AAR profiles, those properties are disqualifying, and AAR's
threat model should cite them as a worked external example of why the
requirement set is shaped as it is.

#### 1.4.4 No outcome layer

NIP-OA models authorization only. There is no representation of whether
anything happened. The NIP does not scope itself to any domain, so this is not
a domain limitation so much as an absent layer; in the deployment it was
written for, Buzz agents post events rather than actuating physical systems,
and nothing there requires the layer.

This is where AAR's requirement set has no external analogue found so far.
`outcome-observation-body` requires a named observer device identity and a
`consistent` / `contradicted` / `unknown` state, with "verified" barred absent
an independent observer (`spec/GATE5-RUBRIC.md`), and GATE5 spent both live
legs hardening exactly this seam: dispatch latches "at action-bearing send",
and `contradicted` is reached only on "positively observed out-of-tolerance"
readback (`spec/GATE5-D2A-REVIEW.md`).

#### 1.4.5 Agent identity does not bind the serving model

**The claim, from the NIP alone.** NIP-OA's preimage covers `event.pubkey` and
the conditions string. Nothing in the tag, and nothing in the clause grammar,
can express or constrain which model, provider, or prompt produced the event.
An owner attestation is therefore silent on the system actually generating the
attested output, and remains valid across any change to it. This holds on the
specification text and requires no facts about any deployment.

**Illustration, from platform behaviour — context only.** Buzz Desktop v0.5.0
(published 2026-07-28) shipped both `feat(acp): bring your own harness (BYOH)
— generic ACP runtime seam + settings gallery` (#2773) and `fix(desktop): make
agent definition authoritative for model/provider/prompt` (#1968). What these
two citations establish, and all they establish, is that a persona's model and
provider are operator-changeable configuration. Whether a persona's key is
stable across such a change does not follow from them and was not checked. Per
§1.6 this block carries no part of the claim above, which stands on the
specification text alone, and no claim is made about what Buzz clients verify.

**Where AAR differs.** `principal-type` is
`"human" / "service" / "workload_instance" / "model_endpoint"`, and the
credential profile carries `subject_kid` and an SPKI `public_key` bound to a
specific issued credential with its own validity window. The identity of the
serving system is a modelled principal, not an unstated assumption.

This is the cleanest available illustration of why "the agent has a key" is not
sufficient for attribution.

### 1.5 Convergences worth recording

Two independent arrivals at the same rule, which strengthen AAR's case rather
than weaken it:

- **No local-clock dependence.** NIP-OA: "Verification MUST NOT depend on the
  verifier's local clock, receipt time, or relay storage time." AAR's reference
  verifier CLI requires an explicit `--at UNIX_SECONDS` and never reads wall
  clock. Both specs independently forbid the same failure mode. They then
  diverge on what replaces it: NIP-OA evaluates its time clauses against the
  event's own self-declared `created_at`, which the agent controls (§1.4.2);
  AAR supplies evaluation time from outside the artifact.
- **Known-answer vectors as spec furniture.** NIP-OA ships valid and invalid
  test vectors in the specification text. AAR's v0.2 wire rubric set a
  seven-point KAT bar for the same reason.

### 1.6 Disposition

Cite NIP-OA as **prior art for the primitive**: an independently-keyed agent
plus an owner counter-signature, with authorship preserved. It is convergent
evidence, from a well-resourced team solving general-purpose agent
collaboration, that the primitive AAR depends on is the right one.

Do **not** cite it as prior art for the evidence model. It has no observation,
inference, dispatch, outcome, anchoring, completeness, or verdict layer to
compare against, and does not claim to.

Suggested framing where a reader has encountered Buzz — orientation, not
arithmetic. The two are not on a single axis: they share no format, curve, or
transport (COSE_Sign1 over deterministic CBOR with P-256, versus Nostr tags
with BIP-340 Schnorr), and §1.4.1 states that "NIP-OA cannot be characterised
as a lightweight AAR." Use:

> NIP-OA answers *may this agent key speak under this owner's authority*.
> AAR answers *what is independently provable about what this agent observed,
> inferred, was authorized to do, and actually did*.

Prohibited framings. These are specific to this document; they are not drawn
from `docs/rfp-language-v0.2.md`, whose strike list governs a different subject
(vendor overclaims about what AAR conformance proves) and shares no items with
this list. Both exist for the same reason.

- Do not describe NIP-OA as insecure, broken, or defective. Its limitations are
  disclosed, and are appropriate to the deployment it was written for. (Note
  that per §1.4.3 the NIP itself declares no domain — the containment comes
  from the deployment, so this justification may not be extended into a claim
  that the NIP is bounded.)
- Do not claim AAR is "more adopted," "production-proven," or "a standard."
  NIP-OA is shipped in a public Apache-2.0 platform; AAR v0.2 is a release
  candidate in a private repository pending a ratify-or-park decision.
- Do not attribute Buzz **platform** behaviour to NIP-OA's normative content.
  The NIP is `optional`, and what the Buzz clients actually verify was not
  audited for this document. Platform facts may be cited as illustration where
  labelled as such and where the underlying claim stands on the NIP text alone
  (the pattern used in §1.4.5); they may not carry a conclusion by themselves.

---

## 2. Prior art pinned inside the wire spec

Each of the following is load-bearing in `spec/` and was resolved against the
named file. NIP-26 is deliberately **not** in this list — see §1.

- **UCAN, Biscuit, JWT** — named and excluded by `spec/aar-core.cddl`:
  delegation tokens are raw detached COSE_Sign1 and "no Biscuit, UCAN, JWT, or
  wrapper token grammar is permitted." The exclusion is deliberate and should
  be defended in any published related-work section, not quietly dropped.
- **RFC 6962 (Certificate Transparency)** — Merkle structure and the v1 anchor
  floor for completeness anchoring (`spec/GATE1-REVIEW.md`,
  `spec/DECISIONS.md`).
- **RFC 8949 / 9052 / 9053** — deterministic CBOR and COSE, governing where
  `spec/CONFORMANCE.md` is silent.
- **EdgeProof SDR v1.1** — wire discipline as frozen at `b9d7bc6`, cited in
  `spec/CONFORMANCE.md`. UNVERIFIED: the further claim that AAR is the Phase-2
  agent-attestation problem deferred by SDR wire-format-v2 §9 is consistent
  with `docs/spec-v0.1.1-requirements-draft.md` but was not checked against the
  SDR repository, which is not vendored here.

## 3. Not yet surveyed

Named so their absence is visible rather than implied. No claim is made about
any of these until someone reads them.

- **C2PA** — content provenance manifests; the closest analogue to AAR's
  producer-authored manifest and the completeness question narrowed under G3.
- **ACME (RFC 8555)** — cited in AAR's strategy as a de-facto-standard-author
  precedent, not yet examined as a technical design.
- **W3C Verifiable Credentials / DIDs** — overlapping credential and status
  vocabulary. May bear on §1's "only shipped instance found so far" claim.
- **SPIFFE/SPIRE** — workload identity, adjacent to `workload_instance`. Same
  caveat.
- **In-toto / SLSA** — attested multi-step pipelines with typed links, the
  closest structural analogue to the receipt DAG found so far.

Any of these may invalidate a novelty claim AAR has not yet made in public.
Surveying them is a precondition for the ratify path, not for rc-stage work.
