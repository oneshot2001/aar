# Related work — AAR v0.2

Status: draft against `v0.2-rc7`. This document records prior art that bears on
AAR's design claims. It exists so that ratification review, the related-work
section of any published spec, and RFP framing can cite convergent or
competing designs precisely rather than by reputation.

Citation discipline: every external artifact cited here is pinned to a commit,
tag, or retrieval date. Specifications marked `draft` upstream may change; a
claim in this document is only as current as its pin. Re-verify before quoting
any of it externally.

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
`e0fdeb2ff5ec959432dd247119b7f80862b6ef14` (2026-05-01). Retrieved 2026-07-29.
Marked `draft` `optional` upstream. Apache-2.0. Note that this file predates
the platform's 2026-07-21 public launch by roughly three months and has been
stable since — it is not a moving target, unlike the surrounding repository.

**Why it is relevant.** Buzz is a team-collaboration platform in which AI
agents hold their own keypairs and sign their own work, with a second signature
binding the agent to a responsible human. That is the same primitive AAR uses
to separate an acting agent from the principal accountable for it. It is, as of
this writing, the only shipped, publicly-specified instance of that primitive
found outside AAR.

### 1.1 What it specifies

An optional Nostr event tag with exactly four elements:

```json
["auth", "<owner-pubkey-hex>", "<conditions>", "<sig-hex>"]
```

- The owner produces a BIP-340 Schnorr signature over
  `SHA256("nostr:agent-auth:" || event.pubkey || ":" || <conditions>)`.
- `<conditions>` is an ASCII string of zero or more `&`-separated clauses. The
  entire clause grammar is three forms: `kind=<decimal>`, `created_at<t>`,
  `created_at>t`.
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
   results, and any provenance display MUST be visually distinguished from
   authorship. This is the same separation AAR encodes structurally in
   `principal-role` (`agent`, `approver`, `enforcement_point`, … —
   `spec/aar-core.cddl` §principal-role), and NIP-OA states it more concisely
   than AAR does anywhere in prose.

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
| Scope expression | `kind=<n>` only | `delegation-scope`: `actions`, `targets`, `purpose_ids`, `allowed_profiles`, plus `tenant_id` / `site_id` |
| Replay defense | none | `use: "one_time" / "reusable"`, `replay_domain`, optional `invocation_id` |
| Validity window | `created_at` clauses (see §1.4.2) | `not_before` / `not_after` evaluated against verifier-supplied time |
| Revocation | issue no further tags | credential status snapshots, `status_snapshot_ids`, `status_max_age_s: 86400`, D-52 anti-masking, credential path length ≤ 8 |
| Outcome of the act | not modelled | `outcome-observation-body`: independent `observer` device identity, `state: consistent / contradicted / unknown` |
| Verification obligation | optional; relays not required, clients SHOULD | signed verdict over one normative validation order; a bare `PASS` is never a conformant verdict (`spec/CONFORMANCE.md` §preamble) |
| Independent implementations | not specified | two, clean-room, 0 divergences (GATE4) |

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
the consequence plainly, and it is quoted here in full because the disclosure
is a point in the spec's favour:

> These clauses do not enforce wall-clock expiry; a misbehaving agent can
> backdate `event.created_at` to satisfy an expired window. Relays or clients
> that require wall-clock freshness MUST enforce it independently of this NIP.

The bound is set by the party it constrains, and the mitigation is pushed out
of scope. AAR places delegation validity in signed claims (`not_before` /
`not_after`) evaluated against an explicit verifier-supplied evaluation time,
with time classes ranked by provenance strength and `externally_anchored`
defined as a prior-epoch anchor sandwich.

Note for citation: this is a **disclosed limitation**, not a discovered flaw.
Any AAR material citing it must present it as such.

#### 1.4.3 Revocation is non-renewal

The spec's revocation guidance is that owners "MAY revoke future authorization
by refusing to issue new `auth` tags." Combined with §1.4.1, previously issued
reusable capabilities remain verifiable; there is no status channel, compromise
signal, or path constraint. AAR carries credential status as first-class
evidence, bounds its age, and under D-52 evaluates status content before
resolving references so that a `compromised` status cannot be downgraded to
`status-missing` by withholding the reference.

Composed, §1.4.1–§1.4.3 mean a leaked agent key yields an attacker an
action-unbound, unrevocable, effectively unexpiring owner attestation. For a
chat workspace that is a bounded harm. It is disqualifying for the actuation
boundary AAR profiles, and AAR's threat model should cite it as a worked
external example of why the requirement set is shaped as it is.

#### 1.4.4 No outcome layer

NIP-OA models authorization only. There is no representation of whether
anything happened, and none is implied by its problem domain — Buzz agents post
events, they do not actuate physical systems.

This is where AAR's requirement set has no external analogue found so far.
`outcome-observation-body` requires a named observer device identity and a
`consistent` / `contradicted` / `unknown` state, with "verified" barred absent
an independent observer, and GATE5 spent both live legs hardening exactly this
seam (dispatch latching at action-bearing send; `contradicted` only on
positively-observed off-tolerance).

#### 1.4.5 Agent identity does not bind the serving model

NIP-OA binds the owner's signature to the agent's pubkey. Buzz's agent runtime
treats the agent definition as authoritative for model, provider, and prompt,
and shipped a generic "bring your own harness" runtime seam in desktop v0.5.0
(2026-07-28). The pubkey is therefore stable across a change of the model
serving the persona, and an owner attestation issued before such a change
remains valid after it, with no signal on the wire.

AAR distinguishes these: `principal-type` is
`"human" / "service" / "workload_instance" / "model_endpoint"`, and the
credential profile carries `subject_kid` and an SPKI `public_key` bound to a
specific issued credential with its own validity window.

This is a concrete, demonstrable divergence rather than a theoretical one, and
it is the cleanest available illustration of why "the agent has a key" is not
sufficient for attribution.

### 1.5 Convergences worth recording

Two independent arrivals at the same rule, which strengthen AAR's case rather
than weaken it:

- **No local-clock dependence.** NIP-OA: "Verification MUST NOT depend on the
  verifier's local clock, receipt time, or relay storage time." AAR's reference
  verifier CLI requires an explicit `--at UNIX_SECONDS` and never reads wall
  clock. Both specs independently forbid the same failure mode. The designs
  then diverge on what replaces it: AAR supplies evaluation time from outside
  the artifact, NIP-OA supplies nothing and performs no time evaluation.
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

Suggested framing where a reader has encountered Buzz: AAR is NIP-OA plus
action binding, scope, replay defense, externally-supplied time, revocation,
and an outcome oracle — with a conformant offline verifier that emits a signed
verdict instead of leaving verification optional.

Prohibited framings, for consistency with `docs/rfp-language-v0.2.md`:

- Do not describe NIP-OA as insecure, broken, or defective. Its limitations are
  disclosed, and are appropriate to its domain.
- Do not claim AAR is "more adopted," "production-proven," or "a standard."
  NIP-OA is shipped in a public Apache-2.0 platform; AAR v0.2 is a release
  candidate in a private repository pending a ratify-or-park decision.
- Do not attribute Buzz platform behaviour to NIP-OA. The NIP is `optional`;
  what the Buzz clients actually verify was not audited for this document.

---

## 2. Prior art already pinned inside the wire spec

Recorded here for completeness; each is already load-bearing in `spec/`.

- **NIP-26 (Nostr delegated event signing)** — the format and signing-flow
  ancestor NIP-OA builds on and whose delegator-assignment semantics it
  explicitly declines. Same reason AAR keeps `agent` and `approver` distinct.
- **UCAN, Biscuit, JWT** — named and excluded by `spec/aar-core.cddl`:
  delegation tokens are raw detached COSE_Sign1 and "no Biscuit, UCAN, JWT, or
  wrapper token grammar is permitted." The exclusion is deliberate and should
  be defended in any published related-work section, not quietly dropped.
- **RFC 6962 (Certificate Transparency)** — Merkle structure and the v1 anchor
  floor for completeness anchoring.
- **RFC 8949 / 9052 / 9053** — deterministic CBOR and COSE, governing where
  `spec/CONFORMANCE.md` is silent.
- **EdgeProof SDR v1.1** — wire discipline as frozen at `b9d7bc6`; AAR is the
  Phase-2 agent-attestation problem SDR wire-format-v2 §9 defers.

## 3. Not yet surveyed

Named so their absence is visible rather than implied. No claim is made about
any of these until someone reads them.

- **C2PA** — content provenance manifests; the closest analogue to AAR's
  producer-authored manifest and the completeness question narrowed under G3.
- **ACME (RFC 8555)** — cited in AAR's strategy as a de-facto-standard-author
  precedent, not yet examined as a technical design.
- **W3C Verifiable Credentials / DIDs** — overlapping credential and status
  vocabulary.
- **SPIFFE/SPIRE** — workload identity, adjacent to `workload_instance`.
- **In-toto / SLSA** — attested multi-step pipelines with typed links, the
  closest structural analogue to the receipt DAG found so far.

Any of these may invalidate a novelty claim AAR has not yet made in public.
Surveying them is a precondition for the ratify path, not for rc-stage work.
