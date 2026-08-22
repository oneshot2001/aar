# Attestation Vantage Points — Who Signs, From Where

**Status:** 2026-08-22, adversarially reviewed (round-1 FIX-FIRST, 11
findings applied → round-2 SHIP). Companion to `threat-model-v0.1.md`, which
models the receipt *wire* (what a bundle proves once emitted, G1–G4). This page
models the step before the wire: **where the receipt producer sits relative to
the agent it reports on**, and which attackers each position can and cannot
defeat. The trust boundary is the architectural decision; schemas are cheap to
change, an attestation boundary implemented against is not.

Domain note: `threat-model-v0.1.md` was written against the physec actuation
topology (Enforcement Point between agent and camera/VMS). This page
generalizes the same question to any agent harness — coding agents, desktop
agents, MCP-tool-calling agents — because the receipts category is forming
there, and every framework in it must answer the same question first.

## 1. Attackers

- **A1 — Lying agent.** The model/agent proper claims actions it did not
  take, or omits actions it did take. Includes the honest-but-wrong case: a
  model confabulating its own tool history. No key compromise needed — A1
  only requires that the record be authored from inside the thing being
  reported on. A *compromised harness* — the process hosting the model — is
  deliberately not A1: it holds A2's capabilities live, during the session,
  and is treated under A2.
- **A2 — Retroactive operator (and compromised harness).** Whoever controls
  the machine, and the processes, that the record lives on edits or shapes
  the record —
  after the session (deleting an action, altering an argument, re-writing an
  outcome) or during it (a subverted harness starving or feeding a
  recorder).
- **A3 — Cherry-picking presenter.** Hands a verifier a *real but incomplete*
  set of records: every item authentic, the damning ones absent. Attacks the
  completeness claim, not integrity or attribution.

These map onto the wire threat model as follows: A1 is the producer-honesty
question G4 deliberately excludes from wire conformance; A2 is the
tamper-evidence question G2 answers *for emitted bytes* (with G2's documented
pre-emission equivocation window, T-E1/T-E2, until emission is pinned per
R-26); A3 is the completeness question G3 deliberately *narrows* — answered
only where an independently committed ingress census exists or cross-stream
reconciliation (R-15) is performed. What the wire model takes as given — "a
producer emitted this" — is exactly what the vantage point decides.

## 2. Vantage points

### L1 — The transcript file

The harness's own session log (e.g. a Claude Code JSONL transcript), written
by the agent process to storage the operator controls.

**Defeats: nobody.** The record is authored by the harness — recording the
agent's claims — and stored inside A2's boundary. It is an *unsigned self-observation* — evidentially, testimony,
not a receipt. The working exhibit: a transcript viewer such as zoetrope
(`zoe`) renders an edited transcript exactly as confidently as a genuine one,
because there is nothing in the format that could distinguish them. L1 is
valuable as *ingress* — a source of claims to be checked against attested
records — and is out of scope as evidence.

### L2 — The harness hook layer

A recorder registered at the harness's tool-call boundary (PostToolUse-style
hooks): a separate process the harness invokes on every tool call, outside
the model's control, holding its own signing key.

**Defeats A1 within a session** — the model cannot un-invoke a hook or forge
its input; the record of "tool X called with args Y, returned Z" is authored
outside the agent. Two qualifications bound the claim:

1. **A1 is defeated only down to the harness's honesty.** L2 attests what the
   *harness* reports at the hook boundary. A compromised or buggy harness is
   an A2 capability under this taxonomy — it can starve or feed the hook,
   during the session, and no L2 construction detects that alone. This is
   the same shape as v0.1's TB-1: signed observations are claims *as
   asserted by* the named source.
2. **A2's retroactive half and A3 are defeated only with the chain
   machinery** (qualification 1 stands for A2's live half). A signed-but-
   unlinked pile of L2 receipts can be edited by re-signing (operator holds
   the machine the key lives on) and cherry-picked freely. Hash-chaining
   (G2), a signed session-close record (§4), and an **external anchor** (G3;
   a SCITT transparency log is the candidate anchor class) are what turn L2
   from "signed notes" into evidence against A2/A3.

### L3 — The tool boundary

The tool itself attests: an MCP server, gateway, or Enforcement Point signs
"I was called with X and returned Y" under its own key, as a **second party**
to the interaction.

**Defeats A1 fully** for covered tools: the agent's claims are corroborated
or contradicted by a counterparty the agent does not contain and the harness
does not author. This is the strongest basis, and it is where AAR already
lives — the v0.2 **reference demo-EP** is a working L3 attester for
`camera.stream.view` / `camera.ptz.preset` (Gate-5-closed as a demo, claim
of record in `spec/GATE5-CLOSE.md`), and the onvif-mcp producer is a working
L3 attester at the MCP boundary within its disclosed scope (per-install key,
demo-EP wire machinery, same-operator anchoring). Bounds:

- Coverage is per-tool. Actions through uninstrumented tools produce no L3
  receipts (the instrumented-control boundary, restated).
- A2 at the *tool operator* is still real when the tool and the agent share
  an operator — the Gate-5 F22 same-operator-demo-anchoring disclosure
  (`spec/GATE5-CLOSE.md`) carries over unchanged. External anchoring is what
  removes the shared-operator caveat.
- A3 is defeated only by completeness machinery (§4), same as L2. Attestation
  strength and completeness are orthogonal properties.

## 3. Position

**L3 is the ideal; L2 is the practical v1; L1 is ingress, never evidence.**

Rationale: L3 requires each tool to adopt receipt emission — the right end
state and the slow path. L2 requires only harness hook support, which exists
today and covers *every* tool call in a session (solving L3's per-tool
coverage gap at the cost of one trust step). The intended wire delta is
small and declarative: an `attestation_point` field (proposed, Phase-2 spec
work — today's CDDL carries neither this field nor an L2-recorder role) plus
verifier semantics that rank it. Under that delta, nothing structural
changes when a tool upgrades from being L2-observed to L3-attesting; the
declared attestation class of its receipts does.

### Provider-side records (noted, not yet a rung)

The model provider's server-side record of tool-use blocks sits outside both
the agent and the operator's machine — the wire already reserves a
`provider_attested` provenance class for exactly this kind of source. It is
the strongest available answer to the shared-machine problem in L2, and it
is excluded from the v1 ladder for a practical reason, not a principled one:
no provider currently signs or exports such records in a verifiable form.
When one does, it slots in above L2 without changing the taxonomy. Cloud-
hosted harnesses (harness operator ≠ record custodian) split A2 into two
parties the same way; the taxonomy treats whoever controls the record's
machine as A2.

## 4. Completeness — the property that separates a receipt chain from a highlight reel

Per-receipt signatures, at any vantage point, prove only that *these* actions
happened. They cannot prove **only** these actions happened — which is the
claim an adjudicator actually needs, and the claim A3 attacks.

The completeness construction, restated from G2/G3 for this setting:

1. every receipt carries the digest of its predecessor (hash chain — deletion
   or reordering breaks the chain);
2. a **signed session-close record** asserts "this session comprised N
   actions, final chain digest H" (a bounded, falsifiable totality claim for
   the session);
3. the session-close record is **anchored externally** — registered on a
   transparency log outside the operator's control — so A2 cannot re-close
   the session after the fact.

Absent (2)+(3), a chain is only internally consistent — a well-formed
highlight reel. With them, an omitted receipt is not merely missing but
*provably missing relative to the recorder's own close*: the construction
defeats A3 outright, and A2 post-anchor. What it does not defeat is
pre-close omission by a compromised recorder — an action starved from the
hook never enters the chain or the count, and the closed, anchored session
is internally consistent and wrong. That residual is T-H1-shaped (the close
record is a producer-declared manifest, only as strong as its committer's
independence) and is retired only by an independent ingress census or
cross-stream reconciliation (R-15) — this is G3's narrowing restated at
session granularity, not escaped by it. The unseeded slot our reading of
draft-mih-scitt-agent-action-capsule-02 finds in its effect-attestation
registry — independent sensor confirmation of a claimed effect — is the
same move one level up: independent corroboration where self-assertion is
structurally insufficient.

## 5. Non-goals

- Not observability or tracing — no latency, cost, or quality signal.
- Not a transcript format — L1 formats stay whatever the harness makes them.
- No claim about **intent** — a receipt proves *occurrence at a boundary*,
  never why, and never that the recorded action was wise (G4's verifier rule,
  unchanged: artifacts satisfy their declared class; process honesty is out).
- No compromised-signer immunity — a subverted L2 recorder or L3 tool signs
  lies with a valid key; the guarantee remains attribution + post-emission
  tamper evidence + census-conditional completeness, per the narrowed G3 of
  `threat-model-v0.1.md` §2.
