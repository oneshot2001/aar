# Draft: peer note to Obsigna / agent-receipts

Status: 2026-08-22 round-0, pre-humanizer. Channel: GitHub issue or the
contact route Matthew prefers. Sources: reviewed
related-work-addendum-2026-08-19.md §B (§B.4 EXCLUDED: internal-only; no
roadmap/cadence/launch references anywhere in this note),
attestation-threat-model.md, attestation-spec-deltas.md. Matthew reviews and
sends; nothing sent by tooling.

Subject: Agent Action Receipts, independent implementations, possible cross-pollination

---

Hi, I build Agent Action Receipts (AAR), an open spec and offline verifier
for evidence-grade records of AI-agent actions, grown out of physical
security (agents driving cameras and PTZ, where the record may end up in
front of an adjuster or a court). Found your spec through the agent-receipts
work and read it properly, including the conformance page and the Alloy
models. It's careful work. The frozen MUST-reject vectors and the honest
disclosure of what a self-anchored chain can't prove are both rarer than
they should be.

Your conformance page names the requirement you can't yet meet alone:
implementations from independent parties. That's the part I can offer
directly. AAR has two clean-room implementations (TypeScript and stdlib-only
Python, the second built from spec text with the first off-limits),
cross-verified over a byte-pinned fixture corpus. First contact produced 20
divergences, every one a spec ambiguity rather than a bug, and each got
pinned as a normative ruling. If a third-party read of your spec would help your
conformance story, I'd genuinely enjoy doing one; ambiguity-hunting in this
exact problem space is most of what the last month of my project has been.

Two places our work converges from opposite directions:

- Your open-chain tail-truncation disclosure is the honest statement of the
  problem my newest pages attack head-on: a signed session-close record
  ("this session comprised N actions, final chain digest H"), externally
  anchored, is the construction that turns a chain from internally
  consistent into evidence against cherry-picking. The residual is stated
  plainly on our side too: a compromised recorder that never emits a
  receipt beats it, and only an independent ingress census retires that. "Only these
  happened" is the claim an adjuster actually needs, and neither
  per-receipt signatures nor a chain alone delivers it.
- Your Alloy invariant checking is something I want to adopt; AAR pins its
  graph properties by construction (content-addressing makes the DAG
  acyclic) but has nothing like machine-checked chain invariants. If you've
  written anything about the workflow, I'd read it.

The rest of AAR, if useful for comparison: conformance profiles
(observe/advise/act), deterministic CBOR + COSE_Sign1, signed verifier
verdicts, an outcome layer that bars "verified" without a named independent
observer, live legs on real PTZ hardware. Apache-2.0/CC-BY at
github.com/oneshot2001/aar. Different design points than yours in several
places (closed ontology vs your taxonomy, loud-crash verifier vs structured
result). I've been keeping a public related-work file that tries to state
those differences without ranking anyone, and I'd rather compare notes than
compete on naming.

Matthew Visher
github.com/oneshot2001/aar
