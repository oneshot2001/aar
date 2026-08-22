# Draft: intro note to scitt@ietf.org (cc spec@actionstate.ai)

Status: 2026-08-22 round-0, pre-humanizer. Sources: reviewed
related-work-addendum-2026-08-19.md §A (B.4 excluded), attestation-threat-model.md,
attestation-spec-deltas.md. Matthew reviews and sends; nothing sent by tooling.

Subject: Agent Action Receipts, a deployed wire format adjacent to draft-mih-scitt-agent-action-capsule-02

---

Hello all,

I've been building Agent Action Receipts (AAR), an open spec and verifier for
evidence-grade records of AI-agent actions on physical security systems
(cameras, PTZ, video management), where an agent's output can trigger
physical-world action or end up as evidence. Reading
draft-mih-scitt-agent-action-capsule-02 closely, the overlap with this group's
work is large enough that I wanted to introduce it here rather than keep
building in parallel.

What AAR is: conformance profiles (observe / advise / act) over a
deterministic-CBOR, COSE_Sign1 wire format, with an offline verifier that
emits signed verdicts; a bare PASS is never a conformant result. Everything
is Apache-2.0/CC-BY at github.com/oneshot2001/aar. Two things might be
useful to this group:

1. Two clean-room implementations (TypeScript and stdlib-only Python) built
   from the spec text alone, cross-verified over a byte-pinned fixture
   corpus. The adjudication record is public: 20 divergences at first
   contact, each one a spec ambiguity we then pinned. The lesson we keep
   relearning is that byte-identity between two implementations proves
   unambiguity only over the corpus's coverage, never completeness of the
   rules. That seems relevant
   to any spec in this space heading toward multiple implementations.

2. An outcome layer that requires a named independent observer before
   "verified" language is permitted. The capsule draft's effect_attestation
   registry leaves independent sensor confirmation of a claimed effect
   unseeded. That slot is where most of our work has gone (live legs on real
   PTZ hardware, with restore semantics and a contradicted-outcome path),
   and I'd like to contribute a registry entry or a profile there.

One convergence worth naming: the draft's §13 honesty boundary ("tamper-evidence
is for record bytes, not recorder honesty") matches a rule we arrived at
independently. Our verifier checks that artifacts satisfy their declared
class and makes no claim about producer honesty. Refusal receipts likewise:
our conformance suite includes a zero-attributable-dispatch scenario, and our
MCP producer wire-emits policy denials.

Where SCITT fits for us: our current anchor class is an operator-run RFC 6962
log, with the shared-operator caveat disclosed. Registration on a SCITT
Transparency Service (per RFC 9943) is the natural stronger anchor class, and
our newest working pages (a threat model over attestation vantage points,
who signs from where, plus a signed session-close record) lean on exactly
the property registration provides: it bounds the timing of a record and
makes later substitution detectable, while proving nothing about content
truth.

Terminology note to avoid confusion: "AAR" here is unrelated to
draft-sahu-agent-action-receipts; the convergence on obvious words seems to
be the norm in this space, and I'll always cite drafts by full name.

If a physec-actuation profile, an effect-attestation registry entry, or the
two-implementation adjudication record would be useful inputs, I'm happy to
write any of them up for the list.

Matthew Visher
github.com/oneshot2001/aar
