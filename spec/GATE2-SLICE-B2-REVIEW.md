# Gate 2, slice B2 — Claude review + rulings
2026-07-14. Independently verified: `bun test` 14/14 (1,119 assertions), tsc
clean, 186 CBOR fixtures (33 positive / 141 stateless negative / 3 stateful /
9 class-boundary), double-generation byte-identical, full positive bundle
passes steps 1–20 with a signed round-tripping verdict. **Slice B2 ACCEPTED**
(partial-by-contract, not by execution), with five rulings:

**B2-Q1 — `graph/cycle`: DELETE; claim acyclicity as a design property.**
Content-derived receipt IDs make any cycle a SHA-256 fixed point — the DAG is
acyclic BY CONSTRUCTION once step 7 passes. Delete the code; rewrite the §1
"cycle rejection" resource language as a non-normative defensive-iteration
bound for implementations. Add one CDDL/CONFORMANCE sentence stating the
property explicitly — it is a selling point, not an accident. (D-47)

**B2-Q2 — `merkle/duplicate-leaf`: KEEP, redefine over index-less content.**
`leaf_index` stays in the leaf preimage (positional binding). Duplicate =
two membership proofs in one bundle proving leaves that share
(tenant, site, epoch, item_digest) at different indices within one signed
batch. Detection is scoped to leaves present in the bundle — the verifier
cannot see unproven leaves; state that scope. (D-48)

**B2-Q3 — attestation artifacts: carry bytes opaquely; deep verification out
of v0.2.** `boot/capture/provider_attestation_id` and
`qualifying_predicate_id` MUST resolve to a `canonical-manifest-payload` in
the bundle whose digest equals the ID (bytes carried, hash-bound, media-typed;
`manifest/payload-missing` fires when absent). Cryptographic validation of
attestation *content* (TPM quotes, provider signature formats) is explicitly
OUT of the v0.2 freeze; the verdict's class limits mean "declared and
structurally supported (bytes committed)" — CONFORMANCE step 19 and §5 gain
that sentence. Deep attestation verification is a v0.3/stronger-profile item.
This matches the threat model's G4 rule: artifacts satisfy the declared
class; process assurance is never claimed. (D-49)

**B2-Q4 — `externally_anchored` time: reference a PRIOR epoch's anchor.**
Sustained — same-epoch reference is self-referential by construction.
`evidence.time.anchor_id` MUST name a verified anchor of an EARLIER epoch
with `accepted_at <= committed_at`: the prior anchor gives the lower time
bound; the receipt's own epoch anchor (verified separately when present)
gives the upper bound. The class is established as a sandwich across two
anchors, never by self-reference. Positive class-boundary KAT: receipt in
epoch N+1 referencing epoch N's anchor — build it in the fix pass. (D-50)

**B2-Q5 — verdict digest preimages: FREEZE; early-failure sentinels: FREEZE.**
- `limits_digest` = SHA-256(det-CBOR(["AAR-VERDICT-LIMITS-v1", limits-map]))
  over a defined closed map of the §1 table values; likewise
  `anchor_heads_digest` ("AAR-VERDICT-HEADS-v1", expected-anchor-heads array)
  and `replay_state_digest` ("AAR-VERDICT-REPLAY-v1", defined replay-state
  map; all-zero digest when no replay state was supplied).
- `build_digest`/`config_digest`: implementation-defined preimages, but MUST
  be stable per release/configuration and documented by the implementation —
  they bind identity, not interop.
- Early-failure verdicts (bundle undecodable before scope/trust known): scope
  and trust-policy blocks use all-zero ids/digests/times as the normative
  sentinel, `evaluation_time` stays real, and requested values are used where
  the verifier was configured with them. Adopt the harness's zero/default
  convention as the wire rule. (D-51)

## Fix pass (slice B2.1) — then gate-2 coverage audit
Apply D-47..D-51 to spec/CONFORMANCE.md (+ CDDL comment for B2-Q4/Q1),
DECISIONS.md; update verifier + fixtures (incl. the withheld same-epoch
positive KAT rebuilt as prior-epoch); delete the graph/cycle fixture
expectation; keep everything green. Then Claude audits gate-2 coverage
against the rubric KAT bar; residue → slice C.
