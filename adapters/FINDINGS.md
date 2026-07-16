# Gate 5 findings

## G5-D1-001 — no exported harness receipt/bundle builder API

- Status: open; documentation/producer API question, non-wire.
- Contract relied on: “receipt DAG construction ... via harness builders” and
  “build on `harness/` (deterministic CBOR encoder, COSE, Merkle).”
- Finding: `harness/fixtures.ts` contains the only receipt/bundle builders, but
  they are private functions coupled to published KAT keys and fixed KAT
  coordinates. D1 cannot use them with distinct demo keys without modifying
  `harness/`, which the slice forbids.
- D1 reading: implement demo producer builders that import and reuse the
  harness CBOR, hashing, and Merkle primitives, and follow the fixture builder
  preimages exactly. Do not import fixture builders or KAT private keys.

## G5-D1-002 — refusal DAG termination

- Status: open; demo-content question, non-wire.
- Contract relied on: S3 requires “refusal receipted as `action_attempt` +
  `not_dispatched`” and zero invocation-attributable dispatch, while the D1
  topology lists the general DAG through dispatch and outcome observation.
- Finding: the rubric does not say whether a refusal should fabricate later
  receipt kinds.
- D1 reading: S3 terminates at the `action_attempt`. It emits neither dispatch
  nor outcome-observation receipts because no dispatch/effect exists.

## G5-D1-003 — local log integration before live anchor timing exists

- Status: open; demo-content question, non-wire.
- Contract relied on: D1 requires a minimal local RFC 6962 v1 log and describes
  same-operator demo anchoring, but D2 owns the real transport/effect timing.
- Finding: the rubric does not pin whether D1 synthetic bundles must carry a
  wire anchor record or only exercise the local log.
- D1 reading: append the signed epoch-manifest payload digest to the local log
  and pin that head in trust inputs. Do not manufacture a wire anchor record in
  D1; add it once D2 can commit real submitted/accepted timing and target data.

## G5-D1-004 — harness encoder loses the high byte of uint32 values

- Status: open; build-on implementation blocker for lab-era Unix time,
  non-wire if corrected in the harness implementation.
- Contract relied on: “MUST build on `harness/` (deterministic CBOR encoder,
  COSE, Merkle)” and D1’s prohibition on modifying `harness/`.
- Finding: `harness/cbor.ts` encodes the first payload byte of a four-byte
  unsigned integer as `value / 2^32` rather than the high uint32 byte. For
  example, `1800000000` encodes as `1a0049d200` and decodes as `4837888`.
  The committed positive KAT likewise carries `7636552` rather than its source
  builder's `1735689800`. A Gate 5 run using a current Unix timestamp therefore
  fails pyref step 5 because carried `evaluation_time` differs from `--at`.
- D1 reading: do not fork the frozen harness or silently introduce a second
  CBOR stack. Synthetic tests use a gate-pinned time below `2^24`. D2 needs an
  adjudicated harness implementation fix (with regenerated KAT impact audited)
  or an explicit ruling that Gate 5 evaluation times remain below this bound.
