# L2 Reference Emitter — Claude Code Hooks

The harness-hook vantage point (`attestation-threat-model.md` §2 L2) made
concrete: a recorder registered at Claude Code's tool-call boundary that signs
one hash-chained receipt per tool call and a session-close record on Stop.

**Wire status: CANDIDATE.** Payloads implement the D-62/D-63 proposals
(`docs/attestation-spec-deltas.md`) under draft content types
(`;v=0.3-draft`). They are NOT v0.2-conformant AAR receipts, are not covered
by the frozen fixture corpus, and change if ratification amends the
candidates. This emitter is the fixture-generating vehicle for that
ratification, not a conformant producer.

## What it does

- `recorder.ts` (PostToolUse hook): reads the hook event on stdin, emits a
  signed receipt — session/tenant/site ids, sequence, `session_prev_digest`
  (payload-bstr digest of the predecessor, nil at genesis), an `attestation`
  block (`point: harness_hook`, recorder kid, `agent_kid: nil`), tool name,
  input/response digests, `committed_at`. Deterministic CBOR, detached
  COSE_Sign1 ES256 (RFC 6979, low-S) — the same primitives as the main wire,
  reusing `harness/cbor.ts`.
- `close.ts` (Stop hook): emits the signed session-close exactly once —
  item count, first/final chain digests, close window. A second Stop is a
  no-op; a tool call after close is dropped and logged (`errors.log`), never
  appended — a closed session is never extended (D-63).
- `verify.ts`: offline, walks the D-63 evaluation — signatures, the six
  chain checks (successor uniqueness: the walk MUST be a function, a fork is
  `session/chain-broken`), close/receipt coordinate agreement, single close.
  Exit 0 only on an intact, closed chain.

State lives under `~/.aar-l2/` (override: `AAR_L2_DIR`): a per-install P-256
recorder key (0600) and per-session `receipts.hexl` / `close.hex`.

## Install (manual, deliberately)

Add to `~/.claude/settings.json` hooks (adjust the repo path):

```json
"PostToolUse": [{ "matcher": "", "hooks": [{ "type": "command",
  "command": "bun run /path/to/aar/emitter/l2-claude-code/recorder.ts" }] }],
"Stop": [{ "matcher": "", "hooks": [{ "type": "command",
  "command": "bun run /path/to/aar/emitter/l2-claude-code/close.ts" }] }]
```

Verify a session:

```
bun run verify.ts ~/.aar-l2/sessions/<id> ~/.aar-l2/recorder.pub <id>
# derive <id> from the raw harness session id, NOT from the evidence dir:
#   bun -e 'const{createHash}=require("node:crypto");console.log(createHash("sha256").update(process.argv[1]).digest("hex").slice(0,32))' <raw-session-id>
```

The expected session id is a required input, not inferred from the evidence:
a verifier that trusts the artifact to name its own session can be replayed a
genuine close from a different session.

## What a verified session does and does not prove

Proves: these receipts were signed by the recorder key, the chain is
complete and unforked between the declared endpoints, the count matches, and
the close is single and coordinate-consistent. Editing, deleting, or
reordering any receipt after emission breaks it (see `emitter.test.ts`: one
flipped byte, one deleted interior receipt).

Does NOT prove:

- **Recorder honesty (T-H1).** The recorder is a process on the same machine
  as the harness and operator. A compromised harness can starve it before
  emission; the closed chain is then internally consistent and wrong.
- **Agent identity.** No agent credential exists at the Claude Code hook
  boundary, so `agent_kid` is nil and receipts rank as *undeclared* for
  self-report purposes under the D-62 candidate.
- **A2's retroactive half.** The operator holds the recorder key's machine.
  Without an external anchor for the session-close, a determined operator
  can rebuild the whole chain. Anchoring is the missing rung, not this
  emitter's claim.
- **Tenant/site authority.** The ids are fixed demo placeholders, same
  posture as the demo-EP's F22 disclosure.

Run the tests: `bun test emitter` (10 cases: intact, double-close refusal,
post-close drop, tamper, omission, missing close, forged close, duplicate
close, coordinate-mismatch, cross-session close replay).

## Honesty Ledger

- **fixed_in_round_2 (adversarial review):** P1 — cross-session close replay:
  a genuine empty-session close transplanted into another session's directory
  verified "intact, 0 action(s)" because nothing bound the close to the
  session being asked about. Fixed: the expected session id is now a required
  verifier argument checked against `close.session_id` (repro is a test).
  Also: `close.ts` failures now log to errors.log instead of being swallowed;
  test env leak removed.
- **fixed_in_round_1 (adversarial review):** P1 fail-open — a validly-signed
  receipt substituted as `close.hex` with an emptied log verified "intact"
  (non-integer `item_count` skipped every chain check; content type and kid
  were never checked). Fixed: field-shape validation before any branch
  (malformed = `session/fields-inconsistent`, never a skip, per D-60),
  content-type and kid checks on every envelope, `item_count` capped at
  10000, endpoint-digest/count consistency checks, 3 new negative tests
  including the live P1 repro; crash logs write `BASE_DIR/errors.log` (per-session
  `errors.log` keeps the post-close drop log — deliberate, two locations);
  concurrency race disclosed in `recorder.ts`.
- **noticed_not_fixed:** `state.json` read-modify-write races under
  concurrent tool calls (lost receipt or fork; verify rejects the fork —
  corruption is loud, not silent, but serialization is future work).
  `close_id` is written but not recomputed by the verifier. One recorder key
  signs both receipts and close, so D-63's `session/close-signer-mismatch`
  collapses to the single-spki check — a simplification, not the spec's
  close-authority rule.
- **verification_gap:** the hooks have not yet run in a live Claude Code
  session — all tests drive synthetic hook-event JSON through the real
  entrypoints as subprocesses. The install snippet above is untested config;
  whether Stop fires exactly once per session is unverified until a live
  install.
