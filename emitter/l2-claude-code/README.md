# L2 Reference Emitter — Claude Code Hooks

The harness-hook vantage point (`attestation-threat-model.md` §2 L2) made
concrete: a recorder registered at Claude Code's tool-call boundary that signs
one hash-chained receipt per tool call that reaches `PostToolUse` and a
session-close record on SessionEnd.

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
  reusing `harness/cbor.ts`. A failed tool call fires `PostToolUseFailure`,
  not `PostToolUse`, and gets no receipt yet; that hook is added in the next
  commit. Parallel tool calls run this hook concurrently: each append runs
  under a per-session lock (`lock.db`, an exclusive SQLite transaction) that
  the operating system holds and releases when the process dies. The lock
  assumes `lock.db` is not deleted or renamed while hooks run: SQLite locks
  the file, not the path. After each append the recorder writes the new chain
  head (`seq`, predecessor digest) to `state.json`. The next append follows
  one rule: with no `state.json` it trusts the log and continues from its
  last line; with a `state.json` it continues from the log when the log
  contains the recorded head (some line is that head and every later line
  links to the line before it, so the log may be any number of entries
  ahead); otherwise it chains from the recorded head, so the verifier reports
  the break, and logs one line in the session `errors.log`. So a lost log
  tail is reported only when the lost lines include the entry `state.json`
  last recorded and a later entry is then appended. `seq` is one more than
  the last line's own `seq` and never below the recorded next `seq`.
- `close.ts` (SessionEnd hook): emits the signed session-close exactly once —
  item count, first/final chain digests, close window. It takes the same
  lock, so no receipt lands between its log read and the close write. A
  second close is a no-op; a tool call after close is dropped and logged
  (`errors.log`), never appended — a closed session is never extended (D-63).
- `verify.ts`: offline, walks the D-63 evaluation — signatures, the six
  chain checks (successor uniqueness: the walk MUST be a function, a fork is
  `session/chain-broken`), close/receipt coordinate agreement, single close.
  Exit 0 only on an intact, closed chain.

State lives under `~/.aar-l2/` (override: `AAR_L2_DIR`): a per-install P-256
recorder key (0600) and per-session `receipts.hexl` / `state.json` /
`close.hex`. The key, state and close files are written under a temporary
name and renamed into place, so a killed hook leaves none of them partial;
the receipt log is appended in place. A new key pair publishes
`recorder.pub` first and `recorder.key` last, so a private key on disk always
has its public key beside it.

## Install (manual, deliberately)

Add to `~/.claude/settings.json` hooks (adjust the repo path):

```json
"PostToolUse": [{ "matcher": "", "hooks": [{ "type": "command",
  "command": "bun run /path/to/aar/emitter/l2-claude-code/recorder.ts" }] }],
"SessionEnd": [{ "matcher": "", "hooks": [{ "type": "command",
  "command": "bun run /path/to/aar/emitter/l2-claude-code/close.ts", "timeout": 60 }] }]
```

The close runs on `SessionEnd`, not `Stop`: Claude Code fires `Stop` once per
turn, so a close there would end the recording after the first reply and drop
every later tool call. `SessionEnd` hooks get 1.5 s by default; 60 seconds is
the documented ceiling for the SessionEnd timeout budget.

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
the close is single and coordinate-consistent.

Verification detects an edited or deleted interior entry (see
`emitter.test.ts`: one flipped byte, one deleted interior receipt). It
detects a lost tail only when the lost lines include the entry `state.json`
last recorded and a later entry was then appended (see `lifecycle.test.ts`).
It does not detect: a tail removed just before the close; a tail removed
while there was no `state.json`; entries appended after the last successful
`state.json` write (a recorder killed between its append and its state
write leaves such an entry, and removing it afterwards goes unreported); or a
tail removed by someone who can also edit `state.json`. Those need an
external anchor. Lines
reordered after the close still verify, because the verifier walks digest
links, not line order. Reordering before the close can fail, because the
close takes its first and final digests from physical line order.

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

Run the tests: `bun test emitter`. `emitter.test.ts` covers the verifier and
the close rules (intact, double-close refusal, post-close drop, tamper,
omission, missing close, forged close, duplicate close, coordinate mismatch,
cross-session close replay, close after state loss). `lifecycle.test.ts`
covers the recorder lifecycle: lost and stale `state.json`, a lost log tail,
a final line without its newline, the key files, and the lock. Its
recorders-started-at-once, close-racing-appends and concurrent-first-use
tests are stress tests: they pass when no race shows up in that run. The
test that shows exclusion is the marker-based one: a second process is seen
attempting the lock, is not inside it while the holder lives, and gets in
once the holder is killed.

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
- **noticed_not_fixed:** a killed Claude Code process runs no `SessionEnd`
  hook and leaves no close; verify then reports "completeness
  not_established". A session resumed under the same id after its close is
  not extended: its tool calls are dropped and logged (D-63: a closed session
  is never extended). A failed tool call (`PostToolUseFailure`) gets no
  receipt yet. A torn last log line (a hook killed mid-append) still stops
  recording for that session: every later hook logs `recorder: …` in the base
  `errors.log` and appends nothing. The lock has no wait cap: a hook waits on
  a live holder until Claude Code's hook timeout ends it. Renamed-into-place
  files survive a killed process, not a power loss (nothing is fsynced). A
  `recorder.pub` emptied or replaced by hand beside an existing key is not
  repaired; only a missing one is rewritten.
  `close_id` is written but not recomputed by the verifier. One recorder key
  signs both receipts and close, so D-63's `session/close-signer-mismatch`
  collapses to the single-spki check — a simplification, not the spec's
  close-authority rule.
- **verification_gap:** the hooks have not yet run in a live Claude Code
  session — all tests drive synthetic hook-event JSON through the real
  entrypoints as subprocesses. The install snippet above is untested config:
  that `SessionEnd` fires once per session, honours `"timeout": 60`, and that
  parallel `PostToolUse` hooks behave like the test's concurrent processes
  comes from the hooks reference, unverified until a live install. The lock
  has run only on macOS (APFS) with Bun 1.3.5; SQLite file locks on a network
  filesystem are untested.
