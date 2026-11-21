# L2 Reference Emitter — Claude Code Hooks

The harness-hook vantage point (`attestation-threat-model.md` §2 L2) made
concrete: a recorder registered at Claude Code's hooks that signs one
hash-chained receipt per tool call that reaches `PostToolUse` or
`PostToolUseFailure`, one prompt entry per `UserPromptSubmit` event, and a
session-close record on SessionEnd.

**Wire status: CANDIDATE.** Payloads implement the D-62/D-63 proposals
(`docs/attestation-spec-deltas.md`) under draft content types
(`;v=0.3-draft`). They are NOT v0.2-conformant AAR receipts, are not covered
by the frozen fixture corpus, and change if ratification amends the
candidates. This emitter is the fixture-generating vehicle for that
ratification, not a conformant producer.

## What it does

- `recorder.ts` (PostToolUse and PostToolUseFailure hook): reads the hook
  event on stdin, emits a signed receipt — session/tenant/site ids, sequence,
  `session_prev_digest` (payload-bstr digest of the predecessor, nil at
  genesis), an `attestation` block (`point: harness_hook`, recorder kid,
  `agent_kid: nil`), tool name, input/response digests, `committed_at`.
  Deterministic CBOR, detached COSE_Sign1 ES256 (RFC 6979, low-S) — the same
  primitives as the main wire, reusing `harness/cbor.ts`. When the hook input
  carries them as non-empty strings, the receipt also carries `prompt_id`
  (the prompt the harness said it was processing) and `tool_use_id`, each
  exactly as given, and `hook_event_name` when the input has one. A
  `PostToolUseFailure` receipt carries `error_digest`, which the recorder
  computes (SHA-256 of the UTF-8 of `JSON.stringify(error ?? null)`), and no
  `response_digest`. The hook does nothing unless `session_id` is a non-empty
  string. An input whose `hook_event_name` is present and is neither
  `PostToolUse` nor `PostToolUseFailure` is dropped with one line in the base
  `errors.log`; one without a non-empty string `tool_name` is dropped with a
  line in the session `errors.log`. The digests are computed after the close
  check. Parallel tool calls run this hook concurrently: each append runs
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
  last recorded and a later entry is then appended. `seq` is the larger of
  the last line's own `seq` plus one and the next `seq` recorded in
  `state.json`; the line count stands in when the last line's `seq` cannot be
  read.
- `prompt.ts` (UserPromptSubmit hook): appends one signed prompt entry to the
  same log, chained and locked exactly like a tool receipt (one append
  function in `lib.ts` serves both). The entry carries `prompt_id` as given,
  `prompt_commitment` = SHA-256 of the deterministic CBOR of
  `["AAR-L2-PROMPT-COMMITMENT-v1", opening, prompt]` with a fresh 32-byte
  random `opening`, and `hook_source` when the hook input has a string
  `source`. The prompt text and the opening never enter the chain. Inside
  the same lock the chain entry is appended first; then `prompts.jsonl` in
  the session directory is rewritten whole (its existing bytes, carried
  forward without decoding them, plus one JSON line `{prompt_id, opening, prompt}`, the opening as 64 lowercase hex)
  under a temporary name and renamed into place at mode 0600. This reverses
  the order this recorder was first built with (text line first): a hook
  killed between the two writes now leaves an entry whose text is
  unavailable, and the recorder itself writes no torn line and no line
  without an entry. The hook does nothing unless `session_id` is a non-empty
  string. An input whose `hook_event_name` is present and is not
  `UserPromptSubmit` is dropped with one line in the base `errors.log`. An
  event without a string `prompt` or a non-empty string `prompt_id`, and a
  prompt after the close, is dropped and logged in the session `errors.log`.
- Text fields are well-formed Unicode. A string with a lone UTF-16
  surrogate would be signed as a different string (the surrogate becomes
  U+FFFD), so the hooks treat such a `session_id`, `tool_name`, `prompt_id`,
  `tool_use_id` or `source` as not being a string, and `prompt.ts` commits
  to and stores the prompt's well-formed form, so the committed text and the
  stored text are the same string.
- `close.ts` (SessionEnd hook): emits the signed session-close exactly once —
  item count (tool receipts and prompt entries), first/final chain digests,
  close window. It takes the same lock, so no entry lands between its log
  read and the close write. A second close is a no-op; a tool call or prompt
  after close is dropped and logged (`errors.log`), never appended — a closed
  session is never extended (D-63).
- `verify.ts`: offline, walks the D-63 evaluation — signatures, the six
  chain checks (successor uniqueness: the walk MUST be a function, a fork is
  `session/chain-broken`), close/receipt coordinate agreement, single close.
  Exit 0 only on an intact, closed chain. Every check applies to tool
  receipts and prompt entries alike. Before any other use, each entry's
  payload is checked against the closed field list of its kind (the kind is
  the signed content type; the two lists are in the candidate section of
  `docs/attestation-spec-deltas.md`): a missing, malformed or unlisted field
  is `session/fields-inconsistent`, naming the entry and the field. A log,
  close or `prompts.jsonl` that exists and cannot be read, and a line that
  cannot be decoded, is a reason code, not a thrown error. On an intact
  session it
  then reports, in the text line and in `--json`: `prompts`, `tool_receipts`,
  `bound`, `unbound`, `duplicate_prompt_ids` and `prompt_text: { available,
  unavailable, orphan_lines }` (`receipts` stays the count of all chain
  entries). A session that fails any check reports none of these. A session
  written before prompt entries existed verifies as before, with zero
  prompts and every tool receipt unbound.

State lives under `~/.aar-l2/` (override: `AAR_L2_DIR`): a per-install P-256
recorder key (0600) and per-session `receipts.hexl` / `state.json` /
`close.hex` / `prompts.jsonl` (0600). The key, state, close and prompt-text
files are written under a temporary name and renamed into place, so a killed
hook leaves none of them partial; the receipt log is appended in place, under
the session lock, with a newline written first when the file is non-empty
and does not end with one. A new key pair publishes
`recorder.pub` first and `recorder.key` last, so a private key on disk always
has its public key beside it.

## Install (manual, deliberately)

Add to `~/.claude/settings.json` hooks (adjust the repo path):

```json
"UserPromptSubmit": [{ "matcher": "", "hooks": [{ "type": "command",
  "command": "bun run /path/to/aar/emitter/l2-claude-code/prompt.ts" }] }],
"PostToolUse": [{ "matcher": "", "hooks": [{ "type": "command",
  "command": "bun run /path/to/aar/emitter/l2-claude-code/recorder.ts" }] }],
"PostToolUseFailure": [{ "matcher": "", "hooks": [{ "type": "command",
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

### Prompt entries, binding and prompt text

A prompt entry says the recorder saw this text arrive as a prompt event
before the entries that follow it in the chain. It does not say a person
typed it, and it does not say the calls stayed inside it.

- **Bound.** A tool receipt is `bound` when a prompt entry earlier in the
  chain walk carries the same `prompt_id`; otherwise it is `unbound`, which
  includes a receipt with no `prompt_id`, one naming an unknown `prompt_id`,
  and one that precedes its prompt entry in the walk. Binding is computed
  along the digest walk, never from line order, timestamps or `seq`. It
  repeats what the hook input said about which prompt was being processed;
  it is not a finding that the prompt asked for the call. A prompt entry
  whose `prompt_id` already appeared earlier in the walk is counted in
  `duplicate_prompt_ids`. Unbound receipts and duplicates are reported, not
  failed.
- **Prompt text.** `prompts.jsonl` holds each prompt's text and opening on
  local disk. It is not signed and not part of the chain. The verifier reads
  it when it is present in the session directory: a prompt entry's text is
  `available` only when a line reproduces that entry's commitment. A file
  that exists and cannot be read or is not valid UTF-8 (the verifier decodes
  the log, the close and this file strictly), a line that cannot be read (not a JSON
  object with a text `prompt_id`, a 64 lowercase hex `opening` and a text
  `prompt`, both texts well-formed Unicode), and a line that names an
  entry's `prompt_id` and reproduces no such entry's commitment, each fail
  with `session/prompt-text-mismatch` (a candidate code); a line failure
  names the physical line. A line naming no entry is counted in `orphan_lines` and is not a
  failure; the recorder writes none, so one comes from outside the recorder.
  A prompt entry with no reproducing line (its line was removed, or the hook
  was killed between the entry and the text write), or a session whose
  `prompts.jsonl` is withheld, has that text `unavailable`: reported, not a
  failure. So removing a line or the whole file is not detected as
  tampering; it only makes the text unavailable. When two prompt entries
  carry the same `prompt_id`, a receipt with that id is bound, and the
  record cannot say which of the two texts it ran under.
- **The opening.** The commitment hides the text only while the opening
  stays private. Anyone given an entry's opening can test guesses of its
  text against the chain; anyone given `prompts.jsonl` has the text itself.
- **`hook_source`** is the hook input's `source` string, a transport label
  (Code Mode script output arrives as a prompt event with `source:
  "poll_event"`). It is not a D-78 origin and no origin is declared.
- **`tool_use_id`** is recorded as the hook gave it. Claude Code 2.1.330
  passes the same id to MCP servers as `_meta["claudecode/toolUseId"]`, which
  makes it the key for matching a receipt to a server's own record of the
  call. The verifier does not perform that match.

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
cross-session close replay, close after state loss). `prompt.test.ts` covers
prompt entries, the join fields, binding and the prompt-text check.
`lifecycle.test.ts` covers the recorder lifecycle: lost and stale `state.json`, a lost log tail,
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
  is never extended); the same holds for its prompts. A torn last log line (a hook killed mid-append) still stops
  recording for that session: every later hook logs `recorder: …` or
  `prompt: …` in the base `errors.log` and appends nothing. A prompt hook
  killed between its chain entry and its text write leaves that prompt's
  text unavailable for good; the entry itself stays in the chain. A
  `prompts.jsonl` the recorder cannot read or replace (a directory in its
  place, no permission) has the same effect and logs `prompt: …` in the base
  `errors.log`. The no-`tool_name` drop in `recorder.ts` and the base
  `errors.log` lines are still written outside the lock. The lock has no wait cap: a hook waits on
  a live holder until Claude Code's hook timeout ends it. Renamed-into-place
  files survive a killed process, not a power loss (nothing is fsynced). A
  `recorder.pub` emptied or replaced by hand beside an existing key is not
  repaired; only a missing one is rewritten.
  `close_id` is written but not recomputed by the verifier. One recorder key
  signs both receipts and close, so D-63's `session/close-signer-mismatch`
  collapses to the single-spki check — a simplification, not the spec's
  close-authority rule.
- **verification_gap:** the automated tests drive synthetic hook-event JSON
  through the real entrypoints as subprocesses. Beyond that, the install
  snippet was run by hand on 2026-11-21 in live Claude Code 2.1.330 sessions
  on macOS, with the hooks pointed at a scratch `AAR_L2_DIR`: a headless
  `-p` session (one prompt, seven tool calls, `SessionEnd` wrote the close),
  and an interactive two-prompt session whose first turn made three tool
  calls at the same instant. Each verified intact with every tool receipt
  bound. Not exercised live: `PostToolUseFailure`, a hook input carrying
  `source`, a resumed session, a session ended by a kill, and the
  `"timeout": 60` setting under load. The lock has run only on macOS (APFS)
  with Bun 1.3.5; SQLite file locks on a network filesystem are untested.
