# Exhibit — A Transcript Viewer Cannot Tell a Forged Log From a Real One

**Status:** 2026-08-22, empirical — both renders below were actually produced
and diffed, commands shown. Supports `attestation-threat-model.md` §2 L1
("a transcript viewer renders an edited transcript exactly as confidently as
a genuine one"). Viewer: zoetrope (`zoe 0.1.0`), a session-transcript
visualizer for Claude Code JSONL logs — used here as a stand-in for *any* L1
consumer; the point is about the format, not the tool.

## The experiment

1. Took a real Claude Code session transcript (34 tool calls, 5 file edits).
2. Made **one single-line edit** to the log file: the last shell command
   `git push origin main` was changed to `git push --force origin main` —
   a one-word forgery that changes what the operator appears to have done.
3. Rendered both files with `zoe inspect` and diffed the outputs.

## Result

```
$ diff <(zoe inspect real.jsonl) <(zoe inspect edited.jsonl)
1c1
< session real — Review Twitter prompt engineering thread
---
> session edited — Review Twitter prompt engineering thread
4c4
<   last prompt: "git ... push origin main"
---
>   last prompt: "git ... push --force origin main"
```

The only differences in the rendered output are the file's own name and **the
content of the lie itself**. Every count, every status glyph, every checkmark
is identical: `34 tool call(s)`, `34✓ 0✗`, same token totals. The forged
render:

```
session edited — Review Twitter prompt engineering thread
  mode: normal · permission: —
  1 agent(s), 34 tool call(s) · 5 queued · 5 file edit(s)
  last prompt: "git ... push --force origin main"

  ◌ [main] main  (idle) — id=main
      model: claude-opus-5
      tools: 34 (34✓ 0✗ 0⏳)   tokens: 28712
```

Nothing flags the edit, because nothing in the format *could*: the transcript
is an unsigned self-observation, authored by the harness and stored on a
machine its operator controls. The viewer is doing its job correctly — the
format has no integrity to check.

## What a receipt chain does differently

Under the D-63 session construction (`attestation-spec-deltas.md`,
candidate): every receipt carries the digest of its predecessor's signed
bytes (`session_prev_digest`), and a signed session-close asserts "N actions,
final chain digest H."

- Editing the command changes the receipt's payload bytes → its payload
  digest no longer matches its successor's `session_prev_digest` →
  `session/chain-broken`, in both independent verifier implementations.
- Re-signing the edited receipt requires the recorder key the agent doesn't
  hold; re-closing the session after the fact is defeated by anchoring the
  close externally.
- Deleting the receipt instead of editing it breaks the same linkage and the
  close's `item_count`.

Same one-line attack, opposite outcome: the transcript renders it; the
receipt chain rejects it.

Honesty bounds (per the threat model, restated so this exhibit can't
overclaim): this defeats post-emission tampering (A2's retroactive half) and
cherry-picking (A3). It does not defeat a compromised recorder that never
emits the receipt at all (T-H1-shaped residual), and a receipt proves
occurrence at a boundary, never intent.

## Reproduce

```
cp <any-session>.jsonl real.jsonl
sed 's/push origin main/push --force origin main/' real.jsonl > edited.jsonl
diff <(zoe inspect real.jsonl) <(zoe inspect edited.jsonl)
```
