// PostToolUse hook entrypoint: reads the hook event JSON on stdin, appends one
// hash-chained signed L2 receipt to the session's receipt log.
// A hook must never break the harness: on any internal error we exit 0 after
// writing a line to errors.log — a starved receipt is exactly the T-H1
// residual the threat model discloses, and the verifier surfaces it as a
// count/chain mismatch rather than this process masking it with a crash.
// KNOWN LIMIT (disclosed): the state.json read-modify-write is not atomic.
// Two concurrent PostToolUse hooks (parallel tool calls) can race, producing
// a lost receipt or a fork — verify.ts rejects the fork rather than masking
// it. Serializing via a lock file is deliberate future work, not claimed.
import { appendFileSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  loadOrCreateRecorderKey, sessionDir, sessionId16, signEnvelope, sha256,
  toHex, decodeCbor, RECEIPT_CONTENT_TYPE, TENANT_ID, SITE_ID, BASE_DIR, type CborValue,
} from "./lib";

function main(): void {
  const raw = readFileSync(0, "utf8");
  const event = JSON.parse(raw) as {
    session_id?: string;
    tool_name?: string;
    tool_input?: unknown;
    tool_response?: unknown;
  };
  if (!event.session_id || !event.tool_name) return;

  const key = loadOrCreateRecorderKey();
  const sid = sessionId16(event.session_id);
  const dir = sessionDir(sid);
  const receiptsPath = join(dir, "receipts.hexl");
  const statePath = join(dir, "state.json");

  if (existsSync(join(dir, "close.hex"))) {
    // D-63: a closed session is never re-opened or re-closed. Receipts after
    // close would be unverifiable; record the starvation visibly instead.
    appendFileSync(join(dir, "errors.log"), `post-close tool call dropped: ${event.tool_name}\n`);
    return;
  }

  const state = existsSync(statePath)
    ? (JSON.parse(readFileSync(statePath, "utf8")) as { seq: number; prevDigest: string; openedAt: number })
    : { seq: 0, prevDigest: "", openedAt: Math.floor(Date.now() / 1000) };

  const enc = new TextEncoder();
  const payload = new Map<string, CborValue>([
    ["v", 3],
    ["session_id", sid],
    ["tenant_id", TENANT_ID],
    ["site_id", SITE_ID],
    ["seq", state.seq],
    ["session_prev_digest", state.prevDigest === "" ? null : Uint8Array.from(Buffer.from(state.prevDigest, "hex"))],
    ["attestation", new Map<string, CborValue>([
      ["point", "harness_hook"],
      ["recorder_kid", key.kid],
      // No agent credential exists at the Claude Code hook boundary; per the
      // D-62 candidate this receipt ranks as undeclared for self-report purposes.
      ["agent_kid", null],
    ])],
    ["tool_name", event.tool_name],
    ["input_digest", sha256(enc.encode(JSON.stringify(event.tool_input ?? null)))],
    ["response_digest", sha256(enc.encode(JSON.stringify(event.tool_response ?? null)))],
    ["committed_at", Math.floor(Date.now() / 1000)],
  ]);

  const envelopeBytes = signEnvelope(payload, RECEIPT_CONTENT_TYPE, key);
  // The chain links payload-bstr digests (the signed bytes), per D-63.
  const payloadBytes = (decodeCbor(envelopeBytes) as CborValue[])[0] as Uint8Array;
  appendFileSync(receiptsPath, toHex(envelopeBytes) + "\n");
  writeFileSync(statePath, JSON.stringify({ seq: state.seq + 1, prevDigest: toHex(sha256(payloadBytes)), openedAt: state.openedAt }));
}

try {
  main();
} catch (err) {
  try {
    appendFileSync(join(BASE_DIR, "errors.log"), `recorder: ${String(err)}\n`);
  } catch {}
}
