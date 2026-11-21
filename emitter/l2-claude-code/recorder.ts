// PostToolUse hook entrypoint: reads the hook event JSON on stdin, appends one
// hash-chained signed L2 receipt to the session's receipt log.
// A hook must never break the harness: on any internal error we exit 0 after
// writing a line to errors.log — a starved receipt is exactly the T-H1
// residual the threat model discloses, and the verifier surfaces it as a
// count/chain mismatch rather than this process masking it with a crash.
// Parallel tool calls run this hook concurrently: the close check, the chain
// head read and the append happen under the session lock (lib.ts withLock).
// The chain continues from the log; state.json records the last head, so
// losing the entry it recorded is reported once a later entry is appended.
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  loadOrCreateRecorderKey, sessionDir, sessionId16, signEnvelope, sha256, withLock, writeFileAtomic,
  toHex, fromHex, decodeCbor, RECEIPT_CONTENT_TYPE, TENANT_ID, SITE_ID, BASE_DIR, type CborValue,
} from "./lib";

function main(): void {
  const raw = readFileSync(0, "utf8");
  const event = JSON.parse(raw) as {
    session_id?: string;
    tool_name?: string;
    tool_input?: unknown;
    tool_response?: unknown;
  };
  if (!event.session_id) return;

  const key = loadOrCreateRecorderKey();
  const sid = sessionId16(event.session_id);
  const dir = sessionDir(sid);
  const toolName = event.tool_name;
  if (!toolName) {
    appendFileSync(join(dir, "errors.log"), "tool call without tool_name dropped\n");
    return;
  }
  const receiptsPath = join(dir, "receipts.hexl");
  const statePath = join(dir, "state.json");

  withLock(dir, () => {
    if (existsSync(join(dir, "close.hex"))) {
      // D-63: a closed session is never re-opened or re-closed. Receipts after
      // close would be unverifiable; record the starvation visibly instead.
      appendFileSync(join(dir, "errors.log"), `post-close tool call dropped: ${JSON.stringify(toolName)}\n`);
      return;
    }

    // Continue from the log: its head is the payload-bstr digest (the signed
    // bytes, per D-63) of its last line. A last line that is not an envelope
    // throws: nothing is appended after a torn line.
    const log = existsSync(receiptsPath) ? readFileSync(receiptsPath, "utf8") : "";
    const lines = log.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
    const lastPayload = lines.length > 0 ? payloadOf(lines.at(-1)!) : undefined;
    let prevDigest = lastPayload ? toHex(sha256(lastPayload)) : "";
    // seq is one more than the last line's own seq and never below the
    // recorded next seq, so losing lines or state.json does not make the
    // recorder sign a number again or count backwards.
    let seq = lines.length;
    try {
      const lastSeq = lastPayload && (decodeCbor(lastPayload) as Record<string, CborValue>).seq;
      if (typeof lastSeq === "number") seq = lastSeq + 1;
    } catch {}
    const state = existsSync(statePath)
      ? JSON.parse(readFileSync(statePath, "utf8")) as { seq: number; prevDigest: string; openedAt?: unknown }
      : undefined;
    if (state) {
      seq = Math.max(seq, state.seq);
      if (!logContainsHead(lines, state.prevDigest)) {
        // Entries were lost or the log is a different chain: chain from the
        // recorded head, so the verifier reports the break.
        prevDigest = state.prevDigest;
        appendFileSync(join(dir, "errors.log"), "receipt log does not contain the recorded chain head\n");
      }
    }
    // openedAt: the recorded value; now for the first entry of a new session;
    // left out after a lost state.json (the close then takes opened_at from
    // the earliest receipt).
    const openedAt = typeof state?.openedAt === "number" ? state.openedAt
      : !state && lines.length === 0 ? Math.floor(Date.now() / 1000) : undefined;

    const enc = new TextEncoder();
    const payload = new Map<string, CborValue>([
      ["v", 3],
      ["session_id", sid],
      ["tenant_id", TENANT_ID],
      ["site_id", SITE_ID],
      ["seq", seq],
      ["session_prev_digest", prevDigest === "" ? null : fromHex(prevDigest)],
      ["attestation", new Map<string, CborValue>([
        ["point", "harness_hook"],
        ["recorder_kid", key.kid],
        // No agent credential exists at the Claude Code hook boundary; per the
        // D-62 candidate this receipt ranks as undeclared for self-report purposes.
        ["agent_kid", null],
      ])],
      ["tool_name", toolName],
      ["input_digest", sha256(enc.encode(JSON.stringify(event.tool_input ?? null)))],
      ["response_digest", sha256(enc.encode(JSON.stringify(event.tool_response ?? null)))],
      ["committed_at", Math.floor(Date.now() / 1000)],
    ]);

    const line = toHex(signEnvelope(payload, RECEIPT_CONTENT_TYPE, key));
    // A final line left without its newline must not merge with this entry.
    appendFileSync(receiptsPath, (log.length > 0 && !log.endsWith("\n") ? "\n" : "") + line + "\n");
    // Always rewritten, so checkpointing resumes after a lost state.json.
    writeFileAtomic(statePath, JSON.stringify({ seq: seq + 1, prevDigest: toHex(sha256(payloadOf(line))), openedAt }));
  });
}

// The payload bstr of a receipt line; throws unless the line is an envelope
// (a two-element array, byte string first).
function payloadOf(line: string): Uint8Array {
  const envelope = decodeCbor(fromHex(line));
  if (!Array.isArray(envelope) || envelope.length !== 2 || !(envelope[0] instanceof Uint8Array)) {
    throw new Error("receipt line is not an envelope");
  }
  return envelope[0];
}

// The log contains the recorded head when some line's payload digest equals it
// and every later line links to the line before it. Searched backwards: the
// log may be any number of entries ahead of state.json. A line that cannot be
// decoded does not match.
function logContainsHead(lines: string[], head: string): boolean {
  try {
    for (let i = lines.length - 1; i >= 0; i--) {
      const payloadBytes = payloadOf(lines[i]!);
      if (toHex(sha256(payloadBytes)) === head) return true;
      const prev = (decodeCbor(payloadBytes) as Record<string, CborValue>).session_prev_digest;
      if (i === 0 || !(prev instanceof Uint8Array) || toHex(prev) !== toHex(sha256(payloadOf(lines[i - 1]!)))) return false;
    }
  } catch {}
  return false;
}

try {
  main();
} catch (err) {
  try {
    appendFileSync(join(BASE_DIR, "errors.log"), `recorder: ${String(err)}\n`);
  } catch {}
}
