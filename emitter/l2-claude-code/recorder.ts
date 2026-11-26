// PostToolUse / PostToolUseFailure hook entrypoint: reads the hook event JSON
// on stdin, appends one hash-chained signed L2 receipt to the session's
// receipt log.
// A hook must never break the harness: on any internal error we exit 0 after
// writing a line to errors.log — a starved receipt is exactly the T-H1
// residual the threat model discloses, and the verifier surfaces it as a
// count/chain mismatch rather than this process masking it with a crash.
// Parallel tool calls run this hook concurrently: the close check, the chain
// head read and the append happen under the session lock (lib.ts appendEntry).
// The chain continues from the log; state.json records the last head, so
// losing the entry it recorded is reported once a later entry is appended.
import { appendFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  loadOrCreateRecorderKey, sessionDir, sessionId16, appendEntry, isText, sha256,
  RECEIPT_CONTENT_TYPE, BASE_DIR, type CborValue,
} from "./lib";

function main(): void {
  const raw = readFileSync(0, "utf8");
  const event = JSON.parse(raw) as {
    session_id?: unknown;
    tool_name?: unknown;
    tool_input?: unknown;
    tool_response?: unknown;
    error?: unknown;
    prompt_id?: unknown;
    tool_use_id?: unknown;
    hook_event_name?: unknown;
  };
  const { session_id: sessionId, tool_name: toolName, hook_event_name: hookEvent } = event;
  if (!isText(sessionId)) return;

  const key = loadOrCreateRecorderKey();
  if (hookEvent !== undefined && hookEvent !== "PostToolUse" && hookEvent !== "PostToolUseFailure") {
    throw new Error("hook_event_name is not PostToolUse or PostToolUseFailure: event dropped");
  }
  const sid = sessionId16(sessionId);
  if (!isText(toolName)) {
    appendFileSync(join(sessionDir(sid), "errors.log"), "tool call without tool_name dropped\n", { mode: 0o600 });
    return;
  }

  const digest = (value: unknown): Uint8Array => sha256(new TextEncoder().encode(JSON.stringify(value ?? null)));
  appendEntry(key, sid, RECEIPT_CONTENT_TYPE, `post-close tool call dropped: ${JSON.stringify(toolName)}`, () => {
    const fields: [string, CborValue][] = [
      ["tool_name", toolName],
      ["input_digest", digest(event.tool_input)],
      // A failed call carries the digest of its error and no response digest.
      hookEvent === "PostToolUseFailure"
        ? ["error_digest", digest(event.error)]
        : ["response_digest", digest(event.tool_response)],
    ];
    // The join fields, as the hook gave them: prompt_id is the prompt the
    // harness said it was processing, tool_use_id is the id an MCP server
    // sees for the same call.
    if (isText(event.prompt_id)) fields.push(["prompt_id", event.prompt_id]);
    if (isText(event.tool_use_id)) fields.push(["tool_use_id", event.tool_use_id]);
    if (hookEvent !== undefined) fields.push(["hook_event_name", hookEvent]);
    return fields;
  });
}

try {
  main();
} catch (err) {
  try {
    appendFileSync(join(BASE_DIR, "errors.log"), `recorder: ${String(err)}\n`, { mode: 0o600 });
  } catch {}
}
