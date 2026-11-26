// UserPromptSubmit hook entrypoint: reads the hook event JSON on stdin and
// appends one signed prompt entry to the session's receipt log, chained like a
// tool receipt. The entry carries a commitment to the prompt text; the text
// and the commitment's opening go to prompts.jsonl beside the log, never into
// the chain. The entry says the recorder saw this text arrive as a prompt
// event before the entries that follow it in the chain. It does not say a
// person typed it, and it does not say the calls that follow stayed inside it.
// Like the other hooks it always exits 0; errors go to errors.log.
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  loadOrCreateRecorderKey, sessionDir, sessionId16, appendEntry, promptCommitment, withLock,
  writeFileAtomic, isText, isWellFormed, toWellFormed, toHex, PROMPT_CONTENT_TYPE, BASE_DIR, type CborValue,
} from "./lib";

function main(): void {
  const event = JSON.parse(readFileSync(0, "utf8")) as {
    session_id?: unknown;
    hook_event_name?: unknown;
    prompt?: unknown;
    prompt_id?: unknown;
    source?: unknown;
  };
  const { session_id: sessionId, prompt_id: promptId, source } = event;
  if (!isText(sessionId)) return;

  const key = loadOrCreateRecorderKey();
  if (event.hook_event_name !== undefined && event.hook_event_name !== "UserPromptSubmit") {
    throw new Error("hook_event_name is not UserPromptSubmit: event dropped");
  }
  const sid = sessionId16(sessionId);
  const dir = sessionDir(sid);
  if (typeof event.prompt !== "string" || !isText(promptId)) {
    withLock(dir, () => appendFileSync(join(dir, "errors.log"), "prompt event without prompt or prompt_id dropped\n", { mode: 0o600 }));
    return;
  }
  // The committed text and the stored text are the same, well-formed string.
  const prompt = toWellFormed(event.prompt);
  const opening = crypto.getRandomValues(new Uint8Array(32));
  const textPath = join(dir, "prompts.jsonl");

  appendEntry(key, sid, PROMPT_CONTENT_TYPE, "post-close prompt dropped", () => {
    const fields: [string, CborValue][] = [
      ["prompt_id", promptId],
      ["prompt_commitment", promptCommitment(opening, prompt)],
    ];
    // A transport label from the hook (Code Mode script output arrives with
    // source "poll_event"); not a D-78 origin.
    if (typeof source === "string" && isWellFormed(source)) fields.push(["hook_source", source]);
    return fields;
  }, () => {
    // After the entry: the text file is rewritten whole and renamed into
    // place at 0600, so the recorder leaves no torn or stray line. A kill
    // between the entry and this write leaves the entry's text unavailable.
    // The existing file is carried forward as bytes, never decoded: decoding
    // would repair invalid UTF-8 in an earlier line and save the repair.
    const existing = existsSync(textPath) ? readFileSync(textPath) : new Uint8Array();
    const line = new TextEncoder().encode(JSON.stringify({ prompt_id: promptId, opening: toHex(opening), prompt }) + "\n");
    const newline = Uint8Array.from(existing.length > 0 && existing.at(-1) !== 0x0a ? [0x0a] : []);
    writeFileAtomic(textPath, Buffer.concat([existing, newline, line]), 0o600);
  });
}

try {
  main();
} catch (err) {
  try {
    appendFileSync(join(BASE_DIR, "errors.log"), `prompt: ${String(err)}\n`, { mode: 0o600 });
  } catch {}
}
