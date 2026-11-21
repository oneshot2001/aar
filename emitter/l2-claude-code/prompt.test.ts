// Prompt entries and join fields: prompt.ts → recorder.ts → close.ts → verify.ts.
// Runs the real entrypoints as subprocesses on its own AAR_L2_DIR.
import { describe, expect, test, beforeAll } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmdirSync, statSync, unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  fromHex, openEnvelope, readHexLines, sessionId16, sha256, signEnvelope, toHex,
  CLOSE_CONTENT_TYPE, PROMPT_CONTENT_TYPE, RECEIPT_CONTENT_TYPE, type CborValue,
} from "./lib";

const base = mkdtempSync(join(tmpdir(), "aar-l2-prompt-"));
const here = import.meta.dir;
const MAIN = "prompt-session-main";

type Payload = Record<string, CborValue>;
type Entry = { contentType: string; payload: Payload | null };

// `event` as an object is sent as JSON; as a string it is sent as is.
function run(script: string, event: object | string, env: Record<string, string> = {}, preload: string[] = []): void {
  const proc = Bun.spawnSync(["bun", "run", ...preload, join(here, script)], {
    stdin: Buffer.from(typeof event === "string" ? event : JSON.stringify(event)),
    env: { ...process.env, AAR_L2_DIR: base, ...env },
  });
  expect(proc.exitCode).toBe(0);
}

const sessionPath = (session: string): string => join(base, "sessions", toHex(sessionId16(session)));

// Runs the verifier in text and --json mode. The two must agree on the exit
// code, neither may write to stderr (no stack trace), and --json must parse.
function verify(session: string, dir = sessionPath(session)): { code: number; text: string; report: Record<string, unknown> } {
  const args = [dir, join(base, "recorder.pub"), toHex(sessionId16(session))];
  const text = Bun.spawnSync(["bun", "run", join(here, "verify.ts"), ...args]);
  const json = Bun.spawnSync(["bun", "run", join(here, "verify.ts"), "--json", ...args]);
  expect(text.stderr.toString() + json.stderr.toString()).toBe("");
  expect(json.exitCode).toBe(text.exitCode);
  return { code: text.exitCode, text: text.stdout.toString(), report: JSON.parse(json.stdout.toString()) };
}

const spki = (): Uint8Array => fromHex(readFileSync(join(base, "recorder.pub"), "utf8").trim());
const key = () => ({
  privateKey: fromHex(readFileSync(join(base, "recorder.key"), "utf8").trim()), spki: spki(), kid: sha256(spki()),
});

function entries(dir: string): { contentType: string; payload: Payload }[] {
  return readHexLines(join(dir, "receipts.hexl")).map((envelope) => {
    const opened = openEnvelope(envelope, spki());
    return { contentType: opened.contentType as string, payload: opened.payload as Payload };
  });
}

const textLines = (dir: string): { prompt_id: string; opening: string; prompt: string }[] =>
  readFileSync(join(dir, "prompts.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));

const promptEvent = (session: string, promptId: string, prompt: string): object =>
  ({ session_id: session, hook_event_name: "UserPromptSubmit", prompt_id: promptId, prompt });

const toolEvent = (session: string, i: number, promptId?: string): object => ({
  session_id: session, hook_event_name: "PostToolUse", tool_name: `Tool${i}`, tool_input: { arg: i },
  tool_response: { ok: true }, tool_use_id: `toolu_${i}`, ...(promptId === undefined ? {} : { prompt_id: promptId }),
});

const close = (session: string): void => run("close.ts", { session_id: session });

const counts = (prompts: number, toolReceipts: number, bound: number, duplicates: number,
  available: number, unavailable: number, orphanLines: number): object => ({
  prompts, tool_receipts: toolReceipts, bound, unbound: toolReceipts - bound, duplicate_prompt_ids: duplicates,
  prompt_text: { available, unavailable, orphan_lines: orphanLines },
});

// A copy of the closed MAIN session (one prompt, two tool receipts under it) to tamper with.
function copyOfMain(): string {
  const dir = mkdtempSync(join(base, "copy-"));
  cpSync(sessionPath(MAIN), dir, { recursive: true });
  return dir;
}

// A copy of MAIN whose log is replaced by `list`, signed with the recorder key,
// each entry linked to the one before it, under a close re-signed over them.
// So a session built here fails only for what the test put in a payload.
function resigned(list: Entry[]): string {
  const dir = copyOfMain();
  let prev: Uint8Array | null = null;
  const digests: Uint8Array[] = [];
  const lines = list.map(({ contentType, payload }) => {
    const envelope = signEnvelope(payload && { ...payload, session_prev_digest: prev }, contentType, key());
    prev = sha256(openEnvelope(envelope, spki()).payloadBytes);
    digests.push(prev);
    return toHex(envelope);
  });
  writeFileSync(join(dir, "receipts.hexl"), lines.join("\n") + "\n");
  const closePayload = openEnvelope(readHexLines(join(dir, "close.hex"))[0]!, spki()).payload as Payload;
  writeFileSync(join(dir, "close.hex"), toHex(signEnvelope({
    ...closePayload, item_count: list.length, first_receipt_digest: digests[0]!, final_chain_digest: digests.at(-1)!,
  }, CLOSE_CONTENT_TYPE, key())) + "\n");
  return dir;
}

const without = (payload: Payload, ...fields: string[]): Payload =>
  Object.fromEntries(Object.entries(payload).filter(([field]) => !fields.includes(field)));

// The commitment, computed here from its definition without lib.ts or the
// CBOR encoder: SHA-256 over the deterministic CBOR of
// ["AAR-L2-PROMPT-COMMITMENT-v1", opening (bstr), prompt (tstr)].
function independentCommitment(openingHex: string, prompt: string): string {
  const head = (major: number, length: number): Buffer =>
    Buffer.from(length < 24 ? [major << 5 | length] : length < 256 ? [major << 5 | 24, length] : [major << 5 | 25, length >> 8, length & 255]);
  const tag = Buffer.from("AAR-L2-PROMPT-COMMITMENT-v1", "utf8");
  const opening = Buffer.from(openingHex, "hex");
  const text = Buffer.from(prompt, "utf8");
  return createHash("sha256").update(Buffer.concat([
    head(4, 3), head(3, tag.length), tag, head(2, opening.length), opening, head(3, text.length), text,
  ])).digest("hex");
}

beforeAll(() => {
  run("prompt.ts", promptEvent(MAIN, "p1", "list the cameras"));
  run("recorder.ts", toolEvent(MAIN, 0, "p1"));
  run("recorder.ts", toolEvent(MAIN, 1, "p1"));
  close(MAIN);
});

describe("l2 prompt entry", () => {
  test("a prompt entry and its tool receipts verify intact and are reported bound", () => {
    const result = verify(MAIN);
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, receipts: 3, ...counts(1, 2, 2, 0, 1, 0, 0) });
    expect(result.text).toContain("intact");
    expect(result.text).toContain("2 action(s)");
    expect(result.text).toContain("1 prompt(s), 0 with a repeated prompt_id; tool receipts: 2 bound, 0 unbound; "
      + "prompt text: 1 available, 0 unavailable, 0 orphan line(s)");
    expect(entries(sessionPath(MAIN)).map((entry) => entry.contentType))
      .toEqual([PROMPT_CONTENT_TYPE, RECEIPT_CONTENT_TYPE, RECEIPT_CONTENT_TYPE]);
  });

  test("tool receipts carry prompt_id, tool_use_id and hook_event_name from the hook input", () => {
    const [, first, second] = entries(sessionPath(MAIN));
    expect(first!.payload).toMatchObject({ prompt_id: "p1", tool_use_id: "toolu_0", hook_event_name: "PostToolUse" });
    expect(second!.payload).toMatchObject({ prompt_id: "p1", tool_use_id: "toolu_1", hook_event_name: "PostToolUse" });
  });

  test("the prompt commitment equals an independent recomputation and differs between identical prompts", () => {
    const session = "prompt-session-commitment";
    run("prompt.ts", promptEvent(session, "p1", "same text"));
    run("prompt.ts", promptEvent(session, "p2", "same text"));
    const dir = sessionPath(session);
    const lines = textLines(dir);
    const commitments = entries(dir).map((entry) => toHex(entry.payload.prompt_commitment as Uint8Array));
    expect(lines.map((line) => line.prompt)).toEqual(["same text", "same text"]);
    expect(commitments).toEqual(lines.map((line) => independentCommitment(line.opening, line.prompt)));
    expect(commitments[0]).not.toBe(commitments[1]);
    expect(lines[0]!.opening).not.toBe(lines[1]!.opening);
  });

  test("a tool receipt naming an unknown prompt_id is reported unbound, not failed", () => {
    const session = "prompt-session-unbound";
    run("recorder.ts", toolEvent(session, 0, "p1")); // before its prompt in the chain: unbound
    run("prompt.ts", promptEvent(session, "p1", "first"));
    run("recorder.ts", toolEvent(session, 1, "p1")); // bound
    run("recorder.ts", toolEvent(session, 2, "p-unknown"));
    run("recorder.ts", toolEvent(session, 3)); // no prompt_id
    close(session);
    const result = verify(session);
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, receipts: 5, ...counts(1, 4, 1, 0, 1, 0, 0) });
  });

  test("binding follows the chain walk when the file lines are reordered", () => {
    const dir = copyOfMain();
    const path = join(dir, "receipts.hexl");
    // The prompt entry moves to the last line; the digest links are untouched.
    writeFileSync(path, readFileSync(path, "utf8").trim().split("\n").reverse().join("\n") + "\n");
    const reordered = verify(MAIN, dir);
    expect(reordered.code).toBe(0);
    expect(reordered.report).toEqual(verify(MAIN).report);
    expect(reordered.report).toMatchObject(counts(1, 2, 2, 0, 1, 0, 0));
  });

  test("binding follows the chain walk when seq runs against it", () => {
    const [prompt, first, second] = entries(sessionPath(MAIN));
    // The walk is prompt, tool, tool; by seq the prompt entry would come last.
    const dir = resigned([
      { ...prompt!, payload: { ...prompt!.payload, seq: 2 } },
      { ...first!, payload: { ...first!.payload, seq: 1 } },
      { ...second!, payload: { ...second!.payload, seq: 0 } },
    ]);
    const result = verify(MAIN, dir);
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, receipts: 3, ...counts(1, 2, 2, 0, 1, 0, 0) });
  });

  test("a repeated prompt_id is reported as a duplicate", () => {
    const session = "prompt-session-duplicate";
    run("prompt.ts", promptEvent(session, "p1", "first"));
    run("prompt.ts", promptEvent(session, "p1", "second"));
    run("recorder.ts", toolEvent(session, 0, "p1"));
    close(session);
    const result = verify(session);
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, receipts: 3, ...counts(2, 1, 1, 1, 2, 0, 0) });
  });

  test("edited prompt text fails with session/prompt-text-mismatch", () => {
    const dir = copyOfMain();
    const [line] = textLines(dir);
    writeFileSync(join(dir, "prompts.jsonl"), JSON.stringify({ ...line, prompt: "list the doors" }) + "\n");
    const result = verify(MAIN, dir);
    expect(result.code).toBe(1);
    expect(result.text).toBe("nonconformant session/prompt-text-mismatch — prompts.jsonl line 1: does not reproduce the commitment\n");
    // A failed session reports no prompt, binding or prompt-text counts.
    expect(result.report).toMatchObject({ ok: false, receipts: 3 });
    for (const field of ["prompts", "tool_receipts", "bound", "unbound", "duplicate_prompt_ids", "prompt_text"]) {
      expect(result.report).not.toHaveProperty(field);
    }
  });

  test("an unreadable prompts.jsonl line fails with session/prompt-text-mismatch", () => {
    const genuine = readFileSync(join(sessionPath(MAIN), "prompts.jsonl"), "utf8");
    const [line] = textLines(sessionPath(MAIN));
    const unreadable = [
      "not json",
      "null",
      // Text that is not well-formed Unicode (a lone surrogate).
      JSON.stringify({ ...line, prompt: "list the cameras\ud800" }),
      JSON.stringify({ ...line, prompt_id: "p1\ud800" }),
    ];
    for (const bad of unreadable) {
      const dir = copyOfMain();
      // On physical line 3, after the genuine line and a blank one.
      writeFileSync(join(dir, "prompts.jsonl"), genuine + "\n" + bad + "\n");
      const result = verify(MAIN, dir);
      expect(result.code).toBe(1);
      expect(result.text).toBe("nonconformant session/prompt-text-mismatch — prompts.jsonl line 3: unreadable\n");
    }
  });

  test("a genuine prompts.jsonl line with its opening in upper case is unreadable", () => {
    const session = "prompt-session-uppercase-opening";
    const dir = sessionPath(session);
    // Record prompts until one's random opening has a hex letter, so its upper-case form differs.
    let lines: ReturnType<typeof textLines>;
    do {
      run("prompt.ts", promptEvent(session, "p1", "list the cameras"));
      lines = textLines(dir);
    } while (!/[a-f]/.test(lines.at(-1)!.opening));
    close(session);
    const count = lines.length;
    expect(verify(session).report).toMatchObject({ ok: true, ...counts(count, 0, 0, count - 1, count, 0, 0) });
    // The same bytes for the opening, so the commitment still reproduces: only the 64 lowercase hex form rejects it.
    const last = lines.at(-1)!;
    const upper = { ...last, opening: last.opening.toUpperCase() };
    expect(upper.opening).not.toBe(last.opening);
    writeFileSync(join(dir, "prompts.jsonl"), [...lines.slice(0, -1), upper].map((line) => JSON.stringify(line)).join("\n") + "\n");
    const result = verify(session);
    expect(result.code).toBe(1);
    expect(result.text).toBe(`nonconformant session/prompt-text-mismatch — prompts.jsonl line ${count}: unreadable\n`);
  });

  test("a prompts.jsonl with an invalid UTF-8 byte fails with session/prompt-text-mismatch", () => {
    const session = "prompt-session-invalid-utf8";
    const path = join(sessionPath(session), "prompts.jsonl");
    run("prompt.ts", promptEvent(session, "p1", "open \ufffd door"));
    close(session);
    expect(verify(session).report).toMatchObject({ ok: true, ...counts(1, 0, 0, 0, 1, 0, 0) });
    // U+FFFD (EF BF BD) replaced by the single invalid byte FF: a lenient
    // decoder would read the same text back.
    const bytes = readFileSync(path);
    const at = bytes.indexOf(Buffer.from([0xef, 0xbf, 0xbd]));
    expect(at).toBeGreaterThan(0);
    writeFileSync(path, Buffer.concat([bytes.subarray(0, at), Buffer.from([0xff]), bytes.subarray(at + 3)]));
    const result = verify(session);
    expect(result.code).toBe(1);
    expect(result.text).toBe("nonconformant session/prompt-text-mismatch — prompts.jsonl: unreadable file\n");
    expect(result.report).toMatchObject({ ok: false });
  });

  test("an earlier prompts.jsonl line is carried forward byte for byte by the next prompt", () => {
    const session = "prompt-session-bytes-kept";
    const path = join(sessionPath(session), "prompts.jsonl");
    run("prompt.ts", promptEvent(session, "p1", "first"));
    // An invalid byte in the first line, and no final newline.
    const first = readFileSync(path);
    const damaged = Buffer.concat([first.subarray(0, first.indexOf("first")), Buffer.from([0xff]), first.subarray(first.indexOf("first") + 1, -1)]);
    writeFileSync(path, damaged);
    run("prompt.ts", promptEvent(session, "p2", "second"));
    const after = readFileSync(path);
    expect(after.subarray(0, damaged.length).equals(damaged)).toBe(true);
    const rest = after.subarray(damaged.length).toString("utf8");
    expect(rest.startsWith("\n") && rest.endsWith("\n")).toBe(true);
    expect(JSON.parse(rest)).toMatchObject({ prompt_id: "p2", prompt: "second" });
  });

  test("a prompts.jsonl that cannot be read fails with session/prompt-text-mismatch", () => {
    const dir = copyOfMain();
    unlinkSync(join(dir, "prompts.jsonl"));
    mkdirSync(join(dir, "prompts.jsonl"));
    const result = verify(MAIN, dir);
    expect(result.code).toBe(1);
    expect(result.text).toBe("nonconformant session/prompt-text-mismatch — prompts.jsonl: unreadable file\n");
    expect(result.report).toMatchObject({ ok: false, receipts: 3 });
  });

  test("a withheld prompts.jsonl reports the text unavailable and still verifies", () => {
    const dir = copyOfMain();
    unlinkSync(join(dir, "prompts.jsonl"));
    const result = verify(MAIN, dir);
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, ...counts(1, 2, 2, 0, 0, 1, 0) });
  });

  test("a prompts.jsonl line with no entry is reported as an orphan", () => {
    const dir = copyOfMain();
    const path = join(dir, "prompts.jsonl");
    const orphan = JSON.stringify({ prompt_id: "p-none", opening: "00".repeat(32), prompt: "never chained" }) + "\n";
    writeFileSync(path, readFileSync(path, "utf8") + orphan);
    const result = verify(MAIN, dir);
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, ...counts(1, 2, 2, 0, 1, 0, 1) });
    // With the entry's own line removed, its text is unavailable, not a failure.
    writeFileSync(path, orphan);
    const removed = verify(MAIN, dir);
    expect(removed.code).toBe(0);
    expect(removed.report).toMatchObject({ ok: true, ...counts(1, 2, 2, 0, 0, 1, 1) });
  });

  test("a prompt whose text write did not happen is reported unavailable", () => {
    const session = "prompt-session-no-text";
    const dir = sessionPath(session);
    // A directory in the text file's place makes the write fail after the entry is appended.
    mkdirSync(join(dir, "prompts.jsonl"), { recursive: true });
    run("prompt.ts", promptEvent(session, "p1", "text never stored"));
    rmdirSync(join(dir, "prompts.jsonl"));
    run("recorder.ts", toolEvent(session, 0, "p1"));
    close(session);
    expect(readFileSync(join(base, "errors.log"), "utf8")).toContain("prompt: ");
    const result = verify(session);
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, receipts: 2, ...counts(1, 1, 1, 0, 0, 1, 0) });
  });

  test("a retried prompt id after an interrupted first attempt verifies", () => {
    const session = "prompt-session-retried";
    const dir = sessionPath(session);
    mkdirSync(join(dir, "prompts.jsonl"), { recursive: true });
    run("prompt.ts", promptEvent(session, "p1", "first attempt")); // entry appended, text not written
    rmdirSync(join(dir, "prompts.jsonl"));
    run("prompt.ts", promptEvent(session, "p1", "second attempt"));
    run("recorder.ts", toolEvent(session, 0, "p1"));
    close(session);
    expect(textLines(dir).map((line) => line.prompt)).toEqual(["second attempt"]);
    const result = verify(session);
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, receipts: 3, ...counts(2, 1, 1, 1, 1, 1, 0) });
  });

  test("a prompt after close is dropped and logged, not appended", () => {
    const dir = sessionPath(MAIN);
    const text = readFileSync(join(dir, "prompts.jsonl"), "utf8");
    run("prompt.ts", promptEvent(MAIN, "p2", "after the close"));
    expect(readHexLines(join(dir, "receipts.hexl"))).toHaveLength(3);
    expect(readFileSync(join(dir, "prompts.jsonl"), "utf8")).toBe(text);
    expect(readFileSync(join(dir, "errors.log"), "utf8")).toBe("post-close prompt dropped\n");
    expect(verify(MAIN).code).toBe(0);
  });

  test("a tool call after close is logged as dropped even when its input cannot be stringified", () => {
    const session = "prompt-session-closed-deep-input";
    run("recorder.ts", toolEvent(session, 0));
    close(session);
    const deep = "[".repeat(50_000) + "]".repeat(50_000);
    run("recorder.ts", `{"session_id":${JSON.stringify(session)},"tool_name":"Deep","tool_input":${deep}}`);
    expect(readFileSync(join(sessionPath(session), "errors.log"), "utf8")).toBe('post-close tool call dropped: "Deep"\n');
    expect(readHexLines(join(sessionPath(session), "receipts.hexl"))).toHaveLength(1);
  });

  test("a prompt event without prompt or prompt_id is dropped and logged", () => {
    const session = "prompt-session-malformed-event";
    const dir = sessionPath(session);
    const events = [
      { session_id: session, prompt_id: "p1" },
      { session_id: session, prompt: "no id" },
      { session_id: session, prompt: "empty id", prompt_id: "" },
      { session_id: session, prompt: 5, prompt_id: "p1" },
      { session_id: session, prompt: "id is not well-formed text", prompt_id: "p1\ud800" },
    ];
    for (const event of events) run("prompt.ts", event);
    expect(readFileSync(join(dir, "errors.log"), "utf8"))
      .toBe("prompt event without prompt or prompt_id dropped\n".repeat(events.length));
    expect(existsSync(join(dir, "receipts.hexl"))).toBe(false);
    expect(existsSync(join(dir, "prompts.jsonl"))).toBe(false);
  });

  test("a hook event whose session_id is not a non-empty string writes nothing", () => {
    const fresh = mkdtempSync(join(tmpdir(), "aar-l2-prompt-no-session-"));
    for (const sessionId of [7, ["s"], { a: 1 }, "", null, "s\ud800"]) {
      run("prompt.ts", { session_id: sessionId, prompt_id: "p1", prompt: "x" }, { AAR_L2_DIR: fresh });
      run("recorder.ts", { session_id: sessionId, tool_name: "Bash" }, { AAR_L2_DIR: fresh });
    }
    expect(readdirSync(fresh)).toEqual([]);
  });

  test("a hook event carrying another hook's event name is dropped and logged", () => {
    const fresh = mkdtempSync(join(tmpdir(), "aar-l2-prompt-wrong-event-"));
    const session = "prompt-session-wrong-event";
    run("prompt.ts", { ...promptEvent(session, "p1", "x"), hook_event_name: "PostToolUse" }, { AAR_L2_DIR: fresh });
    run("recorder.ts", { ...toolEvent(session, 0), hook_event_name: "UserPromptSubmit" }, { AAR_L2_DIR: fresh });
    run("recorder.ts", { ...toolEvent(session, 1), hook_event_name: 5 }, { AAR_L2_DIR: fresh });
    expect(readFileSync(join(fresh, "errors.log"), "utf8")).toBe(
      "prompt: Error: hook_event_name is not UserPromptSubmit: event dropped\n"
      + "recorder: Error: hook_event_name is not PostToolUse or PostToolUseFailure: event dropped\n".repeat(2));
    expect(existsSync(join(fresh, "sessions"))).toBe(false);
  });

  test("hook text that is not well-formed Unicode is not recorded as text", () => {
    const session = "prompt-session-not-well-formed";
    const dir = sessionPath(session);
    run("prompt.ts", { ...promptEvent(session, "p1", "typed"), source: "poll\ud800" });
    run("recorder.ts", { session_id: session, tool_name: "Bash", prompt_id: "p1\ud800", tool_use_id: "toolu\udfff" });
    run("recorder.ts", { session_id: session, tool_name: "Bash\ud800" });
    const [prompt, tool, ...rest] = entries(dir);
    expect(rest).toEqual([]);
    expect(prompt!.payload).not.toHaveProperty("hook_source");
    expect(tool!.payload).not.toHaveProperty("prompt_id");
    expect(tool!.payload).not.toHaveProperty("tool_use_id");
    expect(readFileSync(join(dir, "errors.log"), "utf8")).toBe("tool call without tool_name dropped\n");
  });

  test("a prompt with a lone surrogate is committed and stored in its well-formed form", () => {
    const session = "prompt-session-lone-surrogate";
    const dir = sessionPath(session);
    run("prompt.ts", promptEvent(session, "p1", "open \ud800 door"));
    close(session);
    const [line] = textLines(dir);
    expect(line!.prompt).toBe("open � door");
    expect(toHex(entries(dir)[0]!.payload.prompt_commitment as Uint8Array))
      .toBe(independentCommitment(line!.opening, "open � door"));
    expect(verify(session).report).toMatchObject({ ok: true, ...counts(1, 0, 0, 0, 1, 0, 0) });
    // The other string that encodes to the same bytes is not accepted in its place.
    writeFileSync(join(dir, "prompts.jsonl"), JSON.stringify({ ...line, prompt: "open \ud800 door" }) + "\n");
    const swapped = verify(session);
    expect(swapped.code).toBe(1);
    expect(swapped.text).toBe("nonconformant session/prompt-text-mismatch — prompts.jsonl line 1: unreadable\n");
  });

  test("a PostToolUseFailure event is recorded with error_digest and no response_digest", () => {
    const session = "prompt-session-failure";
    run("prompt.ts", promptEvent(session, "p1", "move the camera"));
    run("recorder.ts", {
      session_id: session, hook_event_name: "PostToolUseFailure", tool_name: "ptz_move", tool_input: { pan: 1 },
      error: "DENIED: out of bounds", tool_use_id: "toolu_failed", prompt_id: "p1",
    });
    run("recorder.ts", toolEvent(session, 1, "p1"));
    close(session);
    const [, failed, succeeded] = entries(sessionPath(session));
    expect(failed!.payload).toMatchObject({ hook_event_name: "PostToolUseFailure", tool_use_id: "toolu_failed", prompt_id: "p1" });
    expect(toHex(failed!.payload.error_digest as Uint8Array))
      .toBe(toHex(sha256(new TextEncoder().encode(JSON.stringify("DENIED: out of bounds")))));
    expect(failed!.payload).not.toHaveProperty("response_digest");
    expect(succeeded!.payload.response_digest).toBeInstanceOf(Uint8Array);
    expect(succeeded!.payload).not.toHaveProperty("error_digest");
    const result = verify(session);
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, ...counts(1, 2, 2, 0, 1, 0, 0) });
  });

  test("hook_source is recorded only when the hook input carries a source", () => {
    const session = "prompt-session-source";
    run("prompt.ts", promptEvent(session, "p1", "typed"));
    run("prompt.ts", { ...promptEvent(session, "p2", "script output"), source: "poll_event" });
    run("prompt.ts", { ...promptEvent(session, "p3", "odd source"), source: 5 });
    const [typed, polled, odd] = entries(sessionPath(session));
    expect(typed!.payload).not.toHaveProperty("hook_source");
    expect(polled!.payload.hook_source).toBe("poll_event");
    expect(odd!.payload).not.toHaveProperty("hook_source");
  });

  test("a session that starts with a prompt closes after state.json loss", () => {
    const session = "prompt-session-lost-state";
    const dir = sessionPath(session);
    const earliest = Math.floor(Date.now() / 1000) - 60;
    const preload = join(base, "clock.ts");
    writeFileSync(preload, "Date.now = () => Number(process.env.AAR_TEST_NOW_MS);\n");
    run("prompt.ts", promptEvent(session, "p1", "first"), { AAR_TEST_NOW_MS: String(earliest * 1000) }, ["--preload", preload]);
    run("recorder.ts", toolEvent(session, 0, "p1"), { AAR_TEST_NOW_MS: String((earliest + 10) * 1000) }, ["--preload", preload]);
    unlinkSync(join(dir, "state.json"));
    close(session);
    // opened_at falls back to the earliest entry, which is the prompt entry.
    const closePayload = openEnvelope(readHexLines(join(dir, "close.hex"))[0]!, spki()).payload as Payload;
    expect(closePayload.opened_at).toBe(earliest);
    const result = verify(session);
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, receipts: 2, ...counts(1, 1, 1, 0, 1, 0, 0) });
  });

  test("prompts.jsonl is created with mode 0600", () => {
    expect(statSync(join(sessionPath(MAIN), "prompts.jsonl")).mode & 0o777).toBe(0o600);
  });

  test("a prompts.jsonl left at 0644 is 0600 after the next prompt", () => {
    const session = "prompt-session-mode";
    const path = join(sessionPath(session), "prompts.jsonl");
    run("prompt.ts", promptEvent(session, "p1", "first"));
    chmodSync(path, 0o644);
    run("prompt.ts", promptEvent(session, "p2", "second"));
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(textLines(sessionPath(session)).map((line) => line.prompt)).toEqual(["first", "second"]);
  });

  test("a session of tool receipts without the new fields verifies with zero prompts", () => {
    const session = "prompt-session-legacy";
    for (const i of [0, 1]) {
      run("recorder.ts", { session_id: session, tool_name: `Tool${i}`, tool_input: { arg: i }, tool_response: { ok: true } });
    }
    close(session);
    for (const { payload } of entries(sessionPath(session))) {
      expect(Object.keys(payload).sort()).toEqual([
        "attestation", "committed_at", "input_digest", "response_digest", "seq", "session_id", "session_prev_digest",
        "site_id", "tenant_id", "tool_name", "v",
      ]);
    }
    const result = verify(session);
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, receipts: 2, ...counts(0, 2, 0, 0, 0, 0, 0) });
  });

  test("a prompt entry with a malformed commitment fails with session/fields-inconsistent", () => {
    const [prompt, first, second] = entries(sessionPath(MAIN));
    const malformed: [string, CborValue][] = [
      ["prompt_commitment", new Uint8Array(31)],
      ["prompt_commitment", "00".repeat(32)],
      ["prompt_id", ""],
      ["hook_source", 5],
    ];
    for (const [field, value] of malformed) {
      const dir = resigned([{ ...prompt!, payload: { ...prompt!.payload, [field]: value } }, first!, second!]);
      const result = verify(MAIN, dir);
      expect(result.code).toBe(1);
      expect(result.text).toBe(`nonconformant session/fields-inconsistent — prompt entry index 0: field ${field} missing or malformed\n`);
    }
  });

  // Each session below is a correctly chained, signed and closed session with
  // one payload that breaks its kind's field list. The verifier must name the
  // entry and the field under session/fields-inconsistent; verify() also
  // checks that nothing reaches stderr.
  const failure = (payload: Payload): Payload =>
    ({ ...without(payload, "response_digest"), error_digest: new Uint8Array(32), hook_event_name: "PostToolUseFailure" });
  const shapes: [string, (prompt: Entry, tool: Entry) => Entry[], string][] = [
    ["a prompt-shaped payload under the receipt content type",
      (prompt) => [prompt, { contentType: RECEIPT_CONTENT_TYPE, payload: prompt.payload }],
      "receipt index 1: unknown field \"prompt_commitment\""],
    ["a payload with both kinds of fields under the prompt content type",
      (prompt, tool) => [{ contentType: PROMPT_CONTENT_TYPE, payload: { ...tool.payload!, ...prompt.payload! } }],
      "prompt entry index 0: unknown field \"tool_name\""],
    ["a prompt entry without v",
      (prompt) => [{ ...prompt, payload: without(prompt.payload!, "v") }], "prompt entry index 0: field v missing or malformed"],
    ["a prompt entry without seq",
      (prompt) => [{ ...prompt, payload: without(prompt.payload!, "seq") }], "prompt entry index 0: field seq missing or malformed"],
    ["a prompt entry without committed_at",
      (prompt) => [{ ...prompt, payload: without(prompt.payload!, "committed_at") }],
      "prompt entry index 0: field committed_at missing or malformed"],
    ["a prompt entry whose committed_at is text",
      (prompt) => [{ ...prompt, payload: { ...prompt.payload!, committed_at: "yesterday" } }],
      "prompt entry index 0: field committed_at missing or malformed"],
    ["a null payload",
      (prompt) => [prompt, { contentType: RECEIPT_CONTENT_TYPE, payload: null }], "receipt index 1: not a map"],
    ["a receipt without attestation",
      (prompt, tool) => [prompt, { ...tool, payload: without(tool.payload!, "attestation") }],
      "receipt index 1: field attestation missing or malformed"],
    ["a receipt whose attestation has an extra key",
      (prompt, tool) => [prompt, { ...tool, payload: { ...tool.payload!, attestation: { ...tool.payload!.attestation as Payload, extra: 1 } } }],
      "receipt index 1: field attestation missing or malformed"],
    ["a receipt without session_id",
      (prompt, tool) => [prompt, { ...tool, payload: without(tool.payload!, "session_id") }],
      "receipt index 1: field session_id missing or malformed"],
    ["a receipt with an unknown key",
      (prompt, tool) => [prompt, { ...tool, payload: { ...tool.payload!, extra: 1 } }], "receipt index 1: unknown field \"extra\""],
    ["a receipt with an empty tool_use_id",
      (prompt, tool) => [prompt, { ...tool, payload: { ...tool.payload!, tool_use_id: "" } }],
      "receipt index 1: field tool_use_id missing or malformed"],
    ["a receipt with error_digest but not the failure event name",
      (prompt, tool) => [prompt, { ...tool, payload: { ...failure(tool.payload!), hook_event_name: "PostToolUse" } }],
      "receipt index 1: response_digest and error_digest do not fit hook_event_name"],
    ["a failure receipt that also carries response_digest",
      (prompt, tool) => [prompt, { ...tool, payload: { ...failure(tool.payload!), response_digest: new Uint8Array(32) } }],
      "receipt index 1: response_digest and error_digest do not fit hook_event_name"],
    ["a receipt with neither result digest",
      (prompt, tool) => [prompt, { ...tool, payload: without(tool.payload!, "response_digest") }],
      "receipt index 1: response_digest and error_digest do not fit hook_event_name"],
  ];
  test.each(shapes)("%s fails with session/fields-inconsistent", (_name, build, detail) => {
    const [prompt, tool] = entries(sessionPath(MAIN));
    const result = verify(MAIN, resigned(build(prompt!, tool!)));
    expect(result.code).toBe(1);
    expect(result.text).toBe(`nonconformant session/fields-inconsistent — ${detail}\n`);
    expect(result.report).toMatchObject({ ok: false });
  });

  test("evidence that cannot be read or decoded is a reason code, not a thrown error", () => {
    const closePayload = openEnvelope(readHexLines(join(sessionPath(MAIN), "close.hex"))[0]!, spki()).payload as Payload;
    const signedClose = (payload: Payload | null): string => toHex(signEnvelope(payload, CLOSE_CONTENT_TYPE, key())) + "\n";
    const asDirectory = (path: string): void => {
      unlinkSync(path);
      mkdirSync(path);
    };
    const cases: [(dir: string) => void, string][] = [
      [(dir) => writeFileSync(join(dir, "receipts.hexl"), readFileSync(join(dir, "receipts.hexl"), "utf8") + "zz\n"),
        "cose/receipt-signature — receipt index 3: undecodable"],
      [(dir) => asDirectory(join(dir, "receipts.hexl")), "cose/receipt-signature — receipts.hexl: unreadable"],
      [(dir) => asDirectory(join(dir, "close.hex")), "cose/close-signature — close.hex: unreadable"],
      // Not valid UTF-8: the file is unreadable, not repaired.
      [(dir) => writeFileSync(join(dir, "receipts.hexl"), Buffer.concat([readFileSync(join(dir, "receipts.hexl")), Buffer.from([0xff, 0x0a])])),
        "cose/receipt-signature — receipts.hexl: unreadable"],
      [(dir) => writeFileSync(join(dir, "close.hex"), Buffer.concat([readFileSync(join(dir, "close.hex")), Buffer.from([0xff, 0x0a])])),
        "cose/close-signature — close.hex: unreadable"],
      [(dir) => writeFileSync(join(dir, "close.hex"), "zz\n"), "cose/close-signature — session-close: undecodable"],
      [(dir) => writeFileSync(join(dir, "close.hex"), "00\n"), "cose/close-signature — session-close: undecodable"],
      [(dir) => writeFileSync(join(dir, "close.hex"), signedClose(null)), "session/fields-inconsistent — close: not a map"],
      [(dir) => writeFileSync(join(dir, "close.hex"), signedClose(without(closePayload, "tenant_id"))),
        "session/fields-inconsistent — close: field tenant_id missing or malformed"],
      [(dir) => writeFileSync(join(dir, "close.hex"), signedClose({ ...closePayload, recorder_kid: "kid" })),
        "session/fields-inconsistent — close: field recorder_kid missing or malformed"],
    ];
    for (const [damage, expected] of cases) {
      const dir = copyOfMain();
      damage(dir);
      const result = verify(MAIN, dir);
      expect(result.code).toBe(1);
      expect(result.text).toBe(`nonconformant ${expected}\n`);
      expect(result.report).toMatchObject({ ok: false });
    }
  });

  test("a close whose item_count is not a number is named by type, not coerced", () => {
    const closePayload = openEnvelope(readHexLines(join(sessionPath(MAIN), "close.hex"))[0]!, spki()).payload as Payload;
    const cases: [CborValue, string][] = [
      [{ toString: 0 }, "map"],
      [[{ toString: 0 }], "array"],
      ["3", "string"],
      [new Uint8Array(1), "bytes"],
      [null, "null"],
      [-1, "-1"],
    ];
    for (const [itemCount, shown] of cases) {
      const dir = copyOfMain();
      writeFileSync(join(dir, "close.hex"), toHex(signEnvelope({ ...closePayload, item_count: itemCount }, CLOSE_CONTENT_TYPE, key())) + "\n");
      const result = verify(MAIN, dir);
      expect(result.code).toBe(1);
      expect(result.text).toBe(`nonconformant session/fields-inconsistent — item_count not an integer in [0,10000]: ${shown}\n`);
      expect(result.report).toMatchObject({ ok: false });
    }
  });

  test("a re-signed failure receipt of the right shape verifies", () => {
    const [prompt, tool] = entries(sessionPath(MAIN));
    const result = verify(MAIN, resigned([prompt!, { ...tool!, payload: failure(tool!.payload) }]));
    expect(result.code).toBe(0);
    expect(result.report).toMatchObject({ ok: true, receipts: 2, ...counts(1, 1, 1, 0, 1, 0, 0) });
  });
});
