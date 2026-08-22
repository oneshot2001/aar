// End-to-end: recorder → close → verify, then tamper/omission cases.
// Runs the real entrypoints as subprocesses (the hook surface), isolated via AAR_L2_DIR.
import { describe, expect, test, beforeAll } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const base = mkdtempSync(join(tmpdir(), "aar-l2-"));
const env = { ...process.env, AAR_L2_DIR: base };
const here = import.meta.dir;
const SESSION = "test-session-0001";

function run(script: string, stdin: string): void {
  const proc = Bun.spawnSync(["bun", "run", join(here, script)], { stdin: Buffer.from(stdin), env });
  expect(proc.exitCode).toBe(0);
}

function verify(dir: string, sidHex?: string): { code: number; out: string } {
  const sid = sidHex ?? require("node:path").basename(sessionPath());
  const proc = Bun.spawnSync(["bun", "run", join(here, "verify.ts"), dir, join(base, "recorder.pub"), sid], { env });
  return { code: proc.exitCode, out: proc.stdout.toString() + proc.stderr.toString() };
}

function sessionPath(): string {
  // Pinned to SESSION's sid — never readdir order (a second session exists
  // after the replay test).
  const sidHex = (require("node:crypto") as typeof import("node:crypto"))
    .createHash("sha256").update(SESSION).digest("hex").slice(0, 32);
  return join(base, "sessions", sidHex);
}

beforeAll(() => {
  for (let i = 0; i < 3; i++) {
    run("recorder.ts", JSON.stringify({
      session_id: SESSION, tool_name: `Tool${i}`, tool_input: { arg: i }, tool_response: { ok: true },
    }));
  }
  run("close.ts", JSON.stringify({ session_id: SESSION }));
});

describe("l2 emitter", () => {
  test("intact session verifies", () => {
    const r = verify(sessionPath());
    expect(r.out).toContain("intact");
    expect(r.out).toContain("3 action(s)");
    expect(r.code).toBe(0);
  });

  test("second close is refused (single close on disk)", () => {
    run("close.ts", JSON.stringify({ session_id: SESSION }));
    const lines = readFileSync(join(sessionPath(), "close.hex"), "utf8").trim().split("\n");
    expect(lines.length).toBe(1);
  });

  test("post-close tool call is dropped and logged, not appended", () => {
    run("recorder.ts", JSON.stringify({ session_id: SESSION, tool_name: "LateTool", tool_input: {}, tool_response: {} }));
    const receipts = readFileSync(join(sessionPath(), "receipts.hexl"), "utf8").trim().split("\n");
    expect(receipts.length).toBe(3);
    expect(readFileSync(join(sessionPath(), "errors.log"), "utf8")).toContain("post-close");
  });

  test("one flipped byte in a receipt → signature reject", () => {
    const dir = mkdtempSync(join(tmpdir(), "aar-l2-tamper-"));
    cpSync(sessionPath(), dir, { recursive: true });
    const path = join(dir, "receipts.hexl");
    const lines = readFileSync(path, "utf8").trim().split("\n");
    const mid = lines[1]!;
    const pos = Math.floor(mid.length / 2);
    lines[1] = mid.slice(0, pos) + (mid[pos] === "0" ? "1" : "0") + mid.slice(pos + 1);
    writeFileSync(path, lines.join("\n") + "\n");
    const r = verify(dir);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/cose\/receipt-signature|session\/chain-broken/);
  });

  test("deleted interior receipt → chain-broken", () => {
    const dir = mkdtempSync(join(tmpdir(), "aar-l2-omit-"));
    cpSync(sessionPath(), dir, { recursive: true });
    const path = join(dir, "receipts.hexl");
    const lines = readFileSync(path, "utf8").trim().split("\n");
    writeFileSync(path, [lines[0], lines[2]].join("\n") + "\n");
    const r = verify(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("session/chain-broken");
  });

  test("forged close: a validly-signed RECEIPT as close.hex + emptied log → reject (P1 repro)", () => {
    const dir = mkdtempSync(join(tmpdir(), "aar-l2-forge-"));
    cpSync(sessionPath(), dir, { recursive: true });
    const receipts = readFileSync(join(dir, "receipts.hexl"), "utf8").trim().split("\n");
    writeFileSync(join(dir, "close.hex"), receipts[0]! + "\n");
    writeFileSync(join(dir, "receipts.hexl"), "");
    const r = verify(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("session/fields-inconsistent");
  });

  test("duplicate close lines → session/duplicate-close", () => {
    const dir = mkdtempSync(join(tmpdir(), "aar-l2-dup-"));
    cpSync(sessionPath(), dir, { recursive: true });
    const close = readFileSync(join(dir, "close.hex"), "utf8").trim();
    writeFileSync(join(dir, "close.hex"), close + "\n" + close + "\n");
    const r = verify(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("session/duplicate-close");
  });

  test("re-signed close with wrong tenant → close-coordinate-mismatch", async () => {
    const dir = mkdtempSync(join(tmpdir(), "aar-l2-coord-"));
    cpSync(sessionPath(), dir, { recursive: true });
    const lib = await import("./lib");
    // Build the recorder key from the isolated base dir directly — never via
    // loadOrCreateRecorderKey(), which reads BASE_DIR (frozen at module load).
    const spki = lib.fromHex(readFileSync(join(base, "recorder.pub"), "utf8").trim());
    const key = {
      privateKey: lib.fromHex(readFileSync(join(base, "recorder.key"), "utf8").trim()),
      spki,
      kid: lib.sha256(spki),
    };
    const closeEnv = lib.readHexLines(join(dir, "close.hex"))[0]!;
    const payload = lib.openEnvelope(closeEnv, spki).payload as Record<string, unknown>;
    const forged = new Map(Object.entries(payload));
    forged.set("tenant_id", lib.sha256(new TextEncoder().encode("OTHER-TENANT")).slice(0, 16));
    writeFileSync(join(dir, "close.hex"), Buffer.from(lib.signEnvelope(forged as never, lib.CLOSE_CONTENT_TYPE, key)).toString("hex") + "\n");
    const r = verify(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("session/close-coordinate-mismatch");
  });

  test("cross-session close replay → close-coordinate-mismatch (round-2 P1 repro)", () => {
    const victim = mkdtempSync(join(tmpdir(), "aar-l2-replay-"));
    cpSync(sessionPath(), victim, { recursive: true });
    // Close an EMPTY second session with the same recorder key, then replay
    // its genuine close into the victim dir with the receipt log deleted.
    run("close.ts", JSON.stringify({ session_id: "other-session-9999" }));
    const sessions = require("node:fs").readdirSync(join(base, "sessions")) as string[];
    const otherDir = sessions.map((e) => join(base, "sessions", e)).find((d) => d !== sessionPath())!;
    cpSync(join(otherDir, "close.hex"), join(victim, "close.hex"));
    writeFileSync(join(victim, "receipts.hexl"), "");
    const r = verify(victim);
    expect(r.code).toBe(1);
    expect(r.out).toContain("session/close-coordinate-mismatch");
  });

  test("missing close → not_established, never intact", () => {
    const dir = mkdtempSync(join(tmpdir(), "aar-l2-noclose-"));
    cpSync(sessionPath(), dir, { recursive: true });
    writeFileSync(join(dir, "close.hex"), "");
    const r = verify(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("not_established");
  });
});
