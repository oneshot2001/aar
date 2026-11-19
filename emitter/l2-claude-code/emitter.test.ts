// End-to-end: recorder → close → verify, then tamper/omission cases.
// Runs the real entrypoints as subprocesses (the hook surface), isolated via AAR_L2_DIR.
import { describe, expect, test, beforeAll } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync, cpSync, unlinkSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CborValue } from "./lib";

const base = mkdtempSync(join(tmpdir(), "aar-l2-"));
const env = { ...process.env, AAR_L2_DIR: base };
const here = import.meta.dir;
const SESSION = "test-session-0001";

function run(script: string, stdin: string): void {
  const proc = Bun.spawnSync(["bun", "run", join(here, script)], { stdin: Buffer.from(stdin), env });
  expect(proc.exitCode).toBe(0);
}

function verify(dir: string, sidHex?: string, json = false): { code: number; out: string; stdout: string } {
  const sid = sidHex ?? require("node:path").basename(sessionPath());
  const proc = Bun.spawnSync(["bun", "run", join(here, "verify.ts"), dir, join(base, "recorder.pub"), sid, ...(json ? ["--json"] : [])], { env });
  return { code: proc.exitCode, out: proc.stdout.toString() + proc.stderr.toString(), stdout: proc.stdout.toString() };
}

function sessionPath(session = SESSION): string {
  // pinned to the given session's sid (default SESSION), never readdir order.
  const sidHex = (require("node:crypto") as typeof import("node:crypto"))
    .createHash("sha256").update(session).digest("hex").slice(0, 32);
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

  test("--json reports an intact chain and rejects a validly signed fork", async () => {
    const intact = verify(sessionPath(), undefined, true);
    expect(intact.code).toBe(0);
    expect(JSON.parse(intact.stdout)).toEqual({
      ok: true,
      receipts: 3,
      chain_checks: [
        { name: "genesis", pass: true },
        { name: "first_receipt_digest", pass: true },
        { name: "successor_uniqueness", pass: true },
        { name: "predecessor_resolution", pass: true },
        { name: "final_chain_digest", pass: true },
        { name: "walked_length", pass: true },
      ],
      close_present: true,
    });

    const dir = mkdtempSync(join(base, "aar-l2-fork-"));
    cpSync(sessionPath(), dir, { recursive: true });
    const lib = await import("./lib");
    const spki = lib.fromHex(readFileSync(join(base, "recorder.pub"), "utf8").trim());
    const key = {
      privateKey: lib.fromHex(readFileSync(join(base, "recorder.key"), "utf8").trim()),
      spki,
      kid: lib.sha256(spki),
    };
    const path = join(dir, "receipts.hexl");
    const receipts = lib.readHexLines(path);
    const genesis = lib.openEnvelope(receipts[0]!, spki);
    const last = lib.openEnvelope(receipts[2]!, spki).payload as Record<string, CborValue>;
    const fork = new Map(Object.entries(last));
    // Make the second and third receipts distinct, signed successors of genesis.
    fork.set("session_prev_digest", lib.sha256(genesis.payloadBytes));
    receipts[2] = lib.signEnvelope(fork, lib.RECEIPT_CONTENT_TYPE, key);
    writeFileSync(path, receipts.map(lib.toHex).join("\n") + "\n");

    const text = verify(dir);
    expect(text.code).toBe(1);
    expect(text.out).toContain("session/chain-broken");
    expect(text.out).toContain("fork at");
    const forked = verify(dir, undefined, true);
    expect(forked.code).toBe(text.code);
    expect(JSON.parse(forked.stdout)).toEqual({
      ok: false,
      receipts: 3,
      chain_checks: [
        { name: "genesis", pass: true },
        { name: "first_receipt_digest", pass: true },
        { name: "successor_uniqueness", pass: false },
      ],
      close_present: true,
    });
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
    const dir = mkdtempSync(join(base, "aar-l2-tamper-"));
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
    const dir = mkdtempSync(join(base, "aar-l2-omit-"));
    cpSync(sessionPath(), dir, { recursive: true });
    const path = join(dir, "receipts.hexl");
    const lines = readFileSync(path, "utf8").trim().split("\n");
    writeFileSync(path, [lines[0], lines[2]].join("\n") + "\n");
    const r = verify(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("session/chain-broken");
  });

  test("forged close: a validly-signed RECEIPT as close.hex + emptied log → reject (P1 repro)", () => {
    const dir = mkdtempSync(join(base, "aar-l2-forge-"));
    cpSync(sessionPath(), dir, { recursive: true });
    const receipts = readFileSync(join(dir, "receipts.hexl"), "utf8").trim().split("\n");
    writeFileSync(join(dir, "close.hex"), receipts[0]! + "\n");
    writeFileSync(join(dir, "receipts.hexl"), "");
    const r = verify(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("session/fields-inconsistent");
  });

  test("duplicate close lines → session/duplicate-close", () => {
    const dir = mkdtempSync(join(base, "aar-l2-dup-"));
    cpSync(sessionPath(), dir, { recursive: true });
    const close = readFileSync(join(dir, "close.hex"), "utf8").trim();
    writeFileSync(join(dir, "close.hex"), close + "\n" + close + "\n");
    const r = verify(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("session/duplicate-close");
  });

  test("re-signed close with wrong tenant → close-coordinate-mismatch", async () => {
    const dir = mkdtempSync(join(base, "aar-l2-coord-"));
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
    const victim = mkdtempSync(join(base, "aar-l2-replay-"));
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
    const dir = mkdtempSync(join(base, "aar-l2-noclose-"));
    cpSync(sessionPath(), dir, { recursive: true });
    writeFileSync(join(dir, "close.hex"), "");
    const r = verify(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("not_established");
    const json = verify(dir, undefined, true);
    expect(json.code).toBe(r.code);
    expect(JSON.parse(json.stdout)).toEqual({ ok: false, receipts: 3, chain_checks: [], close_present: false });
  });

  test("tool name with a newline is logged as one errors.log line", () => {
    const session = "test-session-newline";
    const dir = sessionPath(session);
    run("recorder.ts", JSON.stringify({ session_id: session, tool_name: "Bash" }));
    run("close.ts", JSON.stringify({ session_id: session }));
    const name = "Bash\npost-close tool call dropped: Forged";
    run("recorder.ts", JSON.stringify({ session_id: session, tool_name: name }));
    const log = readFileSync(join(dir, "errors.log"), "utf8");
    expect(log.endsWith("\n")).toBe(true);
    expect(log.slice(0, -1).split("\n")).toEqual([
      "post-close tool call dropped: " + JSON.stringify(name),
    ]);
  });

  test("tool call without tool_name is dropped and logged, not silently", () => {
    const session = "test-session-no-tool-name";
    const dir = sessionPath(session);
    run("recorder.ts", JSON.stringify({ session_id: session, tool_name: "Bash" }));
    const state = readFileSync(join(dir, "state.json"));
    run("recorder.ts", JSON.stringify({ session_id: session }));
    expect(readFileSync(join(dir, "receipts.hexl"), "utf8").trim().split("\n")).toHaveLength(1);
    expect(readFileSync(join(dir, "state.json"))).toEqual(state);
    expect(readFileSync(join(dir, "errors.log"), "utf8")).toBe("tool call without tool_name dropped\n");
  });

  test("close after state.json loss takes opened_at from the earliest logged receipt: one receipt", async () => {
    const session = "test-session-lost-state-one";
    const dir = sessionPath(session);
    run("recorder.ts", JSON.stringify({ session_id: session, tool_name: "Bash" }));
    const lib = await import("./lib");
    const spki = lib.fromHex(readFileSync(join(base, "recorder.pub"), "utf8").trim());
    const receipt = lib.openEnvelope(lib.readHexLines(join(dir, "receipts.hexl"))[0]!, spki).payload as Record<string, CborValue>;
    await Bun.sleep(1100);
    unlinkSync(join(dir, "state.json"));
    run("close.ts", JSON.stringify({ session_id: session }));
    const close = lib.openEnvelope(lib.readHexLines(join(dir, "close.hex"))[0]!, spki).payload as Record<string, CborValue>;
    expect(close.opened_at).toBe(receipt.committed_at);
    expect(verify(dir, lib.toHex(lib.sessionId16(session))).code).toBe(0);
  });

  test("close after state.json loss takes opened_at from the earliest logged receipt: decreasing timestamps", async () => {
    const session = "test-session-lost-state-decreasing";
    const dir = sessionPath(session);
    const earliest = Math.floor(Date.now() / 1000) - 60;
    const preload = join(base, "clock.ts");
    writeFileSync(preload, "Date.now = () => Number(process.env.AAR_TEST_NOW_MS);\n");
    for (const timestamp of [earliest + 10, earliest]) {
      const proc = Bun.spawnSync(["bun", "run", "--preload", preload, join(here, "recorder.ts")], {
        stdin: Buffer.from(JSON.stringify({ session_id: session, tool_name: "Bash" })),
        env: { ...env, AAR_TEST_NOW_MS: String(timestamp * 1000) },
      });
      expect(proc.exitCode).toBe(0);
    }
    const lib = await import("./lib");
    const spki = lib.fromHex(readFileSync(join(base, "recorder.pub"), "utf8").trim());
    const timestamps = lib.readHexLines(join(dir, "receipts.hexl")).map((receipt) =>
      (lib.openEnvelope(receipt, spki).payload as Record<string, CborValue>).committed_at);
    expect(timestamps).toEqual([earliest + 10, earliest]);
    unlinkSync(join(dir, "state.json"));
    run("close.ts", JSON.stringify({ session_id: session }));
    const close = lib.openEnvelope(lib.readHexLines(join(dir, "close.hex"))[0]!, spki).payload as Record<string, CborValue>;
    expect(close.opened_at).toBe(earliest);
    expect(verify(dir, lib.toHex(lib.sessionId16(session))).code).toBe(0);
  });
  test("close after state.json loss takes opened_at from the earliest logged receipt: non-monotonic timestamps", async () => {
    const session = "test-session-lost-state-non-monotonic";
    const dir = sessionPath(session);
    const earliest = Math.floor(Date.now() / 1000) - 60;
    const preload = join(base, "clock.ts");
    writeFileSync(preload, "Date.now = () => Number(process.env.AAR_TEST_NOW_MS);\n");
    for (const timestamp of [earliest + 10, earliest, earliest + 20]) {
      const proc = Bun.spawnSync(["bun", "run", "--preload", preload, join(here, "recorder.ts")], {
        stdin: Buffer.from(JSON.stringify({ session_id: session, tool_name: "Bash" })),
        env: { ...env, AAR_TEST_NOW_MS: String(timestamp * 1000) },
      });
      expect(proc.exitCode).toBe(0);
    }
    const lib = await import("./lib");
    const spki = lib.fromHex(readFileSync(join(base, "recorder.pub"), "utf8").trim());
    const timestamps = lib.readHexLines(join(dir, "receipts.hexl")).map((receipt) =>
      (lib.openEnvelope(receipt, spki).payload as Record<string, CborValue>).committed_at);
    expect(timestamps).toEqual([earliest + 10, earliest, earliest + 20]);
    unlinkSync(join(dir, "state.json"));
    run("close.ts", JSON.stringify({ session_id: session }));
    const close = lib.openEnvelope(lib.readHexLines(join(dir, "close.hex"))[0]!, spki).payload as Record<string, CborValue>;
    expect(close.opened_at).toBe(earliest);
    expect(verify(dir, lib.toHex(lib.sessionId16(session))).code).toBe(0);
  });

  test("close after state.json loss skips an undecodable receipt", async () => {
    const session = "test-session-lost-state-undecodable";
    const dir = sessionPath(session);
    const earliest = Math.floor(Date.now() / 1000) - 60;
    const preload = join(base, "clock.ts");
    writeFileSync(preload, "Date.now = () => Number(process.env.AAR_TEST_NOW_MS);\n");
    for (const timestamp of [earliest + 10, earliest]) {
      const proc = Bun.spawnSync(["bun", "run", "--preload", preload, join(here, "recorder.ts")], {
        stdin: Buffer.from(JSON.stringify({ session_id: session, tool_name: "Bash" })),
        env: { ...env, AAR_TEST_NOW_MS: String(timestamp * 1000) },
      });
      expect(proc.exitCode).toBe(0);
    }
    const lib = await import("./lib");
    const spki = lib.fromHex(readFileSync(join(base, "recorder.pub"), "utf8").trim());
    const path = join(dir, "receipts.hexl");
    const receipts = lib.readHexLines(path);
    expect(receipts.map((receipt) =>
      (lib.openEnvelope(receipt, spki).payload as Record<string, CborValue>).committed_at))
      .toEqual([earliest + 10, earliest]);
    const lines = receipts.map(lib.toHex);
    lines.splice(1, 0, "00");
    writeFileSync(path, lines.join("\n") + "\n");
    unlinkSync(join(dir, "state.json"));
    run("close.ts", JSON.stringify({ session_id: session }));
    expect(existsSync(join(dir, "close.hex"))).toBe(true);
    const close = lib.openEnvelope(lib.readHexLines(join(dir, "close.hex"))[0]!, spki).payload as Record<string, CborValue>;
    expect(close.opened_at).toBe(earliest);
  });

  test("close after state.json loss ignores unauthenticated receipts for opened_at", async () => {
    const session = "test-session-lost-state-unauthenticated";
    const dir = sessionPath(session);
    const earliest = Math.floor(Date.now() / 1000) - 60;
    const preload = join(base, "clock.ts");
    writeFileSync(preload, "Date.now = () => Number(process.env.AAR_TEST_NOW_MS);\n");
    for (const timestamp of [earliest + 10, earliest]) {
      const proc = Bun.spawnSync(["bun", "run", "--preload", preload, join(here, "recorder.ts")], {
        stdin: Buffer.from(JSON.stringify({ session_id: session, tool_name: "Bash" })),
        env: { ...env, AAR_TEST_NOW_MS: String(timestamp * 1000) },
      });
      expect(proc.exitCode).toBe(0);
    }
    const lib = await import("./lib");
    const spki = lib.fromHex(readFileSync(join(base, "recorder.pub"), "utf8").trim());
    const path = join(dir, "receipts.hexl");
    const receipts = lib.readHexLines(path);
    expect(receipts.map((receipt) =>
      (lib.openEnvelope(receipt, spki).payload as Record<string, CborValue>).committed_at))
      .toEqual([earliest + 10, earliest]);

    const foreignBase = mkdtempSync(join(base, "foreign-recorder-"));
    const proc = Bun.spawnSync(["bun", "run", "--preload", preload, join(here, "recorder.ts")], {
      stdin: Buffer.from(JSON.stringify({ session_id: session, tool_name: "Bash" })),
      env: { ...env, AAR_L2_DIR: foreignBase, AAR_TEST_NOW_MS: "1000000" },
    });
    expect(proc.exitCode).toBe(0);
    const foreignSpki = lib.fromHex(readFileSync(join(foreignBase, "recorder.pub"), "utf8").trim());
    const foreignReceipt = lib.readHexLines(join(foreignBase, "sessions", lib.toHex(lib.sessionId16(session)), "receipts.hexl"))[0]!;
    const foreign = lib.openEnvelope(foreignReceipt, foreignSpki);
    expect(foreign.signatureValid).toBe(true);
    expect((foreign.payload as Record<string, CborValue>).committed_at).toBe(1000);
    // Also claim the genuine kid while signing with the foreign key: the kid
    // check alone must not authenticate the timestamp.
    const claimedKidReceipt = lib.signEnvelope(foreign.payload, lib.RECEIPT_CONTENT_TYPE, {
      privateKey: lib.fromHex(readFileSync(join(foreignBase, "recorder.key"), "utf8").trim()),
      spki: foreignSpki,
      kid: lib.sha256(spki),
    });
    expect(lib.openEnvelope(claimedKidReceipt, spki).kidMatchesSpki).toBe(true);
    unlinkSync(join(dir, "state.json"));
    for (const injected of [foreignReceipt, claimedKidReceipt]) {
      expect(lib.openEnvelope(injected, spki).signatureValid).toBe(false);
      writeFileSync(path, [receipts[0]!, injected, receipts[1]!].map(lib.toHex).join("\n") + "\n");
      run("close.ts", JSON.stringify({ session_id: session }));
      const close = lib.openEnvelope(lib.readHexLines(join(dir, "close.hex"))[0]!, spki);
      expect(close.signatureValid).toBe(true);
      expect((close.payload as Record<string, CborValue>).opened_at).toBe(earliest);
      const result = verify(dir, lib.toHex(lib.sessionId16(session)));
      expect(result.code).toBe(1);
      expect(result.out).toContain("cose/receipt-signature");
      unlinkSync(join(dir, "close.hex"));
    }
  });
});
