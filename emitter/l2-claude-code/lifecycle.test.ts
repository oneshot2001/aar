// Recorder lifecycle: the lock, recovery from lost state and lost log lines,
// key files. Runs the real entrypoints as subprocesses on its own AAR_L2_DIR
// (emitter.test.ts picks a session by directory listing). The eight-at-once,
// close-race and first-use tests are stress tests; the marker test is the one
// that shows exclusion.
import { describe, expect, test, beforeAll } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fromHex, openEnvelope, readHexLines, sessionId16, sha256, toHex, type CborValue } from "./lib";

const base = mkdtempSync(join(tmpdir(), "aar-l2-lifecycle-"));
const here = import.meta.dir;
// Every test here waits on subprocesses. Measured 2026-11-21 (16 cores): the
// slowest test took 1.2 s idle and 2.0 s with six copies of this file running
// at once.
const TIMEOUT_MS = 30_000;

function start(script: string, event: object, dir = base): Promise<number> {
  return Bun.spawn(["bun", "run", join(here, script)], {
    stdin: Buffer.from(JSON.stringify(event)), env: { ...process.env, AAR_L2_DIR: dir },
  }).exited;
}

async function run(script: string, event: object, dir = base): Promise<void> {
  expect(await start(script, event, dir)).toBe(0);
}

const sessionPath = (session: string, dir = base): string =>
  join(dir, "sessions", toHex(sessionId16(session)));

function verify(session: string, dir = base):
  { code: number; ok: boolean; receipts: number; chain_checks: { name: string; pass: boolean }[] } {
  const proc = Bun.spawnSync(["bun", "run", join(here, "verify.ts"), "--json",
    sessionPath(session, dir), join(dir, "recorder.pub"), toHex(sessionId16(session))]);
  return { code: proc.exitCode, ...JSON.parse(proc.stdout.toString()) };
}

const call = (session: string, i: number): object =>
  ({ session_id: session, tool_name: `Tool${i}`, tool_input: { arg: i }, tool_response: { ok: true } });

// The seq of each receipt along the digest walk from genesis.
function seqsAlongWalk(session: string): CborValue[] {
  const spki = fromHex(readFileSync(join(base, "recorder.pub"), "utf8").trim());
  const receipts = readHexLines(join(sessionPath(session), "receipts.hexl")).map((envelope) => {
    const opened = openEnvelope(envelope, spki);
    return { payload: opened.payload as Record<string, CborValue>, digest: toHex(sha256(opened.payloadBytes)) };
  });
  const seqs: CborValue[] = [];
  let cursor = "";
  while (true) {
    const next = receipts.find(({ payload: { session_prev_digest: prev } }) =>
      (prev instanceof Uint8Array ? toHex(prev) : "") === cursor);
    if (!next) return seqs;
    seqs.push(next.payload.seq as CborValue);
    cursor = next.digest;
  }
}

// A helper process on lib.ts withLock: writes <name>.attempting just before
// calling it and <name>.inside once it holds the lock, then holds it for holdMs.
function locker(dir: string, name: string, holdMs: number): ReturnType<typeof Bun.spawn> {
  return Bun.spawn(["bun", "-e", `
    const { withLock } = await import(${JSON.stringify(join(here, "lib.ts"))});
    const { writeFileSync } = require("node:fs");
    const [dir, name, holdMs] = process.argv.slice(1);
    writeFileSync(dir + "/" + name + ".attempting", "");
    withLock(dir, () => { writeFileSync(dir + "/" + name + ".inside", ""); Bun.sleepSync(Number(holdMs)); });
  `, dir, name, String(holdMs)]);
}

async function appears(path: string): Promise<void> {
  while (!existsSync(path)) await Bun.sleep(10);
}

const HEAD_NOT_IN_LOG = "receipt log does not contain the recorded chain head\n";

// The key exists before the races below, so they contend on the session lock
// alone; first use has its own test on a fresh base.
beforeAll(() => run("recorder.ts", call("lifecycle-warm-up", 0)));

describe("l2 recorder lifecycle", () => {
  test("eight recorders started at once leave an intact chain of eight", async () => {
    const session = "lifecycle-eight-at-once";
    const codes = await Promise.all(Array.from({ length: 8 }, (_, i) => start("recorder.ts", call(session, i))));
    expect(codes).toEqual(Array(8).fill(0));
    await run("close.ts", { session_id: session });
    expect(verify(session)).toMatchObject({ code: 0, ok: true, receipts: 8 });

    expect(seqsAlongWalk(session)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  }, TIMEOUT_MS);

  test("a close racing appends never leaves a receipt off the walk", async () => {
    for (let round = 0; round < 5; round++) {
      const session = `lifecycle-close-race-${round}`;
      const codes = await Promise.all([
        ...Array.from({ length: 4 }, (_, i) => start("recorder.ts", call(session, i))),
        start("close.ts", { session_id: session }),
        ...Array.from({ length: 4 }, (_, i) => start("recorder.ts", call(session, i + 4))),
      ]);
      expect(codes).toEqual(Array(9).fill(0));
      const dir = sessionPath(session);
      const spki = fromHex(readFileSync(join(base, "recorder.pub"), "utf8").trim());
      const close = openEnvelope(readHexLines(join(dir, "close.hex"))[0]!, spki).payload as Record<string, CborValue>;
      const recorded = readHexLines(join(dir, "receipts.hexl")).length;
      expect(close.item_count).toBe(recorded);
      expect(verify(session)).toMatchObject({ code: 0, ok: true, receipts: recorded });
      // Every submitted call is in the log or logged as dropped after the close.
      const errors = existsSync(join(dir, "errors.log")) ? readFileSync(join(dir, "errors.log"), "utf8") : "";
      const dropped = errors.split("\n").filter((line) => line.startsWith("post-close tool call dropped")).length;
      expect(recorded + dropped).toBe(8);
    }
    expect(existsSync(join(base, "errors.log"))).toBe(false);
  }, TIMEOUT_MS);

  test("an append after a lost state write continues the chain", async () => {
    for (const lost of ["restored", "deleted"]) {
      const session = `lifecycle-lost-state-${lost}`;
      const statePath = join(sessionPath(session), "state.json");
      await run("recorder.ts", call(session, 0));
      const before = readFileSync(statePath);
      await run("recorder.ts", call(session, 1));
      // Restored: state.json is one entry behind the log. Deleted: no state.json.
      if (lost === "restored") writeFileSync(statePath, before);
      else unlinkSync(statePath);
      await run("recorder.ts", call(session, 2));
      await run("close.ts", { session_id: session });
      expect(verify(session)).toMatchObject({ code: 0, ok: true, receipts: 3 });
    }
  }, TIMEOUT_MS);

  test("a log that lost its tail while state.json survived is not reported intact", async () => {
    const session = "lifecycle-lost-tail";
    const dir = sessionPath(session);
    const log = join(dir, "receipts.hexl");
    await run("recorder.ts", call(session, 0));
    await run("recorder.ts", call(session, 1));
    writeFileSync(log, readFileSync(log, "utf8").split("\n")[0] + "\n");
    await run("recorder.ts", call(session, 2));
    await run("close.ts", { session_id: session });
    const result = verify(session);
    expect(result).toMatchObject({ code: 1, ok: false, receipts: 2 });
    expect(result.chain_checks).toContainEqual({ name: "predecessor_resolution", pass: false });
    expect(readFileSync(join(dir, "errors.log"), "utf8")).toBe(HEAD_NOT_IN_LOG);
  }, TIMEOUT_MS);

  // After receipt 1 is removed from the log, the next two appends must sign 2
  // and 3 whatever then happens to state.json between them.
  test.each([
    ["state.json kept", (_statePath: string, _stale: string) => {}],
    ["the recovery append's state write lost", (statePath: string, stale: string) => writeFileSync(statePath, stale)],
    ["state.json deleted after the recovery append", (statePath: string, _stale: string) => unlinkSync(statePath)],
  ])("a sequence number is not reused after a lost tail: %s", async (label, betweenAppends) => {
    const session = `lifecycle-lost-tail-seq-${label}`;
    const dir = sessionPath(session);
    const log = join(dir, "receipts.hexl");
    const statePath = join(dir, "state.json");
    await run("recorder.ts", call(session, 0));
    await run("recorder.ts", call(session, 1));
    writeFileSync(log, readFileSync(log, "utf8").split("\n")[0] + "\n");
    const stale = readFileSync(statePath, "utf8");
    await run("recorder.ts", call(session, 2));
    betweenAppends(statePath, stale);
    await run("recorder.ts", call(session, 3));
    const spki = fromHex(readFileSync(join(base, "recorder.pub"), "utf8").trim());
    const seqs = readHexLines(log).map((envelope) => (openEnvelope(envelope, spki).payload as Record<string, CborValue>).seq);
    expect(seqs).toEqual([0, 2, 3]);
  }, TIMEOUT_MS);

  test("checkpointing resumes after state.json is lost", async () => {
    const session = "lifecycle-checkpoint-resumes";
    const dir = sessionPath(session);
    const log = join(dir, "receipts.hexl");
    await run("recorder.ts", call(session, 0));
    await run("recorder.ts", call(session, 1));
    unlinkSync(join(dir, "state.json"));
    await run("recorder.ts", call(session, 2));
    await run("recorder.ts", call(session, 3));
    writeFileSync(log, readFileSync(log, "utf8").split("\n").slice(0, 3).join("\n") + "\n");
    await run("recorder.ts", call(session, 4));
    await run("close.ts", { session_id: session });
    const result = verify(session);
    expect(result).toMatchObject({ code: 1, ok: false, receipts: 4 });
    expect(result.chain_checks).toContainEqual({ name: "predecessor_resolution", pass: false });
    expect(readFileSync(join(dir, "errors.log"), "utf8")).toBe(HEAD_NOT_IN_LOG);
  }, TIMEOUT_MS);

  test("two lost state writes in a row do not fork the chain", async () => {
    const session = "lifecycle-two-lost-state-writes";
    const statePath = join(sessionPath(session), "state.json");
    await run("recorder.ts", call(session, 0));
    const afterFirst = readFileSync(statePath);
    await run("recorder.ts", call(session, 1));
    writeFileSync(statePath, afterFirst);
    await run("recorder.ts", call(session, 2));
    writeFileSync(statePath, afterFirst);
    await run("recorder.ts", call(session, 3));
    await run("close.ts", { session_id: session });
    expect(verify(session)).toMatchObject({ code: 0, ok: true, receipts: 4 });
    expect(seqsAlongWalk(session)).toEqual([0, 1, 2, 3]);
  }, TIMEOUT_MS);

  test("a lock holder killed mid-hold does not block the next recorder", async () => {
    const session = "lifecycle-killed-holder";
    const dir = sessionPath(session);
    mkdirSync(dir, { recursive: true });
    // The holder gives up the lock by itself once the test would have timed out.
    const holder = locker(dir, "holder", TIMEOUT_MS);
    let waiter: ReturnType<typeof locker> | undefined;
    try {
      await appears(join(dir, "holder.inside"));
      waiter = locker(dir, "waiter", 0);
      await appears(join(dir, "waiter.attempting"));
      await Bun.sleep(300);
      expect(existsSync(join(dir, "waiter.inside"))).toBe(false);
      holder.kill("SIGKILL");
      await appears(join(dir, "waiter.inside"));
      expect(await waiter.exited).toBe(0);
      await run("recorder.ts", call(session, 0));
      await run("close.ts", { session_id: session });
      expect(verify(session)).toMatchObject({ code: 0, ok: true, receipts: 1 });
    } finally {
      holder.kill("SIGKILL");
      waiter?.kill("SIGKILL");
    }
  }, TIMEOUT_MS);

  test("withLock rethrows the callback's error", () => {
    const dir = mkdtempSync(join(tmpdir(), "aar-l2-rethrow-"));
    // The helper makes ending the transaction fail too: that failure must not
    // replace the callback's error.
    const proc = Bun.spawnSync(["bun", "-e", `
      const { Database } = require("bun:sqlite");
      const { withLock } = await import(${JSON.stringify(join(here, "lib.ts"))});
      const run = Database.prototype.run;
      Database.prototype.run = function (sql, ...rest) {
        if (sql !== "BEGIN EXCLUSIVE") throw new Error("lifecycle-cleanup-error");
        return run.call(this, sql, ...rest);
      };
      try {
        withLock(process.argv[1], () => { throw new Error("lifecycle-callback-error"); });
      } catch (error) {
        console.log(error.message);
      }
    `, dir]);
    expect(proc.stdout.toString()).toBe("lifecycle-callback-error\n");
  }, TIMEOUT_MS);

  test("a final line without its newline is not merged with the next receipt", async () => {
    const session = "lifecycle-missing-newline";
    const log = join(sessionPath(session), "receipts.hexl");
    await run("recorder.ts", call(session, 0));
    writeFileSync(log, readFileSync(log, "utf8").trimEnd());
    await run("recorder.ts", call(session, 1));
    await run("close.ts", { session_id: session });
    expect(verify(session)).toMatchObject({ code: 0, ok: true, receipts: 2 });
  }, TIMEOUT_MS);

  test("concurrent first use creates one recorder key", async () => {
    const fresh = mkdtempSync(join(tmpdir(), "aar-l2-first-use-"));
    const sessions = Array.from({ length: 8 }, (_, i) => `lifecycle-first-use-${i}`);
    const codes = await Promise.all(sessions.map((session, i) => start("recorder.ts", call(session, i), fresh)));
    expect(codes).toEqual(Array(8).fill(0));
    expect(readdirSync(fresh).sort()).toEqual(["lock.db", "recorder.key", "recorder.pub", "sessions"]);
    for (const session of sessions) {
      await run("close.ts", { session_id: session }, fresh);
      expect(verify(session, fresh)).toMatchObject({ code: 0, ok: true, receipts: 1 });
    }
  }, TIMEOUT_MS);

  test("a missing public key is rewritten from the private key", async () => {
    const fresh = mkdtempSync(join(tmpdir(), "aar-l2-missing-pub-"));
    const session = "lifecycle-missing-pub";
    await run("recorder.ts", call(session, 0), fresh);
    const pub = readFileSync(join(fresh, "recorder.pub"), "utf8");
    unlinkSync(join(fresh, "recorder.pub"));
    await run("recorder.ts", call(session, 1), fresh);
    expect(readFileSync(join(fresh, "recorder.pub"), "utf8")).toBe(pub);
    await run("close.ts", { session_id: session }, fresh);
    expect(verify(session, fresh)).toMatchObject({ code: 0, ok: true, receipts: 2 });
  }, TIMEOUT_MS);

  test("a private key recreated beside a stale public key republishes the public key", async () => {
    const fresh = mkdtempSync(join(tmpdir(), "aar-l2-stale-pub-"));
    await run("recorder.ts", call("lifecycle-stale-pub-before", 0), fresh);
    const stale = readFileSync(join(fresh, "recorder.pub"), "utf8");
    unlinkSync(join(fresh, "recorder.key"));
    const session = "lifecycle-stale-pub";
    await run("recorder.ts", call(session, 0), fresh);
    await run("close.ts", { session_id: session }, fresh);
    expect(readFileSync(join(fresh, "recorder.pub"), "utf8")).not.toBe(stale);
    expect(verify(session, fresh)).toMatchObject({ code: 0, ok: true, receipts: 1 });
  }, TIMEOUT_MS);
});
