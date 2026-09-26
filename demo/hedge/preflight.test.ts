import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MockVapixBackend, type MockHedgeConfig, type MockVapixConfig } from "../../adapters/vapix/mock/server";
import { LIVE_TARGETS } from "../../adapters/vapix/live/config";
import type { HttpTransportRequest } from "../../adapters/vapix/digest";
import { parseArgs, runPreflight, type Dependencies, type Options } from "./preflight";

let root: string;
let oldWindow: string | undefined;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "aar-hedge-"));
  oldWindow = process.env.AAR_LIVE_WINDOW;
  process.env.AAR_LIVE_WINDOW = "1";
});
afterEach(async () => {
  if (oldWindow === undefined) delete process.env.AAR_LIVE_WINDOW; else process.env.AAR_LIVE_WINDOW = oldWindow;
  await rm(root, { recursive: true, force: true });
});

function fixture(actorOptions: MockHedgeConfig = {}, observerOptions: MockHedgeConfig = {}, lit = true) {
  const secret = randomBytes(24).toString("hex"); // Synthetic, memory-only credential; never a camera secret.
  const config = (role: "ptz" | "stream", hedge: MockHedgeConfig): MockVapixConfig => ({
    username: "root", password: secret, realm: role, presetBackendName: "Home", streamBackendProfile: "unused",
    model: LIVE_TARGETS[role].expectedModel, firmware: "12.1", serial: LIVE_TARGETS[role].expectedSerial,
    baseline: { pan: 0, tilt: 0, zoom: 1 }, safePreset: { pan: 0, tilt: 0, zoom: 1 }, settlingReads: 1, hedge,
  });
  const actor = new MockVapixBackend(config("ptz", actorOptions));
  const observer = new MockVapixBackend(config("stream", {
    lights: [{ lightID: "observer-ir", enabled: false, active: false, sync: false }],
    frameLuma: () => lit && actor.currentIrCutFilter() === "off" ? 120 : 20, ...observerOptions,
  }));
  const calls: HttpTransportRequest[] = [];
  const credentialRefs: string[] = [];
  const deps: Dependencies = {
    targets: { actor: { ...LIVE_TARGETS.ptz, baseUrl: "http://actor.invalid" }, observer: { ...LIVE_TARGETS.stream, baseUrl: "http://observer.invalid" } },
    credentials: { async get(reference) { credentialRefs.push(reference); return { reference, secret }; } },
    transport: { async exchange(request) {
      calls.push(request);
      return (request.url.hostname === "actor.invalid" ? actor : observer).exchange(request);
    } },
    sleep: async () => {},
  };
  const options = (name: string, toggle = false): Options => ({ mode: toggle ? "toggle" : "probe", frames: 3, intervalMs: 1,
    roi: [0, 0, 8, 8], controlRoi: [8, 8, 8, 8], out: join(root, name),
    ...(toggle ? { probePassed: join(root, "probe/report.json") } : {}) });
  return { actor, observer, deps, calls, credentialRefs, options, secret };
}

function updates(calls: HttpTransportRequest[]) {
  return calls.filter((call) => call.url.searchParams.get("action") === "update");
}

function assertReadOnlyLightApi(calls: HttpTransportRequest[]) {
  for (const call of calls) {
    expect(call.url.pathname).not.toBe("/axis-cgi/basicdeviceinfo.cgi");
    if (call.url.pathname === "/axis-cgi/lightcontrol.cgi") {
      const body = JSON.parse(new TextDecoder().decode(call.body));
      expect(["getServiceCapabilities", "getLightInformation", "getLightStatus", "getLightSynchronizeDayNightMode"]).toContain(body.method);
      expect(call.method).toBe("POST");
    }
  }
}

describe("hedge physical feasibility spike (in-memory Digest transport, no LAN)", () => {
  test("probe feasible, every light queried, snapshot and credential references recorded safely", async () => {
    const f = fixture({ lights: [
      { lightID: "led0", enabled: true, active: false, sync: true },
      { lightID: "led1", enabled: true, active: false, sync: false, syncSupported: false },
    ] });
    const result = await runPreflight(f.options("probe"), f.deps);
    expect(result.feasible).toBe(true);
    expect(result.actor?.firmware).toBe("12.1");
    expect(result.snapshot).toMatchObject({ width: 16, height: 16, roi_mean_milli: 20000, control_mean_milli: 20000 });
    expect(result.actor?.lights).toHaveLength(2);
    expect(updates(f.calls)).toHaveLength(0);
    expect(new Set(f.credentialRefs)).toEqual(new Set(["cam-q6358-vapix", "cam-q6325-vapix"]));
    const lightCalls = f.calls.filter((call) => call.url.hostname === "actor.invalid" && call.url.pathname.endsWith("lightcontrol.cgi"))
      .map((call) => JSON.parse(new TextDecoder().decode(call.body)));
    expect(lightCalls.filter((c) => c.method === "getLightStatus").map((c) => c.params.lightID)).toEqual(["led0", "led1"]);
    expect(lightCalls.filter((c) => c.method === "getLightSynchronizeDayNightMode").map((c) => c.params.lightID)).toEqual(["led0", "led1"]);
    const disk = await readFile(join(root, "probe/report.json"), "utf8");
    expect(disk).not.toContain(f.secret);
    expect(JSON.parse(disk)).toEqual(result);
    assertReadOnlyLightApi(f.calls);
  });

  test("probe refuses enabled observer light even when it is not active", async () => {
    const f = fixture({}, { lights: [{ lightID: "ir", enabled: true, active: false, sync: false }] });
    const report = await runPreflight(f.options("probe"), f.deps);
    expect(report.feasible).toBe(false);
    expect(report.reasons).toContain("observer light enabled or active");
    await expect(runPreflight(f.options("toggle", true), f.deps)).rejects.toThrow("prior probe did not pass");
    expect(updates(f.calls)).toHaveLength(0);
  });

  test("rechecks observer after a passed probe before permitting a toggle", async () => {
    const lights = [{ lightID: "ir", enabled: false, active: false, sync: false }];
    const f = fixture({}, { lights });
    await runPreflight(f.options("probe"), f.deps);
    lights[0]!.enabled = true;
    const report = await runPreflight(f.options("toggle", true), f.deps);
    expect(report.feasible).toBe(false);
    expect(updates(f.calls)).toHaveLength(0);
  });

  for (const lit of [true, false]) test(`toggle computes separation for dark→${lit ? "lit" : "dark"} and restores`, async () => {
    const f = fixture({}, {}, lit);
    await runPreflight(f.options("probe"), f.deps);
    const report = await runPreflight(f.options("toggle", true), f.deps);
    expect(report.feasible).toBe(true);
    expect(report.baseline?.roi).toEqual({ mean_milli: 20000, stddev_milli: 0 });
    expect(report.post?.roi.mean_milli).toBe(lit ? 120000 : 20000);
    expect(report.separation_ratio_milli).toEqual({ roi: lit ? 100000 : 0, control_roi: lit ? 100000 : 0 });
    expect(report.readback).toEqual({ original: "on", during: "off", restored: "on" });
    expect(report.repeatable_reset).toBe(true);
    expect(report.light_status.before?.[0]?.active).toBe(false);
    expect(report.light_status.during.map((poll) => poll[0]?.active)).toEqual([true, true, true]);
    expect(report.light_status.after?.[0]?.active).toBe(false);
    expect(f.actor.currentIrCutFilter()).toBe("on");
    expect(updates(f.calls).map((c) => c.url.searchParams.get("ImageSource.I0.DayNight.IrCutFilter"))).toEqual(["off", "on"]);
    expect(updates(f.calls).every((c) => c.url.hostname === "actor.invalid")).toBe(true);
    for (const frame of [...report.frames.baseline, ...report.frames.post]) {
      const bytes = await readFile(join(root, "toggle", frame.file));
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(frame.sha256);
      expect(Number.isNaN(Date.parse(frame.captured_at))).toBe(false);
    }
    assertReadOnlyLightApi(f.calls);
  });

  test("restore readback mismatch reports repeatable_reset false", async () => {
    const f = fixture({ restoreReadbackMismatch: true });
    await runPreflight(f.options("probe"), f.deps);
    const report = await runPreflight(f.options("toggle", true), f.deps);
    expect(report.repeatable_reset).toBe(false);
    expect(report.feasible).toBe(false);
    expect(report.readback.restored).toBe("off");
    expect(report.reasons).toContain("restore readback mismatch");
  });

  test("restores exact auto value and records optical uncertainty", async () => {
    const f = fixture({ irCutFilter: "auto" });
    await runPreflight(f.options("probe"), f.deps);
    const report = await runPreflight(f.options("toggle", true), f.deps);
    expect(report.readback.restored).toBe("auto");
    expect(report.repeatable_reset).toBe("unknown");
    expect(report.notes.join(" ")).toContain("pre-run optical state");
  });

  test("restores after a post-frame failure and persists partial evidence", async () => {
    const f = fixture();
    await runPreflight(f.options("probe"), f.deps);
    f.observer.config.hedge!.frameLuma = () => { if (f.actor.currentIrCutFilter() === "off") throw new Error("capture failed"); return 20; };
    const report = await runPreflight(f.options("toggle", true), f.deps);
    expect(report.feasible).toBe(false);
    expect(report.frames.baseline).toHaveLength(3);
    expect(report.readback.restored).toBe("on");
    expect(JSON.parse(await readFile(join(root, "toggle/report.json"), "utf8")).readback.restored).toBe("on");
  });

  test("restores even when the toggle acknowledgement is lost after dispatch", async () => {
    const f = fixture();
    await runPreflight(f.options("probe"), f.deps);
    const exchange = f.deps.transport!.exchange;
    f.deps.transport = { async exchange(request) {
      const response = await exchange(request);
      if (request.url.searchParams.get("ImageSource.I0.DayNight.IrCutFilter") === "off") throw new Error("lost acknowledgement");
      return response;
    } };
    const report = await runPreflight(f.options("toggle", true), f.deps);
    expect(report.feasible).toBe(false);
    expect(report.readback.restored).toBe("on");
    expect(updates(f.calls)).toHaveLength(2);
  });

  test("no groups and unreadable snapshots produce explicit infeasibility reasons", async () => {
    const f = fixture({ lights: [] }, { unreadableSnapshot: true });
    const report = await runPreflight(f.options("probe"), f.deps);
    expect(report.feasible).toBe(false);
    expect(report.reasons).toContain("actor: no light groups");
    expect(report.reasons).toContain("snapshot unreadable (JPEG or ROI)");
  });

  test("malformed observer status fails closed", async () => {
    const f = fixture();
    const exchange = f.deps.transport!.exchange;
    f.deps.transport = { async exchange(request) {
      const response = await exchange(request);
      if (request.url.hostname === "observer.invalid" && request.url.pathname.endsWith("lightcontrol.cgi") &&
          JSON.parse(new TextDecoder().decode(request.body)).method === "getLightStatus") {
        return { ...response, body: new TextEncoder().encode(JSON.stringify({ method: "getLightStatus", data: { status: "false" } })) };
      }
      return response;
    } };
    const report = await runPreflight(f.options("probe"), f.deps);
    expect(report.feasible).toBe(false);
    expect(updates(f.calls)).toHaveLength(0);
  });

  test("interruption after changing the actor still restores", async () => {
    const f = fixture();
    await runPreflight(f.options("probe"), f.deps);
    const abort = new AbortController();
    f.deps.signal = abort.signal;
    f.deps.sleep = async () => { if (f.actor.currentIrCutFilter() === "off") abort.abort(); };
    const report = await runPreflight(f.options("toggle", true), f.deps);
    expect(report.feasible).toBe(false);
    expect(report.readback.restored).toBe("on");
    expect(updates(f.calls)).toHaveLength(2);
  });

  test("missing/forged/wrong-target probe files are refused before network access", async () => {
    const f = fixture();
    await expect(runPreflight(f.options("toggle", true), f.deps)).rejects.toThrow();
    await writeFile(join(root, "forged.json"), JSON.stringify({ feasible: true }));
    await expect(runPreflight({ ...f.options("toggle", true), probePassed: join(root, "forged.json") }, f.deps)).rejects.toThrow();
    expect(f.calls).toHaveLength(0);
    await runPreflight(f.options("probe"), f.deps);
    f.calls.length = 0;
    f.deps.targets!.actor = { ...f.deps.targets!.actor, baseUrl: "http://other.invalid" };
    await expect(runPreflight(f.options("toggle", true), f.deps)).rejects.toThrow("targets do not match");
    expect(f.calls).toHaveLength(0);
  });

  test("no network or credential calls without AAR_LIVE_WINDOW=1", async () => {
    const f = fixture();
    for (const value of [undefined, "0", "true"]) {
      if (value === undefined) delete process.env.AAR_LIVE_WINDOW; else process.env.AAR_LIVE_WINDOW = value;
      await expect(runPreflight(f.options("probe"), f.deps)).rejects.toThrow("network refused");
    }
    expect(f.calls).toHaveLength(0);
    expect(f.credentialRefs).toHaveLength(0);
    const child = Bun.spawn([process.execPath, "run", "demo/hedge/preflight.ts"], { env: { ...process.env, AAR_LIVE_WINDOW: "0" }, stdout: "pipe", stderr: "pipe" });
    expect(await child.exited).toBe(1);
    expect(await new Response(child.stderr).text()).toContain("network refused");
  });

  test("CLI rejects unknown operations, malformed numbers, and conflicting modes", () => {
    for (const args of [["--activateLight"], ["--probe", "--toggle"], ["--toggle"], ["--frames", "0"], ["--frames", "2.5"], ["--interval-ms", "-1"], ["--out"], ["--roi", "0,0,0,1"]]) {
      expect(() => parseArgs(args)).toThrow();
    }
    expect(parseArgs([]).mode).toBe("probe");
    expect(parseArgs(["--toggle", "--probe-passed", "probe.json", "--frames", "4"]).frames).toBe(4);
  });
});
