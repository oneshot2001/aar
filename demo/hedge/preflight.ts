import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DigestHttpClient, type HttpTransport } from "../../adapters/vapix/digest";
import { CRED_BINARY, LIVE_TARGETS, type LiveTargetIdentity } from "../../adapters/vapix/live/config";
import type { CredentialProvider } from "../../adapters/shared/types";
import { CredStoreProvider, parseParamList } from "../preflight";
import { measureJpeg, parseRoi, separation, statistics, type Roi } from "./luminance";

const DAY_NIGHT = "ImageSource.I0.DayNight";
const IR_CUT = `${DAY_NIGHT}.IrCutFilter`;
const SCHEMA = "aar-hedge-preflight-v1";
type JsonObject = Record<string, unknown>;
type LightMethod = "getServiceCapabilities" | "getLightInformation" | "getLightStatus" | "getLightSynchronizeDayNightMode";

export interface Options {
  mode: "probe" | "toggle";
  roi?: Roi;
  controlRoi?: Roi;
  frames: number;
  intervalMs: number;
  out: string;
  probePassed?: string;
}

export function parseArgs(args: readonly string[]): Options {
  const options: Options = { mode: "probe", frames: 5, intervalMs: 500,
    out: join("demo/hedge/runs", new Date().toISOString().replaceAll(":", "-")) };
  const seen = new Set<string>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    const key = arg === "--probe" || arg === "--toggle" ? "mode" : arg;
    if (seen.has(key)) throw new Error(`duplicate option: ${arg}`);
    seen.add(key);
    if (arg === "--probe" || arg === "--toggle") { options.mode = arg === "--probe" ? "probe" : "toggle"; continue; }
    if (!["--roi", "--control-roi", "--frames", "--interval-ms", "--out", "--probe-passed"].includes(arg)) {
      throw new Error(`unknown option: ${arg}`);
    }
    const value = args[++i];
    if (!value || value.startsWith("--")) throw new Error(`missing value: ${arg}`);
    if (arg === "--roi") options.roi = parseRoi(value);
    else if (arg === "--control-roi") options.controlRoi = parseRoi(value);
    else if (arg === "--out") options.out = value;
    else if (arg === "--probe-passed") options.probePassed = value;
    else {
      const n = Number(value);
      if (!/^\d+$/.test(value) || !Number.isSafeInteger(n) || n < 1) throw new Error(`${arg} must be a positive integer`);
      if (arg === "--frames") options.frames = n; else options.intervalMs = n;
    }
  }
  if (options.mode === "toggle" && !options.probePassed) throw new Error("--toggle requires --probe-passed FILE (prior probe report.json)");
  if (options.mode === "probe" && options.probePassed) throw new Error("--probe-passed requires --toggle");
  return options;
}

export interface Dependencies {
  credentials?: CredentialProvider;
  targets?: { actor: LiveTargetIdentity; observer: LiveTargetIdentity };
  transport?: HttpTransport;
  sleep?: (ms: number) => Promise<void>;
  signal?: AbortSignal;
}

function object(value: unknown): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid JSON object");
  return value as JsonObject;
}
function bool(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("missing light boolean state");
  return value;
}
function nonempty(value: unknown): string {
  if (typeof value !== "string" || !value.length) throw new Error("missing string");
  return value;
}
function gate(): void {
  if (process.env.AAR_LIVE_WINDOW !== "1") throw new Error("network refused: set AAR_LIVE_WINDOW=1 inside the physical test window");
}

class Camera {
  private readonly client: DigestHttpClient;
  private readonly invocationId = randomUUID();
  constructor(readonly target: LiveTargetIdentity, credentials: CredentialProvider, transport?: HttpTransport) {
    this.client = new DigestHttpClient(target.baseUrl, target.username, target.credentialReference, credentials, 10000, transport);
  }
  async get(path: string, actionBearing = false): Promise<Uint8Array> {
    gate();
    const response = await this.client.request({ method: "GET", url: new URL(path, this.target.baseUrl),
      context: { invocationId: this.invocationId, actionBearing } });
    if (response.status !== 200) throw new Error("camera GET failed");
    return response.body;
  }
  async params(group: string): Promise<Record<string, string>> {
    const bytes = await this.get(`/axis-cgi/param.cgi?action=list&group=${group}`);
    const text = new TextDecoder().decode(bytes);
    if (/^Error/im.test(text)) throw new Error("parameter list failed");
    return Object.fromEntries(Object.entries(parseParamList(text)).map(([key, value]) => [key.replace(/^root\./, ""), value]));
  }
  async setIrCut(value: string): Promise<void> {
    if (!["on", "off", "auto"].includes(value)) throw new Error("unsupported IrCutFilter value");
    const text = new TextDecoder().decode(await this.get(`/axis-cgi/param.cgi?action=update&${IR_CUT}=${encodeURIComponent(value)}`, true));
    if (text.trim() !== "OK") throw new Error("parameter update not acknowledged");
  }
  async light(method: LightMethod, lightID?: string): Promise<JsonObject> {
    gate();
    const response = await this.client.request({ method: "POST", url: new URL("/axis-cgi/lightcontrol.cgi", this.target.baseUrl),
      headers: { "content-type": "application/json" },
      body: new TextEncoder().encode(JSON.stringify({ apiVersion: "1.0", method, params: lightID === undefined ? {} : { lightID } })),
      context: { invocationId: this.invocationId, actionBearing: false } });
    if (response.status !== 200) throw new Error("lightcontrol HTTP failure");
    const result = object(JSON.parse(new TextDecoder().decode(response.body)));
    if (result.error !== undefined || result.method !== method) throw new Error("lightcontrol RPC failure");
    return object(result.data);
  }
  async lights(): Promise<Light[]> {
    const capabilities = await this.light("getServiceCapabilities");
    const info = await this.light("getLightInformation");
    if (!Array.isArray(info.items)) throw new Error("missing light groups");
    if (capabilities.capabilities !== undefined && !Array.isArray(capabilities.capabilities)) throw new Error("invalid light capabilities");
    const groups = (capabilities.capabilities as unknown[] | undefined)?.map(object);
    const lights: Light[] = [];
    for (const value of info.items) {
      const item = object(value);
      const lightID = nonempty(item.lightID);
      if (lights.some((light) => light.lightID === lightID) || item.error === true) throw new Error("invalid light group");
      const capability = groups?.find((group) => group.lightID === lightID) ?? capabilities;
      // Real VAPIX reports dayNightSynchronizeSupport once, device-wide; a light that
      // rejects the query falls back to the value getLightInformation carried.
      let sync: boolean | null = typeof item.synchronizeDayNightMode === "boolean" ? item.synchronizeDayNightMode : null;
      if (capability.dayNightSynchronizeSupport === true) {
        try { sync = bool((await this.light("getLightSynchronizeDayNightMode", lightID)).synchronize); }
        catch { /* keep the getLightInformation value */ }
      }
      lights.push({ lightID, enabled: bool(item.enabled), active: bool((await this.light("getLightStatus", lightID)).status), sync });
    }
    return lights;
  }
  async inspect(): Promise<CameraReport> {
    const dayNight = await this.params(DAY_NIGHT);
    const identity = await this.params("Properties.System,Properties.Firmware,Brand");
    return { target: this.target, model: identity["Brand.ProdFullName"] ?? identity["Properties.System.ProductName"] ?? "",
      firmware: identity["Properties.Firmware.Version"] ?? identity["Properties.System.FirmwareVersion"] ?? "",
      serial: identity["Properties.System.SerialNumber"] ?? "", day_night: dayNight, lights: await this.lights() };
  }
}

interface Light { lightID: string; enabled: boolean; active: boolean; sync: boolean | null }
interface CameraReport { target: LiveTargetIdentity; model: string; firmware: string; serial: string; day_night: Record<string, string>; lights: Light[] }
type Frame = ReturnType<typeof measureJpeg> & { file: string; sha256: string; captured_at: string };
type Summary = { roi: ReturnType<typeof statistics>; control_roi: ReturnType<typeof statistics> };
export interface Report {
  schema: string;
  mode: Options["mode"];
  captured_at: string;
  options: Options;
  units: { luma: string; separation: string };
  feasible: boolean;
  reasons: string[];
  actor?: CameraReport;
  observer?: CameraReport;
  snapshot?: Frame;
  frames: { baseline: Frame[]; post: Frame[] };
  baseline?: Summary;
  post?: Summary;
  separation_ratio_milli?: { roi: number; control_roi: number };
  readback: { original?: string; during?: string; restored?: string };
  light_status: { before?: Light[]; during: Light[][]; after?: Light[] };
  repeatable_reset: boolean | "unknown";
  notes: string[];
}

function summary(frames: Frame[]): Summary {
  return { roi: statistics(frames.map((f) => f.roi_mean_milli)), control_roi: statistics(frames.map((f) => f.control_mean_milli)) };
}
function observerSafe(lights: Light[]): boolean {
  return lights.every((light) => !light.enabled && !light.active);
}

export async function runPreflight(options: Options, deps: Dependencies = {}): Promise<Report> {
  gate(); // Before credentials, transport, output creation, or probe-file processing.
  const targets = deps.targets ?? { actor: LIVE_TARGETS.ptz, observer: LIVE_TARGETS.stream };
  if (options.mode === "toggle") {
    if (!options.probePassed) throw new Error("--toggle requires --probe-passed FILE");
    const prior = object(JSON.parse(await readFile(options.probePassed, "utf8")));
    if (prior.schema !== SCHEMA || prior.mode !== "probe" || prior.feasible !== true ||
        !Array.isArray(prior.reasons) || prior.reasons.length !== 0) throw new Error("prior probe did not pass");
    for (const role of ["actor", "observer"] as const) {
      const previous = object(prior[role]);
      const target = object(previous.target);
      if (target.baseUrl !== targets[role].baseUrl || target.credentialReference !== targets[role].credentialReference ||
          previous.serial !== targets[role].expectedSerial) throw new Error("prior probe targets do not match");
    }
  }
  const credentials = deps.credentials ?? new CredStoreProvider(CRED_BINARY);
  const actor = new Camera(targets.actor, credentials, deps.transport);
  const observer = new Camera(targets.observer, credentials, deps.transport);
  const sleep = deps.sleep ?? ((ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const checkAbort = () => { if (deps.signal?.aborted) throw new Error("interrupted"); };
  const report: Report = { schema: SCHEMA, mode: options.mode, captured_at: new Date().toISOString(), options,
    units: { luma: "Y * 1000; population stddev across frame means", separation: "ratio * 1000; denominator max(baseline stddev, 1 Y)" },
    feasible: false, reasons: [], frames: { baseline: [], post: [] }, readback: {},
    light_status: { during: [] }, repeatable_reset: "unknown", notes: [] };
  // Exclusive creation avoids mixing frames with, or overwriting, a prior run.
  await mkdir(options.out, { recursive: true });
  await mkdir(join(options.out, "frames"));
  const save = () => writeFile(join(options.out, "report.json"), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  const capture = async (file: string): Promise<Frame> => {
    checkAbort();
    const bytes = await observer.get("/axis-cgi/jpg/image.cgi");
    const captured_at = new Date().toISOString();
    await writeFile(join(options.out, file), bytes, { flag: "wx", mode: 0o600 });
    return { file, captured_at, sha256: createHash("sha256").update(bytes).digest("hex"),
      ...measureJpeg(bytes, options.roi, options.controlRoi) };
  };
  let stage = "probe";
  let changed = false;
  try {
    for (const [role, camera] of [["actor", actor], ["observer", observer]] as const) {
      try {
        checkAbort();
        const result = await camera.inspect();
        report[role] = result;
        if (!result.lights.length) report.reasons.push(`${role}: no light groups`);
        if (result.model !== targets[role].expectedModel || result.serial !== targets[role].expectedSerial || !result.firmware) {
          report.reasons.push(`${role}: model/serial/firmware identity check failed`);
        }
      } catch { report.reasons.push(`${role}: probe unreadable`); }
    }
    if (report.observer && !observerSafe(report.observer.lights)) report.reasons.push("observer light enabled or active");
    try { report.snapshot = await capture("frames/probe.jpg"); }
    catch { report.reasons.push("snapshot unreadable (JPEG or ROI)"); }
    report.feasible = report.reasons.length === 0;
    if (!report.feasible || options.mode === "probe") return report;
    const original = report.actor!.day_night[IR_CUT];
    if (!original || !["on", "off", "auto"].includes(original)) throw new Error("unsupported original IrCutFilter");
    report.readback.original = original;
    report.light_status.before = report.actor!.lights;
    if (original === "auto") report.notes.push("Restoring auto may not reproduce the pre-run optical state.");
    stage = "baseline capture";
    for (let i = 0; i < options.frames; i++) {
      if (i) await sleep(options.intervalMs);
      report.frames.baseline.push(await capture(`frames/baseline-${i.toString().padStart(4, "0")}.jpg`));
    }
    report.baseline = summary(report.frames.baseline);
    stage = "pre-toggle observer light check";
    if (!observerSafe(await observer.lights())) throw new Error("observer light enabled");
    checkAbort();
    stage = "toggle update/readback";
    changed = true; // Restore even if dispatch succeeds but its acknowledgement is lost.
    await actor.setIrCut("off");
    report.readback.during = (await actor.params(DAY_NIGHT))[IR_CUT];
    if (report.readback.during !== "off") throw new Error("toggle readback mismatch");
    stage = "post capture/light polling";
    for (let i = 0; i < options.frames; i++) {
      // Give the physical light a sampling interval to react before the first post frame.
      await sleep(options.intervalMs);
      checkAbort();
      report.light_status.during.push(await actor.lights());
      if (!observerSafe(await observer.lights())) throw new Error("observer light enabled");
      report.frames.post.push(await capture(`frames/post-${i.toString().padStart(4, "0")}.jpg`));
    }
    report.post = summary(report.frames.post);
    report.separation_ratio_milli = { roi: separation(report.baseline.roi, report.post.roi),
      control_roi: separation(report.baseline.control_roi, report.post.control_roi) };
  } catch {
    report.reasons.push(`${stage} failed or interrupted`);
    report.feasible = false;
  } finally {
    if (changed) {
      try { await actor.setIrCut(report.readback.original!); }
      catch { report.reasons.push("restore update not acknowledged"); }
      // Attempt readback even after an unacknowledged restore.
      try {
        report.readback.restored = (await actor.params(DAY_NIGHT))[IR_CUT];
        if (report.readback.restored !== report.readback.original) {
          report.repeatable_reset = false;
          report.reasons.push("restore readback mismatch");
        }
      } catch { report.reasons.push("restore readback unavailable"); }
      try {
        // A sync-mode light needs time to follow the restored filter; poll up to
        // `frames` intervals for the light state to match the pre-run state.
        const before = JSON.stringify(report.light_status.before);
        let sameLights = false;
        for (let i = 0; i < options.frames; i++) {
          if (i) await sleep(options.intervalMs);
          report.light_status.after = await actor.lights();
          sameLights = JSON.stringify(report.light_status.after) === before;
          if (sameLights) break;
        }
        if (report.readback.restored === report.readback.original) {
          report.repeatable_reset = report.readback.original === "auto" ? "unknown" : sameLights;
        }
      } catch { report.reasons.push("restore light status unavailable"); }
    }
    if (report.reasons.length) report.feasible = false;
    await save();
  }
  return report;
}

if (import.meta.main) {
  const abort = new AbortController();
  const interrupt = () => abort.abort();
  process.on("SIGINT", interrupt);
  process.on("SIGTERM", interrupt);
  try {
    const report = await runPreflight(parseArgs(process.argv.slice(2)), { signal: abort.signal });
    console.log(JSON.stringify(report, null, 2));
    if (!report.feasible || report.repeatable_reset === false) process.exitCode = 1;
  } catch (error) {
    // Never print transport payloads or credential-provider output.
    console.error(JSON.stringify({ feasible: false, reasons: [process.env.AAR_LIVE_WINDOW !== "1"
      ? "network refused: AAR_LIVE_WINDOW must be 1" : "preflight refused; check arguments, prior probe file, and output directory"] }));
    process.exitCode = 1;
  } finally {
    process.off("SIGINT", interrupt);
    process.off("SIGTERM", interrupt);
  }
}
