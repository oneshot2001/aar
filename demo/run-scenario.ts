import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { DemoAdapter, ScenarioId, WitnessObservation } from "../adapters/shared/types";
import type { CborValue } from "../harness/cbor";
import { decodeCbor, encodeCbor, equalBytes, fromHex, toHex } from "../harness/cbor";
import { hash } from "../harness/crypto";
import { LocalRfc6962Log } from "./anchor/log";
import { createVapixStub, createVmsStub } from "./adapters/stub";
import { DurableInvocationJournal } from "./ep/journal";
import { produce, type ProducerResult } from "./ep/producer";
import { loadDemoKeys } from "./keys/keys";
import { AppendOnlyWitnessLog } from "./witness/log";

type Obj = Record<string, CborValue>;

export interface GateInputFile {
  readonly version: 1;
  readonly evaluated_at: number;
  readonly epoch_id: number;
  readonly invocation_id: string;
  readonly correlation_id: string;
  readonly tenant_id: string;
  readonly site_id: string;
  readonly target_id: string;
  readonly target_logical_name: "ptz-primary" | "fixed-primary";
  readonly action_name: "camera.ptz.preset" | "camera.stream.view";
  readonly parameters: Readonly<Record<string, string | number | boolean>>;
  readonly expected_outcome_level: "accepted" | "device_acknowledged" | "contradicted" | "unknown";
  readonly adapter: "vapix" | "vms";
  readonly delegation_candidates: readonly { readonly not_before: number; readonly not_after: number }[];
  readonly key_dir: string;
  readonly output_dir: string;
  readonly prior_state_file: string;
  readonly preflight_result_file?: string;
}

export interface ScenarioRunResult {
  readonly scenarioId: ScenarioId;
  readonly bundlePath: string;
  readonly trustPolicyPath: string;
  readonly pyrefOutputPath: string;
  readonly pyrefOutput: string;
  readonly producer: ProducerResult;
  readonly witness: readonly WitnessObservation[];
}

function object(value: CborValue | undefined): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Map);
}

function pathFrom(base: string, path: string): string {
  return isAbsolute(path) ? path : resolve(base, path);
}

function decodePayload(envelope: CborValue): Obj {
  if (!Array.isArray(envelope) || !(envelope[0] instanceof Uint8Array)) throw new Error("malformed envelope in produced bundle");
  const payload = decodeCbor(envelope[0], { strict: true });
  if (!object(payload)) throw new Error("non-map payload in produced bundle");
  return payload;
}

function artifactsOf(bundleBytes: Uint8Array): Obj {
  const bundle = decodeCbor(bundleBytes, { strict: true });
  if (!object(bundle) || !object(bundle.artifacts)) throw new Error("produced bundle is not an AAR bundle");
  return bundle.artifacts;
}

export function assertContent(
  scenarioId: ScenarioId,
  gate: GateInputFile,
  adapter: DemoAdapter,
  bundleBytes: Uint8Array,
  pyrefOutput: string,
): void {
  if (!pyrefOutput.includes("Result: conformant")) throw new Error("pyref did not report conformant");
  if (pyrefOutput.includes("empty_scope")) throw new Error("content assertion failed: empty_scope");
  if (pyrefOutput.includes("stateful_not_evaluated")) throw new Error("content assertion failed: stateful_not_evaluated");
  if (!pyrefOutput.includes("evaluated_profile: AAR-3")) throw new Error("content assertion failed: evaluated profile is not AAR-3");
  if (!pyrefOutput.includes("coverage: complete")) throw new Error("content assertion failed: scope is not complete");

  const artifacts = artifactsOf(bundleBytes);
  const receipts = (artifacts.receipts as CborValue[]).map(decodePayload);
  const requests = (artifacts.requests as CborValue[]).map(decodePayload);
  const kinds = new Set(receipts.map((receipt) => receipt.kind as string));
  const expected = scenarioId === "S3"
    ? ["observation", "inference", "authorization", "action_attempt"]
    : ["observation", "inference", "authorization", "action_attempt", "dispatch", "outcome_observation"];
  if (kinds.size !== expected.length || expected.some((kind) => !kinds.has(kind))) throw new Error(`content assertion failed: receipt kinds ${[...kinds].join(",")}`);

  const invocation = fromHex(gate.invocation_id);
  const correlation = fromHex(gate.correlation_id);
  for (const receipt of receipts) {
    if (!equalBytes((receipt.freshness as Obj).invocation_id as Uint8Array, invocation)) throw new Error("content assertion failed: invocation ID missing from receipt");
    if (!equalBytes((receipt.correlation as Obj).correlation_id as Uint8Array, correlation)) throw new Error("content assertion failed: correlation ID missing from receipt");
  }
  if (requests.length !== 1 || !equalBytes((requests[0]!.freshness as Obj).invocation_id as Uint8Array, invocation)) throw new Error("content assertion failed: fresh gate request missing");
  const expectedIntent = hash(encodeCbor({ action: gate.action_name, target: fromHex(gate.target_id), parameters: gate.parameters }));
  if (!equalBytes(requests[0]!.action_intent_digest as Uint8Array, expectedIntent)) throw new Error("content assertion failed: request intent mismatch");

  const attempt = receipts.find((receipt) => receipt.kind === "action_attempt")!;
  const attemptBody = attempt.body as Obj;
  const action = attemptBody.action as Obj;
  const command = attemptBody.command as Obj;
  if (action.action_name !== gate.action_name || !equalBytes(action.target_id as Uint8Array, fromHex(gate.target_id))) throw new Error("content assertion failed: action/target mismatch");
  if (command.adapter_id !== adapter.id) throw new Error("content assertion failed: adapter identity mismatch");
  const authorization = receipts.find((receipt) => receipt.kind === "authorization")!;
  if (((authorization.body as Obj).decision as Obj).profile !== "AAR-3") throw new Error("content assertion failed: decision profile mismatch");

  if (scenarioId === "S3") {
    if (attemptBody.disposition !== "not_dispatched" || attemptBody.refusal_reason !== "delegation-expired") throw new Error("content assertion failed: refusal not receipted");
    if (((attempt.evidence as Obj).outcome as Obj).level !== gate.expected_outcome_level) throw new Error("content assertion failed: refusal outcome level mismatch");
  } else {
    const outcome = receipts.find((receipt) => receipt.kind === "outcome_observation")!;
    if (((outcome.evidence as Obj).outcome as Obj).level !== gate.expected_outcome_level) throw new Error("content assertion failed: outcome level mismatch");
  }
}

export async function assertOnlineOracle(
  scenarioId: ScenarioId,
  gate: GateInputFile,
  producer: ProducerResult,
  witness: readonly WitnessObservation[],
): Promise<void> {
  const attributable = witness.filter((entry) => entry.invocation_id === gate.invocation_id && entry.action_bearing);
  if (scenarioId === "S3") {
    if (producer.dispatchCount !== 0 || attributable.length !== 0) throw new Error("online oracle failed: S3 has attributable dispatch");
    const expired = producer.wire.allDelegations.filter((token) => (token.not_after as number) <= gate.evaluated_at);
    const valid = producer.wire.allDelegations.filter((token) => (token.not_before as number) <= gate.evaluated_at && gate.evaluated_at < (token.not_after as number));
    if (expired.length !== 1 || valid.length !== 1 || producer.wire.selectedDelegation.delegation_id !== expired[0]!.delegation_id) {
      throw new Error("online oracle failed: S3 token-time/refusal binding");
    }
    return;
  }
  if (producer.dispatchCount !== 1 || attributable.length !== 1 || !producer.dispatchResult) throw new Error("online oracle failed: dispatch accounting");
  const attempt = producer.wire.receipts.find((receipt) => receipt.kind === "action_attempt")!;
  const command = (attempt.fields.body as Obj).command as Obj;
  const commandDigest = toHex(command.command_digest as Uint8Array);
  if (attributable[0]!.command_digest !== commandDigest || attributable[0]!.request_body_sha256 !== commandDigest) throw new Error("online oracle failed: witness/command manifest binding");
  if (producer.dispatchResult.effect.invocation_id !== gate.invocation_id || producer.dispatchResult.effect.command_digest !== commandDigest) throw new Error("online oracle failed: effect binding");
  const dispatch = producer.wire.receipts.find((receipt) => receipt.kind === "dispatch")!;
  if (!equalBytes((dispatch.fields.body as Obj).command_id as Uint8Array, command.command_id as Uint8Array)) throw new Error("online oracle failed: dispatch/command ID binding");
  const outcome = producer.wire.receipts.find((receipt) => receipt.kind === "outcome_observation")!;
  if (!equalBytes((outcome.fields.body as Obj).observation_commitment as Uint8Array, fromHex(producer.dispatchResult.effect.observation_digest))) throw new Error("online oracle failed: outcome/effect binding");
}

interface PriorStateJson {
  prior_emissions: Array<{ issuer_kid: string; issuer_seq: number; epoch_owner_kid: string; epoch_id: number; epoch_seq: number; receipt_id: string; envelope_digest: string }>;
  entries: Array<{ replay_domain: string; invocation_id: string; content_digest: string }>;
}

async function ensurePriorState(path: string): Promise<void> {
  try { await readFile(path); } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify({ prior_emissions: [], entries: [] }, null, 2)}\n`);
  }
}

async function advancePriorState(path: string, producer: ProducerResult): Promise<void> {
  const state = JSON.parse(await readFile(path, "utf8")) as PriorStateJson;
  for (const receipt of producer.wire.receipts) {
    const binding = receipt.fields.binding as Obj;
    state.prior_emissions.push({
      issuer_kid: toHex(receipt.issuerKid), issuer_seq: receipt.issuerSeq,
      epoch_owner_kid: toHex(binding.epoch_owner_kid as Uint8Array), epoch_id: binding.epoch_id as number, epoch_seq: receipt.epochSeq,
      receipt_id: toHex(receipt.id), envelope_digest: toHex(hash(receipt.signed.envelopeBytes)),
    });
  }
  await writeFile(path, `${JSON.stringify(state, null, 2)}\n`);
}

export async function runScenario(scenarioId: ScenarioId, gate: GateInputFile, adapter: DemoAdapter, baseDirectory = process.cwd()): Promise<ScenarioRunResult> {
  if (gate.version !== 1) throw new Error("gate input version must be 1");
  if (adapter.id !== `${gate.adapter}-stub` && adapter.id !== gate.adapter) throw new Error("injected adapter does not match gate input backend");
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const keyDirectory = pathFrom(baseDirectory, gate.key_dir);
  if (!relative(repo, keyDirectory).startsWith("..")) throw new Error("private key directory must be outside the repository");
  if (scenarioId === "S1") {
    if (!gate.preflight_result_file) throw new Error("S1 requires a green preflight result");
    const preflight = JSON.parse(await readFile(pathFrom(baseDirectory, gate.preflight_result_file), "utf8")) as { ok?: boolean };
    if (preflight.ok !== true) throw new Error("S1 refuses to run without a green preflight");
  }
  const outputDirectory = pathFrom(baseDirectory, gate.output_dir);
  const priorStatePath = pathFrom(baseDirectory, gate.prior_state_file);
  await mkdir(outputDirectory, { recursive: true });
  await ensurePriorState(priorStatePath);
  const bundlePath = join(outputDirectory, `${scenarioId}.cbor`);
  const trustPolicyPath = join(outputDirectory, `${scenarioId}.trust-policy.json`);
  const witnessLogPath = join(outputDirectory, `${scenarioId}.witness.jsonl`);
  const producer = await produce({
    scenarioId, evaluatedAt: gate.evaluated_at, epochId: gate.epoch_id,
    invocationId: fromHex(gate.invocation_id), correlationId: fromHex(gate.correlation_id), tenantId: fromHex(gate.tenant_id), siteId: fromHex(gate.site_id), targetId: fromHex(gate.target_id),
    targetLogicalName: gate.target_logical_name, actionName: gate.action_name, parameters: gate.parameters,
    delegationWindows: gate.delegation_candidates.map((item) => ({ notBefore: item.not_before, notAfter: item.not_after })),
    bundlePath, trustPolicyPath, witnessLogPath, adapter, keys: await loadDemoKeys(keyDirectory),
    journal: new DurableInvocationJournal(join(outputDirectory, "ep.journal.jsonl")),
    anchorLog: new LocalRfc6962Log(join(outputDirectory, "anchor.jsonl")),
  });
  const process = Bun.spawn([
    "python", "-m", "pyref", "verify", bundlePath, "--at", String(gate.evaluated_at),
    "--trust-policy", trustPolicyPath, "--prior-state", priorStatePath,
  ], { cwd: repo, stdout: "pipe", stderr: "pipe" });
  const [exitCode, stdout, stderr] = await Promise.all([process.exited, new Response(process.stdout).text(), new Response(process.stderr).text()]);
  const pyrefOutput = `${stdout}${stderr}`;
  const pyrefOutputPath = join(outputDirectory, `${scenarioId}.pyref.txt`);
  await writeFile(pyrefOutputPath, pyrefOutput);
  if (exitCode !== 0) throw new Error(`pyref verify exited ${exitCode}\n${pyrefOutput}`);
  assertContent(scenarioId, gate, adapter, producer.wire.bundle, pyrefOutput);
  const witness = await new AppendOnlyWitnessLog(witnessLogPath).entries();
  await assertOnlineOracle(scenarioId, gate, producer, witness);
  await advancePriorState(priorStatePath, producer);
  return { scenarioId, bundlePath, trustPolicyPath, pyrefOutputPath, pyrefOutput, producer, witness };
}

if (import.meta.main) {
  const scenarioId = process.argv[2] as ScenarioId | undefined;
  const gateInputPath = process.argv[3];
  if (!scenarioId || !/^S[1-6]$/.test(scenarioId) || !gateInputPath) throw new Error("usage: bun run demo/run-scenario.ts S1..S6 GATE-INPUT.json");
  const absoluteInput = resolve(gateInputPath);
  const gate = JSON.parse(await readFile(absoluteInput, "utf8")) as GateInputFile;
  const adapter = gate.adapter === "vapix" ? createVapixStub() : createVmsStub();
  const result = await runScenario(scenarioId, gate, adapter, dirname(absoluteInput));
  console.log(`scenario ${scenarioId}: conformant + content assertions + online oracle PASS`);
  console.log(`bundle: ${result.bundlePath}`);
  console.log(`pyref report: ${result.pyrefOutputPath}`);
}
