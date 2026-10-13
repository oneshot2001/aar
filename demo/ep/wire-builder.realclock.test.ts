import { expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateDemoKeys } from "../keys/keys";
import { LocalRfc6962Log } from "../anchor/log";
import { buildCommandManifest } from "./command-manifest";
import { buildDemoBundle, REAL_CLOCK_BOUND_SECONDS, type WireBuildInput } from "./wire-builder";
import { decodeCbor } from "../../harness/cbor";

const T0 = 1_800_000_000;
const dir = mkdtempSync(join(tmpdir(), "aar-realclock-"));
const keys = await generateDemoKeys(join(dir, "keys"), join(dir, "public.json"));
const id = new Uint8Array(16).fill(1);
const dispatch = { status: 200, responseBodyDigest: new Uint8Array(32), outcomeLevel: "device_acknowledged", outcomeState: "unknown", observationDigest: new Uint8Array(32) } as const;
function input(): WireBuildInput {
  return {
    scenarioId: "S1", evaluatedAt: T0, epochId: 1, invocationId: id, correlationId: id,
    tenantId: id, siteId: id, targetId: id, targetLogicalName: "ptz-primary", actionName: "camera.ptz.preset",
    parameters: { preset: "Home" }, sourceDeviceMetadata: { manufacturer: "AXIS", model: "test", firmware: "0" }, adapterId: "vapix",
    command: buildCommandManifest({ actionName: "camera.ptz.preset", targetId: id, targetLogicalName: "ptz-primary", parameters: { preset: "Home" }, invocationId: id }, "vapix", "test"),
    delegationWindows: [{ notBefore: T0 - 1, notAfter: T0 + 1 }], keys,
    anchorLog: new LocalRfc6962Log(join(mkdtempSync(join(dir, "log-")), "anchor.jsonl")),
    narrative: { committedAt: T0, observedAt: T0, epochOpenedAt: T0, epochClosedAt: T0, monotonicNs: 10, realClock: true },
    beforeDispatch: async () => ({ dispatch, timing: { dispatchedAt: T0 + 1, outcomeObservedAt: T0 + 5, committedAt: T0 + 6, monotonicNs: 20, anchorObservedAt: T0 + 6 } }),
  };
}
function verify(wire: Awaited<ReturnType<typeof buildDemoBundle>>, at: number) {
  writeFileSync(join(dir, "bundle.cbor"), wire.bundle);
  writeFileSync(join(dir, "trust.json"), JSON.stringify(wire.trustPolicy));
  writeFileSync(join(dir, "prior.json"), JSON.stringify({ entries: [], prior_emissions: [] }));
  const p = Bun.spawnSync(["python3", "-B", "-m", "pyref", "verify", join(dir, "bundle.cbor"), "--at", String(at), "--trust-policy", join(dir, "trust.json"), "--prior-state", join(dir, "prior.json")]);
  return p.stdout.toString() + p.stderr.toString();
}
test("two phases preserve ancestors, delegation at T0, and verify at T1", async () => {
  const i = input();
  let attemptBytes: Uint8Array;
  const callback = i.beforeDispatch!;
  const wire = await buildDemoBundle({ ...i, beforeDispatch: async a => { attemptBytes = a.signed.envelopeBytes; return callback(a); } });
  expect(wire.receipts[3]!.signed.envelopeBytes).toEqual(attemptBytes!);
  expect(wire.receipts.map(r => r.committedAt)).toEqual([T0, T0, T0, T0, T0 + 6, T0 + 6]);
  expect(wire.evaluatedAt).toBe(T0 + 6);
  const bundle = decodeCbor(wire.bundle) as any;
  expect(bundle.created_at).toBe(T0 + 6);
  expect(bundle.trust_inputs.evaluation_time).toBe(T0 + 6);
  expect(wire.receipts[5]!.fields.evidence).toMatchObject({ time: { monotonic_ns: 20 } });
  const output = verify(wire, T0 + 6);
  expect(output).toContain("Result: conformant");
  expect(output).toContain("evaluated_profile: AAR-3");
});
test("single phase after the send fails D-66", async () => {
  const i = input();
  const wire = await buildDemoBundle({ ...i, evaluatedAt: T0 + 6, beforeDispatch: undefined, dispatch,
    delegationWindows: [{ notBefore: T0 - 1, notAfter: T0 + 100 }], anchorObservedAt: T0 + 6,
    narrative: { committedAt: T0 + 6, epochClosedAt: T0 + 6, dispatchedAt: T0 + 1, outcomeObservedAt: T0 + 5 } });
  expect(verify(wire, T0 + 6)).toContain("journal/uncommitted-dispatch");
});
test("bound 60 verifies", async () => {
  expect(REAL_CLOCK_BOUND_SECONDS).toBe(60);
  const wire = await buildDemoBundle({ ...input(), beforeDispatch: async () => ({ dispatch, timing: { dispatchedAt: T0, outcomeObservedAt: T0 + 60, committedAt: T0 + 60, monotonicNs: 20, anchorObservedAt: T0 + 60 } }) });
  expect(verify(wire, T0 + 60)).toContain("Result: conformant");
});
for (const [name, d, o, t] of [["61", 0, 61, 61], ["backwards", -1, -1, -1], ["dispatch before T0", -1, 5, 6], ["outcome before dispatch", 5, 4, 6], ["commit before outcome", 1, 7, 6]] as const) {
  test(`reject ${name}`, async () => {
    await expect(buildDemoBundle({ ...input(), beforeDispatch: async () => ({ dispatch, timing: { dispatchedAt: T0 + d, outcomeObservedAt: T0 + o, committedAt: T0 + t, monotonicNs: 20, anchorObservedAt: T0 + t } }) })).rejects.toThrow();
  });
}
