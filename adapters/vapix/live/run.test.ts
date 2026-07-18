import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer, request as httpRequest, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { id16 } from "../../../harness/crypto";
import { toHex } from "../../../harness/cbor";
import { createVapixStub } from "../../../demo/adapters/stub";
import { LocalRfc6962Log, type AnchorLogEntry } from "../../../demo/anchor/log";
import { DurableInvocationJournal } from "../../../demo/ep/journal";
import { produce } from "../../../demo/ep/producer";
import { generateDemoKeys } from "../../../demo/keys/keys";
import { CredStoreProvider } from "../../../demo/preflight";
import { AppendOnlyWitnessLog } from "../../../demo/witness/log";
import { createWitnessProxy } from "../../../demo/witness/proxy";
import { assertVapixConfig } from "../config";
import { ABSENT_PRESET_BACKEND_NAME, SAFE_PRESET_BACKEND_NAME, liveVapixConfig } from "./config";
import { runLiveSuite } from "./run";

function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") return reject(new Error("no port"));
      resolve(address.port);
    });
  });
}

function proxied(proxyPort: number, targetUrl: string, kind: "non-action" | "action-unbound" | "command-bound"): Promise<{ status: number; failed: boolean }> {
  return new Promise((resolve) => {
    let settled = false;
    const settle = (result: { status: number; failed: boolean }): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      resolve(result);
    };
    const headers: Record<string, string> = {
      "x-aar-invocation-id": "test",
      "x-aar-action-bearing": kind === "non-action" ? "0" : "1",
    };
    if (kind === "command-bound") headers["x-aar-command-digest"] = "aa".repeat(32);
    const request = httpRequest({ hostname: "127.0.0.1", port: proxyPort, method: "GET", path: targetUrl, agent: false, headers }, (response) => {
      response.resume();
      response.on("end", () => settle({ status: response.statusCode ?? 0, failed: false }));
    });
    const deadline = setTimeout(() => request.destroy(new Error("client deadline")), 1_500);
    request.on("error", () => settle({ status: 0, failed: true }));
    request.on("close", () => { if (!settled) setTimeout(() => settle({ status: 0, failed: true }), 0); });
    request.end();
  });
}

test("witness fault injection forwards upstream then withholds the response from action-bearing requests only", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-live-fault-"));
  let upstreamHits = 0;
  const upstream = createServer((_request, response) => {
    upstreamHits += 1;
    response.writeHead(200, "OK");
    response.end("ok");
  });
  const upstreamPort = await listen(upstream);
  const logPath = join(root, "witness.jsonl");
  const proxy = createWitnessProxy(logPath, { withholdResponseAfterForward: true });
  const proxyPort = await listen(proxy);
  try {
    const target = `http://127.0.0.1:${upstreamPort}/axis-cgi/com/ptz.cgi?gotoserverpresetname=x`;
    // Non-action (challenge discovery/readback) passes through.
    const nonAction = await proxied(proxyPort, target, "non-action");
    expect(nonAction.failed).toBeFalse();
    expect(nonAction.status).toBe(200);
    // Action-bearing but command-UNbound (the F19 restore) must ALSO pass —
    // the withhold is scoped to the command dispatch only (G5-D2b-004).
    const restore = await proxied(proxyPort, target, "action-unbound");
    expect(restore.failed).toBeFalse();
    expect(restore.status).toBe(200);
    // Command-bound dispatch is forwarded (real) then withheld.
    const dispatch = await proxied(proxyPort, target, "command-bound");
    expect(dispatch.failed).toBeTrue();
    expect(upstreamHits).toBe(3);
    const entries = await new AppendOnlyWitnessLog(logPath).entries();
    expect(entries).toHaveLength(3);
    expect(entries[2]!.action_bearing).toBeTrue();
    expect(entries[2]!.response_line).toStartWith("INJECTED_FAULT_WITHHELD_RESPONSE");
    expect(entries[1]!.response_line).toBe("HTTP/1.1 200 OK");
  } finally {
    proxy.close();
    upstream.close();
  }
});

test("live config passes runtime assertions and the rejection variant swaps only the backend preset name", () => {
  const normal = liveVapixConfig("http://127.0.0.1:1", "/tmp/aar-recovery", { exclusiveControl: true });
  assertVapixConfig(normal);
  expect(normal.presetMappings["gate5-safe"]).toBe(SAFE_PRESET_BACKEND_NAME);
  const rejection = liveVapixConfig("http://127.0.0.1:1", "/tmp/aar-recovery", { rejectionVariant: true, exclusiveControl: true });
  assertVapixConfig(rejection);
  expect(rejection.presetMappings["gate5-safe"]).toBe(ABSENT_PRESET_BACKEND_NAME);
  expect(rejection.presetPositions["gate5-safe"]).toEqual(normal.presetPositions["gate5-safe"]);
  expect(liveVapixConfig("http://127.0.0.1:1", "/tmp/aar-recovery").exclusiveControl).toBeFalse();
});

test("cred store provider resolves secrets through the configured binary without a shell", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-live-cred-"));
  const binary = join(root, "fake-cred");
  await writeFile(binary, "#!/bin/sh\n[ \"$1\" = get ] || exit 2\n[ \"$2\" = test-reference ] || exit 3\nprintf 'test-secret-value\\n'\n");
  await chmod(binary, 0o700);
  const credential = await new CredStoreProvider(binary).get("test-reference");
  expect(credential.secret).toBe("test-secret-value");
});

test("anchor_observed_at threads through produce to the local anchor log (G5-D1-003)", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-live-anchor-"));
  const keys = await generateDemoKeys(join(root, "keys"));
  const anchorPath = join(root, "anchor.jsonl");
  const observedAt = 1_752_800_000;
  await produce({
    scenarioId: "S1", evaluatedAt: observedAt, epochId: 31_000,
    invocationId: id16("live-anchor-invocation"), correlationId: id16("live-anchor-correlation"),
    tenantId: id16("tenant"), siteId: id16("site"), targetId: id16("target"),
    targetLogicalName: "ptz-primary", actionName: "camera.ptz.preset", parameters: { preset_name: "gate5-safe" },
    delegationWindows: [{ notBefore: observedAt - 600, notAfter: observedAt + 600 }],
    bundlePath: join(root, "S1.cbor"), trustPolicyPath: join(root, "S1.policy.json"), witnessLogPath: join(root, "witness.jsonl"),
    journal: new DurableInvocationJournal(join(root, "journal.jsonl")),
    anchorLog: new LocalRfc6962Log(anchorPath), anchorObservedAt: observedAt,
    adapter: createVapixStub(), keys,
  });
  const entries = (await readFile(anchorPath, "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line) as AnchorLogEntry);
  expect(entries).toHaveLength(1);
  expect(entries[0]!.appended_at).toBe(observedAt);
  expect(toHex(id16("live-anchor-invocation"))).toHaveLength(32);
});

test("live suite refuses to run outside the operator exclusive-control window", async () => {
  const previous = process.env.AAR_LIVE_WINDOW;
  delete process.env.AAR_LIVE_WINDOW;
  try {
    await expect(runLiveSuite()).rejects.toThrow("AAR_LIVE_WINDOW=1");
  } finally {
    if (previous !== undefined) process.env.AAR_LIVE_WINDOW = previous;
  }
});
