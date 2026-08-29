import { existsSync } from "node:fs";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import type { DemoAdapter } from "../../adapters/shared/types";
import { decodeCbor, toHex } from "../../harness/cbor";
import { hash, id16 } from "../../harness/crypto";
import { LocalRfc6962Log } from "../anchor/log";
import { DurableInvocationJournal } from "../ep/journal";
import { produce } from "../ep/producer";
import { generateDemoKeys } from "./keys";
import { mintMediatorCredential } from "./mediator";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const binary = join(repoRoot, "adapters", "vms", "vigil-control", ".build", "debug", "vigil-control");

test.skipIf(!existsSync(binary))("service-owned Swift mediator key produces a conformant D-67 bundle", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-d67-mediator-"));
  const identityDirectory = join(root, "vigil-control");
  const keys = await generateDemoKeys(join(root, "keys"));
  const tenantId = id16("d67-service-tenant");
  const siteId = id16("d67-service-site");
  const evaluatedAt = 8_000_000;
  await mintMediatorCredential({
    binary, identityDirectory, issuer: keys["verifier-trust"], tenantId, siteId, evaluatedAt,
  });
  expect((await stat(join(identityDirectory, "mediator-key.raw"))).mode & 0o777).toBe(0o600);

  const adapter: DemoAdapter = {
    id: "vms",
    version: "d67-swift-test",
    async dispatch(command, context) {
      if (context.actionAttemptReceiptDigestHex === undefined) throw new Error("attempt digest missing");
      const child = Bun.spawn([
        binary, "--sign-test", identityDirectory, context.actionAttemptReceiptDigestHex,
        context.commandDigestHex, String(evaluatedAt),
      ], { stdout: "pipe", stderr: "pipe" });
      const [exitCode, stdout, stderr] = await Promise.all([
        child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
      ]);
      if (exitCode !== 0) throw new Error(`Swift signer failed (${exitCode}): ${stderr}`);
      const signed = JSON.parse(stdout) as { payload: string; cose: string };
      const credentialBytes = await readFile(join(identityDirectory, "credential.cbor"));
      const observationDigest = hash(new TextEncoder().encode("d67-service-observation"));
      return {
        dispatched: true,
        status: 200,
        responseBodyDigest: hash(new TextEncoder().encode("d67-service-response")),
        effect: {
          adapter_id: "vms", invocation_id: context.invocationIdHex,
          command_digest: toHex(command.command_digest), target_logical_name: "fixed-primary",
          observed_at: evaluatedAt, state: "consistent", outcome_level: "device_acknowledged",
          observation_digest: toHex(observationDigest), backend_evidence: { application_status: "media_payload_valid" },
        },
        mediatorCountersignature: {
          envelope: [Uint8Array.from(Buffer.from(signed.payload, "base64")), Uint8Array.from(Buffer.from(signed.cose, "base64"))],
          credentialEnvelope: decodeCbor(credentialBytes, { strict: true }) as readonly import("../../harness/cbor").CborValue[],
        },
      };
    },
  };
  const bundlePath = join(root, "bundle.cbor");
  const trustPolicyPath = join(root, "policy.json");
  await produce({
    scenarioId: "S2", evaluatedAt, epochId: 67,
    invocationId: id16("d67-service-invocation"), correlationId: id16("d67-service-correlation"),
    tenantId, siteId, targetId: id16("d67-service-target"), targetLogicalName: "fixed-primary",
    actionName: "camera.stream.view", parameters: { stream_profile: "overview" },
    delegationWindows: [{ notBefore: evaluatedAt - 600, notAfter: evaluatedAt + 600 }],
    bundlePath, trustPolicyPath, witnessLogPath: join(root, "witness.jsonl"),
    journal: new DurableInvocationJournal(join(root, "journal.jsonl")),
    anchorLog: new LocalRfc6962Log(join(root, "anchor.jsonl")), adapter, keys,
  });
  const pyref = Bun.spawn([
    "python3", "-m", "pyref", "verify", bundlePath, "--at", String(evaluatedAt),
    "--trust-policy", trustPolicyPath,
  ], { cwd: repoRoot, stdout: "pipe", stderr: "pipe" });
  const [exitCode, stdout, stderr] = await Promise.all([
    pyref.exited, new Response(pyref.stdout).text(), new Response(pyref.stderr).text(),
  ]);
  const output = `${stdout}${stderr}`;
  if (exitCode !== 0) throw new Error(`pyref rejected D-67 service bundle (${exitCode}):\n${output}`);
  expect(output).toContain("mediator_countersigned");
}, 30_000);
