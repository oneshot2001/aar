// Pinned-input demo bundle builder shared by the golden-digest test and the D5
// CDDL schema oracle (`python3 -B -m pyref.schema_kat`). Run directly to dump
// S1.cbor + S3.cbor into argv[2].
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { p256 } from "@noble/curves/nist.js";
import { fromHex } from "../../harness/cbor";
import { hash } from "../../harness/crypto";
import { LocalRfc6962Log } from "../anchor/log";
import type { DemoKey, DemoKeyRole } from "../keys/keys";
import { DEMO_KEY_ROLES } from "../keys/keys";
import { buildCommandManifest } from "./command-manifest";
import { buildDemoBundle, type WireBuildInput } from "./wire-builder";

const P256_SPKI_PREFIX = fromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200");

function pinnedKey(role: DemoKeyRole): DemoKey {
  const privateKey = hash(new TextEncoder().encode(`golden-key:${role}`));
  const publicKey = p256.getPublicKey(privateKey, false);
  const spki = new Uint8Array(P256_SPKI_PREFIX.length + publicKey.length);
  spki.set(P256_SPKI_PREFIX);
  spki.set(publicKey, P256_SPKI_PREFIX.length);
  return { role, privateKey, publicKey, spki, kid: hash(spki) };
}

const id16 = (label: string) => hash(new TextEncoder().encode(`golden:${label}`)).slice(0, 16);
export const EVALUATED_AT = 1_735_689_800; // corpus lab era

export async function goldenBundle(scenarioId: "S1" | "S3"): Promise<Uint8Array> {
  const keys = Object.fromEntries(DEMO_KEY_ROLES.map((role) => [role, pinnedKey(role)])) as Record<DemoKeyRole, DemoKey>;
  const invocationId = id16(`invocation:${scenarioId}`);
  const command = buildCommandManifest({
    actionName: "camera.ptz.preset", targetId: id16("target"), targetLogicalName: "ptz-primary",
    parameters: { preset: "Home" }, invocationId,
  }, "vapix", "golden/0");
  const input: WireBuildInput = {
    scenarioId, evaluatedAt: EVALUATED_AT, epochId: 1, invocationId,
    correlationId: id16(`correlation:${scenarioId}`), tenantId: id16("tenant"), siteId: id16("site"),
    targetId: id16("target"), targetLogicalName: "ptz-primary", actionName: "camera.ptz.preset",
    parameters: { preset: "Home" },
    sourceDeviceMetadata: { manufacturer: "AXIS", model: "golden", firmware: "0" },
    adapterId: "vapix", command,
    delegationWindows: scenarioId === "S3"
      ? [{ notBefore: EVALUATED_AT - 7200, notAfter: EVALUATED_AT - 3600 }, { notBefore: EVALUATED_AT - 60, notAfter: EVALUATED_AT + 3600 }]
      : [{ notBefore: EVALUATED_AT - 60, notAfter: EVALUATED_AT + 3600 }],
    dispatch: scenarioId === "S1" ? {
      status: 200, responseBodyDigest: hash(new Uint8Array([1])), outcomeLevel: "device_acknowledged",
      outcomeState: "consistent", observationDigest: hash(new Uint8Array([2])),
    } : undefined,
    keys, anchorLog: new LocalRfc6962Log(join(await mkdtemp(join(tmpdir(), "aar-golden-")), "anchor.jsonl")),
    anchorObservedAt: EVALUATED_AT - 39,
  };
  return (await buildDemoBundle(input)).bundle;
}

if (import.meta.main) {
  for (const scenarioId of ["S1", "S3"] as const) {
    await writeFile(join(process.argv[2]!, `${scenarioId}.cbor`), await goldenBundle(scenarioId));
  }
}
