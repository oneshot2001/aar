import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CborValue } from "../../harness/cbor";
import { encodeCbor, fromHex, toHex } from "../../harness/cbor";
import { domainHash, hash } from "../../harness/crypto";
import { signDemoDetached } from "../ep/signing";
import { buildDemoCredentialFields } from "../ep/wire-builder";
import type { DemoKey, DemoSigningKey } from "./keys";

type Obj = Record<string, CborValue>;

function opaque(label: string): Uint8Array {
  return hash(new TextEncoder().encode(`AAR-DEMO-OPAQUE-ID:${label}`));
}

interface MediatorPublicIdentity {
  readonly version: 1;
  readonly kid: string;
  readonly spki: string;
}

export interface MintMediatorCredentialInput {
  readonly binary: string;
  readonly identityDirectory: string;
  readonly issuer: DemoKey;
  readonly tenantId: Uint8Array;
  readonly siteId: Uint8Array;
  readonly evaluatedAt: number;
}

export interface BuildMediatorCredentialInput {
  readonly identity: Pick<DemoSigningKey, "kid" | "spki">;
  readonly issuer: DemoKey;
  readonly tenantId: Uint8Array;
  readonly siteId: Uint8Array;
  readonly evaluatedAt: number;
}

export function buildMediatorCredential(input: BuildMediatorCredentialInput): readonly CborValue[] {
  const trustAnchorId = opaque(`trust-anchor:${toHex(input.issuer.kid)}`);
  const rootFields = buildDemoCredentialFields({
    subject: input.issuer, issuerKid: input.issuer.kid,
    principalType: "authority_source", principalRole: "authority_source", keyUsage: "credential_issuing",
    tenantId: input.tenantId, siteId: input.siteId, evaluatedAt: input.evaluatedAt,
    trustAnchorId, path: [],
  });
  const fields = buildDemoCredentialFields({
    subject: input.identity, issuerKid: input.issuer.kid,
    principalType: "service", principalRole: "outcome_observer", keyUsage: "outcome_signing",
    tenantId: input.tenantId, siteId: input.siteId, evaluatedAt: input.evaluatedAt,
    trustAnchorId, path: [domainHash("AAR-CREDENTIAL-ID-v1", rootFields)],
  });
  const payload: Obj = { credential_id: domainHash("AAR-CREDENTIAL-ID-v1", fields), ...fields };
  return signDemoDetached(payload, "application/aar-credential+cbor;v=0.2", input.issuer).envelope;
}

export async function mintMediatorCredential(input: MintMediatorCredentialInput): Promise<Uint8Array> {
  await mkdir(input.identityDirectory, { recursive: true, mode: 0o700 });
  const child = Bun.spawn([input.binary, "--mint-key", input.identityDirectory], { stdout: "pipe", stderr: "pipe" });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (exitCode !== 0) throw new Error(`vigil-control mediator keygen failed (${exitCode}): ${stdout}${stderr}`);
  const identity = JSON.parse(await readFile(join(input.identityDirectory, "public.json"), "utf8")) as MediatorPublicIdentity;
  if (identity.version !== 1 || !/^[0-9a-f]{64}$/u.test(identity.kid) || !/^[0-9a-f]+$/u.test(identity.spki)) {
    throw new Error("vigil-control public identity is malformed");
  }
  const envelope = buildMediatorCredential({
    identity: { kid: fromHex(identity.kid), spki: fromHex(identity.spki) },
    issuer: input.issuer, tenantId: input.tenantId, siteId: input.siteId, evaluatedAt: input.evaluatedAt,
  });
  const bytes = encodeCbor(envelope);
  await writeFile(join(input.identityDirectory, "credential.cbor"), bytes, { mode: 0o644 });
  return bytes;
}
