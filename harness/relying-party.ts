// Relying-party policy: configuration and the step-8 root-acceptance loop (D-83).
// loadConfiguration validates the policy JSON mirror and the signing key in the
// CONFORMANCE section 6 order before any bundle byte is read; every failure is
// a ConfigurationError (the CLI maps it to exit 2, no verdict). The credential
// checks reuse the verifier's own step-6 envelope validation over the chain.
import { readFileSync } from "node:fs";
import { CborValue, decodeCbor, equalBytes, fromHex, toHex } from "./cbor";
import { domainHash, hash, P256_ORDER } from "./crypto";
import { keyFromScalar, TEST_KEYS } from "./testkeys";
import { B1Failure, bytes, compareEncoded, envelopePayload, EnvelopeContext, failure, object, Obj, Parsed, ParsedEnvelope, parseEnvelope, same, signingTime, verifyEnvelope } from "./verifier";

const POLICY_DOMAIN = "AAR-RP-POLICY-v1";
const KEY_USAGES = ["agent_signing", "ep_signing", "authority_signing", "approver_signing", "outcome_signing", "anchor_signing", "verifier_signing", "credential_issuing", "status_signing"];

// D-83 part 9: the kids of the thirteen v0.2.5 fixture scalars, enumerated by
// kid. A policy chain that reaches one is a usage error. The rp_* fixture pair
// is deliberately absent so the rp-* corpus stays reproducible.
export const LEGACY_FIXTURE_KIDS: ReadonlySet<string> = new Set([
  "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3", // agent_signing
  "dc0ce633dbcc913dafafa4b89ac44d8ce683fdfc3f60c8bdf21213b9f2b534ba", // ep_signing
  "2b985badf1bac8293f6b92e8c0acc1139bc5a5ecbbf97a6271dcf0d4f6c68af6", // authority_signing
  "3eab3fba5026b61d007cbf411b90f3c88ff89cf0a8088cbbfc3eaaca867dd663", // approver_signing
  "dafc418eb082e83c76a48f0c526fe45e9ca4d4ecfa82366de3fccd37099fca01", // outcome_signing
  "e26630d1233ed92d8ac231a4bf230fddb2d924d6eace7489946e1e82e9523a70", // anchor_signing
  "11086649cd3e5d1892200a4200b165bbea5c9f9b47ca83792d4f9a1ef0dc8921", // verifier_signing
  "8449111985c4e015d12e2c0b4847278c9d9e5f84a383fd4056a6d89bab795c5d", // credential_issuing
  "e3615fff37474c561c068d1f56f5ec3751cd7eb2ea7046c016a142c932865496", // status_signing
  "f0f6a0003fd9e94ffb16e2206cfdf272ef2e8860d73f32704b5f365b45505138", // agent_signing_successor
  "21af110aa3ea3b9705cc6374830ce5bda521d901c5215f88604cc78385845dc0", // mediator_outcome_signing
  "06bd70e0b4fcc9277de14317373dcf86f8fbeb48d8a52513f726059488c1d768", // d77_outsider
  "c379f258d6ad972fdc80a8574dad37651dd58620a0ccd0808113be2ff6b37de9", // d77_leaf
]);

export class ConfigurationError extends Error {}

export interface Configuration {
  privateKey: Uint8Array;
  kid: Uint8Array;
  policyDigest: Uint8Array;
  verifierKids: ReadonlySet<string>;
  roots: ReadonlyMap<string, Obj>;
}

function fail(message: string): never { throw new ConfigurationError(message); }

function closed(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    fail(`${label} must be a JSON object with exactly ${keys.join(", ")}`);
  }
  return value as Record<string, unknown>;
}

function hex(value: unknown, size: number | undefined, label: string): Uint8Array {
  if (typeof value !== "string" || value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/u.test(value)) fail(`${label} must be a hex string`);
  const decoded = fromHex(value as string);
  if (size !== undefined && decoded.length !== size) fail(`${label} must decode to exactly ${size} bytes`);
  return decoded;
}

// Read the JSON mirror and return the relying-party-policy CBOR map.
function loadPolicy(path: string): Obj {
  let source: unknown; let vSource: string | undefined;
  // The reviver's source text tells the integer 1 apart from 1.0 (JSON numbers are doubles once parsed).
  try { source = JSON.parse(readFileSync(path, "utf8"), function (key, value, context?: { source?: string }) { if (key === "v" && Object.hasOwn(this, "artifact_roots")) vSource = context?.source; return value; }); } catch (error) { fail(`cannot read policy file ${path}: ${(error as Error).message}`); }
  const policy = closed(source, ["v", "artifact_roots", "verifier_root_kid", "verifier_credentials"], "policy");
  if (policy.v !== 1 || vSource !== "1") fail("policy.v must be the integer 1");
  const rootsSource = policy.artifact_roots;
  if (!Array.isArray(rootsSource) || rootsSource.length < 1 || rootsSource.length > 64) fail("policy.artifact_roots must contain 1 to 64 entries");
  const roots = (rootsSource as unknown[]).map((item, index) => {
    const label = `policy.artifact_roots[${index}]`;
    const root = closed(item, ["root_kid", "tenant_id", "allowed_sites", "allowed_key_usages"], label);
    const sites = root.allowed_sites; const usages = root.allowed_key_usages;
    if (!Array.isArray(sites) || sites.length < 1 || sites.length > 256) fail(`${label}.allowed_sites must contain 1 to 256 entries`);
    if (!Array.isArray(usages) || usages.length < 1 || usages.length > 8 || usages.some((usage) => typeof usage !== "string" || !KEY_USAGES.includes(usage))) fail(`${label}.allowed_key_usages must be 1 to 8 key usages`);
    const record = {
      root_kid: hex(root.root_kid, 32, `${label}.root_kid`), tenant_id: hex(root.tenant_id, 16, `${label}.tenant_id`),
      allowed_sites: (sites as unknown[]).map((site, i) => hex(site, 16, `${label}.allowed_sites[${i}]`)), allowed_key_usages: usages as string[],
    };
    // D-83 amendment a: the step-3 trust-root rule (deterministic-encoding order).
    for (const name of ["allowed_sites", "allowed_key_usages"] as const) {
      if (record[name].some((value: CborValue, i: number) => i > 0 && compareEncoded(record[name][i - 1]!, value) >= 0)) fail(`${label}.${name} must be strictly sorted and unique`);
    }
    return record;
  });
  const kids = roots.map((root) => toHex(root.root_kid));
  if (kids.some((kid, index) => index > 0 && kids[index - 1]! >= kid)) fail("policy.artifact_roots must be strictly sorted and unique by root_kid");
  const credentialsSource = policy.verifier_credentials;
  if (!Array.isArray(credentialsSource) || credentialsSource.length < 1 || credentialsSource.length > 9) fail("policy.verifier_credentials must contain 1 to 9 entries");
  const credentials = (credentialsSource as unknown[]).map((item, index) => {
    const label = `policy.verifier_credentials[${index}]`;
    try { return decodeCbor(hex(item, undefined, label), { strict: true }); } catch (error) { return fail(`${label}: ${(error as Error).message}`); }
  });
  return { v: 1, artifact_roots: roots, verifier_root_kid: hex(policy.verifier_root_kid, 32, "policy.verifier_root_kid"), verifier_credentials: credentials };
}

// D-83 amendment b: the exact file text, 64 lowercase hex characters then at most one LF or CRLF.
const KEY_FILE = /^[0-9a-f]{64}(\r?\n)?$/u;

function scalar(path: string): Uint8Array {
  let text = "";
  try { text = readFileSync(path, "utf8"); } catch (error) { fail(`cannot read signing key file ${path}: ${(error as Error).message}`); }
  if (!KEY_FILE.test(text)) fail("signing key file must hold exactly 64 lowercase hexadecimal characters, then at most one LF or CRLF");
  const d = BigInt(`0x${text.slice(0, 64)}`);
  if (d < 1n || d >= P256_ORDER) fail("signing key scalar must satisfy 1 <= d < n");
  return fromHex(text.slice(0, 64));
}

// CONFORMANCE section 6 chain algorithm; returns leaf-first members.
function chain(policy: Obj, kid: Uint8Array, evaluationTime: number): Obj[] {
  const envelopes = policy.verifier_credentials as CborValue[];
  const credentialsByKid = new Map<string, Obj>();
  for (const entry of envelopes) {
    const payload = envelopePayload(entry);
    if (object(payload) && payload.subject_kid instanceof Uint8Array && !credentialsByKid.has(toHex(payload.subject_kid))) credentialsByKid.set(toHex(payload.subject_kid), payload);
  }
  const context: EnvelopeContext = { credentialsByKid, credentials: [], selector: { tenant_id: new Uint8Array(16), site_id: new Uint8Array(16) }, evaluationTime };
  const members = envelopes.map((entry, index) => {
    const parsed = parseEnvelope(entry, "credential", `policy.verifier_credentials[${index}]`);
    const issue = "ok" in parsed ? parsed : verifyEnvelope(parsed, context);
    if (issue !== undefined) fail(`policy.verifier_credentials: ${issue.reason}`);
    return (parsed as ParsedEnvelope).payload;
  });
  const ids = members.map((member) => toHex(member.credential_id as Uint8Array));
  if (ids.some((id, index) => index > 0 && ids[index - 1]! >= id)) fail("policy.verifier_credentials must be strictly sorted and unique by credential_id");
  const leaves = members.filter((member) => same(member.subject_kid, kid));
  if (leaves.length !== 1) fail("signing key matches no single policy.verifier_credentials entry");
  for (const member of members) {
    const { credential_id, ...fields } = member;
    if (!same(credential_id, domainHash("AAR-CREDENTIAL-ID-v1", fields))) fail("policy.verifier_credentials: credential_id does not recompute");
    if (!same(hash(member.public_key as Uint8Array), member.subject_kid)) fail("policy.verifier_credentials: public_key does not hash to subject_kid");
    if (!same(member.tenant_id, new Uint8Array(16)) || !same(member.site_id, new Uint8Array(16))) fail("policy.verifier_credentials: tenant_id and site_id must be all-zero");
    if (!((member.valid_from as number) <= evaluationTime && evaluationTime < (member.valid_until as number))) fail("policy.verifier_credentials: a member is not valid at the evaluation time");
    if (!(member.path as CborValue[]).every((item) => bytes(item, 32))) fail("policy.verifier_credentials: every path element must be a 32-byte byte string"); // typed before any lookup
  }
  const leaf = leaves[0]!;
  const path = leaf.path as CborValue[];
  if (leaf.key_usage !== "verifier_signing" || leaf.principal_role !== "verifier" || path.length === 0) fail("the leaf must have key_usage verifier_signing, principal_role verifier and a non-empty path");
  const byId = new Map(members.map((member) => [toHex(member.credential_id as Uint8Array), member]));
  const links = [leaf];
  for (const [depth, credentialId] of path.entries()) {
    const parent = byId.get(toHex(credentialId as Uint8Array));
    if (parent === undefined || !same(parent.subject_kid, links[links.length - 1]!.issuer_kid) || !same(parent.path, path.slice(depth + 1))) fail("policy.verifier_credentials: the leaf path does not resolve");
    links.push(parent);
  }
  if (new Set(links.map((member) => toHex(member.subject_kid as Uint8Array))).size !== links.length) fail("policy.verifier_credentials: a subject_kid repeats in the chain");
  if (links.slice(1).some((member) => member.key_usage !== "credential_issuing")) fail("every chain member except the leaf must have key_usage credential_issuing");
  const root = links[links.length - 1]!;
  if (!same(root.subject_kid, root.issuer_kid) || !same(root.subject_kid, policy.verifier_root_kid)) fail("the terminal credential must be self-signed by verifier_root_kid");
  if (links.length !== members.length) fail("policy.verifier_credentials must be exactly the leaf plus the credentials its path names");
  return links;
}

// Validate policy and key together, before the bundle; undefined when neither is supplied.
export function loadConfiguration(policyPath: string | undefined, keyPath: string | undefined, evaluationTime: number): Configuration | undefined {
  if ((policyPath === undefined) !== (keyPath === undefined)) fail("--policy and --signing-key must be supplied together");
  if (policyPath === undefined) return undefined;
  const policy = loadPolicy(policyPath);
  const key = keyFromScalar(scalar(keyPath!));
  const links = chain(policy, key.kid, evaluationTime);
  const verifierKids = new Set([toHex(policy.verifier_root_kid as Uint8Array), ...links.map((member) => toHex(member.subject_kid as Uint8Array))]);
  if ([...verifierKids].some((kid) => LEGACY_FIXTURE_KIDS.has(kid))) fail("policy chain contains a published fixture key");
  return {
    privateKey: key.privateKey, kid: key.kid, policyDigest: domainHash(POLICY_DOMAIN, policy), verifierKids,
    roots: new Map((policy.artifact_roots as Obj[]).map((root) => [toHex(root.root_kid as Uint8Array), root])),
  };
}

// The verdict signing key: the configured leaf under a policy, else the corpus verifier (D-83 part 5).
export function signerKey(configuration: Configuration | undefined): Pick<Configuration, "privateKey" | "kid"> {
  return configuration ?? TEST_KEYS.verifier_signing;
}

// D-81: every step-6 envelope uses its signer's key at its signing time; the
// step-6 signer set is captured before the verifier's own evaluation-time use
// (step 20) is added under the signing kid (D-83 part 5), which a D-87 retained
// bundle never gets (no verdict is signed over it).
export function signerUses(parsed: Parsed, evaluation: number, configuration: Configuration | undefined, verifierUse: boolean): { uses: Map<string, number[]>; usedKids: Set<string> } {
  const uses = new Map<string, number[]>();
  for (const item of Object.values(parsed).flat()) {
    const entry = "delegation" in item ? item.delegation : item;
    const kid = toHex(entry.kid);
    uses.set(kid, [...(uses.get(kid) ?? []), signingTime(entry, evaluation) as number]);
  }
  const usedKids = new Set(uses.keys());
  const verifierKid = toHex(signerKey(configuration).kid);
  if (verifierUse) uses.set(verifierKid, [...(uses.get(verifierKid) ?? []), evaluation]);
  return { uses, usedKids };
}

// Step 20: without a policy the corpus verifier key resolves from bundle
// credentials (D-58, D-73 find-first); under a policy no bundle credential is
// consulted (D-83 part 5).
export function verifierIdentity(parsed: Parsed, configuration: Configuration | undefined): B1Failure | undefined {
  if (configuration !== undefined) return undefined;
  const credential = parsed.credential.find((entry) => equalBytes(entry.payload.subject_kid as Uint8Array, TEST_KEYS.verifier_signing.kid));
  return credential === undefined || credential.payload.key_usage !== "verifier_signing" ? failure(20, "key/not-found", "verifier_signing", true) : undefined;
}

function accepts(root: Obj | undefined, credential: Obj, used: boolean): boolean {
  return root !== undefined && same(root.tenant_id, credential.tenant_id)
    && Array.isArray(root.allowed_sites) && root.allowed_sites.some((site) => same(site, credential.site_id))
    && (!used || (Array.isArray(root.allowed_key_usages) && credential.key_usage !== undefined && root.allowed_key_usages.includes(credential.key_usage)));
}

// Step 8 per carried credential: separation, producer acceptance, policy acceptance (D-83 part 4).
export function acceptRoots(configuration: Configuration | undefined, credentials: readonly ParsedEnvelope[], byId: ReadonlyMap<string, ParsedEnvelope>, roots: readonly Obj[], usedKids: ReadonlySet<string>, mediatorKids: ReadonlySet<string>): B1Failure | undefined {
  for (const entry of credentials) {
    const payload = entry.payload;
    const kid = toHex(payload.subject_kid as Uint8Array);
    const code = mediatorKids.has(kid) ? "countersign/credential-invalid" : "credential/root-not-accepted";
    const path = payload.path as CborValue[];
    const terminal = path.length === 0 ? payload : byId.get(toHex(path[path.length - 1] as Uint8Array))?.payload;
    const used = usedKids.has(kid);
    if (configuration !== undefined && configuration.verifierKids.has(kid)) return failure(8, code, "credential.subject_kid");
    if (terminal === undefined || !accepts(roots.find((root) => same(root.root_kid, terminal.subject_kid)), payload, used)) return failure(8, code, "credential.path");
    if (configuration !== undefined && !accepts(configuration.roots.get(toHex(terminal.subject_kid as Uint8Array)), payload, used)) return failure(8, code, "credential.path");
  }
  return undefined;
}
