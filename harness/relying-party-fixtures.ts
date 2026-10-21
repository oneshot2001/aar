// Relying-party policy fixtures (D-83): the rp_* chain, the policy JSON
// mirror, and the CONFORMANCE section 6 failure table that both loaders and
// both CLIs are tested against.
import { CborValue, decodeCbor, encodeCbor, fromHex, toHex } from "./cbor";
import { deterministicId, domainHash, id16, signDetachedWithKey } from "./crypto";
import { keyFromScalar, TEST_KEYS, TestKey } from "./testkeys";

type Obj = Record<string, CborValue>;
type Key = Pick<TestKey, "privateKey" | "spki" | "kid">;

export const AT = 1_735_689_800;
const BASE_TIME = 1_735_689_600;
const CREDENTIAL = "application/aar-credential+cbor;v=0.2";
export const RP_KEY_HEX = "000000000000000000000000000000000000000000000000000000000000000f";
const P256_N = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const OUTSIDER = keyFromScalar(fromHex("0000000000000000000000000000000000000000000000000000000000000010"));

export interface PolicyRoot { root_kid: string; tenant_id: string; allowed_sites: string[]; allowed_key_usages: string[] }
export interface PolicyJson { v: 1; artifact_roots: PolicyRoot[]; verifier_root_kid: string; verifier_credentials: string[] }
export interface PolicyCase { name: string; policy: PolicyJson | string | undefined; key: string | undefined }

export function rpCredential(subject: Key, issuer: Key, path: Uint8Array[], extra: Obj = {}, contentType = CREDENTIAL): { id: Uint8Array; envelope: CborValue[]; fields: Obj } {
  const fields: Obj = {
    v: 2, subject_kid: subject.kid, public_key: subject.spki, issuer_kid: issuer.kid, principal_type: "service",
    principal_role: path.length ? "verifier" : "authority_source", tenant_id: new Uint8Array(16), site_id: new Uint8Array(16),
    valid_from: BASE_TIME - 86400, valid_until: BASE_TIME + 86400 * 30, cose_alg: -7, curve: "P-256",
    key_usage: path.length ? "verifier_signing" : "credential_issuing", trust_anchor_id: deterministicId("trust-anchor:relying-party-root"), path,
    profile_limits: { profile: "AAR-1", status_max_age_s: 86400, lease_max_s: 86400, anchor_max_cadence_s: 86400 }, ...extra,
  };
  const id = (extra.credential_id as Uint8Array | undefined) ?? domainHash("AAR-CREDENTIAL-ID-v1", fields);
  const { credential_id: _, ...rest } = fields;
  return { id, fields, envelope: signDetachedWithKey({ credential_id: id, ...rest }, contentType, issuer).envelope };
}

export function policyJson(roots: PolicyRoot[], credentials: CborValue[][], verifierRootKid: Uint8Array): PolicyJson {
  const byId = (envelope: CborValue[]): string => toHex((decodeCbor(envelope[0] as Uint8Array, { strict: true }) as Obj).credential_id as Uint8Array);
  return {
    v: 1, artifact_roots: [...roots].sort((a, b) => a.root_kid.localeCompare(b.root_kid)), verifier_root_kid: toHex(verifierRootKid),
    verifier_credentials: [...credentials].sort((a, b) => byId(a).localeCompare(byId(b))).map((envelope) => toHex(encodeCbor(envelope))),
  };
}

export function rootRecord(rootKid: Uint8Array, tenant: Uint8Array, sites: Uint8Array[], usages: string[]): PolicyRoot {
  return { root_kid: toHex(rootKid), tenant_id: toHex(tenant), allowed_sites: sites.map(toHex), allowed_key_usages: usages };
}

// The corpus relying-party chain: rp_verifier_signing leaf under the
// self-signed rp_credential_issuing root, all-zero tenant and site.
export function rpPolicy(roots: PolicyRoot[], leafExtra: Obj = {}): PolicyJson {
  const root = rpCredential(TEST_KEYS.rp_credential_issuing, TEST_KEYS.rp_credential_issuing, []);
  const leaf = rpCredential(TEST_KEYS.rp_verifier_signing, TEST_KEYS.rp_credential_issuing, [root.id], leafExtra);
  return policyJson(roots, [root.envelope, leaf.envelope], TEST_KEYS.rp_credential_issuing.kid);
}

export const SAMPLE_ROOTS: PolicyRoot[] = [rootRecord(OUTSIDER.kid, id16("tenant:acme-security"), [id16("site:denver-lab")], ["agent_signing", "credential_issuing"])];

// Every entry is a usage error on both sides (CONFORMANCE section 6; design section 4 item 4).
export function policyCases(): PolicyCase[] {
  const rpRoot = TEST_KEYS.rp_credential_issuing; const rpLeaf = TEST_KEYS.rp_verifier_signing;
  const root = rpCredential(rpRoot, rpRoot, []);
  const leaf = (extra: Obj = {}, contentType?: string) => rpCredential(rpLeaf, rpRoot, [root.id], extra, contentType);
  const policy = (credentials: CborValue[][], verifierRootKid = rpRoot.kid, roots = SAMPLE_ROOTS): PolicyJson => policyJson(roots, credentials, verifierRootKid);
  const two = policy([root.envelope, leaf().envelope]);
  const withKey = (name: string, policyValue: PolicyJson | string | undefined, key: string | undefined = RP_KEY_HEX): PolicyCase => ({ name, policy: policyValue, key });
  const intermediate = (key: Key, extra: Obj = {}) => rpCredential(key, rpRoot, [root.id], { principal_role: "authority_source", key_usage: "credential_issuing", ...extra });
  const threeChain = (middleKey: Key, extra: Obj = {}) => {
    const middle = intermediate(middleKey, extra);
    return policy([root.envelope, middle.envelope, rpCredential(rpLeaf, middleKey, [middle.id, root.id]).envelope]);
  };
  return [
    withKey("policy-not-json", "{"),
    withKey("malformed-policy", { ...two, artifact_roots: undefined as unknown as PolicyRoot[] }),
    withKey("unsorted-artifact-roots", { ...two, artifact_roots: [...SAMPLE_ROOTS, rootRecord(rpRoot.kid, id16("t"), [id16("s")], ["ep_signing"])].sort((a, b) => b.root_kid.localeCompare(a.root_kid)) }),
    withKey("duplicate-root-kid", { ...two, artifact_roots: [...SAMPLE_ROOTS, ...SAMPLE_ROOTS] }),
    withKey("unsorted-verifier-credentials", { ...two, verifier_credentials: [...two.verifier_credentials].reverse() }),
    withKey("key-matches-no-leaf", two, "0000000000000000000000000000000000000000000000000000000000000010"),
    withKey("leaf-expired", policy([root.envelope, leaf({ valid_until: AT - 100 }).envelope])),
    withKey("leaf-valid-until-boundary", policy([root.envelope, leaf({ valid_until: AT }).envelope])),
    withKey("leaf-not-yet-valid", policy([root.envelope, leaf({ valid_from: AT + 1 }).envelope])),
    withKey("broken-path", policy([root.envelope, rpCredential(rpLeaf, rpRoot, [deterministicId("rp-missing-issuer")]).envelope])),
    withKey("issuer-path-not-suffix", threeChain(OUTSIDER, { path: [deterministicId("rp-wrong-suffix")] })),
    withKey("duplicate-intermediate-subject-kid", threeChain(rpRoot)),
    withKey("intermediate-wrong-usage", threeChain(OUTSIDER, { key_usage: "verifier_signing" })),
    withKey("wrong-content-type", policy([root.envelope, leaf({}, "application/aar-status+cbor;v=0.2").envelope])),
    withKey("extra-credential", policy([root.envelope, leaf().envelope, rpCredential(OUTSIDER, rpRoot, [root.id]).envelope])),
    withKey("terminal-not-self-signed", policy([rpCredential(rpRoot, OUTSIDER, []).envelope, rpCredential(OUTSIDER, OUTSIDER, []).envelope, leaf().envelope])),
    withKey("verifier-root-kid-mismatch", policy([root.envelope, leaf().envelope], OUTSIDER.kid)),
    withKey("nonzero-tenant", policy([root.envelope, leaf({ tenant_id: id16("tenant:acme-security") }).envelope])),
    withKey("leaf-wrong-usage", policy([root.envelope, leaf({ key_usage: "credential_issuing" }).envelope])),
    withKey("leaf-wrong-role", policy([root.envelope, leaf({ principal_role: "agent" }).envelope])),
    withKey("leaf-empty-path", policy([root.envelope, rpCredential(rpLeaf, rpRoot, [], { key_usage: "verifier_signing", principal_role: "verifier" }).envelope])),
    withKey("credential-id-mismatch", policy([root.envelope, leaf({ credential_id: deterministicId("rp-wrong-credential-id") }).envelope])),
    withKey("hygiene-legacy-chain", (() => {
      const legacyRoot = rpCredential(TEST_KEYS.credential_issuing, TEST_KEYS.credential_issuing, []);
      return policy([legacyRoot.envelope, rpCredential(TEST_KEYS.verifier_signing, TEST_KEYS.credential_issuing, [legacyRoot.id]).envelope], TEST_KEYS.credential_issuing.kid);
    })(), "0000000000000000000000000000000000000000000000000000000000000007"),
    withKey("key-not-hex", two, "zz".repeat(32)),
    withKey("key-uppercase-hex", two, RP_KEY_HEX.toUpperCase()),
    withKey("key-zero", two, "00".repeat(32)),
    withKey("key-ge-n", two, P256_N),
    { name: "policy-without-key", policy: two, key: undefined },
    { name: "key-without-policy", policy: undefined, key: RP_KEY_HEX },
  ];
}
