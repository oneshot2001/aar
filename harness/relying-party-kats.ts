// kats/relying-party rows (D-83 part 11): each row is a bundle, a descriptor,
// an inputs sidecar naming policy / key / exact pin / prior / replay / time
// (null = not supplied), and its policy JSON. One shared key file signs every row.
import { CborValue, decodeCbor, encodeCbor, fromHex, toHex } from "./cbor";
import { deterministicId, domainHash, hash, id16, signDetachedWithKey } from "./crypto";
import { buildFixtures } from "./fixtures";
import { buildD77PositiveFixtures, buildNegativeFixtures } from "./negative-fixtures";
import { AT, PolicyJson, PolicyRoot, rootRecord, rpChain, rpPolicy } from "./relying-party-fixtures";
import { TEST_KEYS, TestKey } from "./testkeys";
import { Obj } from "./verifier";

type Key = Pick<TestKey, "privateKey" | "spki" | "kid">;
import { RpInputs } from "./relying-party-inputs";
export interface RpRow {
  name: string;
  bytes: Uint8Array;
  descriptor: { name: string; expected_code: string | null; expected_result: "conformant" | "nonconformant" | "indeterminate"; expected_step: number | null; mutation_description: string };
  policy: PolicyJson;
  inputs: RpInputs;
  sidecars: Record<string, unknown>; // extra files (pin, prior, replay) by file name
}

const TENANT = id16("tenant:acme-security");
const SITE = id16("site:denver-lab");
const OTHER_SITE = id16("site:rp-second-site");
const ALL_USAGES = ["agent_signing", "ep_signing", "authority_signing", "approver_signing", "outcome_signing", "anchor_signing", "credential_issuing", "status_signing"];
const CREDENTIAL = "application/aar-credential+cbor;v=0.2";

const decode = (bytes: Uint8Array): Obj => decodeCbor(bytes, { strict: true }) as Obj;
const payload = (envelope: CborValue): Obj => decode((envelope as Uint8Array[])[0]!);
const artifacts = (bundle: Obj): Obj => bundle.artifacts as Obj;
const roots = (bundle: Obj): Obj[] => ((bundle.trust_inputs as Obj).trust_store as Obj).roots as Obj[];
const compare = (a: CborValue, b: CborValue): number => toHex(encodeCbor(a)).localeCompare(toHex(encodeCbor(b)));
const without = (value: Obj, field: string): Obj => Object.fromEntries(Object.entries(value).filter(([key]) => key !== field));

function base(): Obj { return decode(buildFixtures().kats.find((kat) => kat.filename === "bundle-valid-subset")!.bytes); }
let negatives: ReturnType<typeof buildNegativeFixtures> | undefined;
function negative(filename: string): Uint8Array { negatives ??= buildNegativeFixtures(); return negatives.filter((fixture) => fixture.filename === filename).at(-1)!.bytes; }

function recalcTrust(bundle: Obj): void {
  const store = (bundle.trust_inputs as Obj).trust_store as Obj;
  store.digest = domainHash("AAR-TRUST-STORE-v1", without(store, "digest"));
}

function addRootRecord(bundle: Obj, kid: Uint8Array, label: string): void {
  roots(bundle).push({ ...roots(bundle)[0]!, root_id: deterministicId(`trust-root:${label}`), root_kid: kid });
  recalcTrust(bundle);
}

function sortBy(list: CborValue[], field: string): void { list.sort((a, b) => compare(payload(a)[field]!, payload(b)[field]!)); }

// A carried credential cloned from the template with that usage; signed by the issuer key.
function addCredential(bundle: Obj, subject: Key, issuer: Key, path: Uint8Array[], templateUsage: string, extra: Obj = {}): Obj {
  const list = artifacts(bundle).credentials as CborValue[];
  const template = list.map(payload).find((p) => p.key_usage === templateUsage)!;
  const fields: Obj = { ...without(template, "credential_id"), subject_kid: subject.kid, public_key: subject.spki, issuer_kid: issuer.kid, path, ...extra };
  const claims: Obj = { credential_id: domainHash("AAR-CREDENTIAL-ID-v1", fields), ...fields };
  list.push(signDetachedWithKey(claims, CREDENTIAL, issuer).envelope);
  sortBy(list, "credential_id");
  return claims;
}

function credentialOf(bundle: Obj, kid: Uint8Array): Obj { return (artifacts(bundle).credentials as CborValue[]).map(payload).find((p) => toHex(p.subject_kid as Uint8Array) === toHex(kid))!; }

function resignCredential(bundle: Obj, kid: Uint8Array, mutate: (claims: Obj) => void): void {
  const list = artifacts(bundle).credentials as CborValue[];
  const index = list.findIndex((entry) => toHex(payload(entry).subject_kid as Uint8Array) === toHex(kid));
  const fields = without(payload(list[index]!), "credential_id"); mutate(fields);
  list[index] = signDetachedWithKey({ credential_id: domainHash("AAR-CREDENTIAL-ID-v1", fields), ...fields }, CREDENTIAL, TEST_KEYS.credential_issuing).envelope;
  sortBy(list, "credential_id");
}

// A refreshed snapshot cloned from the stapled one (sequence + 1), signed by the status issuer.
function addSnapshot(bundle: Obj, mutate: (status: Obj) => void): void {
  const list = artifacts(bundle).status_snapshots as CborValue[];
  const fields = without(payload(list[0]!), "snapshot_id"); fields.sequence = (fields.sequence as number) + 1; mutate(fields);
  list.push(signDetachedWithKey({ snapshot_id: domainHash("AAR-STATUS-ID-v1", fields), ...fields }, "application/aar-status+cbor;v=0.2", TEST_KEYS.status_signing).envelope);
  sortBy(list, "snapshot_id");
}

function countersign(bundle: Obj, mediator: Key): void {
  const attempt = (artifacts(bundle).receipts as CborValue[]).find((entry) => payload(entry).kind === "action_attempt")!;
  const fields: Obj = { v: 2, action_attempt_receipt_digest: hash(encodeCbor(attempt)), command_digest: ((payload(attempt).body as Obj).command as Obj).command_digest!, mediator_observed_at: bundle.created_at! };
  artifacts(bundle).mediator_countersignatures = [signDetachedWithKey({ countersignature_id: domainHash("AAR-MEDIATOR-COUNTERSIGNATURE-ID-v1", fields), ...fields }, "application/aar-mediator-countersignature+cbor;v=0.2", mediator).envelope];
}

// Base bundle plus a second producer root (d77_outsider, self-signed, in the store) that issues the mediator credential.
function twoRootMediator(mediatorFirst: boolean): Obj {
  const bundle = base();
  const outsider = TEST_KEYS.d77_outsider;
  const root = addCredential(bundle, outsider, outsider, [], "credential_issuing");
  addRootRecord(bundle, outsider.kid, "rp-outsider");
  for (let salt = 0; ; salt += 1) {
    const candidate = decode(encodeCbor(bundle));
    const mediator = addCredential(candidate, TEST_KEYS.mediator_outcome_signing, outsider, [root.credential_id as Uint8Array], "outcome_signing", { trust_anchor_id: deterministicId(`trust-anchor:rp-mediator:${salt}`) });
    if (!mediatorFirst || compare(mediator.credential_id!, root.credential_id!) < 0) { countersign(candidate, TEST_KEYS.mediator_outcome_signing); return candidate; }
  }
}

function pinJson(bundle: Obj): Record<string, unknown> {
  const trust = bundle.trust_inputs as Obj; const store = trust.trust_store as Obj;
  const hex = (value: CborValue) => toHex(value as Uint8Array);
  return {
    trust_store: { digest: hex(store.digest), snapshot_id: hex(store.snapshot_id), created_at: store.created_at,
      roots: (store.roots as Obj[]).map((root) => ({ root_id: hex(root.root_id), root_kid: hex(root.root_kid), tenant_id: hex(root.tenant_id), allowed_sites: (root.allowed_sites as Uint8Array[]).map(toHex), allowed_key_usages: root.allowed_key_usages })) },
    expected_anchor_heads: (trust.expected_anchor_heads as Obj[]).map((head) => ({ target_id: hex(head.target_id), observed_at: head.observed_at, tree_size: head.tree_size, root: hex(head.root) })),
    verifier_policy_digest: hex(trust.verifier_policy_digest),
  };
}

export function buildRelyingPartyFixtures(): RpRow[] {
  const producer = (usages = ALL_USAGES, sites = [SITE]): PolicyRoot => rootRecord(TEST_KEYS.credential_issuing.kid, TENANT, sites, usages);
  const outsider = (usages = ALL_USAGES): PolicyRoot => rootRecord(TEST_KEYS.d77_outsider.kid, TENANT, [SITE], usages);
  const omit = (usage: string): PolicyRoot[] => [producer(ALL_USAGES.filter((item) => item !== usage))];
  const rows: RpRow[] = [];
  const row = (name: string, bytes: Uint8Array | Obj, code: string | null, step: number | null, description: string, policyRoots: PolicyRoot[] = [producer()], extra: Partial<RpInputs> = {}, sidecars: Record<string, unknown> = {}): void => {
    const result = code === null ? "conformant" : code === "key/not-found" ? "indeterminate" : "nonconformant";
    rows.push({
      name: `rp-${name}`, bytes: bytes instanceof Uint8Array ? bytes : encodeCbor(bytes),
      descriptor: { name: `rp-${name}`, expected_code: code, expected_result: result, expected_step: step, mutation_description: description },
      policy: rpPolicy(policyRoots),
      inputs: { policy: `rp-${name}.policy.json`, signing_key: "rp-verifier.key", trust_policy: null, prior_state: null, replay_state: null, at: AT, ...extra },
      sidecars,
    });
  };
  const mutated = (mutate: (bundle: Obj) => void, from: Obj = base()): Obj => { mutate(from); return from; };
  const rpLeaf = TEST_KEYS.rp_verifier_signing;
  const epSession = decode(buildD77PositiveFixtures().find((fixture) => fixture.filename === "repair-d77-presentation-ep-session-positive")!.bytes);

  row("positive-strict-subset", mutated((b) => addRootRecord(b, TEST_KEYS.d77_outsider.kid, "rp-unused-second-root")), null, null,
    "The bundle carries two producer roots; the policy lists only the one every carried credential chains to (a strict subset). Conformant, signed by the policy leaf.");
  row("positive-no-verifier-credential", mutated((b) => { const list = artifacts(b).credentials as CborValue[]; list.splice(list.findIndex((e) => payload(e).key_usage === "verifier_signing"), 1); }), null, null,
    "No verifier_signing credential is carried: key/not-found at step 20 without a policy, conformant under one (D-83 part 6 transition i).");
  row("transition-verifier-revoked", negative("repair-d81-status-verifier-revoked"), null, null,
    "A revoked snapshot names the carried corpus verifier credential at the evaluation time: credential/revoked at step 8 without a policy; under one that key signs nothing and the use moved to the leaf (D-83 part 6 transition ii).");
  row("dangling-snapshot-policy-credential", mutated((b) => addSnapshot(b, (s) => { s.status = "revoked"; s.revoked_at = s.produced_at!; s.credential_id = rpChain().leaf.id; })), "credential/revoked", 8,
    "A revoked snapshot names the policy leaf's credential_id, which no bundle carries; the snapshot fails closed as a use at the evaluation time (D-81).");
  row("root-not-accepted", base(), "credential/root-not-accepted", 8,
    "The policy lists a root no carried credential chains to; the producer root is unlisted, so policy acceptance rejects the first carried credential.", [outsider()]);
  row("mediator-root-not-accepted", twoRootMediator(true), "countersign/credential-invalid", 8,
    "The mediator credential chains to a second producer root the policy does not list (its credential sorts first); the mediator mapping applies.");
  for (const [category, usage] of [["ep", "ep_signing"], ["agent", "agent_signing"], ["authority", "authority_signing"], ["approver", "approver_signing"], ["outcome-observer", "outcome_signing"], ["anchor", "anchor_signing"], ["status-issuer", "status_signing"], ["rotation-issuer", "credential_issuing"]] as const) {
    row(`usage-${category}`, base(), "credential/root-not-accepted", 8, `The policy record for the producer root omits ${usage}; the ${category} credential signs an envelope verified at step 6, so its usage must be allowed.`, omit(usage));
  }
  row("usage-embedded-delegation-signer", mutated((b) => { artifacts(b).delegations = []; }), "credential/root-not-accepted", 8,
    "No top-level delegation is carried, so authority_signing is used only by embedded delegations; the policy record omits it.", omit("authority_signing"));
  row("usage-presentation-signer", epSession, "credential/root-not-accepted", 8,
    "The nested presentation is EP-session signed; the policy record omits ep_signing.", omit("ep_signing"));
  row("usage-mediator", twoRootMediator(false), "countersign/credential-invalid", 8,
    "The mediator credential chains to a second producer root whose policy record omits outcome_signing; the corpus outcome observer stays accepted under the first root.", [producer(), outsider(["credential_issuing"])]);
  row("separation-producer-root-verifier-kid", mutated((b) => addRootRecord(b, TEST_KEYS.rp_credential_issuing.kid, "rp-verifier-root-as-producer")), "credential/root-not-accepted", 5,
    "A producer root record carries the policy's verifier_root_kid; step 5 separation, after the per-root tenant/site checks.");
  row("separation-carried-credential-verifier-kid", mutated((b) => addCredential(b, rpLeaf, TEST_KEYS.credential_issuing, [credentialOf(b, TEST_KEYS.credential_issuing.kid).credential_id as Uint8Array], "agent_signing")), "credential/root-not-accepted", 8,
    "A carried agent credential's subject_kid is the policy leaf's kid; step 8 separation.");
  row("separation-mediator-verifier-kid", mutated((b) => { addCredential(b, rpLeaf, TEST_KEYS.credential_issuing, [credentialOf(b, TEST_KEYS.credential_issuing.kid).credential_id as Uint8Array], "outcome_signing"); countersign(b, rpLeaf); }), "countersign/credential-invalid", 8,
    "The mediator credential's subject_kid is the policy leaf's kid and it signs the countersignature; step 8 separation with the mediator mapping.");
  row("flip-site-listed", base(), null, null, "Flip pair: the policy record lists the bundle's site and a second one; conformant.", [producer(ALL_USAGES, [SITE, OTHER_SITE].sort(compare))]);
  row("flip-site-removed", base(), "credential/root-not-accepted", 8, "Flip pair: the same bundle, the bundle's site removed from the policy record; the result flips and the policy digest differs.", [producer(ALL_USAGES, [OTHER_SITE])]);
  const pin = pinJson(base());
  const early: [string, string, string, number][] = [["step2", "cbor-malformed", "cbor/malformed", 2], ["step3", "schema-missing-field", "schema/missing-field", 3]];
  row("early-step1-alone", negative("resource-bundle-too-large"), "resource/bundle-too-large", 1, "Oversized input under a policy: the step-1 verdict carries the policy digest and the leaf kid. The 16 MiB bytes are the negative corpus file, named by the sidecar's bundle field.", undefined, { bundle: "../negative/resource-bundle-too-large.cbor" });
  for (const [label, filename, code, step] of early) {
    row(`early-${label}-alone`, negative(filename), code, step, `Step-${step} failure under a policy: the verdict carries the policy digest and the leaf kid.`);
    row(`early-${label}-pin`, negative(filename), code, step, `Step-${step} failure under a policy with the exact trust-policy pin: the configured trust values replace their sentinels.`, undefined, { trust_policy: `rp-early-${label}-pin.trust-policy.json` }, { [`rp-early-${label}-pin.trust-policy.json`]: pin });
    row(`early-${label}-state`, negative(filename), code, step, `Step-${step} failure under a policy with empty supplied prior and replay state: both digests bind the empty map.`, undefined,
      { prior_state: `rp-early-${label}-state.prior.json`, replay_state: `rp-early-${label}-state.replay.json` }, { [`rp-early-${label}-state.prior.json`]: {}, [`rp-early-${label}-state.replay.json`]: {} });
  }
  row("order-ceiling-before-bad-signature", mutated((b) => { const list = artifacts(b).credentials as CborValue[]; const cose = decodeCbor((list[0] as Uint8Array[])[1]!, { strict: true }) as CborValue[]; const sig = new Uint8Array(cose[3] as Uint8Array); sig[0] = sig[0]! ^ 1; cose[3] = sig; (list[0] as Uint8Array[])[1] = encodeCbor(cose); }), "sig/verify-failed", 6,
    "Ceiling rejection (ep_signing omitted) combined with a corrupted credential signature; step 6 wins.", omit("ep_signing"));
  row("order-ceiling-before-invalid-path", mutated((b) => resignCredential(b, TEST_KEYS.anchor_signing.kid, (c) => { c.path = [deterministicId("rp-missing-issuer")]; })), "credential/path-invalid", 8,
    "Ceiling rejection (ep_signing omitted) combined with a credential path naming no carried credential; path construction precedes root acceptance.", omit("ep_signing"));
  row("order-ceiling-before-role-key-reuse", mutated((b) => addCredential(b, TEST_KEYS.agent_signing_successor, TEST_KEYS.credential_issuing, [credentialOf(b, TEST_KEYS.credential_issuing.kid).credential_id as Uint8Array], "ep_signing")), "credential/role-key-reuse", 8,
    "Ceiling rejection (ep_signing omitted) combined with one kid carried under two roles; role-key separation precedes root acceptance.", omit("ep_signing"));
  row("order-ceiling-before-revoked-snapshot", mutated((b) => addSnapshot(b, (s) => { s.status = "revoked"; s.revoked_at = s.produced_at!; })), "credential/root-not-accepted", 8,
    "Ceiling rejection (ep_signing omitted) combined with a snapshot revoking the EP credential before its uses; root acceptance precedes status snapshots inside step 8.", omit("ep_signing"));
  row("order-separation-before-step5-digest", mutated((b) => { addRootRecord(b, TEST_KEYS.rp_credential_issuing.kid, "rp-verifier-root-as-producer"); (((b.trust_inputs as Obj).trust_store as Obj)).digest = new Uint8Array(32); }), "hash/mismatch", 5,
    "Separation rejection (a producer root is a verifier kid) combined with a wrong trust-store digest; the digest check precedes separation at step 5.");
  row("order-separation-before-step8-path", mutated((b) => addCredential(b, rpLeaf, TEST_KEYS.credential_issuing, [deterministicId("rp-missing-issuer")], "agent_signing")), "credential/path-invalid", 8,
    "Separation rejection (a carried credential is the leaf kid) combined with a path naming no carried credential; path construction precedes separation at step 8.");
  return rows;
}
