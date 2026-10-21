import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { fromHex } from "./cbor";

// TEST KEYS ONLY. These deliberately tiny, published private scalars provide
// reproducible KATs and MUST NEVER be used outside this harness. The rp_*
// pair signs the kats/relying-party corpus (D-83 part 9): it is outside the
// LEGACY_FIXTURE_KIDS exclusion and is no operational verifier identity.
const PRIVATE_SCALARS = {
  d77_outsider: "000000000000000000000000000000000000000000000000000000000000000c",
  d77_leaf: "000000000000000000000000000000000000000000000000000000000000000d",
  agent_signing: "0000000000000000000000000000000000000000000000000000000000000001",
  ep_signing: "0000000000000000000000000000000000000000000000000000000000000002",
  authority_signing: "0000000000000000000000000000000000000000000000000000000000000003",
  approver_signing: "0000000000000000000000000000000000000000000000000000000000000004",
  outcome_signing: "0000000000000000000000000000000000000000000000000000000000000005",
  anchor_signing: "0000000000000000000000000000000000000000000000000000000000000006",
  verifier_signing: "0000000000000000000000000000000000000000000000000000000000000007",
  credential_issuing: "0000000000000000000000000000000000000000000000000000000000000008",
  status_signing: "0000000000000000000000000000000000000000000000000000000000000009",
  agent_signing_successor: "000000000000000000000000000000000000000000000000000000000000000a",
  mediator_outcome_signing: "000000000000000000000000000000000000000000000000000000000000000b",
  rp_credential_issuing: "000000000000000000000000000000000000000000000000000000000000000e",
  rp_verifier_signing: "000000000000000000000000000000000000000000000000000000000000000f",
} as const;

export type TestKeyName = keyof typeof PRIVATE_SCALARS;

export interface TestKey {
  name: TestKeyName;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  spki: Uint8Array;
  kid: Uint8Array;
}

// DER SubjectPublicKeyInfo prefix for id-ecPublicKey + prime256v1 followed by
// an uncompressed 65-byte SEC1 public key in a BIT STRING.
const P256_SPKI_PREFIX = fromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200");

export function keyFromScalar(privateKey: Uint8Array): Omit<TestKey, "name"> {
  const publicKey = p256.getPublicKey(privateKey, false);
  const spki = new Uint8Array(P256_SPKI_PREFIX.length + publicKey.length);
  spki.set(P256_SPKI_PREFIX);
  spki.set(publicKey, P256_SPKI_PREFIX.length);
  return { privateKey, publicKey, spki, kid: sha256(spki) };
}

function makeKey(name: TestKeyName, scalar: string): TestKey {
  return { name, ...keyFromScalar(fromHex(scalar)) };
}

export const TEST_KEYS: Readonly<Record<TestKeyName, TestKey>> = Object.freeze(
  Object.fromEntries(
    Object.entries(PRIVATE_SCALARS).map(([name, scalar]) => [name, makeKey(name as TestKeyName, scalar)]),
  ) as Record<TestKeyName, TestKey>,
);
