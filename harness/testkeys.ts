import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { fromHex } from "./cbor";

// TEST KEYS ONLY. These deliberately tiny, published private scalars provide
// reproducible KATs and MUST NEVER be used outside this harness.
const PRIVATE_SCALARS = {
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

function makeKey(name: TestKeyName, scalar: string): TestKey {
  const privateKey = fromHex(scalar);
  const publicKey = p256.getPublicKey(privateKey, false);
  const spki = new Uint8Array(P256_SPKI_PREFIX.length + publicKey.length);
  spki.set(P256_SPKI_PREFIX);
  spki.set(publicKey, P256_SPKI_PREFIX.length);
  return { name, privateKey, publicKey, spki, kid: sha256(spki) };
}

export const TEST_KEYS: Readonly<Record<TestKeyName, TestKey>> = Object.freeze(
  Object.fromEntries(
    Object.entries(PRIVATE_SCALARS).map(([name, scalar]) => [name, makeKey(name as TestKeyName, scalar)]),
  ) as Record<TestKeyName, TestKey>,
);
