import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { CborValue, decodeCbor, encodeCbor, equalBytes } from "./cbor";
import { TEST_KEYS, TestKey, TestKeyName } from "./testkeys";

export const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
export const P256_HALF_ORDER = P256_ORDER >> 1n;

const ARTIFACT_CONTENT_TYPES = new Set([
  "application/aar-request+cbor;v=0.2",
  "application/aar-delegation+cbor;v=0.2",
  "application/aar-credential+cbor;v=0.2",
  "application/aar-status+cbor;v=0.2",
  "application/aar-rotation+cbor;v=0.2",
  "application/aar-presentation+cbor;v=0.2",
  "application/aar-epoch-event+cbor;v=0.2",
  "application/aar-epoch-manifest+cbor;v=0.2",
  "application/aar-anchor-record+cbor;v=0.2",
  "application/aar-merkle-batch+cbor;v=0.2",
]);
const RECEIPT_CONTENT_TYPE = "application/aar-receipt+cbor;v=0.2";

export function hash(...parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const input = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    input.set(part, offset);
    offset += part.length;
  }
  return sha256(input);
}

export function domainHash(domain: string, ...values: readonly CborValue[]): Uint8Array {
  return hash(encodeCbor([domain, ...values]));
}

export function deterministicId(label: string): Uint8Array {
  return hash(new TextEncoder().encode(`AAR-KAT-OPAQUE-ID:${label}`));
}

export function id16(label: string): Uint8Array {
  return deterministicId(label).slice(0, 16);
}

export interface SignedEnvelope {
  envelope: CborValue[];
  envelopeBytes: Uint8Array;
  payload: CborValue;
  payloadBytes: Uint8Array;
  protectedBytes: Uint8Array;
  coseBytes: Uint8Array;
  signature: Uint8Array;
  signer: TestKeyName;
  contentType: string;
}

function compactSignature(digest: Uint8Array, key: TestKey): Uint8Array {
  return p256.sign(digest, key.privateKey, { prehash: false, lowS: true, format: "compact", extraEntropy: false });
}

export function signDetached(
  payload: CborValue,
  contentType: string,
  signer: TestKeyName,
  extraProtected: readonly (readonly [number, CborValue])[] = [],
): SignedEnvelope {
  const key = TEST_KEYS[signer];
  const protectedMap = new Map<number, CborValue>([
    [1, -7],
    [3, contentType],
    [4, key.kid],
    ...extraProtected,
  ]);
  const protectedBytes = encodeCbor(protectedMap);
  const payloadBytes = encodeCbor(payload);
  const sigStructure = encodeCbor(["Signature1", protectedBytes, new Uint8Array(), payloadBytes]);
  const signature = compactSignature(hash(sigStructure), key);
  const cose: CborValue[] = [protectedBytes, {}, null, signature];
  const coseBytes = encodeCbor(cose);
  const envelope: CborValue[] = [payloadBytes, coseBytes];
  return {
    envelope,
    envelopeBytes: encodeCbor(envelope),
    payload,
    payloadBytes,
    protectedBytes,
    coseBytes,
    signature,
    signer,
    contentType,
  };
}

export function signatureScalars(signature: Uint8Array): { r: bigint; s: bigint } {
  if (signature.length !== 64) throw new Error("P1363 signature is not 64 bytes");
  const integer = (bytes: Uint8Array): bigint => BigInt(`0x${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`);
  return { r: integer(signature.slice(0, 32)), s: integer(signature.slice(32)) };
}

export function verifySigned(envelopeBytes: Uint8Array, key: TestKey): boolean {
  try {
    const envelope = decodeCbor(envelopeBytes, { strict: true });
    if (!Array.isArray(envelope) || envelope.length !== 2 || !(envelope[0] instanceof Uint8Array) || !(envelope[1] instanceof Uint8Array)) return false;
    const cose = decodeCbor(envelope[1], { strict: true });
    if (!Array.isArray(cose) || cose.length !== 4 || !(cose[0] instanceof Uint8Array) || !(cose[3] instanceof Uint8Array) || cose[2] !== null) return false;
    if (typeof cose[1] !== "object" || cose[1] === null || Array.isArray(cose[1]) || cose[1] instanceof Uint8Array || cose[1] instanceof Map || Object.keys(cose[1]).length !== 0) return false;
    const protectedMap = decodeCbor(cose[0], { strict: true });
    if (!(protectedMap instanceof Map) || protectedMap.get(1) !== -7) return false;
    const kid = protectedMap.get(4);
    const contentType = protectedMap.get(3);
    if (!(kid instanceof Uint8Array) || !equalBytes(kid, key.kid) || typeof contentType !== "string") return false;
    const receipt = contentType === RECEIPT_CONTENT_TYPE;
    if (!receipt && !ARTIFACT_CONTENT_TYPES.has(contentType)) return false;
    const expectedLabels = receipt ? [1, 3, 4, -70000, -70001, -70002, -70003, -70004, -70005, -70006] : [1, 3, 4];
    if (protectedMap.size !== expectedLabels.length || expectedLabels.some((label) => !protectedMap.has(label))) return false;
    const payload = decodeCbor(envelope[0], { strict: true });
    if (receipt) {
      if (typeof payload !== "object" || payload === null || Array.isArray(payload) || payload instanceof Uint8Array || payload instanceof Map) return false;
      const binding = payload.binding;
      const emission = payload.emission;
      if (typeof binding !== "object" || binding === null || Array.isArray(binding) || binding instanceof Uint8Array || binding instanceof Map) return false;
      if (typeof emission !== "object" || emission === null || Array.isArray(emission) || emission instanceof Uint8Array || emission instanceof Map) return false;
      const coordinates: [number, CborValue | undefined][] = [
        [-70000, payload.issuer_principal_type],
        [-70001, binding.tenant_id],
        [-70002, binding.site_id],
        [-70003, binding.epoch_id],
        [-70004, binding.epoch_seq],
        [-70005, emission.issuer_seq],
        [-70006, payload.issuer_role],
      ];
      if (coordinates.some(([label, value]) => value === undefined || !equalBytes(encodeCbor(protectedMap.get(label)!), encodeCbor(value)))) return false;
    }
    const { r, s } = signatureScalars(cose[3]);
    if (r === 0n || s === 0n || s > P256_HALF_ORDER) return false;
    const sigStructure = encodeCbor(["Signature1", cose[0], new Uint8Array(), envelope[0]]);
    return p256.verify(cose[3], hash(sigStructure), key.publicKey, { prehash: false, lowS: true, format: "compact" });
  } catch {
    return false;
  }
}
