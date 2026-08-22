// L2 reference emitter — shared machinery.
// CANDIDATE WIRE (D-62/D-63, unratified): payloads use draft content types and
// are NOT v0.2-conformant AAR receipts. This emitter exists to make the L2
// vantage point concrete and to generate candidate fixtures for ratification.
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { encodeCbor, decodeCbor, toHex, fromHex, type CborValue } from "../../harness/cbor";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

export const RECEIPT_CONTENT_TYPE = "application/aar-l2-receipt+cbor;v=0.3-draft";
export const CLOSE_CONTENT_TYPE = "application/aar-session-close+cbor;v=0.3-draft";

export const BASE_DIR = join(process.env.AAR_L2_DIR ?? join(process.env.HOME ?? "", ".aar-l2"));

// Fixed demo coordinates, same posture as the demo-EP: an L2 recorder on a
// developer machine has no tenant/site authority — these are disclosed
// placeholders, not claims.
export const TENANT_ID = sha256(new TextEncoder().encode("AAR-L2-DEMO-TENANT")).slice(0, 16);
export const SITE_ID = sha256(new TextEncoder().encode("AAR-L2-DEMO-SITE")).slice(0, 16);

const SPKI_PREFIX = fromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200");

export interface RecorderKey {
  privateKey: Uint8Array;
  spki: Uint8Array;
  kid: Uint8Array;
}

export function loadOrCreateRecorderKey(): RecorderKey {
  mkdirSync(BASE_DIR, { recursive: true, mode: 0o700 });
  const keyPath = join(BASE_DIR, "recorder.key");
  let privateKey: Uint8Array;
  if (existsSync(keyPath)) {
    privateKey = fromHex(readFileSync(keyPath, "utf8").trim());
  } else {
    privateKey = crypto.getRandomValues(new Uint8Array(32));
    // Reject the (astronomically unlikely) out-of-range scalar rather than reduce.
    p256.getPublicKey(privateKey, false);
    writeFileSync(keyPath, toHex(privateKey) + "\n", { mode: 0o600 });
  }
  const publicKey = p256.getPublicKey(privateKey, false);
  const spki = new Uint8Array(SPKI_PREFIX.length + publicKey.length);
  spki.set(SPKI_PREFIX);
  spki.set(publicKey, SPKI_PREFIX.length);
  const kid = sha256(spki);
  const pubPath = join(BASE_DIR, "recorder.pub");
  if (!existsSync(pubPath)) writeFileSync(pubPath, toHex(spki) + "\n");
  return { privateKey, spki, kid };
}

export function sessionDir(sessionId16: Uint8Array): string {
  const dir = join(BASE_DIR, "sessions", toHex(sessionId16));
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function sessionId16(rawSessionId: string): Uint8Array {
  return sha256(new TextEncoder().encode(rawSessionId)).slice(0, 16);
}

export function signEnvelope(payload: CborValue, contentType: string, key: RecorderKey): Uint8Array {
  const protectedMap = new Map<number, CborValue>([[1, -7], [3, contentType], [4, key.kid]]);
  const protectedBytes = encodeCbor(protectedMap);
  const payloadBytes = encodeCbor(payload);
  const sigStructure = encodeCbor(["Signature1", protectedBytes, new Uint8Array(), payloadBytes]);
  const signature = p256.sign(sha256(sigStructure), key.privateKey, {
    prehash: false, lowS: true, format: "compact", extraEntropy: false,
  });
  return encodeCbor([payloadBytes, encodeCbor([protectedBytes, new Map(), null, signature])]);
}

export interface OpenedEnvelope {
  payloadBytes: Uint8Array;
  payload: CborValue;
  contentType: CborValue;
  kidMatchesSpki: boolean;
  signatureValid: boolean;
}

export function openEnvelope(envelopeBytes: Uint8Array, spki: Uint8Array): OpenedEnvelope {
  const envelope = decodeCbor(envelopeBytes) as CborValue[];
  const payloadBytes = envelope[0] as Uint8Array;
  const cose = decodeCbor(envelope[1] as Uint8Array) as CborValue[];
  const protectedBytes = cose[0] as Uint8Array;
  const signature = cose[3] as Uint8Array;
  const sigStructure = encodeCbor(["Signature1", protectedBytes, new Uint8Array(), payloadBytes]);
  const publicKey = spki.slice(SPKI_PREFIX.length);
  let signatureValid = false;
  try {
    signatureValid = p256.verify(signature, sha256(sigStructure), publicKey, {
      prehash: false, lowS: true, format: "compact",
    });
  } catch {
    signatureValid = false;
  }
  const protectedMap = decodeCbor(protectedBytes) as Map<CborValue, CborValue>;
  const kidValue = protectedMap instanceof Map ? protectedMap.get(4) : undefined;
  const expectedKid = sha256(spki);
  const kidMatchesSpki = kidValue instanceof Uint8Array && kidValue.length === expectedKid.length
    && kidValue.every((b, i) => b === expectedKid[i]);
  return {
    payloadBytes,
    payload: decodeCbor(payloadBytes),
    contentType: protectedMap instanceof Map ? (protectedMap.get(3) as CborValue) : null,
    kidMatchesSpki,
    signatureValid,
  };
}

export function readHexLines(path: string): Uint8Array[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split("\n").filter((l) => l.trim().length > 0).map(fromHex);
}

export { sha256, encodeCbor, decodeCbor, toHex, fromHex };
export type { CborValue };
