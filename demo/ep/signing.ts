import { p256 } from "@noble/curves/nist.js";
import type { CborValue } from "../../harness/cbor";
import { encodeCbor } from "../../harness/cbor";
import { hash } from "../../harness/crypto";
import type { DemoSigningKey } from "../keys/keys";

export interface DemoSignedEnvelope {
  readonly envelope: CborValue[];
  readonly envelopeBytes: Uint8Array;
  readonly payload: CborValue;
  readonly payloadBytes: Uint8Array;
  readonly protectedBytes: Uint8Array;
  readonly signature: Uint8Array;
}

export function signDemoDetached(
  payload: CborValue,
  contentType: string,
  key: DemoSigningKey,
  extraProtected: readonly (readonly [number, CborValue])[] = [],
): DemoSignedEnvelope {
  const protectedBytes = encodeCbor(new Map<number, CborValue>([
    [1, -7],
    [3, contentType],
    [4, key.kid],
    ...extraProtected,
  ]));
  const payloadBytes = encodeCbor(payload);
  const sigStructure = encodeCbor(["Signature1", protectedBytes, new Uint8Array(), payloadBytes]);
  const signature = p256.sign(hash(sigStructure), key.privateKey, {
    prehash: false,
    lowS: true,
    format: "compact",
    extraEntropy: false,
  });
  const coseBytes = encodeCbor([protectedBytes, {}, null, signature]);
  const envelope: CborValue[] = [payloadBytes, coseBytes];
  return { envelope, envelopeBytes: encodeCbor(envelope), payload, payloadBytes, protectedBytes, signature };
}
