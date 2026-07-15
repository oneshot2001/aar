import { CborValue, decodeCbor, encodeCbor, fromHex, toHex } from "./cbor";
import { deterministicId, hash } from "./crypto";
import { buildFixtures } from "./fixtures";
import { PriorEmission } from "./verifier";

type Obj = Record<string, CborValue>;

export interface StatefulPriorJson {
  prior_emissions: Array<{
    issuer_kid: string;
    issuer_seq: number;
    epoch_owner_kid: string;
    epoch_id: number;
    epoch_seq: number;
    receipt_id: string;
    envelope_digest: string;
  }>;
}

export interface StatefulFixture {
  name: string;
  bundle: Uint8Array;
  prior: StatefulPriorJson;
  descriptor: { name: string; expected_code: string; mutation_description: string };
}

function object(value: CborValue | undefined): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Map);
}

function base(): { bytes: Uint8Array; receipt: Obj; envelope: Uint8Array; kid: Uint8Array } {
  const kat = buildFixtures().kats.find((entry) => entry.filename === "bundle-valid-subset");
  if (kat === undefined) throw new Error("positive bundle missing");
  const bundle = decodeCbor(kat.bytes, { strict: true });
  if (!object(bundle) || !object(bundle.artifacts) || !Array.isArray(bundle.artifacts.receipts)) throw new Error("positive bundle malformed");
  const envelopeValue = bundle.artifacts.receipts[0];
  if (!Array.isArray(envelopeValue) || !(envelopeValue[0] instanceof Uint8Array) || !(envelopeValue[1] instanceof Uint8Array)) throw new Error("receipt envelope malformed");
  const receipt = decodeCbor(envelopeValue[0], { strict: true });
  const cose = decodeCbor(envelopeValue[1], { strict: true });
  if (!object(receipt) || !Array.isArray(cose) || !(cose[0] instanceof Uint8Array)) throw new Error("receipt malformed");
  const protectedMap = decodeCbor(cose[0], { strict: true });
  const kid = protectedMap instanceof Map ? protectedMap.get(4) : undefined;
  if (!(kid instanceof Uint8Array)) throw new Error("receipt kid missing");
  return { bytes: kat.bytes, receipt, envelope: encodeCbor(envelopeValue), kid };
}

function priorJson(value: PriorEmission): StatefulPriorJson {
  return { prior_emissions: [{
    issuer_kid: toHex(value.issuerKid), issuer_seq: value.issuerSeq,
    epoch_owner_kid: toHex(value.epochOwnerKid), epoch_id: value.epochId, epoch_seq: value.epochSeq,
    receipt_id: toHex(value.receiptId), envelope_digest: toHex(value.envelopeDigest),
  }] };
}

export function parseStatefulPrior(value: StatefulPriorJson): PriorEmission[] {
  return value.prior_emissions.map((entry) => ({
    issuerKid: fromHex(entry.issuer_kid), issuerSeq: entry.issuer_seq,
    epochOwnerKid: fromHex(entry.epoch_owner_kid), epochId: entry.epoch_id, epochSeq: entry.epoch_seq,
    receiptId: fromHex(entry.receipt_id), envelopeDigest: fromHex(entry.envelope_digest),
  }));
}

export function buildStatefulFixtures(): StatefulFixture[] {
  const source = base();
  const binding = source.receipt.binding as Obj; const emission = source.receipt.emission as Obj;
  const common = {
    issuerKid: source.kid, issuerSeq: emission.issuer_seq as number,
    epochOwnerKid: binding.epoch_owner_kid as Uint8Array, epochId: binding.epoch_id as number, epochSeq: binding.epoch_seq as number,
    receiptId: source.receipt.receipt_id as Uint8Array, envelopeDigest: hash(source.envelope),
  };
  const fixtures: StatefulFixture[] = [
    {
      name: "identity-reuse", bundle: source.bytes,
      prior: priorJson({ ...common, envelopeDigest: deterministicId("prior:nonidentical-envelope") }),
      descriptor: { name: "identity-reuse", expected_code: "identity/reuse", mutation_description: "Prior evaluated state binds the carried receipt ID to different envelope bytes." },
    },
    {
      name: "identity-issuer-sequence-rollback", bundle: source.bytes,
      prior: priorJson({ ...common, issuerSeq: 9_999_999, epochOwnerKid: deterministicId("prior:other-epoch-owner"), receiptId: deterministicId("prior:other-receipt") }),
      descriptor: { name: "identity-issuer-sequence-rollback", expected_code: "identity/issuer-sequence-rollback", mutation_description: "Prior evaluated state has a greater sequence for the carried issuer kid." },
    },
    {
      name: "identity-epoch-sequence-rollback", bundle: source.bytes,
      prior: priorJson({ ...common, issuerKid: deterministicId("prior:other-issuer"), epochSeq: 9_999_999, receiptId: deterministicId("prior:other-receipt") }),
      descriptor: { name: "identity-epoch-sequence-rollback", expected_code: "identity/epoch-sequence-rollback", mutation_description: "Prior evaluated state has a greater sequence for the carried epoch owner and epoch." },
    },
  ];
  return fixtures;
}
