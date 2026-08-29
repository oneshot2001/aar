import type { CborValue } from "./cbor";
import { decodeCbor, encodeCbor } from "./cbor";
import { domainHash, hash, signDetached } from "./crypto";
import { buildFixtures } from "./fixtures";
import { TEST_KEYS } from "./testkeys";

type Obj = Record<string, CborValue>;

export interface CountersignFixture {
  readonly filename: string;
  readonly bytes: Uint8Array;
  readonly descriptor: {
    readonly name: string;
    readonly object_type: "bundle";
    readonly expectation: "conformant" | "nonconformant";
    readonly expected_code: "countersign/digest-mismatch" | "countersign/credential-invalid" | null;
    readonly expected_observations: readonly string[];
  };
}

function baseBundle(): Obj {
  const kat = buildFixtures().kats.find((item) => item.filename === "bundle-valid-subset");
  if (!kat) throw new Error("positive base bundle missing");
  return decodeCbor(kat.bytes, { strict: true }) as Obj;
}

function actionAttempt(bundle: Obj): CborValue[] {
  const artifacts = bundle.artifacts as Obj;
  for (const envelope of artifacts.receipts as CborValue[]) {
    if (!Array.isArray(envelope) || !(envelope[0] instanceof Uint8Array)) continue;
    const payload = decodeCbor(envelope[0], { strict: true }) as Obj;
    if (payload.kind === "action_attempt") return envelope;
  }
  throw new Error("action_attempt missing from positive base bundle");
}

function envelopePayload(envelope: CborValue): Obj {
  if (!Array.isArray(envelope) || !(envelope[0] instanceof Uint8Array)) throw new Error("signed envelope missing payload");
  return decodeCbor(envelope[0], { strict: true }) as Obj;
}

function withCountersignature(tamperCommandDigest: boolean, expireMediatorCredential = false): Uint8Array {
  const bundle = baseBundle();
  const artifacts = bundle.artifacts as Obj;
  const credentials = artifacts.credentials as CborValue[];
  const template = credentials.find((envelope) => envelopePayload(envelope).key_usage === "outcome_signing");
  if (!template) throw new Error("outcome credential template missing from positive base bundle");
  const templatePayload = envelopePayload(template);
  const evaluationTime = ((bundle.trust_inputs as Obj).evaluation_time as number);
  const credentialFields: Obj = { ...templatePayload };
  delete credentialFields.credential_id;
  credentialFields.subject_kid = TEST_KEYS.mediator_outcome_signing.kid;
  credentialFields.public_key = TEST_KEYS.mediator_outcome_signing.spki;
  if (expireMediatorCredential) credentialFields.valid_until = evaluationTime - 1;
  const credentialPayload: Obj = {
    credential_id: domainHash("AAR-CREDENTIAL-ID-v1", credentialFields),
    ...credentialFields,
  };
  const mediatorCredential = signDetached(
    credentialPayload, "application/aar-credential+cbor;v=0.2", "credential_issuing",
  );
  credentials.push(mediatorCredential.envelope);
  credentials.sort((left, right) => Buffer.compare(
    Buffer.from(envelopePayload(left).credential_id as Uint8Array),
    Buffer.from(envelopePayload(right).credential_id as Uint8Array),
  ));
  const attempt = actionAttempt(bundle);
  const attemptPayload = decodeCbor(attempt[0] as Uint8Array, { strict: true }) as Obj;
  const command = (attemptPayload.body as Obj).command as Obj;
  const fields: Obj = {
    v: 2,
    action_attempt_receipt_digest: hash(encodeCbor(attempt)),
    command_digest: tamperCommandDigest ? hash(new TextEncoder().encode("D-67 tampered command digest")) : command.command_digest!,
    mediator_observed_at: bundle.created_at!,
  };
  const payload: Obj = {
    countersignature_id: domainHash("AAR-MEDIATOR-COUNTERSIGNATURE-ID-v1", fields),
    ...fields,
  };
  const signed = signDetached(payload, "application/aar-mediator-countersignature+cbor;v=0.2", "mediator_outcome_signing");
  artifacts.mediator_countersignatures = [signed.envelope];
  return encodeCbor(bundle);
}

export function buildCountersignFixtures(): CountersignFixture[] {
  return [
    {
      filename: "mediator-countersign-valid",
      bytes: withCountersignature(false),
      descriptor: {
        name: "valid mediator countersignature adds the signed observation",
        object_type: "bundle",
        expectation: "conformant",
        expected_code: null,
        expected_observations: ["mediator_countersigned"],
      },
    },
    {
      filename: "mediator-countersign-command-digest-tampered",
      bytes: withCountersignature(true),
      descriptor: {
        name: "signed mediator command digest differs from the action attempt",
        object_type: "bundle",
        expectation: "nonconformant",
        expected_code: "countersign/digest-mismatch",
        expected_observations: [],
      },
    },
    {
      filename: "mediator-countersign-credential-expired",
      bytes: withCountersignature(false, true),
      descriptor: {
        name: "mediator credential expired at evaluation time",
        object_type: "bundle",
        expectation: "nonconformant",
        expected_code: "countersign/credential-invalid",
        expected_observations: [],
      },
    },
    {
      filename: "mediator-countersign-absent",
      bytes: encodeCbor(baseBundle()),
      descriptor: {
        name: "absent optional mediator countersignature remains conformant",
        object_type: "bundle",
        expectation: "conformant",
        expected_code: null,
        expected_observations: [],
      },
    },
  ];
}
