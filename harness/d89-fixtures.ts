// The D-89 rows (a permit_with_approval presentation must be human_approved, step 10),
// written to kats/negative/ by generate-negative.ts. Kept out of negative-fixtures.ts,
// which the size ratchet pins. Every row starts from bundle-valid-subset and mutates the
// approval authorization's nested presentation: presentation_id recomputed, the
// presentation re-signed by its signer, the enclosing receipt re-signed and re-indexed.
import { decodeCbor, encodeCbor } from "./cbor";
import { domainHash, signDetached } from "./crypto";
import { buildFixtures } from "./fixtures";
import { clone, contentType, mutateReceiptWhere, Obj, payload, signerFor, withoutField } from "./mutate";
import { reindexCarried } from "./mutate-graph";
import type { NegativeFixture } from "./negative-fixtures";
import type { TestKeyName } from "./testkeys";

function presentationBundle(mutation: (presentation: Obj) => void, signer?: TestKeyName): Uint8Array {
  const bundle = decodeCbor(buildFixtures().kats.find((item) => item.filename === "bundle-valid-subset")!.bytes, { strict: true }) as Obj;
  mutateReceiptWhere(bundle, (p) => p.kind === "authorization" && (p.body as Obj).presentation !== undefined, (p) => {
    const envelope = (p.body as Obj).presentation!;
    const next = clone(payload(envelope));
    mutation(next);
    next.presentation_id = domainHash("AAR-PRESENTATION-MANIFEST-v1", withoutField(next, "presentation_id"));
    (p.body as Obj).presentation = signDetached(next, contentType(envelope), signer ?? signerFor(envelope)).envelope;
  });
  reindexCarried(bundle);
  return encodeCbor(bundle);
}

export function buildD89Fixtures(): NegativeFixture[] {
  const row = (name: string, description: string, bytes: Uint8Array): NegativeFixture =>
    ({ filename: name, bytes, descriptor: { name, expected_code: "receipt/decision-presentation", mutation_description: description, expected_result: "nonconformant", expected_step: 10 } });
  const lower = (state: string): NegativeFixture => row(`d89-pwa-state-${state}`,
    `The approval authorization's approver-originated presentation has state ${state} (re-identified, re-signed); permit_with_approval requires human_approved.`,
    presentationBundle((p) => { p.state = state; }));
  return [
    lower("assembled"),
    lower("delivered"),
    lower("rendered"),
    row("d89-pwa-state-delivered-ep-session",
      "The approval presentation is EP-authenticated-session (signed by the enclosing authorization's EP key) with state delivered; the rule holds for both signer modes.",
      presentationBundle((p) => { p.signer_mode = "ep_authenticated_session"; p.state = "delivered"; }, "ep_signing")),
    row("d89-order-state-before-ordinals",
      "The approval presentation has state delivered AND artifact ordinals [1, 0]; the state check precedes the artifact-ordinal check (was receipt/manifest-inconsistent on v0.4.1).",
      presentationBundle((p) => { const first = (p.artifacts as Obj[])[0]!; p.artifacts = [{ ...first, ordinal: 1 }, { ...first, ordinal: 0 }]; p.state = "delivered"; })),
  ];
}
