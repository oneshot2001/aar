// The D-88 rows (closed action-name enum at step 6), written to kats/negative/ by
// generate-negative.ts, and the amendment (m) probe for crossimpl.test.ts. Kept out
// of negative-fixtures.ts, which the size ratchet pins. Every row starts from
// bundle-valid-subset; a changed command manifest gets its command_id back and a
// re-identified receipt is re-indexed. Outside the d88-order-* rows the action name is
// the only planted fault; on v0.4.0 it still surfaces through its consequences
// (action-command mismatch@10, or delegation/scope@13 for the embedded row).
import { decodeCbor, encodeCbor } from "./cbor";
import { domainHash, hash } from "./crypto";
import { buildFixtures } from "./fixtures";
import { addTopLevelDelegation, clone, mutateArtifact, mutateReceiptWhere, Obj, payload, resign, withoutField } from "./mutate";
import { mutateEmbeddedDelegation, receiptBy, reindexCarried } from "./mutate-graph";
import type { NegativeFixture } from "./negative-fixtures";

const EXPORT = "camera.export_clip";
const refused = (value: Obj): boolean => value.kind === "action_attempt" && (value.body as Obj).disposition === "not_dispatched";
const body = (receipt: Obj, field: string): Obj => (receipt.body as Obj)[field] as Obj;
const scope = (delegation: Obj): Obj => delegation.scope as Obj;
// The approval authorization's embedded delegation, which no attempt uses.
const approval = (value: Obj): boolean => value.kind === "authorization" && ((value.body as Obj).decision as Obj).decision === "permit_with_approval";

function bundleWith(mutation: (bundle: Obj) => void): Uint8Array {
  const bundle = decodeCbor(buildFixtures().kats.find((item) => item.filename === "bundle-valid-subset")!.bytes, { strict: true }) as Obj;
  mutation(bundle);
  reindexCarried(bundle);
  return encodeCbor(bundle);
}

// Mutate the refused attempt's command manifest, then recompute its command_id.
const onCommand = (mutation: (command: Obj, receipt: Obj) => void) => (bundle: Obj): void => mutateReceiptWhere(bundle, refused, (p) => {
  const command = body(p, "command");
  mutation(command, p);
  command.command_id = domainHash("AAR-COMMAND-MANIFEST-v1", withoutField(command, "command_id"));
});
const onAction = (mutation: (action: Obj) => void) => (bundle: Obj): void => mutateReceiptWhere(bundle, refused, (p) => mutation(body(p, "action")));

export function buildD88Fixtures(): NegativeFixture[] {
  const row = (name: string, code: string, description: string, mutation: (bundle: Obj) => void): NegativeFixture =>
    ({ filename: name, bytes: bundleWith(mutation), descriptor: { name, expected_code: code, mutation_description: description, expected_result: "nonconformant", expected_step: 6 } });
  return [
    row("d88-action-name-missing", "schema/missing-field", "The refused attempt's normalized action has no action_name.", onAction((a) => { delete a.action_name; })),
    row("d88-action-name-int", "schema/bad-type", "The refused attempt's normalized action_name is the integer 7.", onAction((a) => { a.action_name = 7; })),
    row("d88-action-name-export-clip", "schema/enum-unknown", `The refused attempt's normalized action_name is ${EXPORT}.`, onAction((a) => { a.action_name = EXPORT; })),
    row("d88-command-action-name-missing", "schema/missing-field", "The refused attempt's command manifest has no action_name (command_id recomputed); the normalized action is valid.", onCommand((c) => { delete c.action_name; })),
    row("d88-command-action-name-unknown", "schema/enum-unknown", `The refused attempt's command manifest action_name is ${EXPORT} (command_id recomputed); the normalized action is valid.`, onCommand((c) => { c.action_name = EXPORT; })),
    row("d88-scope-embedded-unknown", "schema/enum-unknown", `The permit authorization's embedded delegation scope.actions is [${EXPORT}].`, (b) => mutateEmbeddedDelegation(b, (d) => { scope(d).actions = [EXPORT]; })),
    row("d88-scope-non-text-member", "schema/bad-type", "The approval authorization's unused embedded delegation scope.actions is [7].", (b) => mutateEmbeddedDelegation(b, (d) => { scope(d).actions = [7]; }, approval)),
    row("d88-scope-unused-top-level-unknown", "schema/enum-unknown", `An added, unused top-level delegation whose scope.actions is [${EXPORT}].`, (b) => { addTopLevelDelegation(b, (d) => { scope(d).actions = [EXPORT]; }); }),
    row("d88-scope-mixed-array", "schema/enum-unknown", `The permit authorization's embedded delegation scope.actions is [camera.stream.view, ${EXPORT}, 7]: members in array order.`, (b) => mutateEmbeddedDelegation(b, (d) => { scope(d).actions = ["camera.stream.view", EXPORT, 7]; })),
    row("d88-order-scope-before-not-before", "schema/enum-unknown", `An added top-level delegation with scope.actions [${EXPORT}] AND not_before text; scope actions precede the not_before rule.`, (b) => { addTopLevelDelegation(b, (d) => { scope(d).actions = [EXPORT]; d.not_before = "early"; }); }),
    row("d88-order-closed-map-first", "schema/missing-field", `The top-level delegation without not_before AND scope.actions [${EXPORT}]; the closed-map presence check comes first.`, (b) => mutateArtifact(b, "delegations", () => true, (d) => { delete d.not_before; scope(d).actions = [EXPORT]; })),
    row("d88-order-reversibility-before-command", "schema/enum-unknown", "The refused attempt's informational_reversibility partially AND its command manifest without action_name (command_id recomputed); the action's checks come first.", onCommand((c, p) => { body(p, "action").informational_reversibility = "partially"; delete c.action_name; })),
    row("d88-order-command-before-excluded", "schema/enum-unknown", `The refused attempt's command manifest action_name ${EXPORT} AND no excluded_fields (command_id recomputed); action_name comes first.`, onCommand((c) => { c.action_name = EXPORT; delete c.excluded_fields; })),
    row("d88-refusal-export-clip-consistent", "schema/enum-unknown", `A consistent refusal of ${EXPORT} (oneshot2001/aar#1 item 3): the permit's embedded delegation scope adds it, and the refused attempt's action, command manifest and canonical command carry it, command_digest and command_id recomputed; both v0.4.0 verifiers said conformant.`, (b) => {
      mutateEmbeddedDelegation(b, (d) => { scope(d).actions = ["camera.stream.view", EXPORT]; });
      onCommand((c, p) => {
        body(p, "action").action_name = EXPORT; c.action_name = EXPORT;
        c.canonical_command = encodeCbor({ ...(decodeCbor(c.canonical_command as Uint8Array, { strict: true }) as Obj), operation: EXPORT });
        c.command_digest = hash(c.canonical_command as Uint8Array);
      })(b);
    }),
  ];
}

// Amendment (m): a body.delegation on a receipt that is not an authorization stays unvalidated, so both verifiers
// still say conformant. Not a corpus row: the CDDL oracle rejects the extra body member (BACKLOG step-6 traversal item).
export function buildD88Probes() {
  return [{ name: "d88-non-authorization-delegation-ignored", bytes: bundleWith((bundle) => {
    const carried = body(payload(receiptBy(bundle, (value) => value.kind === "authorization")), "delegation") as unknown as Uint8Array[];
    const delegation = clone(payload(carried)); scope(delegation).actions = [EXPORT];
    delegation.delegation_id = domainHash("AAR-DELEGATION-ID-v1", withoutField(delegation, "delegation_id"));
    mutateReceiptWhere(bundle, refused, (p) => { (p.body as Obj).delegation = resign(carried, delegation); });
  }) }];
}
