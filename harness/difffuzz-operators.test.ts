import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { CborValue, decodeCbor, encodeCbor } from "./cbor";
import { Mutant, SeedView, dispatchedAuthorization, envelopes, list, survives } from "./difffuzz-mutant";
import { OPERATORS } from "./difffuzz-operators";
import { Rng } from "./difffuzz-rng";
import { Obj, artifacts, clone, payload } from "./mutate";

const healthy = "positive/bundle-valid-subset";
const operator = (name: string) => OPERATORS.find((entry) => entry.name === name)!;
function seed(path = healthy): SeedView {
  const bytes = new Uint8Array(readFileSync(new URL(`../kats/${path}.cbor`, import.meta.url)));
  return { bytes, bundle: decodeCbor(bytes) as Obj, policy: false, conformant: path === healthy, pinnedStep: null };
}
function withBundle(source: SeedView, change: (bundle: Obj) => void): SeedView {
  const bundle = clone(source.bundle); change(bundle);
  return { ...source, bundle, bytes: encodeCbor(bundle) };
}
function sweep(name: string, source: SeedView, count: number): Mutant[] {
  const op = operator(name);
  expect(op.applicable(source)).toBe(true);
  const mutants: Mutant[] = [];
  for (let i = 1; i <= count; i++) {
    const mutant = op.apply(source, new Rng(i));
    expect(mutant, `${name}, RNG seed ${i}`).not.toBeNull();
    mutants.push(mutant!);
  }
  expect(encodeCbor(source.bundle)).toEqual(source.bytes);
  return mutants;
}
const decoded = (mutant: Mutant): Obj => decodeCbor(mutant.bytes) as Obj;
function delegation(bundle: Obj): Obj {
  const authorization = list(bundle, "receipts").map(payload).find(dispatchedAuthorization(bundle)!)!;
  return payload((authorization.body as Obj).delegation!);
}
function dropReceipt(source: SeedView, field: string): { mutant: Mutant; before: CborValue[] } {
  const op = operator("payload/field-drop"); expect(op.applicable(source)).toBe(true);
  const all = envelopes(source.bundle); const selected = all.findIndex((entry) => entry.category === "receipts");
  const before = list(source.bundle, "receipts")[all[selected]!.index] as CborValue[];
  const keys = Object.keys(payload(before)).filter((key) => !key.endsWith("_id") || key === "subject_credential_id");
  const draws = [selected, keys.indexOf(field)]; expect(draws.every((draw) => draw >= 0)).toBe(true);
  const rng = new Rng(1); rng.int = (n) => { const draw = draws.shift()!; expect(draw).toBeLessThan(n); return draw; };
  const mutant = op.apply(source, rng)!; expect(mutant).not.toBeNull(); expect(draws).toHaveLength(0);
  return { mutant, before };
}

test("fuzz operator contract: only the four repaired operators report version 2", () => {
  const changed = ["payload/field-drop", "epoch/event", "delegation/embedded", "manifest/index"];
  expect(OPERATORS.filter((entry) => entry.version === 2).map((entry) => entry.name).sort()).toEqual(changed.sort());
  for (const entry of OPERATORS) expect(entry.version).toBe(changed.includes(entry.name) ? 2 : 1);
});

test("fuzz operator contract: receipt field-drop sweeps preserve payload-only exceptions", () => {
  const keys = ["binding", "emission", "issuer_role", "issuer_principal_type"];
  for (const path of [healthy, "class-boundary/origin-cross-epoch-ancestry"]) {
    const source = seed(path); const reached = new Set<string>();
    // Seeded draws pin the regression; directed draws guarantee coverage of all four keys.
    const mutants = [...sweep("payload/field-drop", source, 100), ...keys.map((key) => dropReceipt(source, key).mutant)];
    for (const mutant of mutants) {
      expect(survives(source, mutant)).toBe(true);
      const match = /^receipts\[(\d+)\] drop (.+)$/u.exec(mutant.detail);
      if (!match || !keys.includes(match[2]!)) continue;
      const index = Number(match[1]); const field = match[2]!; reached.add(field);
      const before = list(source.bundle, "receipts")[index] as CborValue[];
      const after = list(decoded(mutant), "receipts")[index] as CborValue[];
      expect(payload(after).receipt_id).toEqual(payload(before).receipt_id);
      expect(after.slice(1)).toEqual(before.slice(1)); // Entire COSE encoding stays byte-identical.
      const expected = clone(source.bundle);
      const envelope = list(expected, "receipts")[index] as CborValue[];
      const value = payload(envelope); delete value[field]; envelope[0] = encodeCbor(value);
      expect(mutant.bytes).toEqual(encodeCbor(expected)); // Also pins order and every other artifact.
    }
    expect([...reached].sort()).toEqual([...keys].sort());
  }
}, 30_000);

test("fuzz operator contract: other receipt field deletions still re-identify and re-sign", () => {
  const source = seed(); const { mutant, before } = dropReceipt(source, "freshness");
  const after = list(decoded(mutant), "receipts").find((entry) => payload(entry).freshness === undefined) as CborValue[];
  expect(after).toBeDefined();
  expect(payload(after).receipt_id).not.toEqual(payload(before).receipt_id);
  expect(after[1]).not.toEqual(before[1]);
  expect(survives(source, mutant)).toBe(true);
});

test("fuzz operator contract: null-scope delegation sweeps retain choices 1–3 and healthy scope retains choice 0", () => {
  const source = seed("negative/repair-d82-delegation-scope-null");
  expect(delegation(source.bundle).scope).toBeNull();
  const reached = new Set<string>();
  for (const mutant of sweep("delegation/embedded", source, 60)) {
    const next = delegation(decoded(mutant)); expect(next.scope).toBeNull();
    const field = mutant.detail.split(" ")[2]!;
    expect(["not_before", "not_after", "parent_delegations"]).toContain(field); reached.add(field);
    expect(next[field]).not.toEqual(delegation(source.bundle)[field]);
  }
  expect([...reached].sort()).toEqual(["not_after", "not_before", "parent_delegations"]);
  const valid = seed(); const choices = new Set<string>();
  for (const mutant of sweep("delegation/embedded", valid, 60)) {
    expect(survives(valid, mutant)).toBe(true);
    const field = mutant.detail.split(" ")[2]!; choices.add(field);
    if (field === "scope.actions") expect((delegation(decoded(mutant)).scope as Obj).actions).not.toEqual((delegation(valid.bundle).scope as Obj).actions);
  }
  expect([...choices].sort()).toEqual(["not_after", "not_before", "parent_delegations", "scope.actions"]);
}, 30_000);

test("fuzz operator contract: anchorless epoch sweeps use event_seq 1 and healthy chains exercise both branches", () => {
  for (const name of ["epoch-duration-exceeded", "epoch-anchor-deadline", "epoch-span-count-mismatch"]) {
    const source = seed(`negative/${name}`); const events = list(source.bundle, "epoch_events").map(payload);
    expect(events.some((value) => value.event === "anchor_submitted")).toBe(false);
    expect(events.some((value) => value.event_seq === 1)).toBe(true);
    for (const mutant of sweep("epoch/event", source, 60)) {
      expect(mutant.target).toBe("artifacts.epoch_events.*.payload.previous_event_digest");
      expect(survives(source, mutant)).toBe(true);
    }
  }
  const source = seed(); const targets = new Set<string>();
  for (const mutant of sweep("epoch/event", source, 60)) {
    targets.add(mutant.target); expect(survives(source, mutant)).toBe(true);
  }
  expect([...targets].sort()).toEqual(["artifacts.epoch_events.*.payload.occurred_at", "artifacts.epoch_events.*.payload.previous_event_digest"]);
}, 30_000);

test("fuzz operator contract: epoch branches require their actual targets, including singleton chains", () => {
  const source = seed(); const op = operator("epoch/event");
  for (const [select, target] of [
    [(value: Obj) => value.event_seq === 1, "previous_event_digest"],
    [(value: Obj) => value.event === "anchor_submitted", "occurred_at"],
  ] as const) {
    const only = withBundle(source, (bundle) => { artifacts(bundle).epoch_events = list(bundle, "epoch_events").filter((entry) => select(payload(entry))); });
    expect(list(only.bundle, "epoch_events")).toHaveLength(1);
    for (const mutant of sweep("epoch/event", only, 10)) {
      expect(mutant.target).toBe(`artifacts.epoch_events.*.payload.${target}`); expect(survives(only, mutant)).toBe(true);
    }
  }
  for (const empty of [false, true]) {
    const neither = withBundle(source, (bundle) => { artifacts(bundle).epoch_events = empty ? [] : list(bundle, "epoch_events").filter((entry) => payload(entry).event_seq !== 1 && payload(entry).event !== "anchor_submitted"); });
    expect(op.applicable(neither)).toBe(false);
    expect(op.apply(neither, new Rng(1))).toBeNull();
  }
});

test("fuzz operator contract: manifest index requires empty anchors or an anchor matching the first manifest", () => {
  const source = seed(); const op = operator("manifest/index");
  expect(op.applicable(source)).toBe(true);
  const manifestId = payload(list(source.bundle, "epoch_manifests")[0]!).manifest_id;
  expect(list(source.bundle, "anchors").map((entry) => payload(entry).manifest_id)).toContainEqual(manifestId);
  const empty = withBundle(source, (bundle) => { artifacts(bundle).anchors = []; });
  for (const mutant of sweep("manifest/index", empty, 6)) expect(survives(empty, mutant)).toBe(true);
  expect(op.applicable(seed("negative/repair-d82-anchor-manifest-id-not-bytes"))).toBe(false);
  const unrelated = withBundle(source, (bundle) => {
    for (const entry of list(bundle, "anchors")) {
      const value = payload(entry); value.manifest_id = new Uint8Array(32); (entry as CborValue[])[0] = encodeCbor(value);
    }
  });
  expect(op.applicable(unrelated)).toBe(false);
  const matchingLater = withBundle(unrelated, (bundle) => { list(bundle, "anchors").push(clone(list(source.bundle, "anchors")[0]!)); });
  for (const mutant of sweep("manifest/index", matchingLater, 6)) expect(survives(matchingLater, mutant)).toBe(true);
  const noManifest = withBundle(source, (bundle) => { artifacts(bundle).epoch_manifests = []; });
  expect(op.applicable(noManifest)).toBe(false);
  const shortIndex = withBundle(source, (bundle) => {
    const entry = list(bundle, "epoch_manifests")[0] as CborValue[]; const value = payload(entry);
    (value.receipt_index as Obj).entries = []; entry[0] = encodeCbor(value);
  });
  expect(op.applicable(shortIndex)).toBe(false);
});

test("fuzz operator contract: all six manifest index choices survive on the healthy fixture", () => {
  const source = seed(); const reached = new Set<string>(); const op = operator("manifest/index");
  expect(op.applicable(source)).toBe(true);
  for (let choice = 0; choice < 6; choice++) {
    const rng = new Rng(1); const int = rng.int.bind(rng); let first = true;
    rng.int = (n) => { if (!first) return int(n); first = false; expect(n).toBe(6); return choice; };
    const mutant = op.apply(source, rng)!; expect(mutant).not.toBeNull();
    expect(survives(source, mutant)).toBe(true);
    const index = payload(list(decoded(mutant), "epoch_manifests")[0]!).receipt_index;
    expect(index).not.toEqual(payload(list(source.bundle, "epoch_manifests")[0]!).receipt_index);
    if (mutant.detail.includes("<->")) reached.add("swap");
    else if (mutant.detail.includes(".leaf_index")) reached.add("leaf_index");
    else if (mutant.detail.includes(".epoch_seq")) reached.add("epoch_seq");
    else if (mutant.detail.includes(".receipt_kind")) reached.add("receipt_kind");
    else if (mutant.detail.includes("index root")) reached.add("root");
    else if (mutant.detail.includes("leaf_count")) reached.add("leaf_count");
  }
  expect([...reached].sort()).toEqual(["epoch_seq", "leaf_count", "leaf_index", "receipt_kind", "root", "swap"]);
}, 30_000);
