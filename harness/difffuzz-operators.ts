// Operator tables for the differential fuzz tool (Packet D, Stage C): the raw
// byte stream, the COSE layer, the generic payload operators, and the registry
// that joins them with the step-targeted table.
import { CborValue, decodeCbor, encodeCbor, toHex } from "./cbor";
import { BUNDLE_ENUMS, COUNTERS, ENUMS, ENVELOPED, Operator, REFERENCES, encode, envelopes, fresh, getAt, ids, list, op, pickField, resignAt, setAt } from "./difffuzz-mutant";
import { STEP_OPERATORS } from "./difffuzz-operators-steps";
import { ID_DOMAIN, clone, modifyCose, payload, recalcSelector, recalcTrust, sortArtifacts } from "./mutate";

const always = (): boolean => true;

const RAW: Operator[] = [
  op("raw/flip", "raw", null, "none", always, (seed, rng) => { const bytes = new Uint8Array(seed.bytes); const index = rng.int(bytes.length); bytes[index] = bytes[index]! ^ (1 << rng.int(8)); return { bytes, target: "", detail: `flip bit at ${index}` }; }),
  op("raw/insert", "raw", null, "none", always, (seed, rng) => { const index = rng.int(seed.bytes.length + 1); const byte = rng.next() & 0xff; const bytes = new Uint8Array(seed.bytes.length + 1); bytes.set(seed.bytes.subarray(0, index)); bytes[index] = byte; bytes.set(seed.bytes.subarray(index), index + 1); return { bytes, target: "", detail: `insert ${byte} at ${index}` }; }),
  op("raw/delete", "raw", null, "none", always, (seed, rng) => { const index = rng.int(seed.bytes.length); const bytes = new Uint8Array(seed.bytes.length - 1); bytes.set(seed.bytes.subarray(0, index)); bytes.set(seed.bytes.subarray(index + 1), index); return { bytes, target: "", detail: `delete byte at ${index}` }; }),
  op("raw/truncate", "raw", null, "none", always, (seed, rng) => { const index = rng.int(seed.bytes.length); return { bytes: seed.bytes.slice(0, index), target: "", detail: `truncate at ${index}` }; }),
];

const COSE: Operator[] = [
  op("cose/protected-header", "cose", 6, "none (COSE bytes re-encoded, no re-sign)", (seed) => envelopes(seed.bundle).length > 0, (seed, rng) => {
    const bundle = fresh(seed); const { category, index } = rng.pick(envelopes(bundle)); const label = rng.pick([1, 3, 4] as const);
    modifyCose(bundle, category, index, (value) => {
      const protectedMap = decodeCbor(value[0] as Uint8Array) as Map<number, CborValue>;
      protectedMap.set(label, label === 1 ? rng.pick([-8, 1, -35]) : label === 3 ? "application/octet-stream" : rng.bytes(rng.pick([31, 32, 33])));
      value[0] = encodeCbor(protectedMap);
    });
    return encode(bundle, `artifacts.${category}.*.cose.0`, `${category}[${index}] protected label ${label}`);
  }),
  op("cose/signature-flip", "cose", 6, "none", (seed) => envelopes(seed.bundle).length > 0, (seed, rng) => {
    const bundle = fresh(seed); const { category, index } = rng.pick(envelopes(bundle));
    modifyCose(bundle, category, index, (value) => { const signature = new Uint8Array(value[3] as Uint8Array); const at = rng.int(signature.length); signature[at] = signature[at]! ^ (1 << rng.int(8)); value[3] = signature; });
    return encode(bundle, `artifacts.${category}.*.cose.3`, `${category}[${index}] signature bit`);
  }),
  op("cose/payload-swap", "cose", 6, "none (payload replaced, signature kept)", (seed) => envelopes(seed.bundle).length > 1, (seed, rng) => {
    const bundle = fresh(seed); const all = envelopes(bundle); const a = rng.pick(all); const others = all.filter((entry) => entry.category !== a.category || entry.index !== a.index); const b = rng.pick(others);
    const left = list(bundle, a.category)[a.index] as CborValue[]; const right = list(bundle, b.category)[b.index] as CborValue[];
    [left[0], right[0]] = [right[0]!, left[0]!];
    return encode(bundle, `artifacts.${a.category}`, `${a.category}[${a.index}] <-> ${b.category}[${b.index}] payload`);
  }),
];

const GENERIC: Operator[] = [
  op("payload/enum-swap", "payload", null, "re-id + re-sign + sort", always, (seed, rng) => {
    const bundle = fresh(seed);
    const bundleKeys = Object.keys(BUNDLE_ENUMS).filter((key) => typeof bundle[key] === "string");
    if (rng.int(8) === 0 && bundleKeys.length > 0) { const key = rng.pick(bundleKeys); const next = rng.pick(BUNDLE_ENUMS[key]!.filter((value) => value !== bundle[key])); bundle[key] = next; return encode(bundle, key, `${key} -> ${next}`); }
    const hit = pickField(bundle, rng, Object.keys(ENUMS), (value) => typeof value === "string");
    if (hit === null) return null;
    const next = rng.pick(ENUMS[hit.path]!.filter((value) => value !== hit.value));
    resignAt(bundle, hit.category, hit.index, (value) => setAt(value, hit.path.split("."), next));
    return encode(bundle, `artifacts.${hit.category}.*.payload.${hit.path}`, `${hit.category}[${hit.index}].${hit.path} -> ${next}`);
  }),
  op("payload/counter-pm1", "payload", null, "re-id + re-sign + sort (selector/trust digests recomputed)", always, (seed, rng) => {
    const bundle = fresh(seed);
    if (rng.int(6) === 0) {
      const which = rng.pick(["created_at", "selector.committed_from", "selector.committed_until", "trust_inputs.evaluation_time", "trust_inputs.trust_store.created_at", "trust_inputs.expected_anchor_heads.0.observed_at", "trust_inputs.expected_anchor_heads.0.tree_size"]);
      const tokens = which.split("."); const current = getAt(bundle, tokens); if (typeof current !== "number") return null;
      setAt(bundle, tokens, current + (rng.bool() ? 1 : -1)); if (which.startsWith("selector")) recalcSelector(bundle); if (which.includes("trust_store")) recalcTrust(bundle);
      return encode(bundle, which, `${which} +-1`);
    }
    const hit = pickField(bundle, rng, COUNTERS, (value) => typeof value === "number");
    if (hit === null) return null;
    const delta = rng.bool() ? 1 : -1;
    resignAt(bundle, hit.category, hit.index, (value) => setAt(value, hit.path.split("."), (hit.value as number) + delta));
    return encode(bundle, `artifacts.${hit.category}.*.payload.${hit.path}`, `${hit.category}[${hit.index}].${hit.path} ${delta > 0 ? "+" : "-"}1`);
  }),
  op("payload/bstr-length", "payload", null, "re-id + re-sign + sort", always, (seed, rng) => {
    const bundle = fresh(seed); const { category, index } = rng.pick(envelopes(bundle));
    const fields = Object.entries(payload(list(bundle, category)[index]!)).filter(([, value]) => value instanceof Uint8Array && value.length > 0);
    if (fields.length === 0) return null;
    const [field, value] = rng.pick(fields) as [string, Uint8Array]; const longer = rng.bool();
    resignAt(bundle, category, index, (next) => { next[field] = longer ? Uint8Array.from([...value, 0]) : value.slice(0, -1); });
    return encode(bundle, `artifacts.${category}.*.payload.${field}`, `${category}[${index}].${field} length ${longer ? "+" : "-"}1`);
  }),
  op("payload/field-drop", "payload", null, "re-id + re-sign + sort", always, (seed, rng) => {
    const bundle = fresh(seed); const { category, index } = rng.pick(envelopes(bundle));
    const keys = Object.keys(payload(list(bundle, category)[index]!)).filter((key) => !key.endsWith("_id") || key === "subject_credential_id"); // the id field is recomputed by the repair, dropping it is a no-op
    if (keys.length === 0) return null;
    const field = rng.pick(keys);
    resignAt(bundle, category, index, (next) => { delete next[field]; });
    return encode(bundle, `artifacts.${category}.*.payload.${field}`, `${category}[${index}] drop ${field}`);
  }),
  op("payload/id-swap", "payload", null, "re-id + re-sign + sort", always, (seed, rng) => {
    const bundle = fresh(seed); const pool = ids(bundle);
    // an artifact's own id field is recomputed by the repair, so swapping it would be a no-op
    const hit = pickField(bundle, rng, REFERENCES, (value) => value instanceof Uint8Array && value.length === 32, (category, path) => path === (ID_DOMAIN[category]?.[0] ?? "request_id"));
    if (hit === null || pool.length < 2) return null;
    const others = pool.filter((candidate) => toHex(candidate) !== toHex(hit.value as Uint8Array)); if (others.length === 0) return null;
    const next = rng.pick(others);
    resignAt(bundle, hit.category, hit.index, (value) => setAt(value, hit.path.split("."), next));
    return encode(bundle, `artifacts.${hit.category}.*.payload.${hit.path}`, `${hit.category}[${hit.index}].${hit.path} -> ${toHex(next).slice(0, 8)}`);
  }),
  op("artifact/duplicate", "payload", 3, "none (array left unsorted)", (seed) => envelopes(seed.bundle).length > 0, (seed, rng) => {
    const bundle = fresh(seed); const { category, index } = rng.pick(envelopes(bundle)); const target = list(bundle, category);
    target.splice(rng.int(target.length + 1), 0, clone(target[index]!));
    return encode(bundle, `artifacts.${category}`, `${category}[${index}] duplicated`);
  }),
  op("artifact/reorder", "payload", 3, "none", (seed) => ENVELOPED.some((category) => list(seed.bundle, category).length > 1), (seed, rng) => {
    const bundle = fresh(seed); const category = rng.pick(ENVELOPED.filter((name) => list(bundle, name).length > 1)); const target = list(bundle, category);
    const i = rng.int(target.length); const j = (i + 1 + rng.int(target.length - 1)) % target.length; [target[i], target[j]] = [target[j]!, target[i]!];
    return encode(bundle, `artifacts.${category}`, `${category} swap ${i} <-> ${j}`);
  }),
  op("artifact/delete", "payload", null, "none", (seed) => envelopes(seed.bundle).length > 0, (seed, rng) => {
    const bundle = fresh(seed); const { category, index } = rng.pick(envelopes(bundle)); list(bundle, category).splice(index, 1); sortArtifacts(bundle, category);
    return encode(bundle, `artifacts.${category}`, `${category}[${index}] deleted`);
  }),
];

export const OPERATORS: readonly Operator[] = [...RAW, ...COSE, ...GENERIC, ...STEP_OPERATORS];
