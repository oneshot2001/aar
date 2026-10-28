// The kats/relying-party row protocol (D-83 part 11): one *.inputs.json
// sidecar per row naming policy, key, exact pin, prior and replay state, time,
// and optionally the bundle file (pyref/kat_inputs.py mirror).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fromHex } from "./cbor";
import { loadConfiguration } from "./relying-party";
import { statefulOptions } from "./stateful-fixtures";
import { Obj, VerifyB1Options } from "./verifier";

// null = not supplied; bundle = path of the bundle bytes relative to the sidecar (default <name>.cbor beside it).
export interface RpInputs { policy: string; signing_key: string; trust_policy: string | null; prior_state: string | null; replay_state: string | null; at: number; bundle?: string }

// The exact-pin JSON (pyref --trust-policy format) as the harness configuredTrustPolicy value.
export function parsePin(pin: Record<string, any>): Obj {
  return {
    trust_store: { digest: fromHex(pin.trust_store.digest), snapshot_id: fromHex(pin.trust_store.snapshot_id), created_at: pin.trust_store.created_at,
      roots: pin.trust_store.roots.map((root: Record<string, any>) => ({ root_id: fromHex(root.root_id), root_kid: fromHex(root.root_kid), tenant_id: fromHex(root.tenant_id), allowed_sites: root.allowed_sites.map(fromHex), allowed_key_usages: root.allowed_key_usages })) },
    expected_anchor_heads: pin.expected_anchor_heads.map((head: Record<string, any>) => ({ target_id: fromHex(head.target_id), observed_at: head.observed_at, tree_size: head.tree_size, root: fromHex(head.root) })),
    verifier_policy_digest: fromHex(pin.verifier_policy_digest),
  };
}

export function rpBundlePath(directory: string, name: string, inputs: RpInputs): string { return join(directory, inputs.bundle ?? `${name}.cbor`); }

// verifyBundle options for one row from its inputs sidecar (the harness decodes the policy itself).
export function rpOptions(directory: string, inputs: RpInputs): VerifyB1Options {
  const file = (name: string | null): string | undefined => name === null ? undefined : join(directory, name);
  const json = (name: string): Record<string, any> => JSON.parse(readFileSync(join(directory, name), "utf8"));
  return {
    evaluationTime: inputs.at,
    configuration: loadConfiguration(file(inputs.policy), file(inputs.signing_key), inputs.at),
    configuredTrustPolicy: inputs.trust_policy === null ? undefined : parsePin(json(inputs.trust_policy)),
    ...(inputs.prior_state === null ? {} : statefulOptions(json(inputs.prior_state))),
    replayState: inputs.replay_state === null ? undefined : (json(inputs.replay_state).entries ?? []).map((entry: Record<string, string>) => ({ replayDomain: fromHex(entry.replay_domain!), invocationId: fromHex(entry.invocation_id!), contentDigest: fromHex(entry.content_digest!) })),
  };
}
