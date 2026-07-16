import { encodeCbor } from "../../harness/cbor";
import { domainHash, hash } from "../../harness/crypto";
import type { AdapterId, CommandManifest, LogicalCommandRequest, SecretFree } from "../../adapters/shared/types";

export interface BuiltCommandManifest extends CommandManifest {
  readonly command_id: Uint8Array;
}

export function buildCommandManifest<T extends LogicalCommandRequest>(
  request: SecretFree<T>,
  adapterId: AdapterId,
  adapterVersion: string,
): BuiltCommandManifest {
  const canonicalCommand = encodeCbor({
    operation: request.actionName,
    target: request.targetId,
    logical_target: request.targetLogicalName,
    parameters: request.parameters,
  });
  const fields: CommandManifest = {
    adapter_id: adapterId,
    adapter_version: adapterVersion,
    target_id: request.targetId,
    action_name: request.actionName,
    canonical_command: canonicalCommand,
    command_digest: hash(canonicalCommand),
    excluded_fields: [{ name: "authorization", reason: "injected_only_at_transport" }],
    idempotency_key: request.invocationId,
  };
  return { command_id: domainHash("AAR-COMMAND-MANIFEST-v1", fields), ...fields };
}
