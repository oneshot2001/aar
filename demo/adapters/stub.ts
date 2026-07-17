import type { AdapterId, CommandManifest, DemoAdapter, DispatchContext, DispatchResult } from "../../adapters/shared/types";
import { encodeCbor, toHex } from "../../harness/cbor";
import { hash } from "../../harness/crypto";
import { AppendOnlyWitnessLog } from "../witness/log";

function createStub(id: AdapterId): DemoAdapter {
  return {
    id,
    version: "0.1.0-d1-stub",
    async dispatch(command: CommandManifest, context: DispatchContext): Promise<DispatchResult> {
      const response = encodeCbor({ accepted: true, adapter: id, operation: command.action_name });
      const responseBodyDigest = hash(response);
      await new AppendOnlyWitnessLog(context.witnessLogPath).append({
        timestamp: new Date(context.observedAt * 1000).toISOString(),
        invocation_id: context.invocationIdHex,
        command_digest: context.commandDigestHex,
        action_bearing: true,
        request_line: `POST /synthetic/${command.action_name} HTTP/1.1`,
        request_body_sha256: toHex(hash(command.canonical_command)),
        response_line: "HTTP/1.1 202 Accepted",
        response_body_sha256: toHex(responseBodyDigest),
      });
      await context.afterActionDispatched?.();
      const oracleData = encodeCbor({
        adapter_id: id, invocation_id: context.invocationIdHex, command_digest: context.commandDigestHex,
        action: command.action_name, state: "consistent", observed_at: context.observedAt,
      });
      return {
        dispatched: true,
        status: 202,
        responseBodyDigest,
        effect: {
          adapter_id: id,
          invocation_id: context.invocationIdHex,
          command_digest: context.commandDigestHex,
          target_logical_name: command.action_name === "camera.ptz.preset" ? "ptz-primary" : "fixed-primary",
          observed_at: context.observedAt,
          state: "consistent",
          outcome_level: "device_acknowledged",
          observation_digest: toHex(hash(oracleData)),
          backend_evidence: { synthetic: true, http_status: 202, application_status: "accepted" },
        },
      };
    },
  };
}

export function createVapixStub(): DemoAdapter { return createStub("vapix-stub"); }
export function createVmsStub(): DemoAdapter { return createStub("vms-stub"); }
