import type { CborValue } from "../../harness/cbor";

export type ScenarioId = "S1" | "S2" | "S3" | "S4" | "S5" | "S6" | "S7";
export type ActionName = "camera.ptz.preset" | "camera.stream.view";
export type LogicalTargetName = "ptz-primary" | "fixed-primary";
export type AdapterId = "vapix" | "vms" | `${string}-stub`;

export interface LogicalCommandRequest {
  readonly actionName: ActionName;
  readonly targetId: Uint8Array;
  readonly targetLogicalName: LogicalTargetName;
  readonly parameters: Readonly<Record<string, string | number | boolean>>;
  readonly invocationId: Uint8Array;
}

type CredentialField = "authorization" | "credential" | "credentials" | "password" | "secret" | "ha1" | "headers";
export type SecretFree<T> = T & { readonly [K in CredentialField]?: never };

export interface CommandManifest {
  readonly adapter_id: AdapterId;
  readonly adapter_version: string;
  readonly target_id: Uint8Array;
  readonly action_name: ActionName;
  readonly canonical_command: Uint8Array;
  readonly command_digest: Uint8Array;
  readonly excluded_fields: readonly CborValue[];
  readonly idempotency_key: Uint8Array;
}

export interface WitnessObservation {
  readonly timestamp: string;
  readonly invocation_id: string;
  readonly command_digest: string | null;
  readonly action_bearing: boolean;
  readonly request_line: string;
  readonly request_body_sha256: string;
  readonly response_line: string;
  readonly response_body_sha256: string;
}

export interface EffectOracle {
  readonly adapter_id: AdapterId;
  readonly invocation_id: string;
  readonly command_digest: string;
  readonly target_logical_name: LogicalTargetName;
  readonly observed_at: number;
  readonly state: "consistent" | "contradicted" | "unknown";
  readonly outcome_level: "device_acknowledged" | "contradicted" | "unknown";
  readonly observation_digest: string;
  readonly backend_evidence: Readonly<Record<string, string | number | boolean>>;
}

export interface DispatchResult {
  readonly dispatched: boolean;
  readonly status: number;
  readonly responseBodyDigest: Uint8Array;
  readonly effect: EffectOracle;
}

export interface DispatchContext {
  readonly invocationIdHex: string;
  readonly commandDigestHex: string;
  readonly witnessLogPath: string;
  readonly observedAt: number;
  readonly afterActionDispatched?: () => Promise<void>;
}

export interface DemoAdapter {
  readonly id: AdapterId;
  readonly version: string;
  dispatch(command: CommandManifest, context: DispatchContext): Promise<DispatchResult>;
  reconcile?(command: CommandManifest, context: DispatchContext): Promise<DispatchResult>;
}

export interface CredentialAccess {
  readonly reference: string;
  readonly secret: string;
}

export interface CredentialProvider {
  get(reference: string): Promise<CredentialAccess>;
}
