import type { ActionName, ScenarioId } from "../../adapters/shared/types";
import type { CborValue } from "../../harness/cbor";
import { equalBytes } from "../../harness/cbor";
import { domainHash } from "../../harness/crypto";
import type { DelegationWindow } from "./wire-builder";

export interface DemoTrustPolicy {
  readonly version: 1;
  readonly profile: "AAR-3";
  readonly purposeId: "incident-response";
  readonly authorityKid: Uint8Array;
  readonly allowedActions: readonly ActionName[];
  readonly allowedTargets: readonly Uint8Array[];
}

export interface AuthorizationEvaluation {
  readonly authorized: boolean;
  readonly selected: DelegationWindow;
  readonly policyRoot: Uint8Array;
}

export function policyFields(policy: DemoTrustPolicy): Record<string, CborValue> {
  return {
    version: policy.version,
    profile: policy.profile,
    purpose_id: policy.purposeId,
    authority_kid: policy.authorityKid,
    allowed_actions: [...policy.allowedActions],
    allowed_targets: [...policy.allowedTargets],
  };
}

export function evaluateAuthorization(
  scenarioId: ScenarioId,
  evaluatedAt: number,
  actionName: ActionName,
  targetId: Uint8Array,
  presentedAuthorityKid: Uint8Array,
  candidates: readonly DelegationWindow[],
  policy: DemoTrustPolicy,
): AuthorizationEvaluation {
  if (!equalBytes(presentedAuthorityKid, policy.authorityKid)) throw new Error("delegation authority is not trusted by the demo policy");
  if (!policy.allowedActions.includes(actionName) || !policy.allowedTargets.some((target) => equalBytes(target, targetId))) {
    throw new Error("requested action/target is outside the demo trust policy");
  }
  const valid = candidates.filter((window) => window.notBefore <= evaluatedAt && evaluatedAt < window.notAfter);
  const expired = candidates.filter((window) => window.notAfter <= evaluatedAt);
  if (scenarioId === "S3") {
    if (candidates.length !== 2 || expired.length !== 1 || valid.length !== 1) {
      throw new Error("S3 requires exactly two unlabelled candidates: one expired and one neighboring valid token");
    }
    return { authorized: false, selected: expired[0]!, policyRoot: domainHash("AAR-DEMO-TRUST-POLICY-v1", policyFields(policy)) };
  }
  if (valid.length !== 1) throw new Error("authorized scenario requires exactly one valid delegation candidate");
  return { authorized: true, selected: valid[0]!, policyRoot: domainHash("AAR-DEMO-TRUST-POLICY-v1", policyFields(policy)) };
}
