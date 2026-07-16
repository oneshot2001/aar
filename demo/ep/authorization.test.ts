import { expect, test } from "bun:test";
import { id16 } from "../../harness/crypto";
import { evaluateAuthorization, type DemoTrustPolicy } from "./authorization";

test("demo trust policy selects an unlabelled expired token without dispatch authority", () => {
  const authorityKid = new Uint8Array(32).fill(7);
  const target = id16("authorized-target");
  const policy: DemoTrustPolicy = { version: 1, profile: "AAR-3", purposeId: "incident-response", authorityKid, allowedActions: ["camera.ptz.preset"], allowedTargets: [target] };
  const result = evaluateAuthorization("S3", 100, "camera.ptz.preset", target, authorityKid, [{ notBefore: 1, notAfter: 99 }, { notBefore: 99, notAfter: 200 }], policy);
  expect(result.authorized).toBeFalse();
  expect(result.selected.notAfter).toBe(99);
});
