import { expect, test } from "bun:test";
import { runPreflight, type CredentialProvider, type PreflightTransport } from "./index";

test("preflight checks param.cgi data through mocks without exposing a secret", async () => {
  let requested = "";
  const transport: PreflightTransport = { async get(url, credential) {
    requested = url;
    expect(credential.secret).toBe("canary-secret");
    return { status: 200, body: [
      "root.Brand.ProdFullName=AXIS Q6325-LE",
      "root.Properties.Firmware.Version=12.0.1",
      "root.Properties.System.SerialNumber=SERIAL",
      "root.PTZ.Preset.P0.Name=gate5-safe",
      "root.StreamProfile.S0.Name=Gate5",
    ].join("\n") };
  } };
  const credentials: CredentialProvider = { async get(reference) { return { reference, secret: "canary-secret" }; } };
  const result = await runPreflight({ baseUrl: "http://camera.invalid", credentialReference: "camera", expectedModel: "AXIS Q6325-LE", expectedSerial: "SERIAL", presetName: "gate5-safe", streamProfile: "Gate5", backendMapping: { "ptz-primary": "a", "fixed-primary": "b" } }, transport, credentials);
  expect(result.ok).toBeTrue();
  expect(requested).toContain("param.cgi");
  expect(requested).not.toContain("basicdeviceinfo");
  expect(JSON.stringify(result)).not.toContain("canary-secret");
});
