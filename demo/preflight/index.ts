export interface CredentialAccess {
  readonly reference: string;
  readonly secret: string;
}

export interface CredentialProvider {
  get(reference: string): Promise<CredentialAccess>;
}

export interface PreflightTransport {
  get(url: string, credential: CredentialAccess): Promise<{ status: number; body: string }>;
}

export interface PreflightConfig {
  readonly baseUrl: string;
  readonly credentialReference: string;
  readonly expectedModel: string;
  readonly expectedSerial: string;
  readonly presetName: string;
  readonly streamProfile: string;
  readonly backendMapping: Readonly<Record<string, string>>;
}

export interface PreflightResult {
  readonly ok: boolean;
  readonly checks: Readonly<Record<"credential_access" | "identity" | "model_firmware" | "preset" | "stream_profile" | "backend_mapping", boolean>>;
  readonly sanitized: { readonly model: string; readonly firmware: string; readonly serial: string };
}

export class CredStoreProvider implements CredentialProvider {
  async get(reference: string): Promise<CredentialAccess> {
    const child = Bun.spawn(["cred", "get", reference], { stdout: "pipe", stderr: "ignore" });
    const [exitCode, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()]);
    if (exitCode !== 0) throw new Error(`cred get failed for reference ${reference}`);
    const secret = stdout.replace(/\r?\n$/, "");
    if (!secret) throw new Error(`cred get returned an empty secret for reference ${reference}`);
    return { reference, secret };
  }
}

export function parseParamList(body: string): Readonly<Record<string, string>> {
  return Object.fromEntries(body.split(/\r?\n/).filter(Boolean).map((line) => {
    const separator = line.indexOf("=");
    return separator < 1 ? [line, ""] : [line.slice(0, separator), line.slice(separator + 1)];
  }));
}

export async function runPreflight(config: PreflightConfig, transport: PreflightTransport, credentials: CredentialProvider): Promise<PreflightResult> {
  const credential = await credentials.get(config.credentialReference);
  const query = new URL("/axis-cgi/param.cgi", config.baseUrl);
  query.searchParams.set("action", "list");
  query.searchParams.set("group", "Properties.System,root.Brand,root.PTZ.Preset,root.StreamProfile");
  const response = await transport.get(query.toString(), credential);
  const values = parseParamList(response.body);
  const model = values["root.Brand.ProdFullName"] ?? values["Properties.System.ProductName"] ?? "";
  const firmware = values["root.Properties.Firmware.Version"] ?? values["Properties.System.FirmwareVersion"] ?? "";
  const serial = values["root.Properties.System.SerialNumber"] ?? values["Properties.System.SerialNumber"] ?? "";
  const checks = {
    credential_access: credential.secret.length > 0,
    identity: response.status === 200 && serial === config.expectedSerial,
    model_firmware: model === config.expectedModel && firmware.length > 0,
    preset: Object.entries(values).some(([key, value]) => key.includes("PTZ.Preset") && value === config.presetName),
    stream_profile: Object.entries(values).some(([key, value]) => key.includes("StreamProfile") && value === config.streamProfile),
    backend_mapping: config.backendMapping["ptz-primary"] !== undefined && config.backendMapping["fixed-primary"] !== undefined,
  } as const;
  return { ok: Object.values(checks).every(Boolean), checks, sanitized: { model, firmware, serial } };
}
