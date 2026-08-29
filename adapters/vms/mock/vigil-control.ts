import { createHash } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import type { DigestResponse, HttpTransportRequest } from "../../vapix/digest";
import type { PtzPosition } from "../config";
import type { CborValue } from "../../../harness/cbor";
import { encodeCbor } from "../../../harness/cbor";
import { domainHash, hash } from "../../../harness/crypto";

// In-memory test double for the vigil-control mediator (contract v3). It
// mirrors the real service's HTTP surface exactly — same paths, same query
// routing, same body-digest refusal, same DispatchEffect JSON — so the D3
// live leg swaps only the transport and the FILL-AT-D3 configuration.
// The credential resolver lives inside this mock the way `cred get` lives
// inside the real service: the secret is held here and never appears in any
// response, mirroring the reference-only contract the TS adapter sees.

export type MockVmsFaultMode = "normal" | "reject" | "after-send-timeout" | "invalid-media" | "backend-transport-error";

export interface MockVigilControlConfig {
  readonly credentialReference: string;
  readonly secret: string;
  readonly expectedHost: string;
  readonly expectedUsername: string;
  readonly presetBackendName: string;
  readonly streamBackendProfile: string;
  readonly model: string;
  readonly serial: string;
  readonly firmware: string;
  readonly baseline: PtzPosition;
  readonly safePreset: PtzPosition;
  readonly settlingReads: number;
  readonly mediatorSigner?: { readonly privateKey: Uint8Array; readonly kid: Uint8Array };
  readonly mediatorCredential?: readonly CborValue[] | (() => readonly CborValue[]);
  readonly now?: () => number;
}

export interface MockVigilControlCounters {
  readonly positionReads: number;
  readonly presetDispatches: number;
  readonly restoreDispatches: number;
  readonly streamDispatches: number;
  readonly refusals: number;
}

const JPEG = Uint8Array.from([
  0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
  0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9,
]);

interface Effect {
  op: string;
  http_ok: boolean;
  application_status: string;
  pan?: number;
  tilt?: number;
  zoom?: number;
  content_type?: string;
  payload_bytes?: number;
  media_valid?: boolean;
  profile?: string;
  model?: string;
  serial?: string;
  firmware?: string;
  error?: string;
  countersignature?: string;
  countersignature_payload?: string;
  mediator_credential?: string;
}

function interpolate(current: PtzPosition, target: PtzPosition, remaining: number): PtzPosition {
  if (remaining <= 1) return { ...target };
  return {
    pan: current.pan + (target.pan - current.pan) / remaining,
    tilt: current.tilt + (target.tilt - current.tilt) / remaining,
    zoom: current.zoom + (target.zoom - current.zoom) / remaining,
  };
}

export class MockVigilControl {
  private position: PtzPosition;
  private target: PtzPosition;
  private remaining = 0;
  private mode: MockVmsFaultMode = "normal";
  private counts = { positionReads: 0, presetDispatches: 0, restoreDispatches: 0, streamDispatches: 0, refusals: 0 };

  constructor(readonly config: MockVigilControlConfig) {
    this.position = { ...config.baseline };
    this.target = { ...config.baseline };
  }

  setFaultMode(mode: MockVmsFaultMode): void {
    this.mode = mode;
  }

  counters(): MockVigilControlCounters {
    return { ...this.counts };
  }

  currentPosition(): PtzPosition {
    return { ...this.position };
  }

  private stepPosition(): PtzPosition {
    if (this.remaining > 0) {
      this.position = interpolate(this.position, this.target, this.remaining);
      this.remaining -= 1;
    }
    return this.position;
  }

  private moveTo(position: PtzPosition): void {
    this.target = { ...position };
    this.remaining = Math.max(1, this.config.settlingReads);
  }

  // The mock's `cred get`: resolves the reference to the internally-held
  // secret. A wrong reference or routing mismatch is a mediator-side error;
  // the resolved secret itself is used only within this method's scope, as
  // the real service uses it only inside VAPIXClient.
  private resolveRouting(url: URL): string | undefined {
    if (url.searchParams.get("host") !== this.config.expectedHost) return "routing_error";
    if (url.searchParams.get("username") !== this.config.expectedUsername) return "routing_error";
    if (url.searchParams.get("cred") !== this.config.credentialReference) return "routing_error";
    const secret = this.config.secret;
    if (!secret) return "routing_error";
    return undefined;
  }

  private json(effect: Effect): DigestResponse {
    const body = new TextEncoder().encode(JSON.stringify(effect));
    return { status: 200, statusMessage: "OK", headers: { "content-type": "application/json", "content-length": String(body.length) }, body };
  }

  private countersign(url: URL, commandDigest: string | null): Pick<Effect, "countersignature" | "countersignature_payload" | "mediator_credential"> | undefined {
    const signer = this.config.mediatorSigner;
    const attemptDigest = url.searchParams.get("attempt_digest");
    if (!signer || commandDigest === null || !attemptDigest || !/^[0-9a-f]{64}$/u.test(attemptDigest) || !/^[0-9a-f]{64}$/u.test(commandDigest)) return undefined;
    const fields: Record<string, CborValue> = {
      v: 2,
      action_attempt_receipt_digest: Uint8Array.from(Buffer.from(attemptDigest, "hex")),
      command_digest: Uint8Array.from(Buffer.from(commandDigest, "hex")),
      mediator_observed_at: Math.floor((this.config.now?.() ?? Date.now()) / 1000),
    };
    const payload = { countersignature_id: domainHash("AAR-MEDIATOR-COUNTERSIGNATURE-ID-v1", fields), ...fields };
    const payloadBytes = encodeCbor(payload);
    const protectedBytes = encodeCbor(new Map<number, CborValue>([
      [1, -7], [3, "application/aar-mediator-countersignature+cbor;v=0.2"], [4, signer.kid],
    ]));
    const sigStructure = encodeCbor(["Signature1", protectedBytes, new Uint8Array(), payloadBytes]);
    const signature = p256.sign(hash(sigStructure), signer.privateKey, { prehash: false, lowS: true, format: "compact", extraEntropy: false });
    const coseBytes = encodeCbor([protectedBytes, {}, null, signature]);
    const configuredCredential = this.config.mediatorCredential;
    const mediatorCredential = typeof configuredCredential === "function" ? configuredCredential() : configuredCredential;
    return {
      countersignature: Buffer.from(coseBytes).toString("base64"),
      countersignature_payload: Buffer.from(payloadBytes).toString("base64"),
      ...(mediatorCredential === undefined ? {} : {
        mediator_credential: Buffer.from(encodeCbor(mediatorCredential)).toString("base64"),
      }),
    };
  }

  async exchange(request: Pick<HttpTransportRequest, "method" | "url" | "body">): Promise<DigestResponse> {
    const url = request.url;
    if (request.method === "GET" && url.pathname === "/healthz") {
      const body = new TextEncoder().encode('{"ok":true}');
      return { status: 200, statusMessage: "OK", headers: { "content-type": "application/json" }, body };
    }
    if (request.method === "GET" && url.pathname === "/device/info") {
      const routingError = this.resolveRouting(url);
      if (routingError) return this.json({ op: "device.info", http_ok: false, application_status: routingError });
      return this.json({
        op: "device.info", http_ok: true, application_status: "ok",
        model: this.config.model, serial: this.config.serial, firmware: this.config.firmware,
      });
    }
    if (request.method === "GET" && url.pathname === "/ptz/position") {
      this.counts.positionReads += 1;
      const routingError = this.resolveRouting(url);
      if (routingError) return this.json({ op: "ptz.position", http_ok: false, application_status: routingError });
      const position = this.stepPosition();
      return this.json({ op: "ptz.position", http_ok: true, application_status: "ok", pan: position.pan, tilt: position.tilt, zoom: position.zoom });
    }
    if (request.method === "POST" && url.pathname === "/dispatch") {
      const op = url.searchParams.get("op") ?? "unknown";
      const digest = url.searchParams.get("digest");
      if (digest !== null) {
        const bodyDigest = createHash("sha256").update(request.body).digest("hex");
        if (bodyDigest !== digest.toLowerCase()) {
          this.counts.refusals += 1;
          return this.json({ op, http_ok: false, application_status: "body_digest_mismatch" });
        }
      }
      const attemptDigest = url.searchParams.get("attempt_digest");
      if (this.config.mediatorSigner && digest !== null && attemptDigest !== null && !/^[0-9a-f]{64}$/u.test(attemptDigest)) {
        return this.json({ op, http_ok: false, application_status: "countersignature_failed" });
      }
      const respond = (effect: Effect): DigestResponse => this.json({ ...effect, ...this.countersign(url, digest) });
      const routingError = this.resolveRouting(url);
      if (routingError) return respond({ op, http_ok: false, application_status: routingError });
      if (op === "ptz.goto_preset") {
        this.counts.presetDispatches += 1;
        if (digest === null) return respond({ op, http_ok: false, application_status: "digest_required" });
        const mode = this.mode;
        this.mode = "normal";
        if (mode === "reject") return respond({ op, http_ok: false, application_status: "http_rejected_503" });
        if (mode === "after-send-timeout") return new Promise<DigestResponse>(() => {});
        if (mode === "backend-transport-error") return respond({ op, http_ok: false, application_status: "transport_error", error: "mock backend unreachable" });
        if (url.searchParams.get("preset") !== this.config.presetBackendName) {
          return respond({ op, http_ok: false, application_status: "http_rejected_404" });
        }
        this.moveTo(this.config.safePreset);
        return respond({ op, http_ok: true, application_status: "ok" });
      }
      if (op === "ptz.goto") {
        this.counts.restoreDispatches += 1;
        const restored = {
          pan: Number(url.searchParams.get("pan")),
          tilt: Number(url.searchParams.get("tilt")),
          zoom: Number(url.searchParams.get("zoom")),
        };
        if (!Object.values(restored).every(Number.isFinite)) return respond({ op, http_ok: false, application_status: "missing_coordinates" });
        this.moveTo(restored);
        return respond({ op, http_ok: true, application_status: "ok" });
      }
      if (op === "stream.view") {
        this.counts.streamDispatches += 1;
        if (digest === null) return respond({ op, http_ok: false, application_status: "digest_required" });
        const mode = this.mode;
        this.mode = "normal";
        if (mode === "reject") return respond({ op, http_ok: false, application_status: "http_rejected_503" });
        if (mode === "after-send-timeout") return new Promise<DigestResponse>(() => {});
        if (mode === "backend-transport-error") return respond({ op, http_ok: false, application_status: "transport_error", error: "mock backend unreachable" });
        // G5-D3-003: the real mediator fetches via the VMS snapshot seam and
        // ECHOES the profile — it does not bind the fetch to it. The mock
        // mirrors that (a profile-mismatch rejection here would fake a check
        // the live leg does not perform).
        const profile = url.searchParams.get("profile") ?? "";
        if (mode === "invalid-media") {
          return respond({ op, http_ok: true, application_status: "media_payload_invalid", profile, content_type: "unknown", payload_bytes: 5, media_valid: false });
        }
        return respond({
          op, http_ok: true, application_status: "media_payload_valid",
          profile, content_type: "image/jpeg", payload_bytes: JPEG.length, media_valid: true,
        });
      }
      return respond({ op, http_ok: false, application_status: "unsupported_op" });
    }
    const body = new TextEncoder().encode('{"error":"not_found"}');
    return { status: 404, statusMessage: "Not Found", headers: { "content-type": "application/json" }, body };
  }
}
