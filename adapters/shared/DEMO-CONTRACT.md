# AAR Gate 5 demo contract v0.1

Status: versioned, non-wire D1 contract. It does not extend or reinterpret the
AAR v0.2 wire format. Values marked **FILL-AT-D2** require the owned lab.

## Abstract commands and logical targets

Adapters accept only these secret-free commands:

| Action | Logical target | Parameters |
|---|---|---|
| `camera.ptz.preset` | `ptz-primary` | `{preset_name}` |
| `camera.stream.view` | `fixed-primary` | `{stream_profile}` |

Logical names are resolved by backend configuration outside the repository.
The mapping is one-to-one for a run and is committed by target ID in the AAR
command manifest. Hostnames, credentials, raw URLs, and backend object IDs are
not command-manifest fields.

## Preset mapping

`preset_name` is a stable logical name. Each backend maps it independently:

| Logical preset | VAPIX preset number | VMS preset/object ID |
|---|---|---|
| `gate5-safe` | **FILL-AT-D2** | **FILL-AT-D2** |

Only `gate5-safe` is permitted in Gate 5. The VAPIX adapter must capture the
baseline, obtain an exclusive-control window, move once, poll without
redispatch, and restore/verify the baseline. Exact safe-preset and exclusion
procedures are **FILL-AT-D2**.

## Stream-view success

- VAPIX: one explicitly requested stream response returns an accepted HTTP
  status and at least one syntactically valid media payload unit from the
  mapped profile. Digest challenges and TCP connection success are not stream
  success. Profile name and minimum payload rule are **FILL-AT-D2**.
- VMS: the headless control seam confirms the mapped live-view resource is
  open and returns the backend's device/media acknowledgement. Queue acceptance
  alone is not success. The exact API field and resource-release behavior are
  **FILL-AT-D2** after the Vigil spike.

## PTZ tolerance and settling

The oracle compares device-reported pan/tilt/zoom to the designated preset.
Pan and tilt tolerance, zoom tolerance, poll cadence, and hard settling
deadline are **FILL-AT-D2**. Timeout, transport rejection, application error,
or inability to read position downgrades the outcome to `unknown`; polling may
not redispatch the move.

## Outcome evidence levels and downgrade rules

| Adapter/action | Success level | Effect oracle | Mandatory downgrade |
|---|---|---|---|
| VAPIX PTZ | `device_acknowledged` | Same camera's position readback is within the pinned tolerance before the deadline. | Rejection, VAPIX error in HTTP 2xx, timeout, missing/invalid readback, or tolerance miss -> `unknown` or `contradicted` when contrary position is positively observed. |
| VAPIX stream | `device_acknowledged` | Stream rule above succeeds for the mapped profile. | Challenge-only traffic, empty/invalid media, rejection, or timeout -> `unknown`/`contradicted` as observed. |
| VMS PTZ | **FILL-AT-D2**; never above `device_acknowledged` without device readback | VMS queue/command acknowledgement plus the strongest reachable effect observation, pinned after the spike. | Queue acceptance without effect observation cannot be reported as device acknowledgement. |
| VMS stream | **FILL-AT-D2**; never above `device_acknowledged` without device/media acknowledgement | VMS live-view rule above. | Queue-only acceptance, timeout, or rejection -> `unknown`/`contradicted`. |

Same-device PTZ readback is not independent evidence. The demo therefore bars
any `independently_sensed`/“verified” claim for it.

## Effect-oracle result shape

Every adapter returns this non-wire shape to the online oracle:

```ts
type EffectOracle = {
  adapter_id: "vapix" | "vms" | `${string}-stub`;
  invocation_id: string;       // 16-byte lowercase hex
  command_digest: string;      // 32-byte lowercase hex
  target_logical_name: "ptz-primary" | "fixed-primary";
  observed_at: number;
  state: "consistent" | "contradicted" | "unknown";
  outcome_level: "device_acknowledged" | "contradicted" | "unknown";
  observation_digest: string;  // digest of sanitized oracle data
  backend_evidence: Record<string, string | number | boolean>;
};
```

VAPIX evidence keys are `http_status`, `application_status`, and either
sanitized position/tolerance values or stream/profile validation values. VMS
keys are **FILL-AT-D2**. No credential, Authorization header, HA1, raw response
body, or credential-derived commitment is permitted.
