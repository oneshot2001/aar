# VMS adapter (D3 — Vigil-mediated leg)

The Gate 5 VMS leg: the AAR EP dispatches abstract commands through the
transport witness to **vigil-control**, a loopback Swift service that wraps
`VigilCore.AxisEngine.VAPIXClient` (the Vigil VMS's own device engine; Vigil
source unmodified). The witness sits at the **AAR→mediator boundary** — it
attests whether the EP handed a command to the VMS at all; the device-facing
wire is the mediator's internal effect channel (GATE5-D3-PLAN.md).

## Claim boundary (verbatim, per operator ruling)

D3 demonstrates **VMS-mediated dispatch** and a **second independent adapter
implementation** (Swift `VigilCore.VAPIXClient` vs D2b's TypeScript
`DigestHttpClient`). It does **NOT** claim a second wire protocol or
cross-vendor support — Vigil speaks VAPIX to the same Axis devices.

## Command binding

The action-bearing dispatch is `POST /dispatch?...&digest=<sha256>` whose
**body is the canonical command CBOR** the EP committed to in the bundle, so
the witnessed `request_body_sha256` equals the command digest (the online
oracle's POST-body binding). vigil-control independently refuses to act when
`sha256(body) != digest`. The F19 restore (`op=ptz.goto`) is action-bearing
but intentionally unbound — safety orchestration, not the committed command.

## Known limitations (on the record)

- **Stream profile is echo-only** (G5-D3-003): the mediator fetches the media
  unit via the VMS's snapshot seam and echoes the logical profile for
  evidence; it does not bind the fetch to the mapped backend profile. The
  evidence claim is "one validated media unit via the VMS control seam", not
  "media from the mapped profile". The mock mirrors this.
- **Error-in-200 masking** (G5-D3-001): `VigilCore.PTZPosition.parse` never
  fails, so vigil-control refuses all-zeros readbacks (impossible on real
  Axis PTZ — zoom is 1-based) rather than report a fabricated position. A
  live S6-rejection induced by an unknown preset surfaces as position-based
  contradiction (`position_outside_tolerance`), not `http_rejected_N` —
  plan the live fault induction accordingly.
- `FILL-AT-D3` values must not contain spaces (URLSearchParams `+` encoding
  vs Swift URLComponents non-decoding mismatch — fail-closed, but confusing).

## Secrets

The TS process never holds a device secret. Requests carry a credential
REFERENCE; vigil-control resolves it via `cred get` in its own process. The
offline suite holds a canary secret inside the mock mediator and sweeps all
artifacts for every transform of it.

## Layout

- `config.ts` — runtime config + `FILL-AT-D3` placeholders (live values)
- `client.ts` — witnessed plain-HTTP mediator client (after-send latching)
- `adapter.ts` — `VmsAdapter` (`DemoAdapter` id `vms`), F19 orchestration
  mirrored from the D2b VAPIX adapter
- `vigil-control/` — SwiftPM executable mediator (path-dep on the Vigil repo)
- `mock/` — in-memory vigil-control double + witness transport
- `offline/run.ts` — S1–S4 + S6 suite through pyref (S5 crash-cut runs once
  on the EP+VAPIX leg per Q5-2; this leg encodes `outcome_unknown` via
  S6-after-send-timeout)

Run offline: `bun test adapters/vms` or `bun run adapters/vms/offline/run.ts`.
