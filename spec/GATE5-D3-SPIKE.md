# Gate 5 — D3 Vigil headless-seam spike (Q5-1)

2026-07-18. Time-boxed spike per the Q5-1 ruling: before building the VMS
leg, prove a **headless control seam** is reachable in Vigil (which has no
`IntentInvocationRecord` in code today). Independent IP (Vigil), IP-isolated
from Alpha Vision.

## Verdict: headless seam PROVEN reachable — spike SUCCEEDS on the Q5-1 criterion.

### Evidence (code + live, not code-reading alone)

- **VigilCore is a standalone SwiftPM package** (library targets +
  `vigil-spike` executable). It builds headlessly outside Xcode / the GUI
  app: `swift build --target AxisEngine` succeeds in ~6 s.
- **`VigilCore.AxisEngine.VAPIXClient`** (a Swift `actor`) already implements
  the full control surface the AAR abstract commands need:
  `ptzGotoPreset(name:)`, `ptzGetPosition()`, `ptzMove`, `ptzGoto`,
  `ptzListPresets()`, `getSnapshot(...)`, `getStreamProfiles()`. Init takes
  `host / username / password` directly and uses `URLSession` — no app
  dependency.
- The pre-flight blocker from the 2026-06-25 App Intents spike
  (Keychain `kSecAttrAccessGroup` + SwiftData `ModelConfiguration` reachable
  ONLY from the `com.vigil.mac` process) **does not bind this path**: the
  control seam takes creds as parameters and runs as its OWN process, exactly
  like an AAR adapter would inject `cred get` values. App Intents /
  in-process / Keychain are the SiriKit surface; they are not the seam D3
  needs.
- **Live proof (owned Q6358-LE .33):** a throwaway SwiftPM executable
  depending on `VigilCore` drove the real camera headlessly —
  `device: Q6358-LE fw=12.9.57 serial=E82725146996`, `presets: ["Home"]`,
  and a real `ptzGotoPreset("Home")` physically moved the camera
  (173.93/−0.08/7998 → 0.0/−44.99/1.0). Camera returned to park after.
  Probe was throwaway (scratchpad), Vigil source unmodified.

## The load-bearing nuance (this is the decision, and it is Matthew's)

Vigil's control seam speaks **VAPIX** to the Axis camera (`VAPIXClient`). So a
Vigil-mediated D3 leg would demonstrate:

- ✅ **VMS-mediated dispatch** — the AAR EP hands an abstract command to a
  VMS (Vigil), which translates + dispatches. Distinct mediation architecture
  from D2b's direct adapter.
- ✅ **A second, independent adapter IMPLEMENTATION** — Swift `VAPIXClient`
  (actor, URLSession, its own digest auth) vs D2b's TypeScript
  `DigestHttpClient`. Cross-implementation agreement is real signal.
- ❌ **NOT a second wire protocol** — the terminal wire is still VAPIX, same
  as D2b.
- ❌ **NOT cross-vendor** — still Axis.

The rubric's two-adapter demo (title: "VAPIX + one VMS") and the Q5-1
fallback clause both turn on exactly this: the ONVIF fallback was framed as
"two-protocol / same-vendor demo, VMS + cross-vendor claim deferred." The
Vigil path inverts that trade: it IS VMS-mediated (the thing ONVIF is not)
but is NOT a second protocol (the thing ONVIF is).

## Options for D3 (Matthew rules the external-claim wording — rubric line 168)

**A. Vigil VMS leg.** Build a small headless `vigil-control` executable target
in VigilCore (maps the AAR abstract commands → `VAPIXClient` calls, JSON I/O,
routed through the transport witness); the AAR TS adapter drives it. Claim =
"validated across VMS-mediated dispatch + a second independent adapter
implementation." Honestly NOT cross-protocol / cross-vendor.
Build est: ~1 day (seam exists; work is the CLI wrapper + witness routing +
the 6 scenarios). Witness-routing note: `VAPIXClient` uses `URLSession`, so
routing through the HTTP witness needs `connectionProxyDictionary` or a
base-host override — a D3-build detail, not a blocker.

**B. ONVIF fallback (P3285-LVE .19).** Genuine second WIRE protocol (ONVIF vs
VAPIX), same vendor (Axis). Claim = "two-protocol / same-vendor"; VMS +
cross-vendor deferred. This is direct-to-device, NOT VMS-mediated. The P3285
ONVIF stack is already provisioned (2026-04-27, Digest auth, 368 events / 41
topics captured). Build est: ~1–1.5 days (new ONVIF adapter, no existing
code to lean on the way Vigil gives us).

**C. Both.** Vigil (VMS-mediation) + ONVIF (second protocol) → strongest
evidence for the RFP, weakest on time. Build est: ~2–2.5 days.

## Recommendation

**Option A (Vigil VMS leg)** — it is what the Q5-1 ruling pre-authorized on
spike success, the seam is proven and cheap to wrap, and VMS-mediation is the
architecturally interesting axis (it exercises the AAR authorization boundary
being handed to a mediator, which is closer to the real deployment shape than
a second direct wire). Pair it with an explicit GATE5-CLOSE sentence stating
the claim is VMS-mediated-dispatch + second-implementation, NOT
cross-protocol / cross-vendor — so the honest boundary is on the record and
ONVIF (Option B) stays available as a later, additive "second protocol" leg
if the RFP needs that specific claim. This keeps every claim earned.

Deferred either way: `IntentInvocationRecord` / EdgeProof-signed audit seam
in Vigil is still not built — the AAR EP supplies the receipt/authorization
layer here, so D3 does not depend on it. The Vigil App Intents v1 build
remains a separate, not-yet-greenlit track.
