# VAPIX adapter — Gate 5 D2a offline

Run the complete offline scenario set from the repository root:

```sh
bun run adapters/vapix/offline/run.ts
```

Pass an external output directory as the optional first argument to retain the
bundles, trust policies, prior state, transport-witness logs, oracle evidence,
and hygiene result. The runner creates a fresh signed agent request and fresh
invocation/correlation IDs for each scenario. It runs `python3 -m pyref verify`
with pinned `--at`, the emitted trust policy, and one advanced `--prior-state`.

The offline backend is a separate test double under `mock/`. It implements the
Digest challenge, authenticated PTZ/position and single-JPEG endpoints,
settling, HTTP rejection, HTTP-200 VAPIX application errors, and after-send
timeout. The independent offline transport witness records request boundaries
without recording headers. The adapter itself contains no mock modes; with no
test transport injected it uses the Node HTTP transport through the configured
witness proxy.

S7 injects a command-digest-scoped failure at the EP's pre-send action-attempt
journal commit. It produces a conformant `not_dispatched` receipt with
`journal/unavailable`, zero invocation-attributable witness entries, unchanged
mock camera position, and a `refused_pre_dispatch` pyref observation. The same
scenario is present in the live runner but remains gated by
`AAR_LIVE_WINDOW=1`.

## D2b configuration

D2b must supply the named values represented by `VAPIX_FILL_AT_D2`: PTZ and
stream base URLs, `cred get` reference and Digest username, designated safe
preset mapping and expected position, pan/tilt/zoom tolerances, poll cadence,
settling deadline, stream profile mapping, minimum JPEG payload size, and the
sanitized model/firmware values confirmed by green preflight. The
operator must also set `exclusiveControl: true` only during the physical
exclusive-control window. Private credentials and live configuration remain
outside the repository.

These offline runs do **not** satisfy Gate 5 exit bar #8 (F17). A mock backend
cannot replace the required gate-run S1 and S3 checks against the owned live
VAPIX cameras.
