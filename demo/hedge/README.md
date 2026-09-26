# Independent observer feasibility spike

Actor: `LIVE_TARGETS.ptz` (Q6358-LE, `cam-q6358-vapix`). Observer:
`LIVE_TARGETS.stream` (Q6325-LE, `cam-q6325-vapix`). Runtime secrets come
from `CredStoreProvider`; reports contain credential references only.

Inside an authorized physical test window:

```sh
AAR_LIVE_WINDOW=1 bun run hedge:preflight --probe \
  --roi 0,0,320,240 --control-roi 320,0,320,240 --out /tmp/hedge-probe
AAR_LIVE_WINDOW=1 bun run hedge:preflight --toggle \
  --probe-passed /tmp/hedge-probe/report.json \
  --roi 0,0,320,240 --control-roi 320,0,320,240 \
  --frames 5 --interval-ms 500 --out /tmp/hedge-toggle
```

ROIs use integer pixels (`x,y,width,height`); choose them for the actual
observer scene. Each omitted ROI defaults to the full frame. Defaults are
probe mode, 5 frames per phase, 500 ms between captures, and a timestamped
directory under `demo/hedge/runs/`. Use a separate output directory per run.
The probe report prints JSON and is saved as `report.json`; frames are in
`frames/`. Toggle validates the prior report's targets and repeats the probe,
including a fresh observer light check. Enabled but unlit observer lights
also refuse the toggle. Nonzero exit means refusal, failure, or reset mismatch.

Luma uses full-range BT.601 weights on decoded RGB, reported as integers
in `Y * 1000` (0–255000). Standard deviation is the population deviation
across frame means. Separation is `(post mean - baseline mean) /
max(baseline stddev, 1 Y)`, reported as `ratio * 1000`. Control ROI uses
the same calculation independently; it is not subtracted from the ROI.
This spike measures physical separation, not causal proof or repeated trials.

The only mutation is the actor's `IrCutFilter=off`, followed by restoring
its exact original value in `finally`. Readbacks and light polls are saved.
SIGINT/SIGTERM request graceful cancellation with restoration. Successful
readback and light-state restoration give `repeatable_reset: true` for a
fixed original mode; a mismatch gives `false`. Restoring `auto`, or missing
reset evidence, gives `unknown`: parameter restoration does not establish
the previous optical state. A hard kill cannot execute restoration.

`bun test demo/hedge` uses the existing Digest client and two in-memory mock
backends, with runtime-generated synthetic credentials. It needs no LAN or
credential store. Mock frames are JPEGs with controllable gray levels.

`jpeg-js` 0.4.4 declares `BSD-3-Clause` in its package manifest, recorded in
the root `package.json` under `dependencyLicenses`. Its bundled README also
includes the decoder's Apache-2.0 notice and encoder's Adobe BSD notice.
