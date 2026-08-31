#!/bin/sh
# One-command re-runner for the TrustMeBro fabricated-tool-output efficacy eval.
# Runs Arm A (raw-output gate), Arm B (receipt/AAR gate, legit + attack) and
# Arm C1 (keyless-signer control) and writes every transcript + pyref verdict
# to eval/trustmebro/out/.
# Run from the repo root:  sh eval/trustmebro/run.sh
set -eu

DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO=$(CDPATH= cd "$DIR/../.." && pwd)
OUTDIR="$DIR/out"

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

echo "== Arm A =="
sh "$DIR/arm_a.sh" "$OUTDIR"
echo
echo "== Arm B + Arm C1 =="
cd "$REPO"
python3 -m pyref --help >/dev/null 2>&1 || { echo "pyref unavailable" >&2; exit 1; }
python3 "$DIR/arm_b.py" "$OUTDIR"

echo "transcripts written to $OUTDIR"
