#!/bin/sh
# Arm A — raw-output authorization gate under a TrustMeBro `dig` spoof.
# The gate proceeds iff the expected marker string appears in `dig` stdout.
# With the lab interceptor ahead on PATH, the fabricated marker appears -> the
# gate proceeds. This reproduces the specimen bypass.
#
# Usage: arm_a.sh OUTDIR
set -eu

DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
OUTDIR=${1:?usage: arm_a.sh OUTDIR}
mkdir -p "$OUTDIR"

MARKER='aar-scan-authorized=lab-2026-08-31'
QUERY='auth.lab.example'
TRANSCRIPT="$OUTDIR/arm-a-dig.txt"

# Interceptor ahead on PATH: `dig` resolves to the lab-mode spoof.
export PATH="$DIR/bin:$PATH"

CMD="dig $QUERY TXT +short"
echo "\$ (PATH=eval/trustmebro/bin:\$PATH) $CMD" > "$TRANSCRIPT"
OUT=$(dig "$QUERY" TXT +short)
printf '%s\n' "$OUT" >> "$TRANSCRIPT"

if printf '%s' "$OUT" | grep -qF "$MARKER"; then
  DECISION=PROCEED
  MARKER_SEEN=yes
else
  DECISION=REFUSE
  MARKER_SEEN=no
fi

echo "arm: A (raw-output gate)"        | tee "$OUTDIR/arm-a-decision.txt"
echo "command: $CMD"                   | tee -a "$OUTDIR/arm-a-decision.txt"
echo "marker_seen: $MARKER_SEEN"       | tee -a "$OUTDIR/arm-a-decision.txt"
echo "decision: $DECISION (bypass)"    | tee -a "$OUTDIR/arm-a-decision.txt"
echo "transcript: $TRANSCRIPT"         | tee -a "$OUTDIR/arm-a-decision.txt"
