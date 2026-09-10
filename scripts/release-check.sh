#!/usr/bin/env bash
# Release gate. Every tag must pass all of this; CI runs it on every push/PR.
set -euo pipefail
cd "$(dirname "$0")/.."
run() { echo; echo "== $*"; "$@"; }
run bunx tsc --noEmit -p tsconfig.json
run bun test harness
run python3 -B -m pyref.kat --slice all
run python3 -B -m pyref.schema_kat
run bun test demo/ep/wire-builder.golden.test.ts
run bun test adapters
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo; echo "release-check: working tree is dirty after the gate (generated files changed?)"; git status --short; exit 1
fi
echo; echo "release-check: PASS"
