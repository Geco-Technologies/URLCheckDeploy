#!/usr/bin/env bash
# Full local suite: syntax of every shipped JS file, manifest/schema JSON, HubSpot unit tests.
# Browser E2E (optional, needs playwright chromium): python tests/e2e/e2e.py <unpacked-ext-dir>
set -e; cd "$(dirname "$0")/.."
n=0; for f in $(find scripts popup options -name '*.js'); do
  if grep -qE '^\s*(import|export) ' "$f"; then node --input-type=module --check < "$f"; else node --check "$f"; fi; n=$((n+1)); done
echo "syntax ok: $n js files"
for j in manifest.json config/*.json rules/*.json; do python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$j"; done; echo "json ok"
node tests/hubspot-tracking-exempt.test.js | tail -1
node tests/unlock-online.test.mjs 2>&1 | grep -E "^(PASS|FAIL)|passed"
