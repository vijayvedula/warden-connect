#!/usr/bin/env bash
# The countable claims in docs/08-lld.md §8.15 must match what is actually in the tree.
#
# The test-strategy table quotes sizes — "Lua suite (18)", "kong-drill.sh (15)" — and those are
# the most useful numbers in the document and the easiest to leave behind. Both had: the Lua
# suite said 19 against 18 cases, and the Kong drill said 11 after four phases were added to it
# in the same week. Nothing failed, because a number in a table is not executable.
#
# It is now. Adding a drill phase without updating the sentence that counts them fails here.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
claim() {   # claim <label> <actual> <regex capturing the number in the LLD>
  local label="$1" actual="$2" pattern="$3"
  local stated
  stated=$(grep -oE "$pattern" docs/08-lld.md | grep -oE '[0-9]+' | head -1)
  if [ -z "$stated" ]; then
    echo "  FAIL  $label: docs/08-lld.md no longer states a number here"; fail=1
  elif [ "$stated" != "$actual" ]; then
    echo "  FAIL  $label: the LLD says $stated, the tree has $actual"; fail=1
  else
    echo "  ok    $label: $actual"
  fi
}

claim "wc-kong ABI tests" \
  "$(grep -c '#\[test\]' crates/wc-kong/tests/abi.rs)" \
  'wc-kong` ABI tests \([0-9]+\)'

claim "Lua suite cases" \
  "$(grep -chE '^\s*t\.case\(' crates/wc-kong/lua/spec/*_spec.lua | paste -sd+ - | bc)" \
  'Lua suite \([0-9]+'

# Distinct phase numbers the drill actually reports, ok or bad — `1`, `10b` and so on.
claim "kong-drill phases" \
  "$(grep -oE '(ok|bad) +"[0-9]+[a-z]?' scripts/kong-drill.sh | grep -oE '[0-9]+[a-z]?$' \
     | sort -u | wc -l | tr -d ' ')" \
  'kong-drill\.sh` \([0-9]+\)'

[ "$fail" = 0 ] || { echo; echo "  update docs/08-lld.md §8.15 to match the tree"; exit 1; }
echo "ok    every counted claim in §8.15 matches the tree"
