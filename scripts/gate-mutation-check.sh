#!/usr/bin/env bash
# Can each gate in the decision core actually fail a test?
#
#     scripts/gate-mutation-check.sh
#
# `fuzz-mutation-check.sh` asks this of the fuzz targets. Nothing asked it of `wc-gateway`,
# which is the crate that decides whether a call proceeds — so the suite that guards the
# product's central claim had never been checked for whether it guards anything.
#
# For each gate: break it with a one-line edit, run the crate's tests, and REQUIRE a failure.
# A gate whose mutation survives is reported as NOT COVERED, which has the two readings this
# project's fuzz equivalent already names: either no test reaches the gate, or the mutation is
# unreachable and the mutation is wrong. Both are worth a look; only the first is a finding.
#
# The mutations are deliberately the ones an inattentive refactor would produce — a refusal
# turned into a pass, a filter that keeps everything — rather than syntax damage a compiler
# catches for free.
set -uo pipefail
cd "$(dirname "$0")/.."

pass=0
fail=0

# name | file | from | to
run_mutation() {
  local name="$1" file="$2" from="$3" to="$4"
  cp "$file" "$file.mutbak"
  if ! python3 - "$file" "$from" "$to" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
if s.count(old) != 1:
    sys.exit(f"anchor appears {s.count(old)} times")
open(path, 'w').write(s.replace(old, new))
PY
  then
    mv "$file.mutbak" "$file"
    echo "  SKIP $name — the anchor no longer matches; the mutation needs updating"
    fail=$((fail + 1))
    return
  fi

  if cargo test -q -p warden-connect-gateway >/dev/null 2>&1; then
    echo "  NOT COVERED  $name — the gate was broken and every test still passed"
    fail=$((fail + 1))
  else
    echo "  ok           $name"
    pass=$((pass + 1))
  fi
  mv "$file.mutbak" "$file"
}

echo "gate mutations"

run_mutation "an uncontracted tool is refused" \
  crates/wc-gateway/src/lib.rs \
  '.filter(|(_, (a, _))| a.items.contains(&tool))' \
  '.filter(|(_, (a, _))| a.items.contains(&tool) || true)'

# Substituting a caller that a test fixture actually holds a contract for, not an empty string.
# The first version of this mutation used `Some("")` and was reported as NOT COVERED, which was
# wrong twice over: the gate has an explicit test (`resolve(None, CALLEE).is_empty()`), and the
# empty id is rejected by `EntityId::new` on the very next line, so the mutation never reached
# past the parser. A mutation the code neutralises for its own reasons proves nothing about the
# test suite — it just looks like a finding.
run_mutation "no identity means no contract" \
  crates/wc-gateway/src/contracts.rs \
  '        let Some(caller) = caller else {
            return Vec::new();
        };' \
  '        let Some(caller) = caller.or(Some("spiffe://org/ns/agents/sa/recon-bot")) else {
            return Vec::new();
        };'

run_mutation "a set past max_stale refuses every call" \
  crates/wc-gateway/src/contracts.rs \
  '        (age > self.max_stale).then_some(age)' \
  '        (age > self.max_stale).then_some(age).filter(|_| false)'

run_mutation "a JSON-RPC batch is refused whole" \
  crates/wc-gateway/src/adapter.rs \
  '    if frame.is_array() {' \
  '    if frame.is_array() && false {'

run_mutation "an unverified pin refuses the call" \
  crates/wc-gateway/src/lib.rs \
  '            if let Some(pins) = &self.pins {
                let jti = admitted.jti.as_str();' \
  '            if let Some(pins) = &self.pins.clone().filter(|_| false) {
                let jti = admitted.jti.as_str();'

echo
if [ "$fail" = 0 ]; then
  echo "every gate mutation was caught ($pass/$pass)"
  exit 0
fi
echo "$fail gate mutation(s) survived or could not be applied"
exit 1
