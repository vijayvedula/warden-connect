#!/usr/bin/env bash
# Every child process this workspace starts must go through `wc_core::proc::spawn_piped`.
#
# The gate serialises spawns so no thread forks while another is between creating a pipe and
# marking it close-on-exec. A spawn that bypasses it can still inherit — and hold open — a pipe
# belonging to a call that did use it, so the protection is exactly as complete as its adoption.
# That makes adoption the thing worth failing a build over: the lock itself is four lines and does
# not rot, whereas a new `Command::new(..).spawn()` is one plausible-looking line away at any time.
#
# The symptom, when it does rot, is a verifier reporting `no answer within 20s` about a shim that
# exited 0 having printed the verdict — a refusal whose stated reason is fiction, cleared by a
# rerun. Measured at 4 hangs in 60 runs of the `scm` suite under `--test-threads 8`; 0 in 180 with
# the gate.
set -euo pipefail
cd "$(dirname "$0")/.."

# Anything that forks and wires up pipes. `.status()` and `.output()` count: both create pipes,
# and a brief thief is still a thief.
readonly PATTERN='\.(spawn|output|status)\(\)'
readonly GATE='crates/wc-core/src/proc.rs'

hits=$(
  grep -rnE --include='*.rs' "$PATTERN" crates/*/src daemon/*/src \
    | grep -v "^$GATE:" \
    | grep -v 'thread::spawn' \
    | grep -vE '(response|resp|r)\.status\(\)' \
    || true
)

if [ -n "$hits" ]; then
  echo "FAIL  a process is spawned outside the gate ($GATE):"
  echo "$hits" | sed 's/^/      /'
  echo
  echo "      Use wc_core::proc::spawn_piped(&mut cmd) instead of cmd.spawn()."
  exit 1
fi

echo "ok    every spawn goes through wc_core::proc::spawn_piped"
