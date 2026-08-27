#!/usr/bin/env bash
# The Lua suite: the real plugin, the real library, a stubbed Kong.
#
# A plugin nobody executed is a plugin nobody has tested, and the FFI layer is where the three
# statements of this ABI — Rust, the C header, and the cdef — can silently disagree.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$ROOT"

command -v luajit >/dev/null || {
  echo "luajit is required: brew install luajit (or apt install luajit)" >&2
  exit 127
}

echo "== building the cdylib"
cargo build -q -p warden-connect-kong

LIB=""
for cand in target/debug/libwc_kong.dylib target/debug/libwc_kong.so; do
  [ -f "$cand" ] && LIB="$ROOT/$cand" && break
done
[ -n "$LIB" ] || { echo "no cdylib built" >&2; exit 1; }

FIX=$(mktemp -d)
trap 'rm -rf "$FIX"' EXIT
echo "== minting a fixture contract"
cargo run -q -p warden-connect-kong --example mkfixture -- "$FIX" >/dev/null

echo "== spec"
WC_ROOT="$ROOT" WC_LIB="$LIB" WC_FIX="$FIX" luajit -e '
  package.path = "crates/wc-kong/lua/?.lua;" .. package.path
  require("spec.abi_spec")
  require("spec.handler_spec")
  require("spec.harness").report()
'
