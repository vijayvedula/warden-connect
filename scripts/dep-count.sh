#!/usr/bin/env bash
# Assert the dependency-count ceilings §8.3 claims.
#
# cargo-deny cannot express "no more than N crates", and the LLD quotes numbers. When
# this was first measured the document said 30 and 61 and the tree resolved to 80 and
# 110 — jsonwebtoken's `rust_crypto` feature alone brings 75, because it is a bundle
# (ed25519-dalek, hmac, p256, p384, rand, rsa, sha2) with no way to take the curves
# without RSA.
#
# So the ceilings here are the measured truth plus a little headroom, not the
# aspiration. The point is that the next addition is *visible*: a claim that drifts
# silently is worse than no claim.
set -euo pipefail

fail=0
check() {
  local crate=$1 ceiling=$2
  local n
  n=$(cargo tree -p "$crate" --edges normal --prefix none \
      | sed 's/ (.*//;s/ v.*//' | sort -u | grep -c '[^[:space:]]')
  if [ "$n" -gt "$ceiling" ]; then
    echo "FAIL  $crate resolves to $n crates, ceiling is $ceiling"
    fail=1
  else
    echo "ok    $crate  $n / $ceiling"
  fi
}

# Runtime edges only — dev-dependencies are not what ships.
# Package names, not directory names. `cargo tree -p` takes the published name, and the crate
# rename left these three pointing at packages that no longer exist — so this gate reported
# `did not match any packages` and failed the job rather than measuring anything.
check warden-connect-core      85
check warden-connect-control  115
check warden-connect-mediator 116
# The gateway decision core. Sync and transport-free ON PURPOSE: §8.3 rules out an async
# runtime for anything embeddable, and this crate is linked into a filter that runs in
# somebody else's data path. The ext_proc daemon that drives it is a separate artifact with
# its own gate — a ceiling here is what stops tokio arriving through this door.
check warden-connect-gateway  117

# The daemons in `daemon/` are OUTSIDE this workspace, so nothing above measures them and the
# ban below cannot see them. That is the point — they own their own `main` and are linked into
# nothing, so §8.2's "no async runtime" does not apply. What DOES have to hold is the boundary:
# a daemon may depend on the workspace crates, and none of them may acquire an async runtime
# through that edge. Asserted from the daemon's own side, because the check above cannot.
for d in daemon/*/; do
  [ -f "$d/Cargo.toml" ] || continue
  name=$(basename "$d")
  if ! cargo metadata --manifest-path "$d/Cargo.toml" --format-version 1 --no-deps \
        >/dev/null 2>&1; then
    echo "FAIL  daemon/$name does not resolve; it is unbuilt, not exempt"
    fail=1
    continue
  fi
  # Every workspace crate this daemon pulls in must still be runtime-free. `cargo tree
  # --invert` names what depends on tokio: if a `warden-connect-*` crate appears there, the
  # runtime has crossed back into the embeddable surface.
  crossed=$(cargo tree --manifest-path "$d/Cargo.toml" --edges normal --invert tokio \
              --prefix none 2>/dev/null | sed 's/ v.*//' | grep -c '^warden-connect-' || true)
  if [ "${crossed:-0}" -gt 0 ]; then
    echo "FAIL  daemon/$name: a warden-connect crate now depends on tokio (§8.2)"
    cargo tree --manifest-path "$d/Cargo.toml" --edges normal --invert tokio --prefix none \
      2>/dev/null | sed 's/ v.*//' | grep '^warden-connect-' | sed 's/^/      /'
    fail=1
  else
    echo "ok    daemon/$name  async stops at the binary"
  fi
done

# The categories §8.3 rules out are enforced by deny.toml's ban list; this is the
# belt-and-braces version for anything that arrives transitively under a new name.
for banned in tokio async-std smol diesel sqlx sea-orm rusqlite openssl-sys; do
  if cargo tree --workspace --edges normal --prefix none 2>/dev/null \
       | sed 's/ v.*//' | grep -qx "$banned"; then
    echo "FAIL  $banned is in the tree; §8.3 rules out its whole category"
    fail=1
  fi
done

[ "$fail" -eq 0 ] && echo "dependency ceilings ok"
exit "$fail"
