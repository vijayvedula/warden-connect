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
check wc-core     85
check wc-control 115
check wc-mediator 116

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
