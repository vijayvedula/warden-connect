#!/usr/bin/env bash
# Every error code is either emitted somewhere, or declared RESERVED with the reason.
#
# A `Code` constant that nothing constructs is a refusal that cannot fire. That is harmless
# inside the crate and harmful outside it: the codes are the product's public vocabulary, the
# docs trace use cases to them, and an operator who alerts on one waits for a signal no code
# path can send. Eleven of eighty-two were in that state when this check was written, six of
# them named in `docs/08-lld.md` and three traced from a use case.
#
# Most were not bugs -- the mechanism existed and reported through posture, a clamp or a
# truncation instead. `WC-2020` is the sharpest: `broker` throttles by truncating and never
# refusing, on purpose, because a status that flips at a threshold is the enumeration oracle
# throttling exists to deny. Emitting it would be the defect; documenting it as emitted was.
#
# So the rule is not "emit every code". It is "say which ones you do not, and why".
set -euo pipefail
cd "$(dirname "$0")/.."

readonly ERR='crates/wc-core/src/error.rs'
missing=""

while read -r name; do
  grep -rqE --include='*.rs' "Code::${name}\b" crates daemon --exclude-dir=tests 2>/dev/null \
    && continue
  # Not emitted. It must then carry a RESERVED note in its doc comment.
  if ! grep -B12 "pub const ${name}: Code" "$ERR" | grep -q 'RESERVED'; then
    missing="${missing}  ${name}"$'\n'
  fi
done < <(grep -oE 'pub const [A-Z_0-9]+: Code' "$ERR" | awk '{print $3}' | tr -d ':')

if [ -n "$missing" ]; then
  echo "FAIL  these codes are never emitted and are not marked RESERVED in $ERR:"
  printf '%s' "$missing"
  echo
  echo "      Either emit the code, or document why it cannot be, starting the line RESERVED:."
  exit 1
fi

echo "ok    every error code is emitted or documented as reserved"
