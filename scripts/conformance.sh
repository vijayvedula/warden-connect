#!/usr/bin/env bash
# The connection-contract conformance harness (production-readiness P2 #16).
#
# The independence argument — *implement the checks in your own egress layer and still
# interoperate* — rests on `connect verify` being ground truth. Until now that meant 19 files
# and an `expected.json`, with no harness a third party could point at their own verifier.
# So "no lock-in to our data plane" was an assertion.
#
# This runs the vectors against **any** verifier, ours or yours.
#
# Usage:
#     scripts/conformance.sh                          # our verifier
#     scripts/conformance.sh ./my-verifier            # yours
#     scripts/conformance.sh ./my-verifier --json     # machine-readable
#
# ── The contract your verifier must satisfy ────────────────────────────────────
#
# It is invoked once per vector as:
#
#     <your-verifier> <artifact.jws> <issuer-pub.pem> <kid> <mediator-id> <unix-time> <alg>
#
# `<kid>` and `<alg>` are how your verifier must be **configured** — the key it trusts and
# the algorithm it trusts that key for. They are deliberately not the artifact's own header
# values: `unknown-kid.jws` is a vector precisely because the artifact claims a `kid` nobody
# published, and a harness that configured itself from the artifact's claim would register
# the trusted key under the attacker's name and admit it.
#
# and must:
#
#   · exit 0 if the contract is valid;
#   · exit non-zero and print the `WC-NNNN` code **somewhere on stdout or stderr** if not.
#
# The code is what is compared, not the exit status alone. "It rejected it" is half the
# claim; "it rejected it for the right reason" is the half that makes two implementations
# interoperable — a verifier that returns WC-3102 where the vector says WC-3101 has confused
# a signature failure with an algorithm confusion, and those have different responses.
#
# Exit codes: 0 conformant · 1 one or more vectors disagreed · 2 setup.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VECTORS="$REPO/fixtures/contracts"
EXPECTED="$VECTORS/expected.json"

VERIFIER="${1:-}"
JSON=0
for arg in "$@"; do
    [ "$arg" = "--json" ] && JSON=1
done
[ "$VERIFIER" = "--json" ] && VERIFIER=""

command -v python3 >/dev/null 2>&1 || { echo "need python3 to read expected.json" >&2; exit 2; }
[ -f "$EXPECTED" ] || { echo "no $EXPECTED" >&2; exit 2; }

# Ours by default, so `scripts/conformance.sh` with no arguments is a self-check.
if [ -z "$VERIFIER" ]; then
    OURS="$REPO/target/release/connect"
    [ -x "$OURS" ] || OURS="$REPO/target/debug/connect"
    [ -x "$OURS" ] || { echo "no connect binary; run cargo build" >&2; exit 2; }
    VERIFIER="$REPO/scripts/.conformance-ours.sh"
    cat > "$VERIFIER" <<SHIM
#!/usr/bin/env bash
# Adapter from the harness's calling convention to \`connect verify\`.
exec "$OURS" verify "\$1" --issuer-pub "\$2" --kid "\$3" --mediator-id "\$4" --now "\$5" --alg "\$6"
SHIM
    chmod +x "$VERIFIER"
    trap 'rm -f "$REPO/scripts/.conformance-ours.sh"' EXIT
fi

[ -x "$VERIFIER" ] || { echo "$VERIFIER is not executable" >&2; exit 2; }

# Read the manifest once, into records separated by ASCII unit separator.
#
# **Not tab.** Tab is IFS whitespace, so bash collapses runs of it and an empty field
# disappears — which silently shifted every column right for the two vectors that must be
# admitted, and reported a conformant verifier as broken. Found by running this against our
# own verifier, which is the reason a harness ships with a self-check.
US=$'\x1f'
PLAN=$(python3 "$REPO/scripts/.conformance-plan.py" "$EXPECTED")

MEDIATOR=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['mediator_id'])" "$EXPECTED")
NOW=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['now'])" "$EXPECTED")
VERSION=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('vectors_version','?'))" "$EXPECTED")

PASS=0
FAIL=0
DEFERRED=0
RESULTS=""

[ "$JSON" = 0 ] && printf '\033[1mconformance\033[0m  %s\n  vectors  v%s in %s\n  clock    %s (fixed: several vectors are about the validity window)\n  mediator %s\n\n' \
    "$VERIFIER" "$VERSION" "$VECTORS" "$NOW" "$MEDIATOR"

while IFS="$US" read -r file expect stage kid alg keypath description; do
    [ -z "$file" ] && continue
    pub="$REPO/$keypath"
    [ -f "$pub" ] || { echo "missing key $pub" >&2; exit 2; }

    out=$("$VERIFIER" "$VECTORS/$file" "$pub" "$kid" "$MEDIATOR" "$NOW" "$alg" 2>&1) && status=0 || status=$?

    if [ "$stage" = "context" ]; then
        # Checks 6-11 need an authenticated peer, the callee's presented surface, a
        # revocation feed or local zone policy. A verifier given only an artifact and a key
        # has none of those, so these are **valid artifacts to it** and it must ADMIT them.
        #
        # Reported as deferred rather than passed. A harness that counted them as passes
        # would tell an implementer they had covered nineteen checks when they had covered
        # fifteen, and the four they had not are the ones that need a mediator.
        if [ "$status" = 0 ]; then
            verdict="deferred"; DEFERRED=$((DEFERRED + 1))
        else
            verdict="REJECTED an artifact that is valid until context is applied"
            FAIL=$((FAIL + 1))
        fi
    elif [ -z "$expect" ]; then
        # Must be ADMITTED. The direction that matters most: a verifier that rejects
        # everything satisfies every rejection vector perfectly.
        if [ "$status" = 0 ]; then
            verdict=ok; PASS=$((PASS + 1))
        else
            got=$(printf '%s' "$out" | grep -oE 'WC-[0-9]{4}' | head -1)
            verdict="REJECTED a valid contract (${got:-no code})"; FAIL=$((FAIL + 1))
        fi
    elif [ "$status" = 0 ]; then
        verdict="ACCEPTED, expected $expect"; FAIL=$((FAIL + 1))
    elif printf '%s' "$out" | grep -q "$expect"; then
        verdict=ok; PASS=$((PASS + 1))
    else
        got=$(printf '%s' "$out" | grep -oE 'WC-[0-9]{4}' | head -1)
        verdict="expected $expect, got ${got:-no WC code}"; FAIL=$((FAIL + 1))
    fi

    if [ "$JSON" = 1 ]; then
        RESULTS="$RESULTS$(printf '{"vector":"%s","stage":"%s","expected":"%s","verdict":"%s"}' \
            "$file" "$stage" "${expect:-valid}" "$verdict"),"
    elif [ "$verdict" = ok ]; then
        printf '  \033[32mPASS\033[0m %-34s %-9s %s\n' "$file" "${expect:-ADMIT}" "$description"
    elif [ "$verdict" = "deferred" ]; then
        printf '  \033[33mDEFR\033[0m %-34s %-9s needs a mediator: %s\n' \
            "$file" "$expect" "$description"
    else
        printf '  \033[31mFAIL\033[0m %-34s %-9s \033[31m%s\033[0m\n' \
            "$file" "${expect:-ADMIT}" "$verdict"
    fi
done <<< "$PLAN"

TOTAL=$((PASS + FAIL + DEFERRED))

if [ "$JSON" = 1 ]; then
    printf '{"vectors":%d,"passed":%d,"deferred":%d,"failed":%d,"conformant":%s,"vectors_version":"%s","results":[%s]}\n' \
        "$TOTAL" "$PASS" "$DEFERRED" "$FAIL" \
        "$([ "$FAIL" = 0 ] && echo true || echo false)" \
        "$VERSION" "${RESULTS%,}"
else
    printf '\n'
    if [ "$FAIL" = 0 ]; then
        printf '\033[32mCONFORMANT\033[0m  %d/%d artifact-stage vectors\n' "$PASS" "$((PASS + FAIL))"
        [ "$DEFERRED" = 0 ] || printf '%d vector(s) deferred: they need an authenticated peer, a presented\nsurface, a revocation feed or zone policy, so only a mediator can answer them.\n' "$DEFERRED"
    else
        printf '\033[31mNOT CONFORMANT\033[0m  %d passed - %d disagreed - %d deferred\n' \
            "$PASS" "$FAIL" "$DEFERRED"
        printf '\nA disagreement is worth reporting even when you are not sure whose bug it is:\n'
        printf 'in a format meant to be interoperable, disagreeing about what is valid IS the bug.\n'
        printf 'See SECURITY.md > Conformance findings.\n'
    fi
fi

[ "$FAIL" = 0 ] || exit 1
