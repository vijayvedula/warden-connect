#!/usr/bin/env bash
# Can each fuzz target actually fail?
#
#     scripts/fuzz-mutation-check.sh                 # all five
#     scripts/fuzz-mutation-check.sh parse_contract  # one
#
# ## Why this exists
#
# `docs/proving-ground.md` item 2.6 says it plainly, as a warning against spending money:
#
#     Before buying CPU, mutation-check each target — break the code deliberately and confirm
#     the fuzzer catches it. Hours against an assertion that cannot fail is the most expensive
#     way to learn nothing.
#
# It is not a hypothetical warning. This project shipped a fuzz target whose invariant was
# **stale** and which had never been run, and the same session found three alert rules asserted
# nowhere and a two-branch `assert!` whose first branch could never match. A green campaign is
# indistinguishable from a campaign against an assertion that is always true, and the difference is
# only visible if you go and break something.
#
# ## What it does
#
# For each target: apply a one-line mutation to the code the target exercises, run the target
# against its **committed corpus only** — no new input generation, so this takes seconds rather
# than minutes — and require a crash. Then restore.
#
# A target that survives its mutation is reported as **NOT EXERCISED**, which has two readings and
# the script says both: either the corpus cannot reach the assertion (add a seed), or the mutation
# is unreachable in the target's own fixed context (the mutation is wrong). Both are worth a look;
# only the first is a finding about the target.
#
# The first run of this script found one of each, which is why the distinction is spelled out.
# `parse_contract` registered its trusted key under `wc-e2e-es256` while every corpus file names
# `wc-test-es256` — same key material, different label — so `verify_artifact` failed at key
# resolution for **every** input and none of the target's post-verification assertions had ever
# executed. Its doc comment claims "no contract verifies unless it is internally consistent"; that
# ceiling had never run. A 10-minute campaign had just passed against it.
#
# ## What it does not do
#
# It does not prove a target would find a *novel* bug. It proves the target's assertions are
# reachable and can fail, which is the property that makes a campaign worth its CPU. One mutation
# per target, chosen to be the most obvious violation of the property the target's own doc comment
# claims to enforce — a target that misses a subtler one is still possible and this cannot say.
#
# Requires: nightly + cargo-fuzz (same as scripts/fuzz.sh), python3.
# Exit 0 every target detected its mutation · 1 one or more did not · 2 setup.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ONLY="${1:-}"
command -v python3 >/dev/null || { echo "need python3" >&2; exit 2; }
if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
    echo "cannot run \`cargo +nightly fuzz\` — see scripts/fuzz.sh for the diagnosis it prints" >&2
    exit 2
fi
HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
[ -n "$HOST_TRIPLE" ] || { echo "cannot determine the host triple" >&2; exit 2; }

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }
fail=0

# Each entry: target | file to mutate | python-quoted old | python-quoted new | what it breaks.
#
# The mutations are chosen to violate the property each target's own doc comment claims. Anything
# subtler would be testing the mutation rather than the target.
run_one() {  # run_one <target> <file> <old> <new> <what>
    local target="$1" file="$2" old="$3" new="$4" what="$5"
    if [ -n "$ONLY" ] && [ "$ONLY" != "$target" ]; then
        return 0
    fi
    bold "$target"
    printf '  breaking  %s\n' "$what"

    local abs="$REPO/$file"
    cp "$abs" "$abs.mutcheck.bak"
    if ! python3 - "$abs" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
if old not in s:
    sys.stderr.write(f"mutation target not found in {path}\n")
    sys.exit(3)
open(path, "w").write(s.replace(old, new, 1))
PY
    then
        printf '  SKIP  the mutation no longer applies — the code moved, so this check is stale\n'
        mv "$abs.mutcheck.bak" "$abs"
        fail=1
        return 0
    fi

    # `-runs=0` replays the committed corpus and generates nothing. A target whose assertions are
    # reachable fails here in seconds; one that needs new inputs to fail is a weaker target than
    # its corpus suggests, and worth knowing about either way.
    local out
    out="$(cd "$REPO/fuzz" && cargo +nightly fuzz run --target "$HOST_TRIPLE" "$target" \
        "corpus/$target" -- -runs=0 -timeout=10 2>&1)"
    local rc=$?
    mv "$abs.mutcheck.bak" "$abs"

    # Case-insensitive, and it must include cargo-fuzz's own wording. The first version grepped for
    # uppercase `ERROR` and missed `Error: Fuzz target exited with exit status: 77`, so a target that
    # HAD detected its mutation was reported as not exercised — a false finding produced by the
    # checker, which is the one kind of bug a checker must not have.
    if [ "$rc" -ne 0 ] && printf '%s' "$out" \
        | grep -qiE "panicked|assertion|deadly signal|fuzz target exited|SUMMARY: libFuzzer"; then
        ok "detected — the corpus alone is enough to trip it"
        printf '%s' "$out" | grep -m1 -iE "panicked at|assertion|fuzz target exited" \
            | cut -c1-104 | sed 's/^/       /'
    else
        bad "NOT EXERCISED: the committed corpus does not trip this target with $what"
        printf '  %s\n' "Two readings, and they need different fixes:"
        printf '  %s\n' "  · the corpus cannot reach the assertion — add a seed that can;"
        printf '  %s\n' "  · or the mutation is unreachable in this target's fixed context, in"
        printf '  %s\n' "    which case the mutation is wrong and the target may be fine."
        printf '  %s\n' "Either way a campaign here cannot tell working code from broken."
        printf '%s' "$out" | tail -3 | sed 's/^/       /'
    fi
    echo
}

bold "fuzz target mutation check"
printf '  host      %s\n\n' "$HOST_TRIPLE"

# canon_surface asserts the canonicaliser respects its own limits. `too-many-tools` in the corpus
# carries 4000 tools against a limit of 512, so this is reachable from the committed seeds.
run_one canon_surface "crates/wc-core/src/canon.rs" \
    "if items.len() > limits.max_items {" "if false {" \
    "the item-count limit, so a 4000-tool surface canonicalises"

# parse_contract asserts anything that verified is self-consistent — including that `aud` is this
# mediator, which the target checks with `assert_eq!(p.aud, MEDIATOR)`.
run_one parse_contract "crates/wc-core/src/contract.rs" \
    "if payload.aud != opts.mediator_id {" "if false {" \
    "the audience check, so another mediator's contract verifies here"

# parse_connect_policy asserts a policy that parses has usable decisions.
run_one parse_connect_policy "crates/wc-control/src/cpolicy.rs" \
    'Decision::Allow => "allow"' 'Decision::Allow => ""' \
    "a decision's name, so a parsed rule carries an empty decision"

# screen_text asserts every detector is accounted for as run OR skipped, never silently absent.
#
# Mutating the *skipped* branch would test nothing: the target fixes `ScreenRules::default()`, which
# enables every detector, so that branch never executes. The `ran` branch is the reachable half.
# A mutation the target's own context cannot reach reports on the mutation, not on the target.
run_one screen_text "crates/wc-control/src/screen.rs" \
    "            ran.push(d);" "            let _ = d;" \
    "the run bookkeeping, so an enabled detector is never reported as having run"

# revocation_event asserts a bad pull poisons the set rather than installing a partial one.
run_one revocation_event "crates/wc-mediator/src/client.rs" \
    "        set.distrust(why);" "" \
    "the distrust on an unclean pull, so a corrupt feed produces a trusted set"

if [ "$fail" -eq 0 ]; then
    bold "EVERY TARGET DETECTED ITS MUTATION"
    echo "Their assertions are reachable and can fail, so CPU spent on a campaign buys something."
    exit 0
fi
bold "AT LEAST ONE TARGET WAS NOT EXERCISED"
cat <<'NOTE'
Fix the target before running a campaign. A target that cannot fail turns hours of CPU into a
green tick that means nothing — which is the specific waste docs/proving-ground.md item 2.6 warns
about, and which this project has already shipped once.
NOTE
exit 1
