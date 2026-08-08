#!/usr/bin/env bash
# Run a coverage-guided fuzz campaign (production-readiness P2 #15).
#
# Five targets and seed corpora existed; no campaign had ever been run. The stable mirror in
# `crates/wc-e2e/tests/fuzz.rs` runs on `cargo test` and exists so the targets cannot rot
# into not compiling — which is a different and much weaker claim, and the README already
# said so.
#
# This is the campaign. It is a script rather than a note in a README because the thing that
# stops fuzzing from happening is not difficulty, it is that nobody remembers the flags.
#
# Usage:
#     scripts/fuzz.sh                       # 60s per target, all five
#     scripts/fuzz.sh 600                   # 10 minutes per target
#     scripts/fuzz.sh 600 parse_contract    # one target
#
# Exit codes: 0 no crashes · 1 a crash was found (and the next step is printed) · 2 setup.

set -euo pipefail

SECS="${1:-60}"
ONLY="${2:-}"
FUZZ_DIR="$(cd "$(dirname "$0")/../fuzz" && pwd)"
TARGETS=(parse_contract canon_surface parse_connect_policy screen_text revocation_event)
FOUND=0

if [ -n "$ONLY" ]; then
    TARGETS=("$ONLY")
fi

command -v cargo >/dev/null 2>&1 || { echo "no cargo" >&2; exit 2; }

if ! cargo +nightly --version >/dev/null 2>&1; then
    cat >&2 <<'MSG'
This needs the nightly toolchain: libfuzzer-sys requires it, which is why `fuzz/` is
excluded from the workspace in the first place.

    rustup toolchain install nightly
MSG
    exit 2
fi

if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
    cat >&2 <<'MSG'
This needs cargo-fuzz:

    cargo install cargo-fuzz

Deliberately not vendored. §8.3's dependency argument is about what a *build* of this
component pulls in, and a fuzzing tool is not that — but it does mean a campaign is
something somebody has to choose to run, which is what this script is for.
MSG
    exit 2
fi

cd "$FUZZ_DIR"

# ---------------------------------------------------------------------------
# The tracked corpus is read-only during a campaign
# ---------------------------------------------------------------------------
#
# Found by running this script the first time it existed: pointing `cargo fuzz` at
# `corpus/<target>` and then running `cmin` **deleted the hand-written seeds**. Minimisation
# keeps one input per coverage edge and does not care which; a generated blob with the same
# coverage as `alg-confusion-ed-for-es` wins on size, so 23 named, readable, deliberately
# chosen inputs became 787 files called things like `a3f0e1…`.
#
# That is not a smaller corpus, it is a corpus nobody can review or prune, and it destroys
# the property `fuzz/README.md` describes: the seeds are the *interesting* inputs, including
# near misses that a detector set must not fire on. So new inputs go to a scratch directory
# and the tracked corpus is only ever read.
GROWTH="${FUZZ_GROWTH:-$(mktemp -d "${TMPDIR:-/tmp}/wc-fuzz-growth.XXXXXX")}"
mkdir -p "$GROWTH"

printf '\033[1mfuzz campaign\033[0m  %ss per target · %d target(s)\n' "$SECS" "${#TARGETS[@]}"
printf 'growth   %s  (tracked corpus is read-only)\n' "$GROWTH"

for target in "${TARGETS[@]}"; do
    seeds=$(find "corpus/$target" -type f 2>/dev/null | wc -l | tr -d ' ')
    mkdir -p "$GROWTH/$target"
    printf '\n\033[1m%s\033[0m  (%s seeds)\n' "$target" "$seeds"

    # Two corpus directories: libfuzzer writes new inputs to the **first** and reads the
    # rest. That is what keeps the curated seeds intact.
    #
    # `-max_total_time` bounds the run. `-timeout=10` catches a hang, which for a *parser* is
    # as much a bug as a panic — a mediator that blocks forever on a malformed frame is a
    # denial of service delivered through a tool description.
    if cargo +nightly fuzz run "$target" "$GROWTH/$target" "corpus/$target" -- \
        -max_total_time="$SECS" -timeout=10 -rss_limit_mb=4096
    then
        grown=$(find "$GROWTH/$target" -type f 2>/dev/null | wc -l | tr -d ' ')
        printf '   clean · %s new input(s) reaching coverage the seeds did not\n' "$grown"
    else
        FOUND=1
        printf '\033[31m   CRASH\033[0m\n'
    fi
done

if [ "$FOUND" = 1 ]; then
    cat <<'CRASH'

A crash was found. Turn it into a permanent regression test:

  1 · The artifact is in `fuzz/artifacts/<target>/`. Reproduce it:
        cd fuzz && cargo +nightly fuzz run <target> artifacts/<target>/<file>

  2 · Copy it into the corpus with a name that says what it is:
        cp fuzz/artifacts/<target>/crash-abc123 fuzz/corpus/<target>/panics-on-<what>

  3 · Commit it. That is the whole regression test.

     `crates/wc-e2e/tests/fuzz.rs` reads every file in `fuzz/corpus/<target>` and drives the
     target's assertions over it on `cargo test`. So a committed crash runs on stable, on
     every push, for everybody, with no nightly and no cargo-fuzz — and it keeps running
     long after whoever found it has forgotten. `a_committed_crash_becomes_a_stable_
     regression_test` is the test that keeps that loop closed.

  4 · Fix it, and say in the commit which corpus file now covers it.

CRASH
    exit 1
fi

printf '\n\033[32mno crashes in %ss per target\033[0m\n' "$SECS"
cat <<GROWTHNOTE

The growth corpus is in $GROWTH and is deliberately **not** committed.

The tracked corpus stays curated: every file in it is named for what it attacks, and
\`fuzz/README.md\` explains why — including that \`screen_text\` holds near misses on purpose,
because a detector set that fires on an honest description mentioning credentials is a
detector set nobody leaves switched on. Machine-generated inputs with hash names would make
that unreviewable, and an unreviewable corpus never gets pruned.

So commit from it only deliberately:

  · a crash, always, named for the bug — that is the regression test;
  · an input that reaches something a human recognises as a new *shape*, named for it.

CI keeps the accumulated growth in a cache between nightly runs, so coverage is not lost by
leaving it out of git.
GROWTHNOTE
