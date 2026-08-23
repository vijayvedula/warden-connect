#!/usr/bin/env bash
# Run the CI workflow locally, step for step.
#
# `.github/workflows/ci.yml` is the authority; this mirrors it. It exists because a hosted
# runner is not always reachable — quota, an outage, a fork without secrets — and a repository
# whose only proof lives somewhere it cannot currently reach is back to "true on one laptop",
# which is the exact condition CI was added to end.
#
# Two rules, both taken from ci.yml's own header:
#
#   1. A step that could not run FAILS. It does not skip. A missing toolchain is a failure of
#      this run, not an absence of evidence — the one exception is a step ci.yml itself guards
#      with `if command -v`, and that guard is reproduced rather than invented.
#   2. The release-mode gates are named, because a latency gate in a debug build measures
#      nothing and `cargo test` defaults to debug.
#
# Usage:  scripts/ci-local.sh [job ...]     jobs: check msrv gates supply-chain image fuzz
#         scripts/ci-local.sh               all of them
#
# Exit 0 every step passed · 1 a step failed · 2 setup.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

bold=$'\e[1m'; dim=$'\e[2m'; off=$'\e[0m'
pass=0; fail=0; failed=()
LOG="${TMPDIR:-/tmp}/wc-ci-local"
mkdir -p "$LOG"

step() {
    local name="$1"; shift
    local slug; slug="$(printf '%s' "$name" | tr -c 'a-zA-Z0-9' '-')"
    printf '  %-52s ' "$name"
    if "$@" >"$LOG/$slug.log" 2>&1; then
        printf 'ok\n'; pass=$((pass + 1))
    else
        printf 'FAIL\n'; fail=$((fail + 1)); failed+=("$name -> $LOG/$slug.log")
        sed 's/^/       /' "$LOG/$slug.log" | tail -8
    fi
}
sh_step() { local n="$1"; shift; step "$n" bash -c "$*"; }
job() { printf '\n%s%s%s\n' "$bold" "$1" "$off"; }

# The sibling checkout the `warden-proxy` feature needs. ci.yml checks it out; here it has to
# already exist, and its absence is a failure rather than a quietly skipped step.
WARDEN_SIBLING="$ROOT/../warden"

want() { [ $# -eq 0 ] && return 0; local j; for j in "$@"; do [ "$j" = "$WANT" ] && return 0; done; return 1; }
JOBS=("$@"); [ ${#JOBS[@]} -eq 0 ] && JOBS=(check msrv gates supply-chain image fuzz)
has_job() { local j; for j in "${JOBS[@]}"; do [ "$j" = "$1" ] && return 0; done; return 1; }

# --- check: fmt · clippy · test ---------------------------------------------
if has_job check; then
job "fmt · clippy · test"
step "cargo fmt --all --check"            cargo fmt --all --check
sh_step "cargo clippy -D warnings"        "cargo clippy --workspace --all-targets -- -D warnings"
sh_step "cargo test --workspace"          "cargo test --workspace --no-fail-fast"
if [ -d "$WARDEN_SIBLING" ]; then
    sh_step "warden-proxy clippy"         "cargo clippy -p warden-connect-mediator --all-targets --features warden-proxy -- -D warnings"
    sh_step "warden-proxy tests"          "cargo test -p warden-connect-mediator --features warden-proxy"
else
    step "warden-proxy adapter (needs ../warden)" false
fi
sh_step "attestation, real verifiers"     "cargo test -p wc-e2e --test attest"
for d in attest custody upgrade oidc catalogue distribution containment rotation \
         adoption inventory proposal scale; do
    [ -f "scripts/$d-drill.sh" ] && step "drill · $d" bash "scripts/$d-drill.sh"
done
step "drill · scm parse"                  bash scripts/scm/parse-drill.sh
sh_step "conformance kit, through the harness" "cargo build -p warden-connect-cli --quiet && ./scripts/conformance.sh"
sh_step "conformance vectors (§8.15.3)"   "cargo test -p warden-connect-core --lib conformance"
step "wcs1 canonicalisation vectors"      bash scripts/canon-conformance.sh
sh_step "screening calibration (§8.16)"   "cargo test -p warden-connect-control --lib calibration"
sh_step "SDK tests"                       "cd sdk/python && python3 -m pytest -q"
fi

# --- msrv --------------------------------------------------------------------
if has_job msrv; then
job "MSRV 1.89"
if rustup toolchain list 2>/dev/null | grep -q '^1\.89'; then
    sh_step "cargo test on the pinned MSRV"  "cargo +1.89 test --workspace --no-fail-fast"
else
    step "1.89 toolchain (rustup toolchain install 1.89)" false
fi
fi

# --- gates -------------------------------------------------------------------
if has_job gates; then
job "latency gates (§8.10.3) + §8.16 acceptance criteria"
sh_step "filter_tools_list, 256 tools"    "cargo test -p warden-connect-mediator --release --test mediation gate_filter"
sh_step "connect bench" "cargo build --release -p warden-connect-cli --quiet && \
    ./target/release/connect bench --iterations 400 --scale 100000 \
      --signing-key fixtures/keys/test_issuer_es256_priv.pem \
      --verify-pub fixtures/keys/test_issuer_es256_pub.pem --kid wc-test-es256"
step "containment drill"                  bash scripts/containment-drill.sh
sh_step "cross-organisation federation"   "cargo test -p wc-e2e --test federation"
fi

# --- supply-chain ------------------------------------------------------------
if has_job supply-chain; then
job "cargo-deny"
step "cargo deny check"                   cargo deny check
step "dependency-count ceilings (§8.3)"   bash scripts/dep-count.sh
step "alert coverage"                     bash scripts/alert-coverage.sh
# Guarded in ci.yml too, so the guard is reproduced rather than turned into a failure.
if command -v promtool >/dev/null 2>&1; then
    step "promtool check rules"           promtool check rules deploy/prometheus/alerts.yml
    step "promtool test rules"            promtool test rules deploy/prometheus/alerts_test.yml
else
    printf '  %-52s %s\n' "promtool rules" "${dim}absent — ci.yml guards this step too${off}"
fi
sh_step "SBOM is reproducible"            "python3 scripts/sbom.py --check && \
    python3 scripts/sbom.py > warden-connect.cdx.json && \
    python3 scripts/sbom.py | diff -q - warden-connect.cdx.json"
fi

# --- image -------------------------------------------------------------------
if has_job image; then
job "container image"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    sh_step "docker build"                "cd .. && docker build -f warden-connect/Dockerfile -t warden-connect:ci ."
    sh_step "the image actually runs"     "docker run --rm --entrypoint connect-mediate warden-connect:ci --help | head -3"
else
    step "docker (not installed, or the daemon is not running)" false
fi
fi

# --- fuzz --------------------------------------------------------------------
if has_job fuzz; then
job "fuzz targets compile"
if rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    sh_step "cargo check the fuzz targets" "cd fuzz && cargo +nightly check --all-targets"
else
    step "nightly toolchain (rustup toolchain install nightly)" false
fi
fi

# -----------------------------------------------------------------------------
printf '\n'
if [ "$fail" -eq 0 ]; then
    printf '%sALL %d STEPS PASSED%s\n' "$bold" "$pass" "$off"
    printf 'Mirrors .github/workflows/ci.yml. It is a mirror, not the authority: a step added\n'
    printf 'there and not here passes locally by not existing.\n'
    exit 0
fi
printf '%s%d PASSED, %d FAILED%s\n' "$bold" "$pass" "$fail" "$off"
for f in "${failed[@]}"; do printf '  %s\n' "$f"; done
exit 1
