#!/usr/bin/env bash
# What you need to exercise every flow end to end, and which flows you cannot yet reach.
#
#     scripts/preflight.sh
#
# The hardening pass in `docs/production-readiness.md` has one rule: **run the binaries.**
# Every defect this build turned up was found by executing a flow, not by reading code. So
# the first question is which flows are actually reachable on this machine, and that is a
# question a script should answer rather than a document.
#
# Nothing here is installed for you. Each miss prints the install line and says what it
# unlocks, because a dependency you cannot justify is one you should not add.
#
# Exit codes: 0 every flow reachable · 1 a core flow is blocked · 2 only deep flows blocked.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CORE_MISSING=0
DEEP_MISSING=0

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32mok\033[0m    %-22s %s\n' "$1" "${2:-}"; }
miss() { printf '  \033[31mMISS\033[0m  %-22s %s\n' "$1" "$2"; }
warn() { printf '  \033[33m--\033[0m    %-22s %s\n' "$1" "$2"; }

have() { command -v "$1" >/dev/null 2>&1; }

# --- core: the flows that must work -----------------------------------------
bold "Core toolchain — without these, nothing runs"

if have cargo; then ok "cargo" "$(cargo --version | cut -d' ' -f2)"; else
    miss "cargo" "https://rustup.rs"; CORE_MISSING=1; fi

if rustup run 1.89 rustc --version >/dev/null 2>&1; then
    ok "rust 1.89 (MSRV)" "CI pins it; a newer-only toolchain hides MSRV breaks"
else
    miss "rust 1.89 (MSRV)" "rustup toolchain install 1.89"; CORE_MISSING=1
fi

if [ -d "$REPO/../warden" ]; then
    ok "../warden" "path dependency by design (§8.3)"
else
    miss "../warden" "git clone https://github.com/vijayvedula/warden.git (beside this repo)"
    CORE_MISSING=1
fi

if have python3; then ok "python3" "$(python3 --version | cut -d' ' -f2)"; else
    miss "python3" "the SBOM, the conformance plan and the fixture minter need it"; CORE_MISSING=1; fi

if have openssl; then ok "openssl" "key generation in the containment drill"; else
    miss "openssl" "brew install openssl / apt install openssl"; CORE_MISSING=1; fi

# --- verification tooling ---------------------------------------------------
bold "Verification — the checks CI runs"

if have cargo-deny || cargo deny --version >/dev/null 2>&1; then
    ok "cargo-deny" "advisories, licences, the §8.3 bans"
else
    miss "cargo-deny" "cargo install cargo-deny"; DEEP_MISSING=1
fi

if cargo fuzz --version >/dev/null 2>&1; then
    ok "cargo-fuzz" "coverage-guided campaigns (P2 #15)"
else
    miss "cargo-fuzz" "cargo install cargo-fuzz  (+ rustup toolchain install nightly)"
    DEEP_MISSING=1
fi

if rustup run nightly rustc --version >/dev/null 2>&1; then
    ok "nightly" "libfuzzer needs it; that is why fuzz/ is out of the workspace"
else
    miss "nightly" "rustup toolchain install nightly"; DEEP_MISSING=1
fi

if python3 -c "import cryptography" >/dev/null 2>&1; then
    ok "py cryptography" "mints the attestation fixtures independently of our Rust"
else
    miss "py cryptography" "pip install cryptography"; DEEP_MISSING=1
fi

if have docker && docker info >/dev/null 2>&1; then
    ok "docker" "the image job; build context is the PARENT directory"
elif have docker; then
    warn "docker" "installed but the daemon is not running"
    DEEP_MISSING=1
else
    miss "docker" "https://docs.docker.com/get-docker/"; DEEP_MISSING=1
fi

have jq && ok "jq" "convenience in the drills" || warn "jq" "optional: brew install jq"

# --- the data plane ---------------------------------------------------------
bold "Data plane — to drive calls through a mediator"

if [ -f "$REPO/../warden/examples/echo_mcp_server.py" ]; then
    ok "an MCP upstream" "warden/examples/echo_mcp_server.py — no external server needed"
else
    miss "an MCP upstream" "expected warden/examples/echo_mcp_server.py"; DEEP_MISSING=1
fi

# --- attestation: the flows that are still stand-ins ------------------------
bold "Attestation (P0 #3) — these flows run on minted fixtures, not real output"

if have spire-server && have spire-agent; then
    ok "SPIRE" "stage 1 JWT-SVID, and jwtbundles as a JWKS"
else
    miss "SPIRE" "https://spiffe.io/downloads — unlocks stage 1 against a real issuer"
    DEEP_MISSING=1
fi

if have cosign; then
    ok "cosign" "stage 4: a real DSSE/in-toto envelope"
else
    miss "cosign" "brew install cosign — unlocks stage 4 against real provenance"
    DEEP_MISSING=1
fi

# --- key custody: the flows that need a key this process cannot hold --------
bold "Key custody (P0 #5) — --signer / --anchor-signer are untested against real hardware"

if have pkcs11-tool && have softhsm2-util; then
    ok "SoftHSM + p11-kit" "a local stand-in that still exercises the DER vs R||S trap"
else
    miss "SoftHSM + p11-kit" "brew install softhsm opensc / apt install softhsm2 opensc"
    DEEP_MISSING=1
fi

if have ykman; then
    ok "ykman" "a real token for the break-glass revocation key"
else
    warn "ykman" "brew install ykman — only a real token rehearses revoke-offline"
fi

if have aws; then ok "aws cli" "AWS KMS as the delegated signer"; else
    warn "aws cli" "optional: an alternative to SoftHSM for --signer"; fi

# --- observability ----------------------------------------------------------
bold "Observability (P1 #11) — the alert rules are unit-tested; a live scrape is extra"

have prometheus && ok "prometheus" "a live scrape; the rules are already unit-tested" \
    || { miss "prometheus" "brew install prometheus — for a live scrape of the rules"; DEEP_MISSING=1; }

if have promtool; then
    ok "promtool" "checks and TESTS deploy/prometheus/alerts.yml"
else
    miss "promtool" "ships with prometheus — needed to run the alert unit tests"
    DEEP_MISSING=1
fi

if have caddy || have nginx || have haproxy; then
    ok "a TLS proxy" "--behind-tls-proxy already verified behind Caddy; re-runnable"
else
    miss "a TLS proxy" "brew install caddy — to re-verify --behind-tls-proxy end to end"
    DEEP_MISSING=1
fi

# --- summary ----------------------------------------------------------------
printf '\n'
if [ "$CORE_MISSING" = 1 ]; then
    bold "Core dependencies missing — the test suite will not run."
    exit 1
fi

if [ "$DEEP_MISSING" = 1 ]; then
    bold "Every core flow is reachable. Some deep flows are not:"
    cat <<'BLOCKED'

  Reachable now, with nothing further installed:
    · the whole test suite, the conformance kit, the containment drill
    · a mediator in front of a real MCP upstream, enforce and observe
    · backup, restore, audit verify, the standby handover
    · two control planes for federation (two ports, two roots)

  What each missing dependency unlocks is printed above. In value order:
    1 · SoftHSM     — the delegated-signer path, and the DER vs R||S trap it documents
    2 · SPIRE       — attestation stage 1 against a real issuer, and a real JWKS bundle
    3 · Prometheus  — a live scrape; `promtool test rules` already proves each alert fires
    4 · a TLS proxy — to re-verify --behind-tls-proxy end to end (done once already)
    5 · cosign      — attestation stage 4 against real provenance

BLOCKED
    exit 2
fi

bold "Every flow is reachable on this machine."
