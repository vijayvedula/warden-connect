#!/usr/bin/env bash
# Mint `fixtures/spire/` from a real SPIRE server and agent.
#
#     scripts/spire-fixtures.sh [version]
#
# Stage 1 of admission verifies a SPIFFE JWT-SVID. Until this script existed, every SVID
# `JwtSvidIdentity` had ever seen was minted by `scripts/gen-attest-fixtures.py` — an
# independent *reading* of the SPIFFE and JOSE specs, which catches a disagreement about
# what the specs say and cannot catch a disagreement about what an issuer emits. That is
# the gap that made stage 4 reject every real cosign attestation for months.
#
# ## Why Docker
#
# SPIRE publishes linux and windows binaries only — there is no darwin build, so on a Mac
# `command -v spire-server` will never succeed no matter what you install. The official
# images are distroless and have no shell, so this mounts the release binaries into Alpine
# instead. The tarball's digest is checked against the published sum before anything runs.
#
# ## What it produces
#
# A short-lived token, deliberately. SPIRE's default JWT-SVID lifetime is an hour, so the
# checked-in token is expired against the wall clock the moment it lands and always will
# be. That is fine and it is the point: `JwtSvidIdentity::now` is injected, so the test
# judges the token at an instant it chooses. A fixture that never expired would be a
# fixture no real issuer would ever mint.
#
# Requires: docker, curl, python3, shasum/sha256sum.

set -euo pipefail

VERSION="${1:-1.15.2}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
DST="$REPO/fixtures/spire"
AUD="warden-connect://control-plane/apac"
OTHER_AUD="warden-connect://control-plane/emea"
SPIFFE_ID="spiffe://example.org/ns/agents/sa/recon"

# linux/arm64 on Apple silicon, linux/amd64 elsewhere. Both are published as musl builds,
# which is what lets them run under Alpine.
case "$(uname -m)" in
    arm64 | aarch64) ARCH=arm64 ;;
    x86_64 | amd64) ARCH=amd64 ;;
    *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
TARBALL="spire-${VERSION}-linux-${ARCH}-musl.tar.gz"
BASE="https://github.com/spiffe/spire/releases/download/v${VERSION}"

command -v docker >/dev/null || { echo "docker is required; see docs/prerequisites.md" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "the docker daemon is not running" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/out"

echo "==> fetching SPIRE ${VERSION} (linux/${ARCH})"
curl -sSfL -o "$WORK/$TARBALL" "$BASE/$TARBALL"
curl -sSfL -o "$WORK/sum.txt" "$BASE/${TARBALL%.tar.gz}_sha256sum.txt"

# Verify before extracting. This script runs the result, so the digest is not a formality.
EXPECTED="$(awk '{print $1}' "$WORK/sum.txt")"
if command -v sha256sum >/dev/null; then
    ACTUAL="$(sha256sum "$WORK/$TARBALL" | awk '{print $1}')"
else
    ACTUAL="$(shasum -a 256 "$WORK/$TARBALL" | awk '{print $1}')"
fi
[ "$EXPECTED" = "$ACTUAL" ] || {
    echo "digest mismatch for $TARBALL" >&2
    echo "  published $EXPECTED" >&2
    echo "  computed  $ACTUAL" >&2
    exit 1
}
echo "    digest matches the published sum"
tar xzf "$WORK/$TARBALL" -C "$WORK"
BIN="$WORK/spire-${VERSION}/bin"

# The smallest server that can issue a JWT-SVID: sqlite, join-token node attestation, and
# the unix workload attestor so the container's own uid is a selector.
cat > "$WORK/conf/server.conf" <<'CONF'
server {
    bind_address = "127.0.0.1"
    bind_port = "8081"
    trust_domain = "example.org"
    data_dir = "/opt/spire/data/server"
    log_level = "WARN"
    ca_ttl = "24h"
    default_x509_svid_ttl = "1h"
    default_jwt_svid_ttl = "1h"
}
plugins {
    DataStore "sql" { plugin_data { database_type = "sqlite3" connection_string = "/opt/spire/data/server/datastore.sqlite3" } }
    NodeAttestor "join_token" { plugin_data {} }
    KeyManager "disk" { plugin_data { keys_path = "/opt/spire/data/server/keys.json" } }
}
CONF

cat > "$WORK/conf/agent.conf" <<'CONF'
agent {
    data_dir = "/opt/spire/data/agent"
    log_level = "WARN"
    server_address = "127.0.0.1"
    server_port = "8081"
    socket_path = "/tmp/spire-agent/public/api.sock"
    trust_domain = "example.org"
    # A throwaway server whose CA this run creates. Never do this for a real trust domain.
    insecure_bootstrap = true
}
plugins {
    NodeAttestor "join_token" { plugin_data {} }
    KeyManager "memory" { plugin_data {} }
    WorkloadAttestor "unix" { plugin_data {} }
}
CONF

cat > "$WORK/run.sh" <<SH
#!/bin/sh
set -e
BIN=/opt/spire/bin
SOCK=/tmp/spire-agent/public/api.sock
mkdir -p /opt/spire/data/server /opt/spire/data/agent /tmp/spire-agent/public

\$BIN/spire-server run -config /conf/server.conf >/out/server.log 2>&1 &
for i in \$(seq 1 60); do \$BIN/spire-server healthcheck >/dev/null 2>&1 && break; sleep 0.5; done
\$BIN/spire-server healthcheck >/dev/null || { echo "server did not come up"; tail -30 /out/server.log; exit 1; }

TOKEN=\$(\$BIN/spire-server token generate -spiffeID spiffe://example.org/node | sed 's/^Token: //')
\$BIN/spire-server entry create -parentID spiffe://example.org/node \\
    -spiffeID "$SPIFFE_ID" -selector unix:uid:0 >/dev/null

\$BIN/spire-agent run -config /conf/agent.conf -joinToken "\$TOKEN" >/out/agent.log 2>&1 &
for i in \$(seq 1 60); do \$BIN/spire-agent healthcheck -socketPath \$SOCK >/dev/null 2>&1 && break; sleep 0.5; done
\$BIN/spire-agent healthcheck -socketPath \$SOCK >/dev/null || { echo "agent did not come up"; tail -30 /out/agent.log; exit 1; }

# The agent syncs entries from the server on an interval, so the first fetch can race it.
for i in \$(seq 1 20); do
    \$BIN/spire-agent api fetch jwt -audience "$AUD" -output json -socketPath \$SOCK >/out/jwt-apac.json 2>/dev/null \\
        && grep -q svids /out/jwt-apac.json && break
    sleep 1
done
grep -q svids /out/jwt-apac.json || { echo "no SVID issued"; cat /out/jwt-apac.json; tail -30 /out/agent.log; exit 1; }

# A second SVID for a control plane this one is not, so a test can assert the audience
# check against real material rather than a hand-edited token.
\$BIN/spire-agent api fetch jwt -audience "$OTHER_AUD" -output json -socketPath \$SOCK >/out/jwt-emea.json

# The trust bundle. There is no \`api fetch jwtbundles\` subcommand and no
# \`bundle show -format jwks\`; the SPIFFE bundle format *is* a JWKS with extra members,
# which is what \`IssuerKeys::add_jwks\` reads.
\$BIN/spire-server bundle show -format spiffe > /out/bundle.spiffe.json
SH
chmod +x "$WORK/run.sh"

echo "==> standing up a server and an agent"
docker run --rm --platform "linux/${ARCH}" \
    -v "$WORK/conf:/conf:ro" -v "$WORK/out:/out" -v "$WORK/run.sh:/run.sh:ro" \
    -v "$BIN:/opt/spire/bin:ro" \
    alpine:3.20 /run.sh

echo "==> installing fixtures"
mkdir -p "$DST"
VERSION="$VERSION" python3 - "$WORK/out" "$DST" <<'PY'
import base64, json, os, pathlib, sys

out, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])

def claims(jws):
    seg = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))

def header(jws):
    seg = jws.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))

def svid(name):
    """Exactly what `jq -r '.[0].svids[0].svid'` yields."""
    return json.loads(out.joinpath(name).read_text())[0]["svids"][0]["svid"]

apac, emea = svid("jwt-apac.json"), svid("jwt-emea.json")
dst.joinpath("jwt-svid.token").write_text(apac + "\n")
dst.joinpath("jwt-svid-other-audience.token").write_text(emea + "\n")

# The whole SPIFFE bundle, unedited — including the x509-svid key that carries no `kid`,
# because that document is what an operator pastes and `add_jwks` has to survive it.
bundle = json.loads(out.joinpath("bundle.spiffe.json").read_text())
dst.joinpath("bundle.spiffe.json").write_text(json.dumps(bundle, indent=2) + "\n")

h, c = header(apac), claims(apac)
manifest = {
    "_": "Real output from SPIRE. Minted by scripts/spire-fixtures.sh. Do not hand-edit.",
    "spire_version": os.environ["VERSION"],
    "trust_domain": "example.org",
    "spiffe_id": c["sub"],
    "audience": c["aud"][0],
    "other_audience": claims(emea)["aud"][0],
    "jwt_svid_kid": h["kid"],
    "alg": h["alg"],
    "iat": c["iat"],
    "exp": c["exp"],
}
dst.joinpath("manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

print(f"    kid       {h['kid']}")
print(f"    alg       {h['alg']}")
print(f"    sub       {c['sub']}")
print(f"    aud       {c['aud']}")
print(f"    iat/exp   {c['iat']} / {c['exp']}")
print(f"    bundle    {[(k.get('use'), k.get('kid')) for k in bundle['keys']]}")
PY

echo
echo "==> now assert the verifier agrees with a real issuer"
echo "    cargo test -p wc-e2e --test attest"
