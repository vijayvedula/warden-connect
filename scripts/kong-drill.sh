#!/usr/bin/env bash
# The Kong drill: enforcement through a REAL Kong, with real mTLS.
#
#     scripts/kong-drill.sh
#
# The Lua suite (crates/wc-kong/lua/spec) drives the real handler against the real cdylib with
# Kong stubbed. That leaves exactly the parts only Kong can confirm:
#
#   · that ngx.var.ssl_client_raw_cert carries a chain the plugin can read an identity out of,
#     and that ssl_client_verify says SUCCESS only when nginx verified it against the CA
#   · that kong.service.request.enable_buffering() called in `access` actually causes the
#     `response` phase to run with a body — Kong decides buffering before it proxies, so a
#     plugin that asked too late would silently never filter a catalogue
#   · that kong.router.get_service().name is the string routes.toml has to match
#   · that a refusal reaches the client as a 200 JSON-RPC error and the upstream never saw it
#   · that the cdylib loads at all inside Kong's container — a glibc or arch mismatch is a
#     class of failure no test on the build host can reach
#
# The library is built for the container, not the host: Kong runs Linux and this repo is
# developed on macOS. A drill that loaded the host's .dylib would be testing nothing.
#
# Needs docker and openssl and python3. Exit 0 pass · 1 fail · 2 setup.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=${KONG_IMAGE:-kong:3.9}
RUST_IMAGE=${RUST_IMAGE:-rust:1.89-bookworm}

command -v docker >/dev/null || { echo "need docker" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "the docker daemon is not running" >&2; exit 2; }
command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }
command -v python3 >/dev/null || { echo "need python3" >&2; exit 2; }

WORK="$(mktemp -d)"

# Ports are chosen, not assumed. A fixed 8931 collided with a ledger server left running from
# the end-to-end guide, and the drill then ran nine phases against a process it had not started
# — including one that asserts "the upstream never saw it" against a log that process never
# writes to. That phase reported ok and meant nothing.
free_port() {
  python3 -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
busy() { # port
  python3 -c 'import socket,sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1]))); print("free")
except OSError:
    print("busy")
finally:
    s.close()' "$1"
}
UP_PORT=${UP_PORT:-$(free_port)}
PROXY_TLS=${PROXY_TLS:-$(free_port)}
for p in "$UP_PORT" "$PROXY_TLS"; do
  [ "$(busy "$p")" = free ] || { echo "port $p is in use; set UP_PORT / PROXY_TLS" >&2; exit 2; }
done
CID_FILE="$WORK/kong.cid"
cleanup() {
  # Kong's own log is the only account of what happened inside the container, and the container
  # goes away here. Capture it first, always — a drill that discards the log makes every
  # failure a re-run.
  if [ -f "$CID_FILE" ]; then
    docker logs "$(cat "$CID_FILE")" >"$WORK/kong.log" 2>&1 || true
    docker rm -f "$(cat "$CID_FILE")" >/dev/null 2>&1
  fi
  [ -n "${UP_PID:-}" ] && kill "$UP_PID" 2>/dev/null
  [ -n "${PLANE_PID:-}" ] && { kill "$PLANE_PID" 2>/dev/null; wait "$PLANE_PID" 2>/dev/null; }
  wait 2>/dev/null
  if [ -n "${KEEP:-}" ]; then echo "kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

CALLER="spiffe://bank.example/ns/mesh/sa/recon-bot"
OTHER="spiffe://bank.example/ns/mesh/sa/intruder"
CALLEE="spiffe://bank.example/ns/mesh/sa/payments-mcp"
MED="warden:mediator:kong-1"
ISS="https://connect.internal"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  ·    %s\n' "$1"; }
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

bold "Kong drill"
step "work dir  $WORK"
step "kong      $IMAGE"
step "ports     upstream $UP_PORT · proxy tls $PROXY_TLS"

# --- the library, built for the container ----------------------------------
# The library has to be built FOR THE CONTAINER, not for the build host. On Linux the host
# already is Linux, so a native build is right and skips pulling a ~1GB toolchain image; on
# macOS it has to happen inside one. Either way the result is checked below: a glibc or
# architecture mismatch is a class of failure no test on the build host can reach, and the
# check is what keeps that honest if the runner and the Kong image ever drift apart.
if [ "$(uname -s)" = Linux ]; then
  step "building the cdylib natively (host is already linux)"
  cargo build --release -q -p warden-connect-kong >"$WORK/build.log" 2>&1 \
    || { echo "the cdylib does not build; see $WORK/build.log" >&2; cat "$WORK/build.log" >&2; exit 2; }
  SO="$REPO/target/release/libwc_kong.so"
else
  step "building the cdylib for linux (in $RUST_IMAGE)"
  docker run --rm -u "$(id -u):$(id -g)" -v "$REPO:/src" -w /src \
    -e CARGO_HOME=/src/target/docker-cargo \
    "$RUST_IMAGE" cargo build --release -q -p warden-connect-kong \
    --target-dir /src/target/docker >"$WORK/build.log" 2>&1 \
    || { echo "the cdylib does not build for linux; see $WORK/build.log" >&2; cat "$WORK/build.log" >&2; exit 2; }
  SO="$REPO/target/docker/release/libwc_kong.so"
fi
[ -f "$SO" ] || { echo "no linux cdylib at $SO" >&2; exit 2; }

# Loadable BY KONG, asked of Kong. Without this a mismatch surfaces as phase 1 failing to find
# a verified contract, which says nothing about why.
if ! docker run --rm -v "$SO:/probe.so:ro" --entrypoint ldd "$IMAGE" /probe.so >"$WORK/ldd.log" 2>&1 \
   || grep -q 'not found' "$WORK/ldd.log"; then
  echo "the cdylib does not load inside $IMAGE:" >&2
  cat "$WORK/ldd.log" >&2
  echo "build it in a container instead: RUST_IMAGE=$RUST_IMAGE, see the branch above" >&2
  exit 2
fi

cargo build -q -p warden-connect-kong --example mkfixture 2>/dev/null \
  || { echo "mkfixture does not build" >&2; exit 2; }

# --- certificates -----------------------------------------------------------
# A real CA, a real server certificate for Kong's TLS listener, and two client certificates
# with SPIFFE URI SANs. The plugin reads the identity out of the chain nginx verified; nothing
# here sets a header.
cd "$WORK"
openssl ecparam -genkey -name prime256v1 -noout -out ca.key 2>/dev/null
openssl req -new -x509 -key ca.key -out ca.pem -days 2 -subj "/CN=drill-ca" 2>/dev/null

mkcert() { # name, san
  openssl ecparam -genkey -name prime256v1 -noout -out "$1.key" 2>/dev/null
  printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=%s\n[ext]\n%s\n' "$1" "$2" > "$1.cnf"
  openssl req -new -key "$1.key" -out "$1.csr" -config "$1.cnf" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out "$1.pem" -days 2 -extfile "$1.cnf" -extensions ext 2>/dev/null
}
mkcert server "subjectAltName=DNS:localhost,IP:127.0.0.1"
mkcert client "subjectAltName=URI:$CALLER"
mkcert other  "subjectAltName=URI:$OTHER"
chmod 644 ca.key ca.pem ./*.key ./*.pem

# --- the contract -----------------------------------------------------------
# Minted against the surface the ledger server actually emits — schemas included. A contract
# pinned to a surface this script invented would read as drift on the first catalogue.
python3 "$REPO/scripts/envoy/ledger-server.py" --emit-surface > "$WORK/surface.json" \
  || { echo "could not emit the upstream surface" >&2; exit 2; }
cargo run -q -p warden-connect-kong --example mkfixture --manifest-path "$REPO/Cargo.toml" -- \
  "$WORK/fx" "caller=$CALLER" "callee=$CALLEE" "mediator=$MED" "issuer=$ISS" \
  "tools=get_balance,list_transactions" "served_file=$WORK/surface.json" \
  "revoke_party=$CALLER" >/dev/null \
  || { echo "could not mint the drill contract" >&2; exit 2; }

# --- the upstream -----------------------------------------------------------
export LEDGER_LOG="$WORK/ledger.log"; : > "$LEDGER_LOG"

# What the upstream is serving right now, read straight from it rather than through Kong.
# A drill that assumes a restart took is a drill whose drift phase can silently test the
# surface it was trying to replace.
up_desc() {
  curl -s --max-time 3 -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
    "http://127.0.0.1:$UP_PORT/" 2>/dev/null | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)["result"]["tools"]
    print([t["description"] for t in d if t["name"] == "get_balance"][0])
except Exception:
    print("")'
}

stop_upstream() {
  [ -n "${UP_PID:-}" ] || return 0
  kill "$UP_PID" 2>/dev/null
  wait "$UP_PID" 2>/dev/null
  # Until the port is actually released the next bind fails and the OLD process keeps
  # answering — the readiness probe then succeeds against the server we were replacing.
  for _ in $(seq 1 50); do
    [ -z "$(up_desc)" ] && { UP_PID=""; return 0; }
    sleep 0.1
  done
  UP_PID=""
  return 1
}

start_upstream() { # LEDGER_DRIFT=1 to serve a changed surface
  LEDGER_LOG="$LEDGER_LOG" LEDGER_DRIFT="${1:-0}" \
    python3 "$REPO/scripts/envoy/ledger-server.py" "$UP_PORT" >>"$WORK/upstream.log" 2>&1 &
  UP_PID=$!
  for _ in $(seq 1 50); do
    # If the bind failed the process is already gone, and polling the port would otherwise
    # find whatever else is listening and call it ready.
    kill -0 "$UP_PID" 2>/dev/null || { UP_PID=""; return 1; }
    [ -n "$(up_desc)" ] && return 0
    sleep 0.1
  done
  return 1
}
start_upstream || { echo "the upstream did not come up on port $UP_PORT; see $WORK/upstream.log" >&2; exit 2; }

# --- kong -------------------------------------------------------------------
cat > kong.yml <<YAML
_format_version: "3.0"
services:
  - name: payments
    url: http://host.docker.internal:$UP_PORT
    routes:
      - name: mcp
        paths: ["/mcp"]
        strip_path: true
  - name: unmapped
    url: http://host.docker.internal:$UP_PORT
    routes:
      - name: elsewhere
        paths: ["/elsewhere"]
        strip_path: true
plugins:
  - name: warden-connect
    config:
      library_path: /wc/libwc_kong.so
      contracts: ["/wc/fx/c.jws"]
      routes: /wc/fx/routes.toml
      identity: tls
      issuer_pub: /wc/issuer_pub.pem
      kid: wc-test-es256
      mediator_id: "$MED"
      issuer_id: "$ISS"
      mode: enforce
      evidence_path: /wc/evidence/trail-%w.jsonl
YAML
mkdir -p "$WORK/evidence" && chmod 777 "$WORK/evidence"
cp "$REPO/fixtures/keys/test_issuer_es256_pub.pem" issuer_pub.pem
# Copied in rather than bind-mounted: /wc is mounted read-only, and a second mount cannot
# create its own mountpoint inside one.
cp "$SO" libwc_kong.so

# See the note in envoy-drill.sh: without this `host.docker.internal` does not resolve on Linux
# and Kong cannot reach the upstream at all.
docker run -d --cidfile "$CID_FILE" \
  --add-host=host.docker.internal:host-gateway \
  -v "$WORK:/wc:ro" \
  -v "$WORK/evidence:/wc/evidence" \
  -v "$REPO/crates/wc-kong/lua:/wc-lua:ro" \
  -e KONG_DATABASE=off \
  -e KONG_DECLARATIVE_CONFIG=/wc/kong.yml \
  -e "KONG_PLUGINS=bundled,warden-connect" \
  -e "KONG_LUA_PACKAGE_PATH=/wc-lua/?.lua;;" \
  -e "KONG_PROXY_LISTEN=0.0.0.0:8000, 0.0.0.0:8443 ssl" \
  -e KONG_NGINX_PROXY_SSL_CLIENT_CERTIFICATE=/wc/ca.pem \
  -e KONG_NGINX_PROXY_SSL_VERIFY_CLIENT=optional \
  -e KONG_NGINX_PROXY_SSL_VERIFY_DEPTH=2 \
  -e KONG_SSL_CERT=/wc/server.pem \
  -e KONG_SSL_CERT_KEY=/wc/server.key \
  -e KONG_NGINX_WORKER_PROCESSES=2 \
  -e KONG_PROXY_ACCESS_LOG=/dev/stdout \
  -e KONG_PROXY_ERROR_LOG=/dev/stderr \
  -e KONG_LOG_LEVEL=notice \
  -p "$PROXY_TLS:8443" \
  "$IMAGE" >"$WORK/run.log" 2>&1 || {
    echo "kong did not start:" >&2; cat "$WORK/run.log" >&2; exit 2; }

for _ in $(seq 1 80); do
  curl -sk -o /dev/null --max-time 2 "https://127.0.0.1:$PROXY_TLS/mcp" 2>/dev/null && break
  sleep 0.25
done

klog() { docker logs "$(cat "$CID_FILE")" 2>&1; }

# --- the client -------------------------------------------------------------
# curl, so nothing in this drill is code from this repository pretending to be a client.
call() { # cert-base, path, body  -> body on stdout
  local c="$1" p="$2" b="$3" args=()
  [ "$c" != "none" ] && args=(--cert "$WORK/$c.pem" --key "$WORK/$c.key")
  # ${args[@]+...} because `set -u` treats an empty array as unbound on bash 3.2, which ships
  # on macOS — and the no-certificate phase is exactly the one that passes no arguments.
  curl -sk --max-time 10 ${args[@]+"${args[@]}"} \
    -H 'Content-Type: application/json' \
    -X POST --data "$b" "https://127.0.0.1:$PROXY_TLS$p" 2>/dev/null
}
LIST='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
GET='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_balance","arguments":{"account":"a1"}}}'
XFER='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"transfer_funds","arguments":{"amount":1}}}'
BATCH="[$GET]"

echo
bold "phases"

# 1 ---------------------------------------------------------------------------
if klog | grep -q 'contract(s) verified'; then
  ok "1 · the cdylib loaded inside Kong and verified the contract"
else
  bad "1 · the plugin did not report a verified contract"
  klog | tail -20
fi

# 3 ---------------------------------------------------------------------------
R=$(call client /mcp "$LIST")
N=$(printf '%s' "$R" | python3 -c 'import json,sys
try: print(len(json.load(sys.stdin)["result"]["tools"]))
except Exception: print(-1)')
if [ "$N" = "2" ]; then
  ok "3 · the catalogue was filtered to the 2 contracted tools (3 served)"
else
  bad "3 · catalogue: expected 2 tools, got $N"
  printf '       %s\n' "$(printf '%s' "$R" | head -c 300)"
fi

# 4 ---------------------------------------------------------------------------
R=$(call client /mcp "$GET")
if printf '%s' "$R" | grep -q '"result"'; then
  ok "4 · a contracted tool reached the upstream and answered"
else
  bad "4 · a contracted call did not succeed"
  printf '       %s\n' "$(printf '%s' "$R" | head -c 300)"
fi

# 5 ---------------------------------------------------------------------------
BEFORE=$(grep -c transfer_funds "$LEDGER_LOG" 2>/dev/null || echo 0)
R=$(call client /mcp "$XFER")
AFTER=$(grep -c transfer_funds "$LEDGER_LOG" 2>/dev/null || echo 0)
if printf '%s' "$R" | grep -q 'WC-4002'; then
  if [ "$BEFORE" = "$AFTER" ]; then
    ok "5 · an uncontracted tool was refused WC-4002 and the upstream never saw it"
  else
    bad "5 · refused WC-4002 but the upstream executed it anyway"
  fi
else
  bad "5 · an uncontracted tool was not refused: $(printf '%s' "$R" | head -c 200)"
fi

# 6 ---------------------------------------------------------------------------
R=$(call none /mcp "$LIST")
if printf '%s' "$R" | grep -q 'WC-4001'; then
  ok "6 · no client certificate: refused WC-4001, no identity means no contract"
else
  bad "6 · a call with no client certificate was not refused: $(printf '%s' "$R" | head -c 200)"
fi

# 7 ---------------------------------------------------------------------------
R=$(call other /mcp "$LIST")
if printf '%s' "$R" | grep -q 'WC-4001'; then
  ok "7 · a verified certificate for another workload got no contract"
else
  bad "7 · the wrong identity was not refused: $(printf '%s' "$R" | head -c 200)"
fi

# 8 ---------------------------------------------------------------------------
R=$(call client /elsewhere "$LIST")
if printf '%s' "$R" | grep -q 'WC-4001'; then
  ok "8 · an unmapped service was refused, so kong.router.get_service() is doing something"
else
  bad "8 · an unmapped route was not refused: $(printf '%s' "$R" | head -c 200)"
fi

# 9 ---------------------------------------------------------------------------
R=$(call client /mcp "$BATCH")
if printf '%s' "$R" | grep -qi 'batch'; then
  ok "9 · a JSON-RPC batch was refused whole"
else
  bad "9 · a batch was not refused: $(printf '%s' "$R" | head -c 200)"
fi

# 10 --------------------------------------------------------------------------
# The upstream is restarted serving a fourth tool. The contract pins a digest over the
# contracted items against the surface as it was, so the catalogue must now be refused.
stop_upstream || { bad "10 · the upstream would not release port $UP_PORT"; }
start_upstream 1 || { bad "10 · the drifted upstream did not come up"; }
# Assert the surface ACTUALLY changed before asking whether it is refused. Without this the
# phase passes or fails on whatever happens to be listening, which is how a drill reports a
# result about a server it never restarted.
DESC="$(up_desc)"
case "$DESC" in
  *"(v2)"*) : ;;
  *) bad "10 · the upstream is not serving a drifted surface (get_balance: ${DESC:-<none>})" ;;
esac
R=$(call client /mcp "$LIST")
if printf '%s' "$R" | grep -q 'WC-3108'; then
  ok "10 · the callee changed its surface and the catalogue was refused WC-3108"
else
  bad "10 · surface drift was not refused: $(printf '%s' "$R" | head -c 200)"
fi

# 11 --------------------------------------------------------------------------
R=$(call client /mcp "$GET")
if printf '%s' "$R" | grep -q 'WC-1002'; then
  ok "11 · and the drift revoked the pin: a tool call is refused WC-1002"
else
  bad "11 · drift did not revoke the verified pin: $(printf '%s' "$R" | head -c 200)"
fi

# 12 --------------------------------------------------------------------------
# The decision trail. `terms.evidence` has been in the artifact since it was designed and
# nothing read it, so this is the first phase that asks whether a refusal leaves a record.
TRAILS=$(ls "$WORK"/evidence/trail-*.jsonl 2>/dev/null | wc -l | tr -d ' ')
if [ "$TRAILS" = 0 ]; then
  bad "12 · no decision trail was written"
else
  ROWS=$(cat "$WORK"/evidence/trail-*.jsonl 2>/dev/null | wc -l | tr -d ' ')
  DENIES=$(grep -ho '"decision":"deny"' "$WORK"/evidence/trail-*.jsonl 2>/dev/null | wc -l | tr -d ' ')
  CODES=$(grep -ho '"code":"WC-[0-9]*"' "$WORK"/evidence/trail-*.jsonl 2>/dev/null \
          | sort -u | sed 's/.*"\(WC-[0-9]*\)"/\1/' | tr '\n' ' ')
  if [ "$DENIES" -ge 4 ]; then
    ok "12 · $ROWS decisions across $TRAILS worker trail(s); $DENIES refusals recorded"
    step "codes in the trail: $CODES"
  else
    bad "12 · only $DENIES refusals in the trail, expected at least 4"
  fi
fi

# 13 --------------------------------------------------------------------------
# And the chain holds. Every worker keeps its own, because two appending to one file interleave
# into something that never verifies while every row still looks well-formed.
BROKEN=0
for t in "$WORK"/evidence/trail-*.jsonl; do
  [ -f "$t" ] || continue
  cargo run -q -p warden-connect-mediator --example evidence-verify --manifest-path \
    "$REPO/Cargo.toml" -- "$t" >/dev/null 2>&1 || BROKEN=$((BROKEN + 1))
done
if [ "$BROKEN" = 0 ] && [ "$TRAILS" != 0 ]; then
  ok "13 · every worker trail verifies"
else
  bad "13 · $BROKEN of $TRAILS trail(s) do not verify"
fi

# 14 --------------------------------------------------------------------------
# The pull path. Until now this binding had none: a worker held the artifacts it loaded at
# start for the life of those contracts and no containment order could reach it. Revocation
# worked at the Envoy binding and not this one.
#
# Against a stub plane rather than a real one on purpose. The Envoy drill proves the plane end
# of containment against `connect serve`; what is unproven HERE is the binding end — that a
# background thread started after nginx forks actually pulls, applies a revocation, and that
# the request path sees it. A whole estate would test the plane twice and the binding once.
PLANE_PORT=$(free_port)
ARM="$WORK/arm-revocation"
rm -f "$ARM"
python3 "$REPO/scripts/.stub-plane.py" "$PLANE_PORT" "$WORK/fx" "$ARM" \
  >"$WORK/plane.log" 2>&1 &
PLANE_PID=$!
for _ in $(seq 1 40); do
  curl -sf -o /dev/null "http://127.0.0.1:$PLANE_PORT/v1/revocations?since=0" && break
  sleep 0.1
done

# The undrifted upstream, because phase 10 left it serving a changed surface and a fresh Kong
# has an empty pin ledger — the catalogue below has to match the contract or nothing past it
# proves anything about revocation.
stop_upstream || bad "14 · the upstream would not release port $UP_PORT"
start_upstream || bad "14 · the undrifted upstream did not come up"

# Its own heredoc rather than an edit of the first. Patching YAML from a shell one-liner is how
# a quoting mistake becomes a phase that tests the wrong thing — the first attempt at this used
# `sed` with a \n that BSD sed does not support, and produced a config Kong could not parse.
cat > "$WORK/kong-pull.yml" <<YAML
_format_version: "3.0"
services:
  - name: payments
    url: http://host.docker.internal:$UP_PORT
    routes:
      - name: mcp
        paths: ["/mcp"]
        strip_path: true
  - name: unmapped
    url: http://host.docker.internal:$UP_PORT
    routes:
      - name: elsewhere
        paths: ["/elsewhere"]
        strip_path: true
plugins:
  - name: warden-connect
    config:
      library_path: /wc/libwc_kong.so
      contracts: ["/wc/fx/c.jws"]
      routes: /wc/fx/routes.toml
      identity: tls
      issuer_pub: /wc/issuer_pub.pem
      kid: wc-test-es256
      mediator_id: "$MED"
      issuer_id: "$ISS"
      mode: enforce
      evidence_path: /wc/evidence/pull-%w.jsonl
      contracts_url: http://host.docker.internal:$PLANE_PORT
      token: tok_drill_stub_plane_0123456789
      refresh_secs: 1
YAML

docker rm -f "$(cat "$CID_FILE")" >/dev/null 2>&1
rm -f "$CID_FILE"
docker run -d --cidfile "$CID_FILE" \
  --add-host=host.docker.internal:host-gateway \
  -v "$WORK:/wc:ro" -v "$WORK/evidence:/wc/evidence" \
  -e KONG_DATABASE=off -e KONG_DECLARATIVE_CONFIG=/wc/kong-pull.yml \
  -e "KONG_PLUGINS=bundled,warden-connect" \
  -e "KONG_LUA_PACKAGE_PATH=/wc-lua/?.lua;;" \
  -v "$REPO/crates/wc-kong/lua:/wc-lua:ro" \
  -e "KONG_PROXY_LISTEN=0.0.0.0:8000, 0.0.0.0:8443 ssl" \
  -e KONG_NGINX_PROXY_SSL_CLIENT_CERTIFICATE=/wc/ca.pem \
  -e KONG_NGINX_PROXY_SSL_VERIFY_CLIENT=optional \
  -e KONG_SSL_CERT=/wc/server.pem -e KONG_SSL_CERT_KEY=/wc/server.key \
  -e KONG_NGINX_WORKER_PROCESSES=1 \
  -e KONG_PROXY_ACCESS_LOG=/dev/stdout -e KONG_PROXY_ERROR_LOG=/dev/stderr \
  -e KONG_LOG_LEVEL=notice \
  -p "$PROXY_TLS:8443" "$IMAGE" >"$WORK/run2.log" 2>&1 \
  || { bad "14 · kong did not restart against the stub plane"; cat "$WORK/run2.log" >&2; }

for _ in $(seq 1 80); do
  curl -sk -o /dev/null --max-time 2 "https://127.0.0.1:$PROXY_TLS/mcp" 2>/dev/null && break
  sleep 0.25
done

# Pin first, then a working call — the baseline the refusal has to be measured against.
call client /mcp "$LIST" >/dev/null
R=$(call client /mcp "$GET")
if ! printf '%s' "$R" | grep -q '"result"'; then
  bad "14 · the contract does not work before revocation, so the phase proves nothing"
  printf '       %s\n' "$(printf '%s' "$R" | head -c 200)"
else
  ok "14 · pulling from a control plane: the contract works"

  # 15 ------------------------------------------------------------------------
  touch "$ARM"
  sleep 4
  R=$(call client /mcp "$GET")
  if printf '%s' "$R" | grep -q 'WC-4001'; then
    if docker logs "$(cat "$CID_FILE")" 2>&1 | grep -q 'applied 1 revocation'; then
      ok "15 · a revocation reached the nginx worker, via the deny-list"
      docker logs "$(cat "$CID_FILE")" 2>&1 | grep -o 'applied 1 revocation(s), feed at seq [0-9]*' \
        | tail -1 | sed 's/^/       /'
    else
      bad "15 · refused, but the worker never applied a revocation — set membership, not the feed"
    fi
  else
    bad "15 · the contract was still honoured after the party was revoked"
    printf '       %s\n' "$(printf '%s' "$R" | head -c 200)"
  fi
fi

kill "$PLANE_PID" 2>/dev/null
wait "$PLANE_PID" 2>/dev/null
PLANE_PID=""

echo
if [ "$fail" = 0 ]; then
  bold "kong drill: all phases pass"
else
  bold "kong drill: FAILURES"
  docker logs "$(cat "$CID_FILE")" 2>&1 | grep -iE '\[error\]|lua entry|traceback|stack' \
    | tail -12 | sed 's/^/       /'
fi
exit "$fail"
