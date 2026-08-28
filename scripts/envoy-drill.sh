#!/usr/bin/env bash
# The Envoy ext_proc drill: enforcement through a REAL Envoy.
#
#     scripts/envoy-drill.sh
#
# Everything else about E5 is tested against a simulated proxy — real gRPC, real protos, but
# messages this project constructs. That leaves the parts only Envoy can confirm: that
# `allow_mode_override` is honoured from the response-headers phase, that `request_attributes`
# actually delivers `xds.cluster_name`, that `failure_mode_allow: false` denies when the verifier
# is down, and that an immediate_response reaches the client as a JSON-RPC error.
#
# What each phase would catch:
#
#   1  the identity path end to end, INCLUDING the mesh-origin refusal. Phase 1a configures a
#      deliberately wrong origin and expects a refusal; 1b reads the origin Envoy actually
#      connected from out of the verifier's log and restarts with it. A verifier that believed
#      an XFCC header from anywhere would pass 1b and fail 1a.
#   2  a contracted call reaches the upstream and the answer comes back through two proxies.
#   3  an uncontracted call is refused AND THE UPSTREAM NEVER SAW IT. The upstream records every
#      execution, so a refusal that still forwarded fails here rather than looking correct.
#   4  the catalogue is filtered. This is the phase that proves `allow_mode_override` +
#      `mode_override` at ResponseHeaders works against the real filter: without it Envoy never
#      buffers the body, `on_response_body` is never called, and the agent sees both tools.
#   5  gate 8. The upstream is restarted serving a changed surface and the catalogue is refused.
#   6  an unmapped route is refused, so `request_attributes` is doing something.
#   7  the verifier is killed and traffic is DENIED, not allowed. `failure_mode_allow: false`.
#
# Needs docker (for Envoy) and python3. Exit 0 pass · 1 fail · 2 setup.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=${ENVOY_IMAGE:-envoyproxy/envoy:v1.31-latest}
command -v docker >/dev/null || { echo "need docker" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "the docker daemon is not running" >&2; exit 2; }
command -v python3 >/dev/null || { echo "need python3" >&2; exit 2; }
command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }
python3 -c 'import cryptography' 2>/dev/null \
  || { echo "need python cryptography: python3 -m pip install 'cryptography>=42'" >&2; exit 2; }

cargo build --release --workspace --quiet 2>&1 || { echo "workspace does not build" >&2; exit 2; }
cargo build --release --quiet --manifest-path "$REPO/daemon/wc-extproc/Cargo.toml" 2>&1 \
  || { echo "the verifier does not build" >&2; exit 2; }
C="$REPO/target/release/connect"
VERIFY="$REPO/daemon/wc-extproc/target/release/wc-extproc"
[ -x "$C" ] && [ -x "$VERIFY" ] || { echo "missing binaries" >&2; exit 2; }

WORK="$(mktemp -d)"
UP_PORT=8931; GRPC_PORT=9002; ENVOY_PORT=10000

# The ports are fixed because extproc-drill.yaml names them, so a preflight is the only defence
# against a stale process — and the alternative message is "envoy did not start", which is
# equally true of a port conflict, a bad config and a missing mount.
#
# It runs HERE, before this script starts anything. A first version sat just above the
# `docker run` and reported the drill's OWN upstream and verifier as a conflict, because by
# that point it had already bound them. A preflight that fires on itself is worse than none:
# it fails a healthy run and teaches you to skip the check.
for p in "$ENVOY_PORT" "$GRPC_PORT" "$UP_PORT"; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $p is already in use — stop whatever holds it first:" >&2
    lsof -nP -iTCP:"$p" -sTCP:LISTEN 2>/dev/null | tail -n +2 | sed 's/^/  /' >&2
    docker ps --format '  docker: {{.Names}} {{.Ports}}' 2>/dev/null | grep ":$p->" >&2
    exit 2
  fi
done
CID_FILE="$WORK/envoy.cid"
cleanup() {
  [ -f "$CID_FILE" ] && docker rm -f "$(cat "$CID_FILE")" >/dev/null 2>&1
  [ -n "${PLANE_PID:-}" ] && kill "$PLANE_PID" 2>/dev/null
  [ -n "${VERIFY_PID:-}" ] && kill "$VERIFY_PID" 2>/dev/null
  [ -n "${UP_PID:-}" ] && kill "$UP_PID" 2>/dev/null
  wait 2>/dev/null
  if [ -n "${KEEP:-}" ]; then echo "kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
cd "$WORK"
export WARDEN_CONNECT_ROOT="$WORK/root"

CALLEE="spiffe://bank.example/ns/mesh/sa/payments-mcp"
CALLER="spiffe://bank.example/ns/mesh/sa/recon-bot"
MED="warden:mediator:gateway-1"
ISS="https://connect.internal"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  ·    %s\n' "$1"; }
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

bold "Envoy ext_proc drill"
step "work dir  $WORK"
step "envoy     $IMAGE"

# --- the contract -----------------------------------------------------------------
cat > surface.json <<'S'
{"tools":[
  {"name":"get_balance","description":"Read an account balance."},
  {"name":"wire_funds","description":"Move money between accounts."}
]}
S
DIGEST=$("$C" canon surface.json --kind mcp --entity "$CALLEE" | awk '/^manifest/{print $2}')
[ -n "$DIGEST" ] || { echo "could not compute the surface digest" >&2; exit 2; }
BUILDER="https://github.com/bank/payments-mcp/.github/workflows/deploy.yml@refs/heads/main"
python3 "$REPO/scripts/.attest-material.py" "$WORK/material" \
  "$CALLEE" "$MED" "$BUILDER" "$DIGEST" >/dev/null || { echo "material failed" >&2; exit 2; }
M="$WORK/material"
"$C" attest surface --surface surface.json \
  --card-key "card-signer-1=$M/card-signer.priv.pem" --out surface.signed.json >/dev/null 2>&1

cat > connect-policy.toml <<'P'
default = "require_approval"
version = "envoy-drill@v1"
[[zone]]
id = "internal.mesh"
trust = "internal"
[standing]
reviewed_at = 0
[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
decision = "require_approval"
approver_role = "drill.operator"
ttl_max = "7d"
terms = { evidence_sink = "ocsf://siem", evidence_delivery = "fail-safe", max_calls_per_hour = 3, max_concurrent = 2 }
reason = "the drill approves by hand"
P
for k in issuer approver; do
  openssl ecparam -name prime256v1 -genkey -noout -out $k.tmp 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in $k.tmp -out $k.priv.pem 2>/dev/null
  openssl ec -in $k.priv.pem -pubout -out $k.pub.pem 2>/dev/null; rm -f $k.tmp
done
cat > approvers.toml <<'A'
[[approver]]
id = "human:drill@org"
key = "approver.pub.pem"
roles = ["drill.operator"]
A

"$C" register server --id "$CALLEE" --surface surface.signed.json \
  --endpoint "http://127.0.0.1:$UP_PORT/mcp" --owner human:drill@org --zone internal.mesh \
  --by human:drill@org \
  --svid "$M/jwt-svid.token" --trust-key "spiffe-bundle-1=$M/spiffe-bundle.pub.pem" \
  --aud "$MED" \
  --card-key "card-signer-1=$M/card-signer.pub.pem" --require-card-signature \
  --attest "$M/provenance.dsse.json" --prov-key "builder-1=$M/builder.pub.pem" \
  --builder "$BUILDER" --bind-surface > register.log 2>&1
POSTURE=$("$C" show "$CALLEE" 2>/dev/null | awk '/^  posture/{print $2}')
[ "$POSTURE" = "Attested" ] || {
  echo "setup: posture is ${POSTURE:-unknown}, not Attested" >&2
  sed 's/^/  /' register.log | head -15 >&2; exit 2; }

printf '{"name":"recon-bot","description":"Reconciles.","version":"1.0.0","skills":[{"id":"r","name":"r","description":"r"}]}' > card.json
"$C" register agent --card card.json --owner human:drill@org --zone internal.mesh \
  --id "$CALLER" --by human:drill@org >/dev/null 2>&1
"$C" activate "$CALLER" --by human:drill@org >/dev/null 2>&1
"$C" activate "$CALLEE" --by human:drill@org >/dev/null 2>&1

REQ=$("$C" request --from "$CALLER" --to "$CALLEE" --tools get_balance \
  --justify "envoy drill" --ttl 1d --mediator "$MED" \
  --issuer-key issuer.priv.pem --kid issuer-1 --by human:drill@org 2>&1 \
  | grep -oE 'req_[a-f0-9]+' | head -1)
[ -n "$REQ" ] || { echo "setup: no request raised" >&2; exit 2; }
"$C" approve "$REQ" --by human:drill@org --approver-key approver.priv.pem \
  --issuer-key issuer.priv.pem --kid issuer-1 --out . >/dev/null 2>&1
CONTRACT=$(ls ./*.jws 2>/dev/null | head -1)
[ -n "$CONTRACT" ] || { echo "setup: no contract artifact" >&2; exit 2; }
step "contract  get_balance only, of the 2 the callee serves"

# --- mTLS material ------------------------------------------------------------------
# Envoy sets XFCC from a VERIFIED client certificate. Letting the client send its own header
# would test nothing: Envoy sanitizes an inbound XFCC by default, so the verifier would see no
# identity and refuse everything, and the drill would pass its refusal phases for the wrong
# reason. The client cert carries the caller's SPIFFE id as a URI SAN, which is where a real
# mesh puts it.
mkdir -p certs && cd certs

# Every openssl call is checked. They used to end in `2>/dev/null`, so a failure produced an
# empty key, the drill mounted it, and Envoy reported "Failed to load incomplete private key"
# five minutes and one container later — with no hint that generation was where it went wrong.
SSL_LOG="$WORK/openssl.log"
ssl() {
  if ! openssl "$@" >>"$SSL_LOG" 2>&1; then
    echo "setup: openssl $1 failed; see $SSL_LOG" >&2
    tail -5 "$SSL_LOG" >&2
    exit 2
  fi
}

ssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 1 -subj "/CN=wc-drill-ca"
printf '[req]\ndistinguished_name=dn\n[dn]\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > srv.cnf
ssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
ssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt \
  -days 1 -extfile srv.cnf -extensions ext
printf '[req]\ndistinguished_name=dn\n[dn]\n[ext]\nsubjectAltName=URI:%s\n' "$CALLER" > cli.cnf
ssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=recon-bot"
ssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt \
  -days 1 -extfile cli.cnf -extensions ext

# And what was written is checked before anything mounts it. Envoy's "incomplete private key"
# is what an empty or truncated file looks like from inside the container, which is the least
# useful place to find out.
for k in ca.key server.key client.key; do
  [ -s "$k" ] || { echo "setup: $k is empty" >&2; exit 2; }
  openssl pkey -in "$k" -noout >/dev/null 2>&1 \
    || { echo "setup: $k is not a readable private key" >&2; head -1 "$k" >&2; exit 2; }
done
for c in ca.crt server.crt client.crt; do
  [ -s "$c" ] || { echo "setup: $c is empty" >&2; exit 2; }
  openssl x509 -in "$c" -noout >/dev/null 2>&1 \
    || { echo "setup: $c is not a readable certificate" >&2; exit 2; }
done
# Envoy reads these as a non-root user in some images, and a bind mount carries the host mode.
chmod 644 ./*.key ./*.crt
cd ..
openssl x509 -in certs/client.crt -noout -text | grep -q "URI:$CALLER" \
  || { echo "setup: the client certificate does not carry the caller SAN" >&2; exit 2; }
step "mTLS      client cert SAN = $CALLER"

cat > routes.toml <<R
[[route]]
cluster = "payments-mcp"
callee = "$CALLEE"
R

# The issuer key as a published SET, so the verifier runs its rotating trust source. A pinned
# PEM would leave `--jwks-*` untested by anything but unit tests.
"$C" keys add --kid issuer-1 --public issuer.pub.pem --keyring ring.toml >/dev/null 2>&1
"$C" keys jwks --keyring ring.toml --out jwks.json >/dev/null 2>&1
[ -s jwks.json ] || { echo "setup: could not publish the issuer key set" >&2; exit 2; }
step "trust     jwks.json ($(python3 -c 'import json;print(len(json.load(open("jwks.json"))["keys"]))') key)"

cat > tokens.toml <<T
[[client]]
token = "tok_envoy_drill_0123456789"
roles = ["connect.read", "connect.mediator"]
T
cat > mediators.toml <<M
[[mediator]]
id = "$MED"
M

# --- processes --------------------------------------------------------------------
export UPSTREAM_LOG="$WORK/upstream.log"; : > "$UPSTREAM_LOG"
start_upstream() {
  [ -n "${UP_PID:-}" ] && { kill "$UP_PID" 2>/dev/null; wait "$UP_PID" 2>/dev/null; }
  env UPSTREAM_LOG="$UPSTREAM_LOG" ${1:-} python3 "$REPO/scripts/envoy/.mcp-upstream.py" \
    "$UP_PORT" >upstream.err 2>&1 &
  UP_PID=$!
  for _ in $(seq 1 40); do
    curl -sf -o /dev/null -X POST "http://127.0.0.1:$UP_PORT/mcp" \
      -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}' && return 0
    sleep 0.25
  done
  echo "the upstream did not start" >&2; return 1
}
API_PORT=8841
start_plane() {
  [ -n "${PLANE_PID:-}" ] && { kill "$PLANE_PID" 2>/dev/null; wait "$PLANE_PID" 2>/dev/null; }
  "$C" serve --listen "127.0.0.1:$API_PORT" --issuer-key issuer.priv.pem --kid issuer-1 \
    --tokens tokens.toml --approvers approvers.toml >>serve.log 2>&1 &
  PLANE_PID=$!
  for _ in $(seq 1 80); do
    curl -sf -o /dev/null "http://127.0.0.1:$API_PORT/healthz" && return 0
    sleep 0.25
  done
  echo "the control plane did not start" >&2; tail -5 serve.log >&2; return 1
}

start_verifier() {   # $1 = mesh origin
  [ -n "${VERIFY_PID:-}" ] && { kill "$VERIFY_PID" 2>/dev/null; wait "$VERIFY_PID" 2>/dev/null; }
  : > verify.log
  "$VERIFY" --listen "0.0.0.0:$GRPC_PORT" --routes routes.toml \
    --mediator-id "$MED" --issuer-id "$ISS" \
    --jwks-file jwks.json \
    --contract "$CONTRACT" --mesh-origin "$1" \
    --contracts "http://127.0.0.1:$API_PORT" --token tok_envoy_drill_0123456789 \
    --refresh 2 --max-stale 3600 >>verify.log 2>&1 &
  VERIFY_PID=$!
  for _ in $(seq 1 40); do
    grep -q "serving ext_proc" verify.log && return 0
    sleep 0.25
  done
  echo "the verifier did not start" >&2; sed 's/^/  /' verify.log >&2; return 1
}
# No XFCC is sent: Envoy derives it from the client certificate. A header sent here would be
# sanitized away, which is the behaviour that makes mTLS the only honest way to drill this.
call() {   # $1 = json body; prints the response
  curl -s --max-time 10 -X POST "https://localhost:$ENVOY_PORT/mcp" \
    --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt \
    -H 'content-type: application/json' -d "$1"
}

start_upstream || exit 2
start_plane || exit 2
start_verifier "203.0.113.9" || exit 2   # deliberately wrong, for phase 1a

docker rm -f wc-envoy-drill >/dev/null 2>&1
# --add-host is what makes `host.docker.internal` resolve on Linux; Docker Desktop provides it
# already and the flag is harmless there. Without it Envoy cannot reach the verifier OR the
# upstream, every phase that expects a specific refusal code gets a transport error instead, and
# "with the verifier down, traffic is denied" passes trivially because that is the state all the
# way through. The drill passed on macOS and failed nine phases on a Linux runner.
docker run -d --cidfile "$CID_FILE" --name wc-envoy-drill \
  --add-host=host.docker.internal:host-gateway \
  -p "$ENVOY_PORT:$ENVOY_PORT" \
  -v "$REPO/scripts/envoy/extproc-drill.yaml:/etc/envoy/envoy.yaml:ro" \
  -v "$WORK/certs:/certs:ro" \
  "$IMAGE" -c /etc/envoy/envoy.yaml --log-level warning >"$WORK/envoy-run.log" 2>&1 \
  || { echo "envoy did not start:" >&2; cat "$WORK/envoy-run.log" >&2; exit 2; }
# `docker run -d` reports success once the container is CREATED, so a container whose Envoy
# exits on a bad config still returns 0 and the "envoy did not start" branch above never fires.
# The old readiness loop then ran out its 60 tries and printed "listening on 10000" regardless,
# and every phase after it tested an empty response. A drill that proceeds against nothing
# reports failures about a proxy that was never there.
ENVOY_UP=""
for _ in $(seq 1 60); do
  if ! docker ps -q --no-trunc | grep -q "$(cat "$CID_FILE")"; then
    echo "envoy exited during startup:" >&2
    docker logs "$(cat "$CID_FILE")" 2>&1 | tail -20 >&2
    exit 2
  fi
  # WITH the client certificate. The listener sets `require_client_certificate: true`, so a
  # bare `curl -sk` could never complete a handshake — this probe had failed every time since
  # it was written, and nobody noticed because the loop's result was thrown away and the drill
  # printed "listening" regardless. Making the gate authoritative is what exposed it.
  if curl -s -o /dev/null --max-time 2 "https://localhost:$ENVOY_PORT/mcp" \
       --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt; then
    ENVOY_UP=1; break
  fi
  sleep 0.5
done
if [ -z "$ENVOY_UP" ]; then
  echo "envoy is running but never answered on $ENVOY_PORT after 30s:" >&2
  docker logs "$(cat "$CID_FILE")" 2>&1 | tail -20 >&2
  exit 2
fi
step "envoy     listening on $ENVOY_PORT"

# --- 1 · identity, both directions ------------------------------------------------
OUT=$(call '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance","arguments":{}}}')
if printf '%s' "$OUT" | grep -q "WC-4001"; then
  ok "1a · XFCC from an origin the operator did not configure is refused"
else
  bad "1a · a wrong mesh origin was accepted"
  printf '%s\n' "$OUT" | sed 's/^/       /' | head -2
fi

ORIGIN=$(grep -oE 'not established from tcp:[0-9.]+' verify.log | head -1 | sed 's/.*tcp://')
if [ -z "$ORIGIN" ]; then
  bad "1b · the verifier did not report the origin it refused; cannot continue"
  echo "REPORT: this is the diagnostic the log line exists for" >&2
  sed 's/^/       /' verify.log | tail -5
else
  step "envoy connects from $ORIGIN"
  start_verifier "$ORIGIN" || exit 2

  # A tool call BEFORE any catalogue has passed. Gate 8 has nothing to compare against on such
  # a stream, so it is refused — and the code has to be the unpinned one, not WC-4001: the
  # difference proves identity resolved and the PIN gate is what stopped it.
  OUT=$(call '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance","arguments":{}}}')
  if printf '%s' "$OUT" | grep -q "WC-1002"; then
    ok "1b · a tool call before any catalogue is refused: the pin is unverified"
  elif printf '%s' "$OUT" | grep -q "executed get_balance"; then
    bad "1b · an UNPINNED tool call was admitted — the callee's surface was never checked"
  else
    bad "1b · refused for the wrong reason (expected WC-1002)"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -2
  fi

  # The catalogue: identity, the contract, mode_override AND the pin, in one request. This is
  # the first thing any client following the MCP lifecycle does.
  OUT=$(call '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
  SEEN=$(printf '%s' "$OUT" | python3 -c '
import json,sys
try:
    print(",".join(sorted(t["name"] for t in json.load(sys.stdin)["result"]["tools"])))
except Exception:
    print("<unparsed>")' 2>/dev/null)
  if [ "$SEEN" = "get_balance" ]; then
    ok "1c · tools/list filtered to the contracted tool — mode_override is honoured, pin verified"
  elif [ "$SEEN" = "get_balance,wire_funds" ]; then
    bad "1c · the catalogue came through UNFILTERED: Envoy never buffered the response body."
    echo "       allow_mode_override, or the mode_override at ResponseHeaders, is not working." >&2
  else
    bad "1c · unexpected catalogue: $SEEN"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -2
  fi

  OUT=$(call '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_balance","arguments":{}}}')
  if printf '%s' "$OUT" | grep -q "executed get_balance"; then
    ok "1d · once pinned, the contracted call executes"
  else
    bad "1d · the contracted call was refused after the pin was verified"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -2
    grep -E "WC-|refus" verify.log | tail -3 | sed 's/^/       /'
  fi
fi

# --- 2 and 3 · the ceiling, and whether it actually stopped the traffic ------------
: > "$UPSTREAM_LOG"
OUT=$(call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wire_funds","arguments":{"amount":9999}}}')
if printf '%s' "$OUT" | grep -q "WC-4002"; then
  ok "2 · an uncontracted tool is refused through Envoy"
else
  bad "2 · the uncontracted tool was NOT refused"
  printf '%s\n' "$OUT" | sed 's/^/       /' | head -2
fi
if grep -q "EXECUTED wire_funds" "$UPSTREAM_LOG"; then
  bad "3 · the upstream EXECUTED it anyway — the refusal did not stop the request"
else
  ok "3 · the upstream never saw it: no request left Envoy for a denied call"
fi

# --- 5 · gate 8 ------------------------------------------------------------------
start_upstream UPSTREAM_DRIFT=1 || exit 2
OUT=$(call '{"jsonrpc":"2.0","id":4,"method":"tools/list"}')
if printf '%s' "$OUT" | grep -q "WC-3108"; then
  ok "5 · a surface that moved since the pin is refused (gate 8)"
else
  bad "5 · a drifted surface was served"
  printf '%s\n' "$OUT" | sed 's/^/       /' | head -2
fi
# Drift detected must REVOKE the earlier verification, not merely refuse that one catalogue.
# Otherwise tool calls keep flowing on a contract whose callee has demonstrably moved.
OUT=$(call '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_balance","arguments":{}}}')
if printf '%s' "$OUT" | grep -q "WC-1002"; then
  ok "5b · the detected drift revoked the pin: tool calls are refused until it matches again"
elif printf '%s' "$OUT" | grep -q "executed get_balance"; then
  bad "5b · tool calls still flow after drift was detected — the stale verification survived"
else
  bad "5b · refused for the wrong reason after drift"
  printf '%s\n' "$OUT" | sed 's/^/       /' | head -2
fi

start_upstream || exit 2
# Re-pin against the restored surface, so the phases below start from a known state.
call '{"jsonrpc":"2.0","id":6,"method":"tools/list"}' >/dev/null

# --- 6 · an unmapped route -------------------------------------------------------
# The route table maps only `payments-mcp`. Envoy's second route sends /other to a cluster
# nothing maps, so the attribute arrives and matches nothing.
OUT=$(curl -s --max-time 10 -X POST "https://localhost:$ENVOY_PORT/other" \
  --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_balance","arguments":{}}}')
if printf '%s' "$OUT" | grep -qE "WC-4001|WC-400"; then
  ok "6 · a route the table does not map is refused"
else
  bad "6 · an unmapped route was allowed through"
  printf '%s\n' "$OUT" | sed 's/^/       /' | head -2
fi

# --- 7 · the verifier is down ----------------------------------------------------
kill "$VERIFY_PID" 2>/dev/null; wait "$VERIFY_PID" 2>/dev/null; VERIFY_PID=""
: > "$UPSTREAM_LOG"
OUT=$(call '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_balance","arguments":{}}}')
if grep -q "EXECUTED get_balance" "$UPSTREAM_LOG"; then
  bad "7 · with the verifier DOWN the call was forwarded — failure_mode_allow is not false"
else
  ok "7 · with the verifier down, traffic is denied rather than allowed"
fi

# --- 8 · the verifier appears to the deploy gate ---------------------------------
start_verifier "$ORIGIN" >/dev/null 2>&1
sleep 5   # two refresh intervals, so at least one ack has been sent
if grep -qE "refresh failed|not refreshing" verify.log; then
  bad "8 · the verifier could not pull from the control plane"
  grep -E "refresh failed|not refreshing" verify.log | tail -2 | sed 's/^/       /'
else
  # Not "did the command return something" — that is true whether or not this verifier ever
  # spoke. The assertion is that THIS mediator id appears with a non-zero acked sequence and
  # is caught up, which is only possible if the ack actually arrived.
  GATE=$("$C" distribution --mediators mediators.toml --json 2>/dev/null \
    | python3 -c '
import json,sys
d = json.load(sys.stdin)
m = next((x for x in d.get("mediators", []) if x.get("mediator") == sys.argv[1]), None)
if m is None:
    print("absent")
elif not m.get("caught_up") or not m.get("acked_seq"):
    print("stale acked_seq=%s caught_up=%s" % (m.get("acked_seq"), m.get("caught_up")))
else:
    print("ok seq=%s" % m["acked_seq"])' "$MED" 2>/dev/null)
  case "${GATE:-absent}" in
    ok*) ok "8 · the verifier acks as a mediator: \`connect distribution\` sees it, $GATE" ;;
    absent) bad "8 · the verifier never appeared in connect distribution at all" ;;
    *) bad "8 · the verifier appears but has not caught up: $GATE" ;;
  esac
fi

# --- 9 · the rate ceiling, through Envoy ----------------------------------------
# The policy rule caps this contract at 3 calls/hour and phase 1b already spent one. Rather
# than count exactly — brittle if a phase above changes — call until a refusal arrives and
# assert both that it arrives AND that at least one call succeeded first. A ceiling that
# refused everything from the start would pass a refusal-only check.
# The verifier was restarted in phase 8 and the pin ledger is IN MEMORY, so nothing is
# verified again. That is fail-closed and self-healing — the first client to list tools
# restores it — but it does mean the first tool call after any restart is refused. Worth
# knowing before someone reads it as an outage.
call '{"jsonrpc":"2.0","id":8,"method":"tools/list"}' >/dev/null
allowed=0; refused=""
for _ in $(seq 1 8); do
  R=$(call '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"get_balance","arguments":{}}}')
  if printf '%s' "$R" | grep -q "executed get_balance"; then
    allowed=$((allowed + 1))
  elif printf '%s' "$R" | grep -q "WC-4003"; then
    refused="yes"; break
  else
    refused="other"; printf '%s\n' "$R" | sed 's/^/       /' | head -1; break
  fi
done
if [ "$refused" = "yes" ] && [ "$allowed" -ge 1 ]; then
  ok "9 · the rate ceiling holds across separate streams ($allowed allowed, then WC-4003)"
elif [ "$refused" = "yes" ]; then
  bad "9 · the ceiling refused every call, including the first"
elif [ -z "$refused" ]; then
  bad "9 · 8 calls admitted against a ceiling of 3 — the ceiling counts nothing across streams"
else
  bad "9 · the ceiling phase ended on an unexpected refusal"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "DRILL PASSED — enforcement holds through a real Envoy: identity, the surface"
  echo "ceiling, the catalogue filter, gate 8, route mapping, and fail-closed."
  exit 0
fi
echo "DRILL FAILED"
exit 1
