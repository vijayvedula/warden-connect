#!/usr/bin/env bash
# The HTTP-mode drill: mediate a REMOTE MCP server over Streamable HTTP, in ENFORCE mode.
#
#     scripts/http-mode-drill.sh
#
# The stdio path is drilled by attest-drill.sh. This one exists because "the transport does not
# change what is enforced" is a claim, and a claim about a control is worth nothing until the
# control has been watched refusing something over that transport. The same contract, the same
# gates, the same pin — reached over HTTP, and over HTTP with an SSE response body.
#
# What each phase would catch:
#
#   1  the contract, over HTTP with a JSON response. If the pin were computed from the stdio
#      handshake only, or the HTTP client mangled the frame, a contracted call would be refused.
#   2  the surface ceiling still holds over HTTP. `WC-4002` is `Closed`, so a green phase 1 with
#      a red phase 2 is the shape of "the transport bypassed the gates".
#   3  the same two over `text/event-stream`, where the result arrives behind a comment, a
#      progress notification and a split `data:` payload. A parser that takes the first frame
#      reports the notification as the answer and this phase fails.
#   4  the session id is echoed. The upstream refuses any post-initialize request that does not
#      carry it back, so a mediator that dropped the id would fail every call — untestable
#      otherwise, and therefore effectively unimplemented.
#   5  a header passed with --upstream-header actually reaches the server.
#   6  plaintext http to a non-loopback host is REFUSED, and both upstreams together is refused.
#      Configuration checks that only log are the recurring failure in this codebase.
#
# Exit 0 the HTTP path enforces · 1 it does not · 2 setup.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
command -v python3 >/dev/null || { echo "need python3" >&2; exit 2; }
command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }
command -v curl >/dev/null || { echo "need curl" >&2; exit 2; }

# Ask cargo rather than compare mtimes: `cargo fmt` bumps mtimes without changing content, so an
# mtime guard can never clear. A no-op build costs nothing and cannot run a stale binary.
if ! cargo build --release --workspace --quiet 2>&1; then
    echo "the workspace does not build; the drill would be testing nothing" >&2
    exit 2
fi
CONNECT="$REPO/target/release/connect"
MEDIATE="$REPO/target/release/connect-mediate"
[ -x "$CONNECT" ] || CONNECT="$REPO/target/debug/connect"
[ -x "$MEDIATE" ] || MEDIATE="$REPO/target/debug/connect-mediate"
for b in "$CONNECT" "$MEDIATE"; do
    [ -x "$b" ] || { echo "no $b after a successful build" >&2; exit 2; }
done

WORK="$(mktemp -d)"
cleanup() {
    [ -n "${HTTP_PID:-}" ] && kill "$HTTP_PID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"
export WARDEN_CONNECT_ROOT="$WORK/root"

CALLEE="spiffe://drill.example/ns/svc/sa/payments-mcp"
CALLER="spiffe://drill.example/ns/agents/sa/recon-bot"
MEDIATOR_ID="warden:mediator:http-drill"
ISSUER_ID="https://connect.internal"
export UPSTREAM_TOOLS="get_balance=Read an account balance.|transfer_funds=Move money between accounts."

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

bold "HTTP-mode drill"
step "work dir  $WORK"

# --- setup: a contract over the same surface the upstream declares -----------
cat > surface.json <<'SURFACE'
{"tools":[
  {"name":"get_balance","description":"Read an account balance."},
  {"name":"transfer_funds","description":"Move money between accounts."}
]}
SURFACE
printf '{"name":"recon-bot","description":"Reconciles.","version":"1.0.0","skills":[{"id":"reconcile","name":"reconcile","description":"Reconcile."}]}' > card.json

cat > connect-policy.toml <<'POLICY'
default = "require_approval"
version = "http-drill@v1"

[[zone]]
id = "internal.payments"
trust = "internal"

[[zone]]
id = "internal.recon"
trust = "internal"

[standing]
reviewed_at = 0

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
decision = "require_approval"
approver_role = "drill.operator"
ttl_max = "7d"
terms = { evidence_sink = "ocsf://siem", evidence_delivery = "fail-safe" }
reason = "the drill approves by hand"
POLICY

for k in issuer approver; do
    openssl ecparam -name prime256v1 -genkey -noout -out "$k.tmp" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt -in "$k.tmp" -out "$k.priv.pem" 2>/dev/null
    openssl ec -in "$k.priv.pem" -pubout -out "$k.pub.pem" 2>/dev/null
    rm -f "$k.tmp"
done
cat > approvers.toml <<'APPROVERS'
[[approver]]
id = "human:drill@org"
key = "approver.pub.pem"
roles = ["drill.operator"]
APPROVERS

# Attestation is the stdio drill's subject, not this one's; `--observe` is NOT an option here
# because it softens an absent contract and would pass the very phases under test. So the callee
# is taken to Attested with the same material generator attest-drill.sh uses.
SURFACE_DIGEST=$("$CONNECT" canon surface.json --kind mcp --entity "$CALLEE" 2>/dev/null \
    | awk '/^manifest/ {print $2}')
[ -n "$SURFACE_DIGEST" ] || { echo "could not compute the surface digest" >&2; exit 2; }
BUILDER="https://drill.example/ci/builder@v1"
python3 "$REPO/scripts/.attest-material.py" "$WORK/material" \
    "$CALLEE" "$MEDIATOR_ID" "$BUILDER" "$SURFACE_DIGEST" >/dev/null \
    || { echo "could not mint attestation material" >&2; exit 2; }
M="$WORK/material"
"$CONNECT" attest surface --surface surface.json \
    --card-key "card-signer-1=$M/card-signer.priv.pem" \
    --out surface.signed.json >/dev/null 2>&1 \
    || { echo "connect attest surface failed" >&2; exit 2; }

"$CONNECT" register server --id "$CALLEE" --surface surface.signed.json \
    --endpoint stdio://drill --owner human:drill@org --zone internal.payments \
    --by human:drill@org \
    --svid "$M/jwt-svid.token" \
    --trust-key "spiffe-bundle-1=$M/spiffe-bundle.pub.pem" \
    --aud "$MEDIATOR_ID" \
    --card-key "card-signer-1=$M/card-signer.pub.pem" --require-card-signature \
    --attest "$M/provenance.dsse.json" \
    --prov-key "builder-1=$M/builder.pub.pem" \
    --builder "$BUILDER" \
    --bind-surface > register.log 2>&1
POSTURE=$("$CONNECT" show "$CALLEE" 2>/dev/null | awk '/^  posture/ {print $2}')
if [ "$POSTURE" != "Attested" ]; then
    echo "setup: posture is ${POSTURE:-unknown}, not Attested — enforce mode would deny" >&2
    sed 's/^/  /' register.log | head -20 >&2
    exit 2
fi

"$CONNECT" register agent --card card.json --owner human:drill@org \
    --zone internal.recon --id "$CALLER" --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$CALLER" --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$CALLEE" --by human:drill@org >/dev/null 2>&1

REQ=$("$CONNECT" request --from "$CALLER" --to "$CALLEE" --tools get_balance \
    --justify "http mode drill" --ttl 1d --mediator "$MEDIATOR_ID" \
    --issuer-key issuer.priv.pem --kid issuer-1 --by human:drill@org 2>&1 \
    | grep -oE 'req_[a-f0-9]+' | head -1)
[ -n "$REQ" ] || { echo "setup: no contract request was raised" >&2; exit 2; }
"$CONNECT" approve "$REQ" --by human:drill@org --approver-key approver.priv.pem \
    --issuer-key issuer.priv.pem --kid issuer-1 --out . >/dev/null 2>&1
CONTRACT=$(ls ./*.jws 2>/dev/null | head -1)
[ -n "$CONTRACT" ] || { echo "setup: no contract artifact was written" >&2; exit 2; }
step "contract  $(basename "$CONTRACT") · surface pinned to $SURFACE_DIGEST"

# --- the upstream, on an ephemeral port -------------------------------------
start_upstream() {
    [ -n "${HTTP_PID:-}" ] && { kill "$HTTP_PID" 2>/dev/null; wait "$HTTP_PID" 2>/dev/null; }
    rm -f port.txt
    env "$@" python3 "$REPO/scripts/.http-upstream.py" "$WORK/port.txt" >upstream.log 2>&1 &
    HTTP_PID=$!
    for _ in $(seq 1 80); do
        [ -s port.txt ] && { PORT=$(cat port.txt); URL="http://127.0.0.1:$PORT/mcp"; return 0; }
        sleep 0.25
    done
    echo "the HTTP upstream did not start" >&2; sed 's/^/  /' upstream.log >&2; return 1
}

# One mediator run over HTTP. $1 is the tool to call.
mediate() {
    printf '%s\n%s\n' \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"http-drill","version":"1"}}}' \
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":{}}}" \
        | "$MEDIATE" --upstream-url "$URL" \
            --mediator-id "$MEDIATOR_ID" --issuer-id "$ISSUER_ID" \
            --caller "$CALLER" --callee "$CALLEE" \
            --issuer-pub issuer.pub.pem --kid issuer-1 \
            --contract "$CONTRACT" "${EXTRA:-}" 2>mediate.log
}

# --- 1 and 2 · JSON responses ----------------------------------------------
EXTRA=""
start_upstream UPSTREAM_SSE=0 || exit 2
step "upstream  $URL (application/json)"

OUT=$(mediate get_balance)
if printf '%s' "$OUT" | grep -q "executed get_balance"; then
    ok "1 · a contracted call EXECUTED over HTTP in enforce mode"
else
    bad "1 · the contracted call was refused over HTTP"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -4
    sed 's/^/       /' mediate.log | head -12
fi

OUT=$(mediate transfer_funds)
if printf '%s' "$OUT" | grep -q "WC-4002\|not in the contracted surface"; then
    ok "2 · an uncontracted tool is refused over HTTP (the surface is still a ceiling)"
else
    bad "2 · an uncontracted tool was NOT refused on the surface — see the code below"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -3
fi

# --- 3 · the same, with an SSE response body -------------------------------
start_upstream UPSTREAM_SSE=1 || exit 2
step "upstream  $URL (text/event-stream)"

OUT=$(mediate get_balance)
if printf '%s' "$OUT" | grep -q "executed get_balance"; then
    ok "3 · a contracted call EXECUTED with an SSE response body"
else
    bad "3 · the SSE response was not parsed — the result sits behind a notification"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -4
    sed 's/^/       /' mediate.log | head -12
fi

OUT=$(mediate transfer_funds)
if printf '%s' "$OUT" | grep -q "WC-4002\|not in the contracted surface"; then
    ok "     an uncontracted tool is refused over SSE too"
else
    bad "     an uncontracted tool was NOT refused over SSE"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -3
fi

# --- 4 · the session id is echoed -----------------------------------------
start_upstream UPSTREAM_SSE=0 UPSTREAM_STRICT_SESSION=1 || exit 2
OUT=$(mediate get_balance)
if printf '%s' "$OUT" | grep -q "executed get_balance"; then
    ok "4 · Mcp-Session-Id from initialize is echoed on later requests"
elif printf '%s' "$OUT" | grep -q "was not echoed" \
    || grep -q "was not echoed" mediate.log 2>/dev/null \
    || printf '%s' "$OUT" | grep -q "WC-1002"; then
    # WC-1002 is the second face of the same fault: initialize succeeds, tools/list is rejected
    # for the missing id, and the mediator reports the catalogue as unobtainable. Both readings
    # are named here because the first sabotage run of this drill produced the WC-1002 one, and
    # a phase that only recognised the literal message sent the reader hunting the pin instead.
    bad "4 · the session id was NOT echoed; a stateful server rejects every call after initialize"
else
    bad "4 · the strict-session upstream refused for another reason"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -3
fi

# --- 5 · a configured header reaches the server ---------------------------
start_upstream UPSTREAM_SSE=0 || exit 2
printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"http-drill","version":"1"}}}' \
    | "$MEDIATE" --upstream-url "$URL" \
        --mediator-id "$MEDIATOR_ID" --issuer-id "$ISSUER_ID" \
        --caller "$CALLER" --callee "$CALLEE" \
        --issuer-pub issuer.pub.pem --kid issuer-1 \
        --contract "$CONTRACT" \
        --upstream-header "Authorization: Bearer drill-token:9443" >/dev/null 2>&1
if curl -sf "http://127.0.0.1:$PORT/headers" \
    | grep -q "Bearer drill-token:9443"; then
    ok "5 · --upstream-header reaches the server, colons in the value intact"
else
    bad "5 · --upstream-header did not reach the server"
    curl -s "http://127.0.0.1:$PORT/headers" | sed 's/^/       /' | head -3
fi

# --- 6 · the configuration refusals ---------------------------------------
refusal() {
    "$MEDIATE" --mediator-id "$MEDIATOR_ID" --issuer-id "$ISSUER_ID" \
        --caller "$CALLER" --callee "$CALLEE" \
        --issuer-pub issuer.pub.pem --kid issuer-1 \
        --contract "$CONTRACT" "$@" </dev/null 2>&1
}
OUT=$(refusal --upstream-url "http://mcp.corp.example/rpc")
if printf '%s' "$OUT" | grep -q "refusing plaintext"; then
    ok "6 · plaintext http:// to a non-loopback host is refused"
else
    bad "6 · plaintext http:// off-host was ACCEPTED — calls would cross the network in the clear"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -3
fi
OUT=$(refusal --upstream-url "http://127.0.0.1:1/mcp" --upstream "python3 -c pass")
if printf '%s' "$OUT" | grep -q "mutually exclusive"; then
    ok "     --upstream with --upstream-url is refused, not resolved by precedence"
else
    bad "     two upstreams were accepted; one of them was silently ignored"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -3
fi
OUT=$(refusal)
if printf '%s' "$OUT" | grep -q "upstream-url is required\|--upstream or"; then
    ok "     neither upstream flag is refused at startup"
else
    bad "     the mediator started with no upstream at all"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -3
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "DRILL PASSED — the contract, the pin and the surface ceiling hold over"
    echo "Streamable HTTP and over SSE, with the same gates as the stdio path."
    exit 0
fi
echo "DRILL FAILED"
exit 1
