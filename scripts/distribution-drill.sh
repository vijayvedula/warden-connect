#!/usr/bin/env bash
# The distribution drill: the deploy gate, and acks that survive a restart.
#
#     scripts/distribution-drill.sh            # override with API_PORT=…
#
# ## Why this exists
#
# `docs/limitations.md` recorded that contract-set acknowledgements lived in
# `api::ControlPlane.acks`, a `Mutex<HashMap<..>>` built with `HashMap::new()` and **never loaded
# or saved**. Two consequences, and the second is the nastier one:
#
#   * a provider's pipeline could not gate its deploy on distribution having completed, which is
#     the ordering the whole breaking-change upgrade path depends on — publish, re-mint, ACK,
#     *then* deploy;
#   * a control-plane restart zeroed the state, so a gate built naively on it would block every
#     deploy until every mediator happened to refresh.
#
# There was also a wrong claim made out loud, which is why this drill asserts the ledger rather
# than describing it: the architecture notes for the contract plane proposed
# `wc_mediator_unconfirmed` as the deploy gate. That is the *containment* metric, keyed by
# revocation feed sequence. It cannot answer whether a newly minted contract has arrived, and a
# mediator with no outstanding revocations reads as fully confirmed while holding an hour-old set.
#
# ## What it proves
#
#   1  before any mediator has run, the gate REFUSES — exit 1, so `set -e` stops a pipeline;
#   2  a mediator that pulls and acks moves the gate to pass;
#   3  the ack is on DISK, and survives the control plane being killed and restarted — which is
#      the half that makes a gate usable rather than a source of spurious blocks;
#   4  a write advances the log, and the gate refuses again until the mediator polls — the race a
#      pipeline is trying not to lose;
#   5  `--wait` blocks and then passes when the mediator catches up, rather than failing fast;
#   6  a gate with NO mediators configured refuses rather than passing vacuously;
#   7  `serve --read-only` distributes while a PIPELINE holds the writer lock, and refuses state
#      mutations with a message naming the mode — the shape a pipeline-driven estate needs.
#
# Phase 3 and phase 6 are the point. Everything else would have worked before.
#
# ## What it does not prove
#
# * **That the contract works**, only that the set was installed. A mediator installs what
#   verifies and reports the rest; `--require-clean` is the stricter question and is asserted in
#   `dist.rs`'s unit tests rather than here.
# * Nothing about how long distribution takes under load. That is a `docs/proving-ground.md`
#   item and it needs the cluster.
#
# Requires: cargo (built binaries), python3, openssl, curl.
# Exit 0 the gate works · 1 it does not · 2 setup.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
API_PORT=${API_PORT:-8843}
command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }
command -v curl >/dev/null || { echo "need curl" >&2; exit 2; }
if ! cargo build --release --workspace --quiet 2>&1; then
    echo "the workspace does not build; the drill would be testing nothing" >&2
    exit 2
fi
CONNECT="$REPO/target/release/connect"
MEDIATE="$REPO/target/release/connect-mediate"

# A port already answering means somebody else's process, and adopting it is how a leak stays
# invisible. Refuse instead.
if curl -sf -o /dev/null -m 2 "http://127.0.0.1:$API_PORT/healthz" 2>/dev/null; then
    echo "port $API_PORT is already answering; a stale drill is probably still running." >&2
    echo "  pkill -f 'connect serve --listen 127.0.0.1:$API_PORT'  or re-run with API_PORT=…" >&2
    exit 2
fi

WORK="$(mktemp -d)"
SERVE_PID=""
cleanup() {
    [ -n "$SERVE_PID" ] && kill "$SERVE_PID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"
export WARDEN_CONNECT_ROOT="$WORK/root"

AGENT="spiffe://drill.example/ns/agents/sa/recon-bot"
SERVER="spiffe://drill.example/ns/svc/sa/payments-mcp"
MEDIATOR_ID="warden:mediator:dist-drill"
ISSUER_ID="https://connect.internal"
TOKEN="drill-token-0000000000000000"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

bold "distribution drill"
step "work dir  $WORK"
step "api       127.0.0.1:$API_PORT"

# --- the estate ---------------------------------------------------------------
cat > connect-policy.toml <<'POLICY'
default = "allow"
version = "dist-drill@v1"

[[zone]]
id = "internal.drill"
trust = "internal"

[standing]
reviewed_at = 0

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
decision = "allow"
ttl_max = "7d"
terms = { evidence_sink = "ocsf://siem", evidence_delivery = "fail-safe" }
reason = "the gate is under test here, not policy"
POLICY

cat > tokens.toml <<TOKENS
[[client]]
token = "$TOKEN"
roles = ["connect.read", "connect.mediator", "connect.secops", "connect.request", "connect.approve"]
TOKENS

cat > mediators.toml <<MEDIATORS
[[mediator]]
id = "$MEDIATOR_ID"
poll_interval = 5
MEDIATORS

printf '{"tools":[{"name":"get_balance","description":"Read an account balance."},{"name":"list_transactions","description":"List recent transactions."}]}' > surface.json
printf '{"name":"recon","description":"The drill consumer.","version":"1.0.0","skills":[{"id":"drive","name":"drive","description":"Drives the drill."}]}' > card.json

openssl ecparam -name prime256v1 -genkey -noout -out issuer.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in issuer.tmp -out issuer.pem 2>/dev/null
openssl ec -in issuer.pem -pubout -out issuer.pub.pem 2>/dev/null
rm -f issuer.tmp
openssl ecparam -name prime256v1 -genkey -noout -out ap.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in ap.tmp -out approver.priv.pem 2>/dev/null
openssl ec -in approver.priv.pem -pubout -out approver.pub.pem 2>/dev/null
rm -f ap.tmp
cat > approvers.toml <<'APPROVERS'
[[approver]]
id = "human:drill@org"
key = "approver.pub.pem"
roles = ["drill.operator"]
APPROVERS

"$CONNECT" register agent --card card.json --owner human:drill@org --zone internal.drill \
    --id "$AGENT" --by human:drill@org >/dev/null 2>&1
"$CONNECT" register server --id "$SERVER" --surface surface.json --endpoint stdio://drill \
    --owner human:drill@org --zone internal.drill --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$AGENT" --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$SERVER" --by human:drill@org >/dev/null 2>&1

mint() {  # mint <tool>
    REQ="$("$CONNECT" request --from "$AGENT" --to "$SERVER" --tools "$1" \
        --justify "the distribution drill needs a contract to distribute" --ttl 1d \
        --mediator "$MEDIATOR_ID" --issuer-key issuer.pem --kid k1 --by human:drill@org 2>&1 \
        | grep -oE 'req_[a-f0-9]+' | head -1)"
    if [ -n "$REQ" ]; then
        "$CONNECT" approve "$REQ" --by human:drill@org --approver-key approver.priv.pem \
            --approvers approvers.toml --issuer-key issuer.pem --kid k1 >/dev/null 2>&1
    fi
}
serve_up() {
    "$CONNECT" serve --listen "127.0.0.1:$API_PORT" --issuer-key issuer.pem --kid k1 \
        --tokens tokens.toml --approvers approvers.toml >> serve.log 2>&1 &
    SERVE_PID=$!
    for _ in $(seq 1 80); do
        curl -sf -o /dev/null "http://127.0.0.1:$API_PORT/healthz" && return 0
        sleep 0.25
    done
    echo "the control plane did not start:" >&2; tail -5 serve.log >&2; return 1
}
# Run one mediator long enough to pull, ack and exit. `--refresh` is the loop interval; the first
# refresh is a startup gate, so a single initialize is enough to have pulled and acked.
mediate_once() {
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"dist-drill","version":"1"}}}' \
        | "$MEDIATE" --upstream "python3 $REPO/scripts/.rotation-upstream.py" \
            --mediator-id "$MEDIATOR_ID" --issuer-id "$ISSUER_ID" \
            --caller "$AGENT" --callee "$SERVER" \
            --issuer-pub issuer.pub.pem --kid k1 \
            --contracts "http://127.0.0.1:$API_PORT" --token "$TOKEN" \
            --observe >> mediate.log 2>&1
}
gate() { "$CONNECT" distribution --mediators mediators.toml "$@" 2>&1; }
# stdout only. `gate` merges stderr so a failure is legible, and `distribution` exits non-zero
# with a message when it refuses — which lands after the JSON and makes it unparseable.
gate_seq() {
    "$CONNECT" distribution --mediators mediators.toml --json 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_seq"])'
}

mint get_balance
serve_up || exit 2
step "serving   pid $SERVE_PID"

# --- 1 · the gate refuses before anything has acked ---------------------------
bold "1 · nothing has acked yet"
OUT="$(gate)"; RC=$?
if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q "NEVER ACKED"; then
    ok "refused with exit $RC, and says which mediator has never acked"
else
    bad "the gate passed before any mediator had confirmed anything (exit $RC)"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -6
fi

# --- 2 · a mediator pulls and acks -------------------------------------------
bold "2 · one mediator pulls"
mediate_once
OUT="$(gate)"; RC=$?
if [ "$RC" -eq 0 ]; then
    ok "the gate passes: $(printf '%s' "$OUT" | sed -n '2p' | sed 's/^  //')"
else
    bad "the gate still refuses after the mediator acked (exit $RC)"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -8
    tail -4 mediate.log | sed 's/^/       /'
fi

# --- 3 · the ack is on disk and survives a restart ---------------------------
bold "3 · the control plane is killed and restarted"
LEDGER="$WARDEN_CONNECT_ROOT/tenants/default/set-acks.json"
if [ -s "$LEDGER" ]; then
    ok "set-acks.json exists"
    python3 -c "
import json
d = json.load(open('$LEDGER'))
for m, a in d['acked'].items():
    print(f\"       {m}  seq {a['seq']}  {a['set_hash'][:20]}\")"
else
    bad "the ack was never written to disk — this is the restart bug"
fi
kill "$SERVE_PID" 2>/dev/null; wait "$SERVE_PID" 2>/dev/null; SERVE_PID=""
serve_up || exit 2
OUT="$(gate)"; RC=$?
if [ "$RC" -eq 0 ]; then
    ok "and the gate still passes after the restart — it resumed from what the estate confirmed"
else
    bad "the restart lost the acknowledgement; the gate would block every deploy (exit $RC)"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -6
fi

# --- 4 · a new contract advances the log ------------------------------------
bold "4 · a write lands through the API"
# Through the API and not the CLI, deliberately. The state log is single-writer and `serve` holds
# that lock for the life of the process, so `connect request` here would fail with WC-8003 — which
# is correct, and is a topology constraint `docs/limitations.md` now states: an estate whose
# pipelines are the writer runs them against a control plane that is not serving, or it drives
# writes through this API.
BEFORE="$(gate_seq)"
curl -sf -X POST "http://127.0.0.1:$API_PORT/v1/connections" \
    -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    -H "Idempotency-Key: dist-drill-second-set" \
    -d "{\"from\":\"$AGENT\",\"to\":\"$SERVER\",\"tools\":[\"list_transactions\"],
         \"ttl_secs\":86400,\"justification\":\"the drill needs a second set to distribute\",
         \"requester\":\"human:drill@org\",\"mediators\":[\"$MEDIATOR_ID\"]}" \
    > post.json 2>&1
AFTER="$(gate_seq)"
# The POST lands as a *request* row — both parties are Unattested here, so policy routes it to a
# human rather than issuing. The head still moves, and the gate still waits, which is deliberate:
# it compares log position, not contract-set contents. A write that changes no set will still make
# a pipeline wait for one mediator poll. Conservative in the safe direction, and cheap.
if [ "$AFTER" -gt "$BEFORE" ]; then
    ok "the target moved with the log: seq $BEFORE → $AFTER"
else
    bad "minting a contract did not advance the target sequence ($BEFORE → $AFTER)"
    head -3 post.json | sed 's/^/       /'
fi
OUT="$(gate)"; RC=$?
if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q "BEHIND at seq"; then
    ok "     and the gate refuses again — this is the race a pipeline must not lose"
else
    bad "     the gate passed for a set the mediator has not fetched (exit $RC)"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -6
fi

# --- 5 · --wait blocks and then passes --------------------------------------
bold "5 · --wait, with the mediator catching up underneath it"
( sleep 3; mediate_once ) &
CATCHUP=$!
START="$(date +%s)"
OUT="$(gate --wait --timeout 30 --interval 1)"; RC=$?
WAITED=$(( $(date +%s) - START ))
wait "$CATCHUP" 2>/dev/null
if [ "$RC" -eq 0 ] && [ "$WAITED" -ge 2 ]; then
    ok "waited ${WAITED}s and then passed, rather than failing fast"
else
    bad "--wait did not block for a mediator that was about to catch up (exit $RC after ${WAITED}s)"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -6
fi

# --- 6 · a gate with no mediators is not confirmation ------------------------
bold "6 · a gate configured with no mediators"
: > empty-mediators.toml
OUT="$("$CONNECT" distribution --mediators empty-mediators.toml 2>&1)"; RC=$?
if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q "NO MEDIATORS EXPECTED"; then
    ok "refuses rather than passing vacuously"
    printf '%s' "$OUT" | grep -q "this gate is decoration" \
        && ok "     and says so in words an operator can act on" \
        || bad "     but the message does not tell the operator what to fix"
else
    bad "an empty mediator set read as confirmed distribution (exit $RC)"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -6
fi

# --- 7 · read-only serve, so a pipeline can be the writer ---------------------
bold "7 · serve --read-only, with a pipeline writing underneath it"
# The constraint this closes: the state log is single-writer and a writing `serve` holds that lock
# for the life of the process, so `offer publish` and `need apply` — the verbs the whole
# offer/acceptance design is built on — could not run against a live control plane at all.
kill "$SERVE_PID" 2>/dev/null; wait "$SERVE_PID" 2>/dev/null; SERVE_PID=""
"$CONNECT" serve --read-only --refresh-secs 1 --listen "127.0.0.1:$API_PORT" \
    --issuer-key issuer.pem --kid k1 --tokens tokens.toml --approvers approvers.toml \
    >> serve-ro.log 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 80); do
    curl -sf -o /dev/null "http://127.0.0.1:$API_PORT/healthz" && break
    sleep 0.25
done
if grep -q "READ-ONLY" serve-ro.log; then
    ok "started, and says which mode it is in"
else
    bad "serve --read-only did not start or did not announce the mode"
    tail -4 serve-ro.log | sed 's/^/       /'
fi

cat > terms.toml <<TERMS
asset = "$SERVER"

[[term]]
items = ["get_balance"]
approval = "pre_granted"
ttl_max = 604800
to = { zone = "internal.*" }
TERMS
PUB="$("$CONNECT" offer publish --surface surface.json --terms terms.toml --kind mcp \
    --repo drill/payments-mcp --sha aaa --version 1 2>&1)"
if printf '%s' "$PUB" | grep -q "^published"; then
    ok "     a pipeline verb wrote to the state log while the plane served"
else
    bad "     a pipeline verb still cannot run against a serving control plane"
    printf '%s\n' "$PUB" | sed 's/^/       /' | head -4
fi

MUT="$(curl -s -X POST "http://127.0.0.1:$API_PORT/v1/connections" \
    -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    -H 'Idempotency-Key: should-be-refused' \
    -d "{\"from\":\"$AGENT\",\"to\":\"$SERVER\",\"tools\":[\"get_balance\"],
         \"justification\":\"a mutation a read-only plane must refuse\",
         \"requester\":\"human:drill@org\",\"mediators\":[\"$MEDIATOR_ID\"]}")"
if printf '%s' "$MUT" | grep -q "read-only"; then
    ok "     and a state mutation is refused, naming the mode"
else
    bad "     a read-only plane accepted a state mutation"
    printf '%s' "$MUT" | head -c 200 | sed 's/^/       /'
fi

# The refresh loop is the half that makes it usable: without it the plane serves the snapshot it
# opened with, and a mediator would never see a newly minted contract.
sleep 2
RO_SEQ="$(curl -s "http://127.0.0.1:$API_PORT/v1/mediators/$(printf '%s' "$MEDIATOR_ID" | sed 's/:/%3A/g')/contracts" \
    -H "authorization: Bearer $TOKEN" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])' 2>/dev/null)"
if [ -n "$RO_SEQ" ] && [ "$RO_SEQ" -gt "$AFTER" ]; then
    ok "     and it re-read the pipeline's write: serving seq $RO_SEQ (was $AFTER)"
else
    bad "     the read-only plane did not pick up the pipeline's write (seq ${RO_SEQ:-none}, was $AFTER)"
fi

echo
if [ "$fail" -eq 0 ]; then
    bold "DRILL PASSED — the deploy gate works, and it survives a restart"
    cat <<'NOTE'
An ack means the set was installed, not that every contract in it verified: a mediator installs
what verifies and reports the rest. `--require-clean` is the stricter question. And nothing here
measures how long distribution takes under load — that needs the cluster, and
`docs/proving-ground.md` says so.
NOTE
    exit 0
fi
bold "DRILL FAILED"
exit 1
