#!/usr/bin/env bash
# The key rotation drill: publish a new `kid`, withdraw an old one, and prove a **running**
# mediator honours both without a restart.
#
#     scripts/rotation-drill.sh
#
# `docs/limitations.md` listed this as *Unproven*: "the mechanism is tested; the procedure is
# not." That distinction is not academic here. This codebase already had the defect this drill
# exists to catch — **the mediator's refresh thread held boot-time trust**, so contracts
# refreshed every tick and the keys checking them never did. That was fixed and unit-tested,
# and until now no live rotation had ever been performed against a running process.
#
# ## What it proves, in four phases against one process
#
#   1  baseline — the contract's key is published, so the call executes;
#   2  a second key is ADDED — the call still executes, because the overlap every rotation
#      runs through must not cut live traffic;
#   3  the original key is WITHDRAWN — the call is refused, in a process nobody restarted.
#      This is the security property: the key set is replaced rather than merged, so a
#      compromised key can actually be taken out of service;
#   4  the key is republished — the call executes again, proving the refresh loop is still
#      running after it served a refusal.
#
# ## What it does not prove
#
# * **Only the `--jwks-url` path.** `--jwks-file` shares the same `JwksSource` refresh loop.
# * **Nothing about `--contract FILE` mode, which has no refresh loop at all** — the pull
#   thread only starts when there is a control plane, so a mediator handed contracts on disk
#   never re-reads its key set. That is worth knowing before planning a rotation for an
#   air-gapped deployment.
# * The drill runs in `--observe`, because posture is not what is under test. Contract
#   verification happens when the snapshot is built and is unaffected by mode.
#
# Requires: cargo (built binaries), python3, openssl, curl.
# Exit 0 the rotation behaved · 1 it did not · 2 setup.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CONNECT="$REPO/target/release/connect"
MEDIATE="$REPO/target/release/connect-mediate"
[ -x "$CONNECT" ] || CONNECT="$REPO/target/debug/connect"
[ -x "$MEDIATE" ] || MEDIATE="$REPO/target/debug/connect-mediate"
for b in "$CONNECT" "$MEDIATE"; do
    [ -x "$b" ] || { echo "no $b; run cargo build --release --workspace" >&2; exit 2; }
done
command -v python3 >/dev/null || { echo "need python3" >&2; exit 2; }

# Refuse to drill a binary older than the code. The drill reads `target/`, it does not build,
# so a source change followed by `cargo test` (which builds only the test profile) leaves these
# stale — and the drill then reports on a mediator that no longer exists. That happened while
# fixing the very bug this drill found: three phases reported the OLD behaviour after the fix
# was written, tested and committed to the working tree.
newest_src=$(find "$REPO/crates" -name '*.rs' -newer "$MEDIATE" -print -quit 2>/dev/null)
if [ -n "$newest_src" ]; then
    echo "$(basename "$MEDIATE") is older than $newest_src" >&2
    echo "  cargo build --release --workspace" >&2
    exit 2
fi
command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }

WORK="$(mktemp -d)"
API_PORT=${API_PORT:-8841}
JWKS_PORT=${JWKS_PORT:-8842}
TTL=${TTL:-3}
# Enforce by default. The drill ran in `--observe` when it only measured key rotation, on the
# grounds that posture was not under test — but observe mode deliberately SOFTENS an absent
# contract (§8.16: zero behaviour change on the proxy path), and a withdrawn contract reads as
# absent. So containment simply cannot be observed in observe mode, and a drill that ran there
# would report the fix as a failure and the bug as a pass. Both were briefly true here.
# Observe, because the drill's parties are registered but not ATTESTED, and posture
# (`WC-3109`, ClosedUnlessObserve) denies every call in enforce mode. Discovered by defaulting
# this to enforce and watching the containment phases "pass" — they expect a refusal, and
# posture was refusing everything. That is why `check` below asserts the CODE and not merely
# that something was refused: a refusal for the wrong reason is the most convincing false pass
# available, and this drill produced one on its first enforce-mode run.
#
# Containment is still fully under test here: `WC-4001` and `WC-3105` are both registered
# `Closed` in the taxonomy, so they deny in observe mode too.
MODE=${MODE:-observe}
case "$MODE" in
    enforce) MODE_FLAG="" ;;
    observe) MODE_FLAG="--observe" ;;
    *) echo "MODE must be enforce|observe, got $MODE" >&2; exit 2 ;;
esac
MEDIATOR_ID="warden:mediator:drill"
TOKEN="tok_rotation_drill_0123456789"
AGENT="spiffe://drill.example/ns/agents/sa/caller"
SERVER="spiffe://drill.example/ns/svc/sa/callee"

cleanup() {
    [ -n "${SERVE_PID:-}" ] && kill "$SERVE_PID" 2>/dev/null
    [ -n "${HTTP_PID:-}" ] && kill "$HTTP_PID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }

bold "key rotation drill"
step "work dir  $WORK"
step "ttl       ${TTL}s"
step "mode      $MODE"

cd "$WORK"
export WARDEN_CONNECT_ROOT="$WORK/root"

# --- keys --------------------------------------------------------------------
# Two issuer keys. PKCS#8, because a SEC1 key is refused with `WC-3102 issuer key is not an
# EC PKCS#8 PEM` — worth generating correctly rather than discovering in the middle of a drill.
for k in kid-1 kid-2; do
    openssl ecparam -name prime256v1 -genkey -noout -out "$k.tmp" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt -in "$k.tmp" -out "$k.priv.pem" 2>/dev/null
    openssl ec -in "$k.priv.pem" -pubout -out "$k.pub.pem" 2>/dev/null
    rm -f "$k.tmp"
done
step "keys      kid-1, kid-2"

# The three trust sets this drill rotates between. Built from the public keys with the same
# `keys jwks` path an operator would use, so the drill exercises publication too.
"$CONNECT" keys add --kid kid-1 --public kid-1.pub.pem --keyring ring1.toml >/dev/null 2>&1
"$CONNECT" keys jwks --keyring ring1.toml --out jwks-kid1.json >/dev/null 2>&1
cp ring1.toml ring12.toml
"$CONNECT" keys add --kid kid-2 --public kid-2.pub.pem --keyring ring12.toml >/dev/null 2>&1
"$CONNECT" keys jwks --keyring ring12.toml --out jwks-kid1-kid2.json >/dev/null 2>&1
"$CONNECT" keys add --kid kid-2 --public kid-2.pub.pem --keyring ring2.toml >/dev/null 2>&1
"$CONNECT" keys jwks --keyring ring2.toml --out jwks-kid2.json >/dev/null 2>&1
for f in jwks-kid1.json jwks-kid1-kid2.json jwks-kid2.json; do
    [ -s "$f" ] || { echo "could not build $f" >&2; exit 2; }
done
step "trust     $(python3 -c "
import json
for f in ('jwks-kid1.json','jwks-kid1-kid2.json','jwks-kid2.json'):
    kids = ','.join(k['kid'] for k in json.load(open(f))['keys'])
    label = f[5:-5]
    print(label + '=[' + kids + ']', end='  ')")"
cp jwks-kid1.json jwks-live.json

# --- an estate ---------------------------------------------------------------
cat > policy.toml <<'POLICY'
default = "require_approval"
version = "rotation-drill@v1"

[[zone]]
id = "internal.drill"
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
cp policy.toml connect-policy.toml

# No warden.policy.toml. `connect-mediate` runs STANDALONE by default now — connection
# enforcement with no Warden core — so the two-policy confusion this drill used to have to
# explain is gone. That the drill still passes without it is the proof that standalone works
# end to end, which is why this comment replaces the file rather than the file being moved.

cat > approvers.toml <<'APPROVERS'
[[approver]]
id = "human:drill@org"
key = "approver.pub.pem"
roles = ["drill.operator"]
APPROVERS
openssl ecparam -name prime256v1 -genkey -noout -out approver.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in approver.tmp -out approver.priv.pem 2>/dev/null
openssl ec -in approver.priv.pem -pubout -out approver.pub.pem 2>/dev/null
rm -f approver.tmp

cat > tokens.toml <<TOKENS
[[client]]
token = "$TOKEN"
roles = ["connect.read", "connect.mediator", "connect.secops"]
TOKENS

printf '{"tools":[{"name":"alpha","description":"The contracted tool."}]}' > surface.json
printf '{"name":"caller","description":"The drill caller.","version":"1.0.0","skills":[{"id":"drive","name":"drive","description":"Drives the drill."}]}' > card.json

"$CONNECT" register agent --card card.json --owner human:drill@org --zone internal.drill \
    --id "$AGENT" --by human:drill@org >/dev/null 2>&1
"$CONNECT" register server --id "$SERVER" --surface surface.json --endpoint stdio://drill \
    --owner human:drill@org --zone internal.drill --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$AGENT" --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$SERVER" --by human:drill@org >/dev/null 2>&1

# The contract under test, signed by kid-1. Minted before `serve` starts, because the state log
# is single-writer: `serve` holds the lock, so the CLI cannot write while it runs. That
# constraint is why this drill rotates the published TRUST SET rather than issuing new
# contracts mid-flight — which is what a rotation is anyway.
REQ=$("$CONNECT" request --from "$AGENT" --to "$SERVER" --tools alpha \
    --justify "rotation drill" --ttl 7d --mediator "$MEDIATOR_ID" \
    --issuer-key kid-1.priv.pem --kid kid-1 --by human:drill@org 2>&1 \
    | grep -oE 'req_[a-f0-9]+' | head -1)
[ -n "$REQ" ] || { echo "no request was raised" >&2; exit 2; }
"$CONNECT" approve "$REQ" --by human:drill@org --approver-key approver.priv.pem \
    --issuer-key kid-1.priv.pem --kid kid-1 >/dev/null 2>&1 \
    || { echo "the drill contract could not be approved" >&2; exit 2; }
step "contract  signed by kid-1, one tool"

# --- the two servers --------------------------------------------------------
# A port already in use means somebody else's process, and adopting it is how the leak above
# stayed invisible. Refuse instead.
for port in "$API_PORT" "$JWKS_PORT"; do
    if curl -sf -o /dev/null -m 2 "http://127.0.0.1:$port/" 2>/dev/null \
       || curl -sf -o /dev/null -m 2 "http://127.0.0.1:$port/healthz" 2>/dev/null; then
        echo "port $port is already answering; a stale drill is probably still running." >&2
        echo "  pkill -f 'connect serve --listen 127.0.0.1:$API_PORT'" >&2
        echo "  or re-run with API_PORT=… JWKS_PORT=…" >&2
        exit 2
    fi
done

"$CONNECT" serve --listen "127.0.0.1:$API_PORT" --issuer-key kid-1.priv.pem --kid kid-1 \
    --tokens tokens.toml --approvers approvers.toml > serve.log 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 60); do
    curl -sf -o /dev/null "http://127.0.0.1:$API_PORT/healthz" && break
    sleep 0.25
done
curl -sf -o /dev/null "http://127.0.0.1:$API_PORT/healthz" \
    || { echo "the control plane did not start:"; tail -5 serve.log; exit 2; }

# A static server for the key set, so the rotation is a publication an operator performs and
# the mediator's `--jwks-url` fetch path is what is exercised.
python3 -m http.server "$JWKS_PORT" --bind 127.0.0.1 --directory "$WORK" > http.log 2>&1 &
HTTP_PID=$!
for _ in $(seq 1 40); do
    curl -sf -o /dev/null "http://127.0.0.1:$JWKS_PORT/jwks-live.json" && break
    sleep 0.25
done
step "serving   api :$API_PORT · jwks :$JWKS_PORT"

# --- drive it ---------------------------------------------------------------
env API="http://127.0.0.1:$API_PORT" TOKEN="$TOKEN" CALLEE="$SERVER" \
    python3 "$REPO/scripts/.rotation-driver.py" "$WORK" "$TTL" \
    "$MEDIATE" \
    --upstream "python3 $REPO/scripts/.rotation-upstream.py" \
    --mediator-id "$MEDIATOR_ID" \
    --caller "$AGENT" --callee "$SERVER" \
    --contracts "http://127.0.0.1:$API_PORT" --token "$TOKEN" \
    --jwks-url "http://127.0.0.1:$JWKS_PORT/jwks-live.json" \
    --jwks-ttl "$TTL" --refresh "$TTL" \
    $MODE_FLAG

STATUS=$?
# Not `exec`: the EXIT trap has to run, or both servers outlive the drill on fixed ports and
# the NEXT run silently reuses a stale control plane with the previous run's configuration.
# That happened, and it is why the containment phase reported a role the token had.
exit "$STATUS"
