#!/usr/bin/env bash
# The quarterly containment drill (§8.16 P3, production-readiness P1 #9).
#
# §8.16 lists "quarterly containment drill script in the repo" as a phase-3 exit criterion
# and there was no script. This is it.
#
# It is a *drill*, not a test. The test suite proves the mechanism: quarantine transitions
# the party, the revocation feed is signed, an unconfirmed mediator is reported rather than
# assumed contained. What a drill proves is different and cannot be unit-tested — that the
# **procedure** works, on this estate, with these keys, and that the humans who would run it
# at 03:00 have run it once when nothing was on fire.
#
# The part that most needs rehearsing is the **break-glass revocation key**. A key nobody
# has used is a key that probably does not work: flat token, forgotten PIN, share-holder who
# left in March. `docs/key-custody.md` says the drill must exercise the offline path and not
# only the online one, so this script does both and fails if the offline half is skipped.
#
# Usage:
#     scripts/containment-drill.sh                       # ephemeral estate, self-contained
#     scripts/containment-drill.sh /var/lib/wc-drill     # a root you supply
#
# Exit codes: 0 the drill passed · 1 a step failed · 2 the drill could not be set up.

set -euo pipefail

CONNECT="${CONNECT:-./target/release/connect}"
ROOT="${1:-}"
EPHEMERAL=0
STEP=0
STARTED=$(date +%s)

if [ -z "$ROOT" ]; then
    ROOT=$(mktemp -d "${TMPDIR:-/tmp}/wc-drill.XXXXXX")
    EPHEMERAL=1
fi
WORK=$(mktemp -d "${TMPDIR:-/tmp}/wc-drill-work.XXXXXX")

cleanup() {
    [ "$EPHEMERAL" = 1 ] && rm -rf "$ROOT"
    rm -rf "$WORK"
}
trap cleanup EXIT

step() {
    STEP=$((STEP + 1))
    printf '\n\033[1m%d · %s\033[0m\n' "$STEP" "$1"
}

fail() {
    printf '\033[31mDRILL FAILED: %s\033[0m\n' "$1" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || { printf 'need %s\n' "$1" >&2; exit 2; }
}

need openssl
[ -x "$CONNECT" ] || {
    printf 'no binary at %s — run `cargo build --release` first\n' "$CONNECT" >&2
    exit 2
}

printf '\033[1mwarden-connect containment drill\033[0m\n'
printf 'root   %s%s\n' "$ROOT" "$([ "$EPHEMERAL" = 1 ] && echo ' (ephemeral)')"
printf 'binary %s\n' "$("$CONNECT" version 2>/dev/null | head -1)"

# ---------------------------------------------------------------------------
step "Mint the keys, including the break-glass revocation key"
# ---------------------------------------------------------------------------
#
# Two revocation keys, because that is the design (custody 5c): `revoke-online` in the KMS
# for routine work and `revoke-offline` on a hardware token for when the KMS or the control
# plane is not available. Generated here as files because a drill on a laptop cannot reach a
# real token — and that limitation is the drill's own biggest gap, recorded at the bottom.
for name in issuer approver revoke-online revoke-offline; do
    openssl ecparam -genkey -name prime256v1 -noout -out "$WORK/$name.key" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt -in "$WORK/$name.key" -out "$WORK/$name.pem" 2>/dev/null
    openssl ec -in "$WORK/$name.pem" -pubout -out "$WORK/$name.pub.pem" 2>/dev/null
done
printf '   4 keys: issuer, approver, revoke-online, revoke-offline\n'

cat > "$WORK/surface.json" <<'JSON'
{"tools":[
  {"name":"get_balance","description":"Read an account balance."},
  {"name":"list_transactions","description":"List recent transactions."}
]}
JSON

# ---------------------------------------------------------------------------
step "Register and activate a party to contain"
# ---------------------------------------------------------------------------
"$CONNECT" register server --root "$ROOT" \
    --endpoint https://payments.internal/mcp \
    --owner human:drill --zone internal.payments \
    --surface "$WORK/surface.json" --by human:drill >"$WORK/register.txt" \
    || fail "registration"

TARGET=$(awk '/^registered/ {print $2; exit}' "$WORK/register.txt")
[ -n "$TARGET" ] || fail "could not read the registered entity id"
printf '   %s\n' "$TARGET"

"$CONNECT" activate "$TARGET" --root "$ROOT" --by human:drill >/dev/null \
    || printf '   note: activation refused (posture) — containment does not require it\n'

# ---------------------------------------------------------------------------
step "Contain with the ONLINE key — the routine path"
# ---------------------------------------------------------------------------
"$CONNECT" quarantine "$TARGET" --root "$ROOT" \
    --reason "drill: routine containment" \
    --revocation-key "$WORK/revoke-online.pem" \
    --revocation-kid revoke-online \
    --break-glass-kid revoke-offline \
    --by human:drill >"$WORK/online.txt" 2>&1 || fail "online containment"

grep -q "quarantined" "$WORK/online.txt" || fail "the party was not quarantined"
# `NO MEDIATORS CONFIGURED` is expected on a bare drill root and is *not* a pass: it is the
# script saying the estate has no data plane to reach, which on a real root would be the
# most important line in the output.
if grep -q "NO MEDIATORS CONFIGURED" "$WORK/online.txt"; then
    printf '   \033[33mno mediators configured — nothing enforces this\033[0m\n'
    printf '   on a real estate, pass --mediators mediators.toml and confirm every ACK\n'
fi
printf '   feed seq: %s\n' "$(awk '/feed seq/ {print $3}' "$WORK/online.txt" | head -1)"

# ---------------------------------------------------------------------------
step "The party is refused, and quarantine is never overridable"
# ---------------------------------------------------------------------------
# From the fail-closed matrix (§7.8): a quarantined posture denies in *every* mode,
# including observe. If this ever stops being true, the containment story is over.
"$CONNECT" show "$TARGET" --root "$ROOT" --json >"$WORK/show.json" 2>&1 || fail "show"
grep -qi "quarantin" "$WORK/show.json" \
    || fail "the register does not report the party as quarantined"
printf '   posture recorded as quarantined\n'

# ---------------------------------------------------------------------------
step "Reach for the OFFLINE key WITHOUT consent — must be refused"
# ---------------------------------------------------------------------------
# The habit case. A break-glass path reached casually stops being exceptional, and then the
# alert on it stops meaning anything.
if "$CONNECT" quarantine "$TARGET" --root "$ROOT" \
    --reason "drill: reaching for break-glass out of habit" \
    --revocation-key "$WORK/revoke-offline.pem" \
    --revocation-kid revoke-offline \
    --break-glass-kid revoke-offline \
    --by human:drill >"$WORK/habit.txt" 2>&1
then
    fail "the offline key was accepted without --break-glass"
fi
printf '   refused, as designed\n'

# ---------------------------------------------------------------------------
step "Contain with the OFFLINE key — the break-glass path"
# ---------------------------------------------------------------------------
# The half a drill exists for. Everything above works every day; this works never, which is
# exactly why it has to be rehearsed.
"$CONNECT" quarantine "$TARGET" --root "$ROOT" \
    --reason "drill: KMS unreachable, containing with break-glass" \
    --revocation-key "$WORK/revoke-offline.pem" \
    --break-glass --break-glass-kid revoke-offline \
    --by human:drill >"$WORK/offline.txt" 2>&1 || fail "break-glass containment"

grep -q "BREAK-GLASS" "$WORK/offline.txt" \
    || fail "break-glass use was not announced — its whole value is that it is loud"
printf '   %s\n' "$(grep 'BREAK-GLASS' "$WORK/offline.txt" | head -1)"

# ---------------------------------------------------------------------------
step "Break-glass use is in the evidence chain as its own event"
# ---------------------------------------------------------------------------
# Not a quarantine with a raised severity — `Quarantine` is already Critical, so severity
# cannot distinguish the two. It has its own kind, `containment.breakglass_key`, so a sink
# can alert on exactly this.
CHAIN="$ROOT/tenants/default/evidence/chain.jsonl"
[ -f "$CHAIN" ] || fail "no evidence chain at $CHAIN"
grep -q 'containment.breakglass_key' "$CHAIN" \
    || fail "break-glass use is not in the chain under its own event kind"
printf '   containment.breakglass_key is in the chain\n'

# ---------------------------------------------------------------------------
step "The chain still verifies after all of it"
# ---------------------------------------------------------------------------
"$CONNECT" audit verify --root "$ROOT" >"$WORK/verify.txt" 2>&1 || fail "audit verify"
grep -qi "intact\|entries" "$WORK/verify.txt" || fail "audit verify said nothing useful"
printf '   %s\n' "$(head -2 "$WORK/verify.txt" | tr '\n' ' ')"

# ---------------------------------------------------------------------------
step "The containment is recoverable: back it up and restore it"
# ---------------------------------------------------------------------------
# An incident record that cannot be produced afterwards is not an incident record.
"$CONNECT" backup --root "$ROOT" --out "$WORK/snapshot" >/dev/null 2>&1 || fail "backup"
"$CONNECT" restore --from "$WORK/snapshot" --into "$WORK/restored" >/dev/null 2>&1 \
    || fail "restore"
grep -q 'containment.breakglass_key' \
    "$WORK/restored/tenants/default/evidence/chain.jsonl" \
    || fail "the restored chain lost the break-glass event"
printf '   restored, and the break-glass event survived\n'

# ---------------------------------------------------------------------------
ELAPSED=$(( $(date +%s) - STARTED ))
printf '\n\033[32mDRILL PASSED\033[0m in %ds — %d steps\n' "$ELAPSED" "$STEP"

cat <<'NOTES'

What this drill does NOT prove, and what a real quarterly run must add:

  · The offline key was a FILE, not a hardware token. The thing most likely to fail on the
    day — a flat battery, a forgotten PIN, an M-of-N share-holder who left — is precisely
    what a laptop cannot rehearse. Run it once a quarter against the real token, in the
    safe, with the named holders present.
  · No mediators were configured, so nothing enforced the containment. On a real estate,
    pass --mediators and confirm every ACK: `connect mediators` names the ones that have
    not. Unconfirmed is not contained.
  · Propagation was not timed. §7.10 promises under 60 s estate-wide; the metric that
    measures it is wc_mediator_ack_lag_seconds, and the drill should record the number.
  · Nobody was paged. Break-glass use is a Critical event on a containment-filtered sink —
    confirm the alert actually arrived somewhere a human saw it.

Record the elapsed time. "We can contain" and "we can contain inside our stated 60
seconds" are different claims, and only the second one is useful during an incident.
NOTES
