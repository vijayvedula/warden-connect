#!/usr/bin/env bash
# The proposal drill: one repository, one merge, and the owner check that makes it mean something.
#
#     scripts/proposal-drill.sh
#
# ## Why this exists
#
# Rung 2. A contract proposal is a file added by a pull request into **one** repository; the
# registered owner of the called service reviews and merges it; the registry mints on merge. That is
# the whole loop, and it replaces a bilateral path that needed two repositories, two pipelines,
# branch protection on both and a verified shim before anybody saw a contract exist.
#
# Three things it buys over a portal button: the consent is a *reviewed merge verified against the
# source host* rather than a click this system asserts happened; write access is one repository
# rather than every consumer's; and `git log` is the audit trail, in a form an auditor already reads.
#
# ## What it proves
#
#   1  a merged proposal approved by the callee's REGISTERED OWNER mints a contract;
#   2  the same proposal approved by somebody else is REFUSED — this is the whole control, because
#      anyone with write access to the contracts repo could otherwise mint against a service they do
#      not own, which is privilege escalation wearing a review as a disguise;
#   3  the approval is recorded as `Human` with the merge as evidence, NOT as `ReviewedMerge` —
#      there is one merge here, and claiming both parties consented would overstate it;
#   4  it is idempotent: re-running an unchanged merge mints nothing and writes no request row;
#   5  one bad proposal in the directory mints NONE of them, so a half-applied merge cannot leave
#      an estate in a state nobody proposed.
#
# Phase 2 is the point. Everything else would work without it and would be worth nothing.
#
# Requires: cargo (built binaries), python3, openssl.
# Exit 0 the loop works · 1 it does not · 2 setup.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }
if ! cargo build --release --workspace --quiet 2>&1; then
    echo "the workspace does not build; the drill would be testing nothing" >&2
    exit 2
fi
CONNECT="$REPO/target/release/connect"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
export WARDEN_CONNECT_ROOT="$WORK/root"

AGENT="spiffe://bank/ns/agents/sa/recon-bot"
SERVER="spiffe://bank/ns/svc/sa/payments-mcp"
MEDIATOR="warden:mediator:proposal-drill"
OWNER="human:priya@bank.com"
STRANGER="cecil@bank.com"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

bold "proposal drill"
step "work dir  $WORK"
step "owner     $OWNER   stranger $STRANGER"

cat > connect-policy.toml <<'POLICY'
default = "require_approval"
version = "proposal-drill@v1"

[[zone]]
id = "internal.bank"
trust = "internal"

[standing]
reviewed_at = 0

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
decision = "require_approval"
approver_role = "service.owner"
ttl_max = "7d"
terms = { evidence_sink = "ocsf://siem", evidence_delivery = "fail-safe" }
reason = "the merge is the approval; policy still sets the ceiling"
POLICY

printf '{"tools":[{"name":"get_balance","description":"Read an account balance."},{"name":"wire_funds","description":"Move money."}]}' > surface.json
printf '{"name":"recon","description":"The drill consumer.","version":"1.0.0","skills":[{"id":"d","name":"d","description":"d"}]}' > card.json
openssl ecparam -name prime256v1 -genkey -noout -out i.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in i.tmp -out issuer.pem 2>/dev/null
rm -f i.tmp

"$CONNECT" register agent --card card.json --owner "$OWNER" --zone internal.bank \
    --id "$AGENT" --by "$OWNER" >/dev/null 2>&1
"$CONNECT" register server --id "$SERVER" --surface surface.json --endpoint stdio://payments \
    --owner "$OWNER" --zone internal.bank --by "$OWNER" >/dev/null 2>&1
"$CONNECT" activate "$AGENT" --by "$OWNER" >/dev/null 2>&1
"$CONNECT" activate "$SERVER" --by "$OWNER" >/dev/null 2>&1

# A stand-in source host. WC_APPROVER decides who approved the merge, which is the only variable
# phase 2 needs.
cat > shim.py <<'SHIM'
#!/usr/bin/env python3
import json, os, sys
q = json.loads(sys.stdin.read())
if q.get("op") == "merge_evidence":
    print(json.dumps({
        "merged": True, "ref": "refs/heads/main", "protected": True,
        "request_id": "412",
        "author": "dev@bank.com",
        "approvers": [os.environ.get("WC_APPROVER", "")],
    }))
else:
    print(json.dumps({"absent": True}))
SHIM

mkdir -p warden/contracts
cat > warden/contracts/recon-bot--payments.toml <<PROP
caller  = "$AGENT"
callee  = "$SERVER"
tools   = ["get_balance"]
justify = "APAC reconciliation needs end-of-day balances"
ttl     = 86400
ticket  = "CHG-4471"
PROP

apply() {  # apply <approver> [extra args...]
    local who="$1"; shift
    WC_APPROVER="$who" "$CONNECT" proposals apply \
        --dir warden/contracts --repo bank/warden-contracts --sha aaa \
        --shim "python3 $WORK/shim.py" --shim-label gh \
        --mediator "$MEDIATOR" --issuer-key issuer.pem --kid k1 --by "$OWNER" "$@" 2>&1
}

# --- 2 first, deliberately: the control before the happy path ----------------
bold "1 · a stranger approves the merge"
OUT="$(apply "$STRANGER")"; RC=$?
if [ "$RC" -ne 0 ] \
   && printf '%s' "$OUT" | grep -q "REFUSED" \
   && printf '%s' "$OUT" | grep -q "registered owner"; then
    ok "refused (exit $RC) — write access is not consent from a service you do not own"
    printf '%s' "$OUT" | grep -m1 "registered owner" | cut -c1-104 | sed 's/^/       /'
else
    bad "a merge approved by $STRANGER minted a contract against $OWNER's service (exit $RC)"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -8
fi
if printf '%s' "$OUT" | grep -q "minted"; then
    bad "     and it minted something, which is the escalation this check exists to stop"
else
    ok "     and nothing was minted"
fi

bold "2 · the registered owner approves"
OUT="$(apply "priya@bank.com")"; RC=$?
if [ "$RC" -eq 0 ] && printf '%s' "$OUT" | grep -q "^minted"; then
    ok "minted"
    printf '%s' "$OUT" | grep -E "^minted|^  (surface|ttl|ticket)" | sed 's/^/       /'
else
    bad "the owner's own merge did not mint (exit $RC)"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -10
fi

# --- 3 · the approval is Human with merge evidence, not ReviewedMerge --------
bold "3 · what the contract records"
ART="$(ls "$WARDEN_CONNECT_ROOT"/tenants/default/state/contracts/*.jws 2>/dev/null | head -1)"
if [ -n "$ART" ]; then
    python3 - "$ART" <<'PY' > approval.txt
import base64, json, sys
seg = open(sys.argv[1]).read().strip().split('.')[1]
seg += '=' * (-len(seg) % 4)
a = json.loads(base64.urlsafe_b64decode(seg))["approval"]
print(a["mode"])
print(a.get("by", "-"))
print(a.get("ticket", "-"))
print(len(a.get("merges", [])))
print((a.get("merges") or [{}])[0].get("approvers", []))
PY
    read -r MODE BY TICKET NMERGES <<<"$(head -4 approval.txt | tr '\n' ' ')"
    [ "$MODE" = "human" ] && ok "mode is human — one merge, so the weaker true claim" \
                          || bad "mode is $MODE; ReviewedMerge would overstate a one-sided consent"
    [ "$BY" = "$OWNER" ] && ok "     approved by $BY" \
                         || bad "     approved by $BY, expected $OWNER"
    [ "$TICKET" = "CHG-4471" ] && ok "     ticket CHG-4471 carried from the proposal" \
                               || bad "     ticket is $TICKET"
    [ "$NMERGES" = "1" ] && ok "     and the merge travels with it, so an auditor sees the PR" \
                         || bad "     $NMERGES merge records, expected 1"
else
    bad "no artifact was written"
fi

# --- 4 · idempotent ---------------------------------------------------------
bold "4 · the same merge, applied again"
LOG="$WARDEN_CONNECT_ROOT/tenants/default/state/events-000001.jsonl"
BEFORE="$(wc -c < "$LOG" 2>/dev/null || echo 0)"
OUT="$(apply "priya@bank.com")"
AFTER="$(wc -c < "$LOG" 2>/dev/null || echo 0)"
if printf '%s' "$OUT" | grep -q "already current"; then
    ok "reports already current"
else
    bad "an unchanged re-run did not report the contract as current"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -6
fi
[ "$BEFORE" = "$AFTER" ] && ok "     and the state log is byte-for-byte unchanged — no request row" \
                         || bad "     the state log grew by $((AFTER - BEFORE)) bytes"

# --- 5 · one bad proposal mints none ----------------------------------------
bold "5 · a directory with one bad proposal"
cat > warden/contracts/broken.toml <<PROP
caller  = "$AGENT"
callee  = "spiffe://bank/ns/svc/sa/not-registered"
tools   = ["anything"]
justify = "a proposal naming a party nobody registered"
PROP
cat > warden/contracts/second--payments.toml <<PROP
caller  = "$AGENT"
callee  = "$SERVER"
tools   = ["get_balance", "wire_funds"]
justify = "a second, valid proposal that must not be minted alongside a bad one"
PROP
BEFORE="$(wc -c < "$LOG")"
OUT="$(apply "priya@bank.com")"; RC=$?
AFTER="$(wc -c < "$LOG")"
# The reason, not merely a non-zero exit. This phase passed once on exit 2 — a usage error from a
# verb that was not registered — which is a false pass: the drill would have reported the
# all-or-nothing rule as holding in a build where the command did not exist.
if [ "$RC" -ne 0 ] \
   && printf '%s' "$OUT" | grep -q "REFUSED" \
   && printf '%s' "$OUT" | grep -q "is not registered" \
   && ! printf '%s' "$OUT" | grep -q "^minted"; then
    ok "refused (exit $RC) for the stated reason, and minted nothing — including the valid one"
    printf '%s' "$OUT" | grep -m1 "is not registered" | cut -c1-100 | sed 's/^/       /'
else
    bad "a directory with one bad proposal applied anyway (exit $RC)"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -8
fi
[ "$BEFORE" = "$AFTER" ] && ok "     and wrote nothing at all" \
                         || bad "     the log grew by $((AFTER - BEFORE)) bytes"

echo
if [ "$fail" -eq 0 ]; then
    bold "DRILL PASSED — one repo, one merge, and the owner check holds"
    cat <<'NOTE'
The signed artifact stays in the control plane. A contract committed to a repository is a bearer
grant valid until its exp no matter what the registry says, and git has no way to express
"withdrawn" — so the repository holds the record and never the credential.
NOTE
    exit 0
fi
bold "DRILL FAILED"
exit 1
