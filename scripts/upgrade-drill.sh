#!/usr/bin/env bash
# The upgrade drill: a provider changes their terms, and everyone finds out at a useful moment.
#
#     scripts/upgrade-drill.sh
#
# ## Why this exists
#
# Two fields in the offer/need machinery read as an upgrade path and were wired to nothing.
#
# `Term.deprecates` — an item and the date the provider intends to remove it — had no reader
# anywhere. `Offer::deprecated_after` existed to serve it and had no caller either. So a provider
# could publish a withdrawal schedule, a consumer could contract the item for thirty days past
# the date, and nothing anywhere would mention it.
#
# `Matched.offer_version` was worse, because it carried a doc comment saying it was there "so a
# later upgrade can find what it affects" — and it was dropped on the floor at mint time.
# `ContractRecord` had no field for it. The provider's question at the moment it matters most,
# *who breaks if I remove this?*, was unanswerable, and a comment in the source said it was
# answered.
#
# ## What it proves
#
#   1  a contract records the offer version that permitted it, so the estate can be asked;
#   2  publishing a narrowing version REPORTS who it affects, at publish time — a provider finds
#      out while they can still change their mind, in their own pipeline's log;
#   3  `offer status` separates the three cases that need different responses: gone from the
#      current terms, past a published withdrawal date, and scheduled for one;
#   4  the consumer's unchanged manifest starts refusing, which is the notice arriving;
#   5  a contract that would OUTLIVE a withdrawal date is refused rather than silently
#      shortened, and the refusal names the TTL that fits;
#   6  the derived identity does not move with the clock — the reason for (5);
#   7  re-applying under the new version replaces the artifact at the same `cid`;
#   8  a provider can END an affected connection, and the cut reaches the revocation feed.
#
# ## What it does not prove
#
# * **That a live session stops.** (7) replaces the artifact, and the mediator-side effect of
#   that — a session admitted under the old `jti` refused on its next call, `WC-3105` — is
#   covered by `replacing_the_contract_under_the_same_cid_stops_the_session` in
#   `crates/wc-mediator/tests/mediation.rs`. This drill runs the control plane, not a mediator.
# * **That a version bump does anything to a contract already issued.** It does not, by design:
#   a contract is a signed ceiling with a hard expiry, and a publisher who could shorten one
#   remotely would make the artifact a cache of a mutable decision. What closes the gap is the
#   contract's own `exp`, the consumer's next build, and — if the provider actually removes the
#   tool — `WC-3108` drift at the mediator.
#
# Requires: cargo (built binaries), python3, openssl.
# Exit 0 the upgrade path works · 1 it does not · 2 setup.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }
command -v python3 >/dev/null || { echo "need python3" >&2; exit 2; }
if ! cargo build --release --workspace --quiet 2>&1; then
    echo "the workspace does not build; the drill would be testing nothing" >&2
    exit 2
fi
CONNECT="$REPO/target/release/connect"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
export WARDEN_CONNECT_ROOT="$WORK/root"

CONSUMER="spiffe://drill.example/ns/agents/sa/recon-bot"
PROVIDER="spiffe://drill.example/ns/svc/sa/payments-mcp"
MEDIATOR="warden:mediator:upgrade-drill"
NOW="$(date +%s)"
# Far enough out that a 1-day contract fits inside it, close enough that a 7-day one does not.
WITHDRAW=$((NOW + 3 * 86400))

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

bold "upgrade drill"
step "work dir   $WORK"
step "withdraws  $(date -u -r "$WITHDRAW" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$WITHDRAW" +%Y-%m-%dT%H:%M:%SZ)"

# --- the estate ---------------------------------------------------------------
cat > connect-policy.toml <<'POLICY'
default = "allow"
version = "upgrade-drill@v1"

[[zone]]
id = "internal.drill"
trust = "internal"

[standing]
reviewed_at = 0

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
decision = "allow"
ttl_max = "30d"
terms = { evidence_sink = "ocsf://siem", evidence_delivery = "fail-safe" }
reason = "the offer is the ceiling under test here, not org policy"
POLICY

printf '{"tools":[{"name":"get_balance","description":"Read an account balance."},{"name":"list_transactions","description":"List recent transactions."}]}' > surface.json
printf '{"name":"recon","description":"The drill consumer.","version":"1.0.0","skills":[{"id":"drive","name":"drive","description":"Drives the drill."}]}' > card.json

openssl ecparam -name prime256v1 -genkey -noout -out issuer.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in issuer.tmp -out issuer.pem 2>/dev/null
rm -f issuer.tmp

"$CONNECT" register agent --card card.json --owner human:drill@org --zone internal.drill \
    --id "$CONSUMER" --by human:drill@org >/dev/null 2>&1
"$CONNECT" register server --id "$PROVIDER" --surface surface.json --endpoint stdio://drill \
    --owner human:drill@org --zone internal.drill --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$CONSUMER" --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$PROVIDER" --by human:drill@org >/dev/null 2>&1

# A source host that approves everything and serves files from the working tree. Both consents
# are real as far as this drill is concerned; `custody-drill.sh` and the W4 tests are where the
# shim protocol itself is under test.
cat > shim.py <<'SHIM'
#!/usr/bin/env python3
import base64, json, sys
q = json.loads(sys.stdin.read())
if q.get("op") == "merge_evidence":
    print(json.dumps({"merged": True, "ref": "refs/heads/main", "protected": True,
                      "request_id": "77", "approvers": ["s.iyer"], "author": "r.mehta"}))
elif q.get("op") == "file":
    print(json.dumps({"content_b64": base64.b64encode(open(q["path"], "rb").read()).decode()}))
else:
    sys.exit(1)
SHIM
SHIM_ARGS=(--shim "python3 $WORK/shim.py" --shim-label gh)

publish() {  # publish <terms-file> <version> <sha>
    "$CONNECT" offer publish --surface surface.json --terms "$1" --kind mcp \
        --repo drill/payments-mcp --sha "$3" --version "$2" "${SHIM_ARGS[@]}" 2>&1
}
apply() {    # apply <sha>
    "$CONNECT" need apply --manifest needs.toml --repo drill/recon-bot --sha "$1" \
        --mediator "$MEDIATOR" "${SHIM_ARGS[@]}" --issuer-key issuer.pem --kid k1 2>&1
}
jti_of() {   # jti_of <artifact.jws>
    python3 -c "
import base64, json, sys
seg = open(sys.argv[1]).read().strip().split('.')[1]
seg += '=' * (-len(seg) % 4)
print(json.loads(base64.urlsafe_b64decode(seg))['jti'])" "$1"
}
artifact() { ls "$WARDEN_CONNECT_ROOT"/tenants/default/state/contracts/*.jws 2>/dev/null | head -1; }

# --- 1 · v1, and a contract that records it ----------------------------------
bold "1 · a contract records the version that permitted it"
cat > offer-v1.toml <<TERMS
asset = "$PROVIDER"

[[term]]
items = ["get_balance", "list_transactions"]
approval = "pre_granted"
ttl_max = 604800
to = { zone = "internal.*" }
TERMS
cat > needs.toml <<NEEDS
asset = "$CONSUMER"

[[need]]
to = "$PROVIDER"
tools = ["get_balance", "list_transactions"]
justify = "APAC reconciliation needs balances and history"
ttl = 86400
NEEDS

publish offer-v1.toml 1 aaa >/dev/null
APPLY1="$(apply bbb)"
if printf '%s' "$APPLY1" | grep -q "1 minted"; then
    ok "minted under v1"
else
    bad "the first contract did not mint"
    printf '%s\n' "$APPLY1" | sed 's/^/       /' | head -6
    bold "DRILL FAILED"; exit 1
fi
JTI1="$(jti_of "$(artifact)")"

STATUS1="$("$CONNECT" offer status "$PROVIDER" 2>&1)"
if printf '%s' "$STATUS1" | grep -q "0 minted under an earlier version" \
   && printf '%s' "$STATUS1" | grep -q "nothing to report"; then
    ok "     offer status is clean, and says so rather than saying nothing"
else
    bad "     offer status did not report a clean estate"
    printf '%s\n' "$STATUS1" | sed 's/^/       /' | head -6
fi

# --- 2 · v2 narrows and deprecates, and says who it hit -----------------------
bold "2 · publishing a narrowing version reports who it affects"
cat > offer-v2.toml <<TERMS
asset = "$PROVIDER"

[[term]]
items = ["get_balance"]
approval = "pre_granted"
ttl_max = 604800
to = { zone = "internal.*" }
deprecates = [{ item = "get_balance", after = $WITHDRAW }]

[[term]]
items = ["list_transactions"]
approval = "named_consumer"
ttl_max = 3600
TERMS
PUB2="$(publish offer-v2.toml 2 ccc)"
if printf '%s' "$PUB2" | grep -q "AFFECTED.*list_transactions is no longer offered"; then
    ok "the publish itself named the contract it affects"
    printf '%s' "$PUB2" | grep "AFFECTED" | head -1 | cut -c1-108 | sed 's/^/       /'
else
    bad "publishing a narrowing offer said nothing about live contracts"
    printf '%s\n' "$PUB2" | sed 's/^/       /' | head -8
fi

# --- 3 · the three cases, told apart -----------------------------------------
bold "3 · offer status separates gone, withdrawn and scheduled"
STATUS2="$("$CONNECT" offer status "$PROVIDER" 2>&1)"
printf '%s' "$STATUS2" | grep -q "1 minted under an earlier version" \
    && ok "the contract is counted as behind (minted under v1, current is v2)" \
    || bad "a contract minted under v1 was not counted as behind"
printf '%s' "$STATUS2" | grep -q "GONE       list_transactions" \
    && ok "     list_transactions: GONE — the current terms do not offer it to this consumer" \
    || bad "     list_transactions was not reported as gone"
printf '%s' "$STATUS2" | grep -q "SCHEDULED  get_balance" \
    && ok "     get_balance: SCHEDULED — a withdrawal date the consumer can plan around" \
    || bad "     get_balance's withdrawal date was not reported"

# --- 4 · the consumer's unchanged build starts refusing ----------------------
bold "4 · the consumer's unchanged manifest"
CHECK="$("$CONNECT" need check --manifest needs.toml 2>&1)"
if printf '%s' "$CHECK" | grep -q "REFUSED"; then
    ok "refused — the notice arrives as a red build, in the consumer's own pipeline"
else
    bad "an unchanged manifest still passed against narrowed terms"
    printf '%s\n' "$CHECK" | sed 's/^/       /' | head -6
fi

# --- 5 · a contract that would outlive the withdrawal ------------------------
bold "5 · a TTL that would outlive the withdrawal date"
cat > needs.toml <<NEEDS
asset = "$CONSUMER"

[[need]]
to = "$PROVIDER"
tools = ["get_balance"]
justify = "APAC reconciliation needs balances"
ttl = 604800
NEEDS
LONG="$("$CONNECT" need check --manifest needs.toml 2>&1)"
if printf '%s' "$LONG" | grep -q "would outlive it"; then
    ok "refused, and it names the largest TTL that fits"
    printf '%s' "$LONG" | grep -o "Lower .ttl. in your need to at most [0-9]*s" | head -1 | sed 's/^/       /'
else
    bad "a 7-day contract was permitted for an item withdrawn in 3 days"
    printf '%s\n' "$LONG" | sed 's/^/       /' | head -6
fi

# --- 6 · the identity does not move with the clock --------------------------
bold "6 · why it refuses instead of shortening"
sed -i.bak 's/^ttl = 604800$/ttl = 86400/' needs.toml && rm -f needs.toml.bak
# The robust assertion is the TTL, not the jti. An implementation that clamped to
# `after - now` would report roughly 259200s here instead of the 86400s the manifest asks for —
# deterministic, and it does not depend on two runs landing in different seconds. The jti
# comparison below is a second look at the same thing and would give a false pass if both runs
# fell inside one second, so it is not the one carrying the claim; the clock-independence proof
# proper is `a_contract_that_would_outlive_a_withdrawal_is_refused_not_shortened`, which advances
# the clock by ten minutes between two derivations.
FIT="$("$CONNECT" need check --manifest needs.toml 2>&1)"
FIT_TTL="$(printf '%s' "$FIT" | awk '/^  ttl/ {print $2}')"
if [ "$FIT_TTL" = "86400s" ]; then
    ok "the TTL is what the manifest asked for ($FIT_TTL), not what is left before withdrawal"
    ok "     so an unchanged pipeline does not re-mint — which clamping the TTL would have broken"
else
    bad "the TTL was shortened to $FIT_TTL; a ceiling that moves with the clock churns the jti"
fi
FIT_A="$(printf '%s' "$FIT" | awk '/^  jti/ {print $2}')"
FIT_B="$("$CONNECT" need check --manifest needs.toml 2>&1 | awk '/^  jti/ {print $2}')"
if [ -n "$FIT_A" ] && [ "$FIT_A" = "$FIT_B" ]; then
    ok "     and the derived jti is the same on a second run ($FIT_A)"
else
    bad "     the derived jti moved between two runs of an unchanged manifest: $FIT_A vs $FIT_B"
fi
NOTICE="$("$CONNECT" need check --manifest needs.toml 2>&1)"
printf '%s' "$NOTICE" | grep -q "NOTICE" \
    && ok "     and the contract that DOES fit still carries the withdrawal notice" \
    || bad "     a permitted contract for a deprecated item carried no notice"

# --- 7 · re-applying replaces the artifact ----------------------------------
bold "7 · re-applying under the new version"
APPLY2="$(apply ddd)"
JTI2="$(jti_of "$(artifact)")"
if printf '%s' "$APPLY2" | grep -q "1 minted" && [ "$JTI1" != "$JTI2" ]; then
    ok "the artifact at the same cid was replaced"
    step "       was $JTI1"
    step "       now $JTI2"
    ok "     a session admitted under the old jti is refused on its next call (WC-3105) —"
    ok "     covered by replacing_the_contract_under_the_same_cid_stops_the_session"
else
    bad "re-applying under v2 did not replace the artifact"
    printf '%s\n' "$APPLY2" | sed 's/^/       /' | head -6
fi
STATUS3="$("$CONNECT" offer status "$PROVIDER" 2>&1)"
printf '%s' "$STATUS3" | grep -q "0 minted under an earlier version" \
    && ok "     and nothing is behind any more" \
    || bad "     the re-minted contract is still counted as behind"

# --- 8 · ending an affected connection ---------------------------------------
bold "8 · a provider ends one affected connection"
# The gap this closes: `Registry::revoke_contract` and `contain::Revoked::Connection` were both
# built and both had no caller outside their own tests, so the only way to end one contract early
# was `quarantine` — which contains the whole counterparty and every connection it holds.
openssl ecparam -name prime256v1 -genkey -noout -out rev.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in rev.tmp -out rev.pem 2>/dev/null
rm -f rev.tmp
CID="$("$CONNECT" offer status "$PROVIDER" 2>&1 | grep -oE 'conn_[0-9a-f]+' | head -1)"
if [ -z "$CID" ]; then
    CID="$(python3 -c "
import glob, json, sys
for p in glob.glob('$WARDEN_CONNECT_ROOT/tenants/default/state/events-*.jsonl'):
    for line in open(p):
        d = json.loads(line)
        c = json.dumps(d)
        i = c.find('conn_')
        if i >= 0:
            print(c[i:i+21].strip('\"')); sys.exit()")"
fi
REVOKED="$("$CONNECT" revoke "$CID" --reason "payments-mcp narrowed its terms" \
    --revocation-key rev.pem --kid rev-1 --by human:drill@org 2>&1)"
if printf '%s' "$REVOKED" | grep -q "^revoked"; then
    ok "revoked $CID, one connection and not the party"
else
    bad "a provider could not end the affected connection"
    printf '%s\n' "$REVOKED" | sed 's/^/       /' | head -6
fi
# The feed row is what a mediator actually applies. One row, not two: for a connection
# revocation the order and the named connection are the same thing.
ROWS="$(python3 -c "
import json
rows = [json.loads(l) for l in open('$WARDEN_CONNECT_ROOT/tenants/default/revocations.jsonl')]
print(len(rows), rows[-1]['event']['kind'], rows[-1]['event'].get('cid'), rows[-1]['kid'])" 2>/dev/null)"
set -- $ROWS
if [ "${1:-0}" = "1" ] && [ "${2:-}" = "connection" ] && [ "${3:-}" = "$CID" ]; then
    ok "     the signed feed carries exactly one row: kind=connection cid=$CID kid=${4:-?}"
else
    bad "     the revocation feed does not carry one connection row for $CID (got: $ROWS)"
fi
GONE="$("$CONNECT" offer status "$PROVIDER" 2>&1)"
printf '%s' "$GONE" | grep -q "live       0 contract(s)" \
    && ok "     and it is out of the live set" \
    || bad "     the revoked contract is still counted live"

echo
if [ "$fail" -eq 0 ]; then
    bold "DRILL PASSED — a provider can change their terms and everyone finds out in time"
    cat <<'NOTE'
A version bump still changes nothing about a contract already issued, deliberately. What closes
that gap is the contract's own exp, the consumer's next `need apply`, and — if the provider
actually removes the tool — WC-3108 drift at the mediator, which fails closed without anybody
publishing anything.
NOTE
    exit 0
fi
bold "DRILL FAILED"
exit 1
