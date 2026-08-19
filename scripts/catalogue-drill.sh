#!/usr/bin/env bash
# The catalogue drill: a consumer browses, asks, and the provider decides.
#
#     scripts/catalogue-drill.sh
#
# ## Why this exists
#
# `offer.rs` says what an offer is in one line: **"An offer only ever permits the asking."** Until
# this drill existed, the only approval mode that worked contradicted it. `pre_granted` auto-issued;
# `named_consumer` — the mode where the provider decides each consumer, which is the one a provider
# can actually write on the day they publish, before any consumer exists — returned
# `NeedsNamedApproval`, and `match_need` pushed that onto the **refusal** list with the words "not
# wired yet".
#
# So the provider's most guarded terms were the only ones that could not be used at all, and the
# most permissive were the only ones that worked. That is the inversion this drill exists to keep
# closed.
#
# ## What it proves
#
#   1  a provider publishes terms naming an audience, not a consumer, on day one;
#   2  a consumer sees only what their own zone and tier were offered — and a consumer outside
#      every audience sees nothing at all, not an empty row;
#   3  a guarded item is reported as PENDING, not REFUSED, and does not fail the way a
#      "nobody offers you this" would;
#   4  `need apply` opens a request instead of minting;
#   5  the estate's role holder alone cannot approve it (WC-3024) — the provider's own consent
#      is missing;
#   6  the provider's registered owner alone cannot either (WC-3020) — the estate's rules are;
#   7  both together mint the contract;
#   8  a gated need mints nothing under the most permissive policy this drill can build.
#
#      Phase 8 does NOT prove the standing-policy guard. It cannot: `cpolicy` never gives standing
#      work to an `Unattested` party, so the standing path is unreachable here. That guard is
#      covered by a mutation-checked unit test, and phase 8 carries a tripwire that fires if the
#      fixture ever changes enough to make the phase real.
#
# ## What it does not claim
#
# * **That the provider's owner is who they say they are.** The approval is a signature against a
#   key in `approvers.toml`. Binding that key to a person is the directory's job, not this system's.
# * **That standing policy cannot waive a gated term.** See phase 8 — proven in
#   `crates/wc-control/src/issuance.rs`, not here.
# * **That the catalogue is unenumerable.** It proves the filter works. A consumer *can* enumerate
#   everything offered to their own audience, deliberately — that is what the provider consented to
#   expose. `connect discover` and its throttle still cover the rest.
#
# Requires: cargo (built binaries), python3, openssl.
# Exit 0 the path works · 1 it does not · 2 setup.

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
OUTSIDER="spiffe://drill.example/ns/agents/sa/partner-bot"
PROVIDER="spiffe://drill.example/ns/svc/sa/payments-mcp"
MEDIATOR="warden:mediator:catalogue-drill"
NOW="$(date +%s)"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

bold "catalogue drill"
step "work dir   $WORK"
echo

# --- the estate ---------------------------------------------------------------
# `default = "allow"` on purpose, and it is load-bearing for phase 8. The broadest possible estate
# policy must still not satisfy a term the provider gated — if it did, the provider's consent would
# be a formality any permissive rule could waive.
cat > connect-policy.toml <<'POLICY'
default = "allow"
version = "catalogue-drill@v1"

[[zone]]
id = "internal.drill"
trust = "internal"
[[zone]]
id = "partner.acme"
trust = "partner"

[standing]
reviewed_at = 0

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
decision = "require_approval"
approver_role = "drill.operator"
ttl_max = "30d"
terms = { evidence_sink = "ocsf://siem", evidence_delivery = "fail-safe" }
reason = "the provider's own consent is what is under test, not the estate's"
POLICY

printf '{"tools":[{"name":"get_balance","description":"Read an account balance."},{"name":"transfer_funds","description":"Move money between accounts."}]}' > surface.json
printf '{"name":"recon","description":"The drill consumer.","version":"1.0.0","skills":[{"id":"drive","name":"drive","description":"Drives the drill."}]}' > card.json

openssl ecparam -name prime256v1 -genkey -noout -out issuer.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in issuer.tmp -out issuer.pem 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out a1.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in a1.tmp -out arch.priv.pem 2>/dev/null
openssl ec -in arch.priv.pem -pubout -out arch.pub.pem 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out a2.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in a2.tmp -out owner.priv.pem 2>/dev/null
openssl ec -in owner.priv.pem -pubout -out owner.pub.pem 2>/dev/null
rm -f issuer.tmp a1.tmp a2.tmp

# Two distinct humans, and the separation is the whole point. `arch` holds the estate's role and
# owns nothing; `payments-owner` owns the provider and holds no role.
cat > approvers.toml <<'APPROVERS'
[[approver]]
id = "human:arch@org"
key = "arch.pub.pem"
roles = ["drill.operator"]

[[approver]]
id = "human:payments-owner@org"
key = "owner.pub.pem"
roles = []
APPROVERS

"$CONNECT" register agent --card card.json --owner human:drill@org --zone internal.drill \
    --id "$CONSUMER" --by human:drill@org >/dev/null 2>&1
"$CONNECT" register agent --card card.json --owner human:drill@org --zone partner.acme \
    --id "$OUTSIDER" --by human:drill@org >/dev/null 2>&1
# The provider is owned by payments-owner. That registration is what makes the owner check mean
# something later — the owner is read from the registry, never from a flag on the approval.
"$CONNECT" register server --id "$PROVIDER" --surface surface.json --endpoint stdio://drill \
    --owner human:payments-owner@org --zone internal.drill --by human:drill@org >/dev/null 2>&1
for id in "$CONSUMER" "$OUTSIDER" "$PROVIDER"; do
    "$CONNECT" activate "$id" --by human:drill@org >/dev/null 2>&1
done

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

# --- 1 · the provider publishes, knowing no consumer -------------------------
bold "1 · a provider publishes terms about an audience, not about a consumer"
cat > offer.toml <<TERMS
asset = "$PROVIDER"

[[term]]
items = ["get_balance"]
approval = "pre_granted"
ttl_max = 604800
to = { zone = "internal.*" }

[[term]]
items = ["transfer_funds"]
approval = "named_consumer"
ttl_max = 3600
to = { zone = "internal.*" }
TERMS
PUB="$("$CONNECT" offer publish --surface surface.json --terms offer.toml --kind mcp \
    --repo drill/payments-mcp --sha aaa1 --version 1 "${SHIM_ARGS[@]}" 2>&1)"
if printf '%s' "$PUB" | grep -qiE "version 1|published"; then
    ok "published, naming no consumer at all"
else
    bad "the offer did not publish"
    printf '%s\n' "$PUB" | tail -4 | sed 's/^/       /'
    bold "DRILL FAILED"; exit 1
fi

# --- 2 · the catalogue, per consumer -----------------------------------------
bold "2 · the catalogue shows each consumer only their own audience"
CAT="$("$CONNECT" offer list --as "$CONSUMER" 2>&1)"
if printf '%s' "$CAT" | grep -q "now      get_balance" \
   && printf '%s' "$CAT" | grep -q "on ask   transfer_funds"; then
    ok "the in-audience consumer sees both, split by what they can do next"
    printf '%s' "$CAT" | grep -E "now |on ask " | sed 's/^/     /'
else
    bad "the catalogue did not split pre-granted from on-ask"
    printf '%s\n' "$CAT" | sed 's/^/       /' | head -12
fi

# The security property. An empty row would tell a partner the asset exists; absence tells them
# nothing, which is what makes a browsable catalogue safe to hand out at all.
OUT="$("$CONNECT" offer list --as "$OUTSIDER" 2>&1)"
if printf '%s' "$OUT" | grep -q "Nothing is offered" \
   && ! printf '%s' "$OUT" | grep -q "payments-mcp"; then
    ok "     a consumer outside every audience is not told the asset exists"
else
    bad "     the out-of-audience consumer learned something"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -8
fi

# --- 3 · a gate is not a refusal ---------------------------------------------
bold "3 · a guarded item is PENDING, not REFUSED"
cat > needs.toml <<NEEDS
asset = "$CONSUMER"

[[need]]
to = "$PROVIDER"
tools = ["transfer_funds"]
justify = "the drill needs to move money"
ttl = 3600
NEEDS
CHECK="$("$CONNECT" need check --manifest needs.toml 2>&1)"
if printf '%s' "$CHECK" | grep -q "^PENDING" \
   && ! printf '%s' "$CHECK" | grep -q "^REFUSED"; then
    ok "reported as awaiting the provider, not as unavailable"
    printf '%s' "$CHECK" | grep -E "PENDING|items|next" | sed 's/^/     /'
else
    bad "a gated need was reported as a refusal"
    printf '%s\n' "$CHECK" | sed 's/^/       /' | head -10
fi
# Distinct wording matters as much as the distinct state: "your provider must say yes" and "nobody
# offers you this" send a team to different people.
if printf '%s' "$CHECK" | grep -q "awaiting the provider"; then
    ok "     and the summary counts it apart from a refusal"
else
    bad "     the summary does not distinguish the two"
fi

# --- 4 · the ask opens a request ---------------------------------------------
bold "4 · need apply opens a request and mints nothing"
APPLY="$("$CONNECT" need apply --manifest needs.toml --repo drill/recon-bot --sha bbb1 \
    --mediator "$MEDIATOR" "${SHIM_ARGS[@]}" --issuer-key issuer.pem --kid k1 2>&1)"
REQ="$(printf '%s' "$APPLY" | grep -oE 'req_[a-f0-9]+' | head -1)"
if [ -n "$REQ" ] && printf '%s' "$APPLY" | grep -q "0 minted"; then
    ok "opened $REQ, minted nothing"
    printf '%s' "$APPLY" | grep -E "request|gated|approver " | sed 's/^/     /'
else
    bad "no request was opened, or something was minted anyway"
    printf '%s\n' "$APPLY" | sed 's/^/       /' | head -14
    bold "DRILL FAILED"; exit 1
fi
if printf '%s' "$APPLY" | grep -q "payments-owner@org"; then
    ok "     naming the provider's registered owner as the approver"
else
    bad "     the request does not name the owner who must approve"
fi

approve() {  # approve <req> <by> <key> [second-by second-key]
    local req="$1" by="$2" key="$3"; shift 3
    if [ "$#" -eq 2 ]; then
        "$CONNECT" approve "$req" --by "$by" --approver-key "$key" \
            --second "$1" --second-key "$2" \
            --approvers approvers.toml --policy connect-policy.toml \
            --issuer-key issuer.pem --kid k1 2>&1
    else
        "$CONNECT" approve "$req" --by "$by" --approver-key "$key" \
            --approvers approvers.toml --policy connect-policy.toml \
            --issuer-key issuer.pem --kid k1 2>&1
    fi
}

# --- 5 · the estate's role holder is not the provider ------------------------
bold "5 · the estate's approver alone cannot give the provider's consent"
A="$(approve "$REQ" human:arch@org arch.priv.pem)"
if printf '%s' "$A" | grep -q "WC-3024"; then
    ok "refused WC-3024 — the role was satisfied, the provider's consent was not"
    printf '%s' "$A" | grep -oE "WC-3024.*" | cut -c1-96 | sed 's/^/     /'
else
    bad "a role holder alone approved a term the provider guarded"
    printf '%s\n' "$A" | sed 's/^/       /' | head -6
fi

# --- 6 · nor is the provider the estate -------------------------------------
bold "6 · the provider's owner alone does not satisfy the estate"
B="$(approve "$REQ" human:payments-owner@org owner.priv.pem)"
if printf '%s' "$B" | grep -q "WC-3020"; then
    ok "refused WC-3020 — neither consent waives the other"
else
    bad "the owner alone approved without the estate's required role"
    printf '%s\n' "$B" | sed 's/^/       /' | head -6
fi

# --- 7 · both --------------------------------------------------------------
bold "7 · both consents mint the contract"
C="$(approve "$REQ" human:arch@org arch.priv.pem human:payments-owner@org owner.priv.pem)"
if printf '%s' "$C" | grep -qE "conn_[a-f0-9]+"; then
    ok "minted"
    printf '%s' "$C" | grep -oE "conn_[a-f0-9]+" | head -1 | sed 's/^/     /'
else
    bad "both consents were present and nothing minted"
    printf '%s\n' "$C" | sed 's/^/       /' | head -10
fi

# --- 8 · the standing-policy guard, and why this drill cannot prove it -------
bold "8 · standing policy and a gated term — what this drill can and cannot show"
# Read this before trusting the phase. The first version of it asserted "escalated to a request even
# under default = allow" and called that proof of the guard in `Issuer::request`. It was not: with
# the guard deleted the phase still passed, because the escalation had a different cause.
#
# `cpolicy` §5 never gives standing work to a party that is not `Attested`, and both parties here are
# `Unattested` — reaching `Attested` needs the DSSE material `attest-drill.sh` builds. So
# `ConnDecision::Allow` cannot survive evaluation in this fixture at all, and the standing path is
# structurally unreachable no matter how permissive the policy is.
#
# The guard is proven by `standing_policy_cannot_satisfy_a_term_the_provider_gated` in
# `crates/wc-control/src/issuance.rs`, which seeds an attested tier-3 callee, confirms the control
# case really is minted with no human, and is mutation-checked: forcing its condition false fails it.
cat > wide-open.toml <<POLICY
default = "allow"
version = "catalogue-drill@v2"

[[zone]]
id = "internal.drill"
trust = "internal"

[standing]
enabled = true
reviewed_at = $((NOW - 3600))
review_every = "90d"
min_callee_tier = 1
allow_write = true
max_tools = 8
max_per_window = 500

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
decision = "allow"
ttl_max = "30d"
terms = { evidence_sink = "ocsf://siem", evidence_delivery = "fail-safe" }
reason = "as permissive as this system allows"
POLICY
cat > needs3.toml <<NEEDS
asset = "$CONSUMER"

[[need]]
to = "$PROVIDER"
tools = ["get_balance"]
justify = "the control case: is the standing path reachable here at all?"
ttl = 3600
NEEDS
P="$("$CONNECT" need apply --manifest needs3.toml --repo drill/recon-bot --sha ddd1 \
    --mediator "$MEDIATOR" "${SHIM_ARGS[@]}" --issuer-key issuer.pem --kid k1 \
    --policy wide-open.toml 2>&1)"
# A tripwire, not a pass. If somebody later attests these parties, standing becomes reachable, this
# assertion fires, and the note above stops being true — which is exactly when it needs rewriting.
if printf '%s' "$P" | grep -q "issued by standing policy"; then
    bad "the standing path IS reachable now — phase 8's stated reason is stale and the escalation"
    bad "assertion below can finally be made real. Rewrite this phase."
else
    step "standing path unreachable here (both parties Unattested), as documented above."
    step "The guard is covered by the unit test named in this phase's comment, not by this drill."
fi
# Still worth asserting, but for what it is: under the most permissive policy this drill can build,
# a gated need does not mint. Attributed to nothing in particular — several controls would each stop
# it, and that redundancy is itself worth keeping.
cat > needs2.toml <<NEEDS
asset = "$CONSUMER"

[[need]]
to = "$PROVIDER"
tools = ["transfer_funds"]
justify = "the same guarded item under the most permissive policy available"
ttl = 1800
NEEDS
W="$("$CONNECT" need apply --manifest needs2.toml --repo drill/recon-bot --sha ccc1 \
    --mediator "$MEDIATOR" "${SHIM_ARGS[@]}" --issuer-key issuer.pem --kid k1 \
    --policy wide-open.toml 2>&1)"
if printf '%s' "$W" | grep -q "0 minted" && printf '%s' "$W" | grep -qE 'req_[a-f0-9]+'; then
    ok "a gated need mints nothing under the most permissive policy this drill can build"
else
    bad "a wide-open policy minted a term the provider gated"
    printf '%s\n' "$W" | sed 's/^/       /' | head -12
fi

echo
if [ "$fail" -eq 0 ]; then
    bold "DRILL PASSED — browse, ask, and the provider decides"
    cat <<'NOTE'
The provider named an audience on the day they published and never named a consumer. The consumer
found them, asked, and got a contract only once the provider's registered owner signed for it —
which is what `offer.rs` meant by "an offer only ever permits the asking".

What this deliberately does not claim: that the owner's key belongs to the owner. That binding is
the directory's job. And a consumer *can* enumerate everything offered to their own audience — that
is what the provider consented to expose, and `connect discover` still covers the rest.
NOTE
    exit 0
fi
bold "DRILL FAILED"
exit 1
