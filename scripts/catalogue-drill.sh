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
mkdir -p warden

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

printf '{"tools":[{"name":"get_balance","description":"Read an account balance."},{"name":"transfer_funds","description":"Move money between accounts."}]}' > warden/surface.json
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
"$CONNECT" register server --id "$PROVIDER" --surface warden/surface.json --endpoint stdio://drill \
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
cat > warden/offer.toml <<TERMS
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
PUB="$("$CONNECT" offer publish --surface warden/surface.json --terms warden/offer.toml --kind mcp \
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
cat > warden/needs.toml <<NEEDS
asset = "$CONSUMER"

[[need]]
to = "$PROVIDER"
tools = ["transfer_funds"]
justify = "the drill needs to move money"
ttl = 3600
NEEDS
CHECK="$("$CONNECT" need check --manifest warden/needs.toml 2>&1)"
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
APPLY="$("$CONNECT" need apply --manifest warden/needs.toml --repo drill/recon-bot --sha bbb1 \
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

# --- 7b · the same approval, with no provider key at all --------------------
bold "7b · the provider approves by merging, holding no key"
# Why this matters more than it reads. The signed path above needs every provider team to be issued
# a keypair, get its public half into approvers.toml, and keep the private half safe — per team,
# forever. This path needs them to merge a pull request in a repository they already own, and the
# source host authenticates them. For adoption that is the whole difference.
#
# A separate policy, because `owner_merge_approves` must be DECLARED. Silence stays closed: a merge
# cannot satisfy `approver_role` by default, which is the hole this drill's sibling commit closed.
cat > merge-policy.toml <<POLICY
default = "require_approval"
version = "catalogue-drill@v3"

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
owner_merge_approves = true
ttl_max = "30d"
terms = { evidence_sink = "ocsf://siem", evidence_delivery = "fail-safe" }
reason = "the registered owner approving a merge is the consent here"
POLICY
cat > warden/needs.toml <<NEEDS
asset = "$CONSUMER"

[[need]]
to = "$PROVIDER"
tools = ["transfer_funds"]
justify = "settled by a merge, with no approver key in sight"
ttl = 2400
NEEDS
K="$("$CONNECT" need apply --manifest warden/needs.toml --repo drill/recon-bot --sha eee1 \
    --mediator "$MEDIATOR" "${SHIM_ARGS[@]}" --issuer-key issuer.pem --kid k1 \
    --policy merge-policy.toml 2>&1)"
KREQ="$(printf '%s' "$K" | grep -oE 'req_[a-f0-9]+' | head -1)"
if [ -n "$KREQ" ]; then
    ok "opened $KREQ under the merge-consent policy"
else
    bad "no request was opened for the keyless path"
    printf '%s\n' "$K" | tail -6 | sed 's/^/       /'
fi

mkdir -p emitted
EM="$("$CONNECT" approve "$KREQ" --emit emitted 2>&1)"
if [ -f "emitted/$KREQ.toml" ] && printf '%s' "$EM" | grep -q "no key is needed"; then
    ok "     emitted the file the provider commits"
else
    bad "     no approval file was emitted"
    printf '%s\n' "$EM" | tail -4 | sed 's/^/       /'
fi
# The reviewer has to be able to see what they are approving without decoding a hash.
if grep -q 'items    = \["transfer_funds"\]' "emitted/$KREQ.toml" \
   && grep -q "^digest" "emitted/$KREQ.toml"; then
    ok "     and it states the items in words as well as binding them by digest"
else
    bad "     the file does not show a reviewer what they are approving"
    sed 's/^/       /' "emitted/$KREQ.toml" 2>/dev/null | head -8
fi

# A stub whose approver IS the callee's registered owner. The shared stub answers `s.iyer`, which
# is right for the publish/apply merges — those only need *a* reviewer who is not the author — and
# wrong here, where the whole question is whether that particular person owns the service. The first
# version of this phase used the shared stub and failed with WC-3024, which was the control working.
cat > owner-approves.py <<'OWNER'
#!/usr/bin/env python3
import base64, json, sys
q = json.loads(sys.stdin.read())
if q.get("op") == "merge_evidence":
    print(json.dumps({"merged": True, "ref": "refs/heads/main", "protected": True,
                      "request_id": "88", "approvers": ["payments-owner@org"],
                      "author": "r.mehta"}))
elif q.get("op") == "file":
    print(json.dumps({"content_b64": base64.b64encode(open(q["path"], "rb").read()).decode()}))
else:
    sys.exit(1)
OWNER
KOUT="$("$CONNECT" approve "$KREQ" --merge-repo bank/payments-mcp --sha fff1 \
    --approval-file "emitted/$KREQ.toml" \
    --shim "python3 $WORK/owner-approves.py" --shim-label gh \
    --issuer-key issuer.pem --kid k1 --policy merge-policy.toml 2>&1)"
if printf '%s' "$KOUT" | grep -qE "^issued conn_[a-f0-9]+"; then
    ok "     minted from the merge, with no approver registry and no provider key"
    printf '%s' "$KOUT" | grep -E "^issued|approval |approved " | sed 's/^/       /'
else
    bad "     the merge did not settle the request"
    printf '%s\n' "$KOUT" | tail -8 | sed 's/^/       /'
fi
# And the negative direction, which is what makes the positive mean anything.
cat > wrong-owner.py <<'WRONG'
#!/usr/bin/env python3
import base64, json, sys
q = json.loads(sys.stdin.read())
if q.get("op") == "merge_evidence":
    print(json.dumps({"merged": True, "ref": "refs/heads/main", "protected": True,
                      "request_id": "99", "approvers": ["someone-else"], "author": "r.mehta"}))
elif q.get("op") == "file":
    print(json.dumps({"content_b64": base64.b64encode(open(q["path"], "rb").read()).decode()}))
else:
    sys.exit(1)
WRONG
cat > warden/needs.toml <<NEEDS
asset = "$CONSUMER"

[[need]]
to = "$PROVIDER"
tools = ["transfer_funds"]
justify = "the negative direction for the keyless path"
ttl = 2100
NEEDS
K2="$("$CONNECT" need apply --manifest warden/needs.toml --repo drill/recon-bot --sha eee2 \
    --mediator "$MEDIATOR" "${SHIM_ARGS[@]}" --issuer-key issuer.pem --kid k1 \
    --policy merge-policy.toml 2>&1)"
K2REQ="$(printf '%s' "$K2" | grep -oE 'req_[a-f0-9]+' | head -1)"
"$CONNECT" approve "$K2REQ" --emit emitted >/dev/null 2>&1
WOUT="$("$CONNECT" approve "$K2REQ" --merge-repo bank/payments-mcp --sha fff2 \
    --approval-file "emitted/$K2REQ.toml" --shim "python3 $WORK/wrong-owner.py" --shim-label gh \
    --issuer-key issuer.pem --kid k1 --policy merge-policy.toml 2>&1)"
if printf '%s' "$WOUT" | grep -q "WC-3024"; then
    ok "     a merge approved by anyone else refuses WC-3024 — write access is not consent"
else
    bad "     a merge by a non-owner settled the request"
    printf '%s\n' "$WOUT" | tail -5 | sed 's/^/       /'
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
cat > warden/needs.toml <<NEEDS
asset = "$CONSUMER"

[[need]]
to = "$PROVIDER"
tools = ["get_balance"]
justify = "the control case: is the standing path reachable here at all?"
ttl = 3600
NEEDS
P="$("$CONNECT" need apply --manifest warden/needs.toml --repo drill/recon-bot --sha ddd1 \
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
cat > warden/needs.toml <<NEEDS
asset = "$CONSUMER"

[[need]]
to = "$PROVIDER"
tools = ["transfer_funds"]
justify = "the same guarded item under the most permissive policy available"
ttl = 1800
NEEDS
W="$("$CONNECT" need apply --manifest warden/needs.toml --repo drill/recon-bot --sha ccc1 \
    --mediator "$MEDIATOR" "${SHIM_ARGS[@]}" --issuer-key issuer.pem --kid k1 \
    --policy wide-open.toml 2>&1)"
if printf '%s' "$W" | grep -q "0 minted" && printf '%s' "$W" | grep -qE 'req_[a-f0-9]+'; then
    ok "a gated need mints nothing under the most permissive policy this drill can build"
else
    bad "a wide-open policy minted a term the provider gated"
    printf '%s\n' "$W" | sed 's/^/       /' | head -12
fi

# --- 9 · the reserved paths ---------------------------------------------------
bold "9 · a declaration only counts where a sweep will look"
# The basis of the whole discovery model. `.mcp.json` lives at eight speculative paths belonging to
# other ecosystems, so a scan must try all eight and a miss proves nothing. These paths are ours, so
# one read answers the question — but only if nothing is allowed to declare somewhere else, or the
# estate's inventory under-reports by exactly the repositories that did.
cp warden/needs.toml elsewhere.toml
NS="$("$CONNECT" need check --manifest elsewhere.toml 2>&1)"
if printf '%s' "$NS" | grep -q "WC-8004" && printf '%s' "$NS" | grep -q "warden/needs.toml"; then
    ok "a manifest outside warden/needs.toml is refused, and told where to live"
else
    bad "a declaration at an undiscoverable path was accepted"
    printf '%s\n' "$NS" | tail -4 | sed 's/^/       /'
fi
# Deliberate is different from accidental. A monorepo or a migration needs a way through, and it has
# to be a named one — an operator who meant it says so, and one who did not gets told.
OV="$("$CONNECT" need check --manifest elsewhere.toml --allow-nonstandard-path 2>&1)"
if printf '%s' "$OV" | grep -q "WC-8004"; then
    bad "     --allow-nonstandard-path did not let a deliberate override through"
else
    ok "     and --allow-nonstandard-path is the deliberate way past it"
fi
# The default. An ordinary invocation should not have to name the path at all.
DF="$("$CONNECT" need check 2>&1)"
if printf '%s' "$DF" | grep -q "WC-8004"; then
    bad "     the reserved path is not the default"
else
    ok "     and the reserved path is the default, so the flag is optional"
fi

# --- 10 · the cheap sweep ----------------------------------------------------
bold "10 · discovery reads two paths, not eight"
mkdir -p declared-estate/prov/warden declared-estate/cons/warden declared-estate/both/warden declared-estate/none
cp warden/offer.toml declared-estate/prov/warden/offer.toml
cp warden/needs.toml declared-estate/cons/warden/needs.toml
cp warden/offer.toml declared-estate/both/warden/offer.toml
cp warden/needs.toml declared-estate/both/warden/needs.toml
: > declared-estate/none/README.md
cat > declared-shim.py <<'DSHIM'
#!/usr/bin/env python3
"""A host with no search index, so the sweep must fall back to per-repo reads."""
import base64, json, os, sys
q = json.loads(sys.stdin.read())
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "declared-estate")
op = q.get("op")
if op == "search":
    print(json.dumps({"unsupported": True}))
elif op == "repos":
    print(json.dumps({"repos": [f"bank/{d}" for d in sorted(os.listdir(root))]}))
elif op == "file":
    p = os.path.join(root, q["repo"].split("/", 1)[1], q["path"])
    if os.path.isfile(p):
        with open(p, "rb") as fh:
            print(json.dumps({"content_b64": base64.b64encode(fh.read()).decode()}))
    else:
        print(json.dumps({"absent": True}))
else:
    sys.exit(1)
DSHIM
cat > search-shim.py <<'SSHIM'
#!/usr/bin/env python3
"""A host WITH a search index. Must agree with the crawl, or one of them is lying."""
import json, os, sys
q = json.loads(sys.stdin.read())
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "declared-estate")
if q.get("op") == "search":
    hits = [f"bank/{d}" for d in sorted(os.listdir(root))
            if os.path.isfile(os.path.join(root, d, q["path"]))]
    print(json.dumps({"repos": hits}))
else:
    sys.exit(1)
SSHIM
CRAWL="$("$CONNECT" inventory --declared --org bank --quiet \
    --shim "python3 $WORK/declared-shim.py" --shim-label gh --json 2>&1)"
SEARCH="$("$CONNECT" inventory --declared --org bank --quiet \
    --shim "python3 $WORK/search-shim.py" --shim-label gh --json 2>&1)"
read_field() { printf '%s' "$1" | python3 -c "import json,sys; print(json.load(sys.stdin)$2)" 2>/dev/null; }
CP="$(read_field "$CRAWL" "['providers']")"; SP="$(read_field "$SEARCH" "['providers']")"
CC="$(read_field "$CRAWL" "['consumers']")"; SC="$(read_field "$SEARCH" "['consumers']")"
if [ "$CP" = "['bank/both', 'bank/prov']" ] && [ "$CC" = "['bank/both', 'bank/cons']" ]; then
    ok "the crawl found both providers and both consumers, and not the repo that declares nothing"
else
    bad "the crawl found providers=$CP consumers=$CC"
fi
# The accelerator must agree with the fallback. If they can differ, the count depends on which host
# you asked, which makes the inventory unusable as evidence.
if [ "$CP" = "$SP" ] && [ "$CC" = "$SC" ]; then
    ok "     and the search index agrees exactly with the crawl"
else
    bad "     search and crawl disagree: $SP/$SC vs $CP/$CC"
fi
CN="$(read_field "$CRAWL" "['calls']")"; SN="$(read_field "$SEARCH" "['calls']")"
if [ -n "$CN" ] && [ -n "$SN" ] && [ "$SN" -lt "$CN" ]; then
    ok "     the index cost $SN calls against the crawl's $CN — the reason it exists"
else
    bad "     the index did not cost less than the crawl ($SN vs $CN)"
fi
if printf '%s' "$CRAWL" | grep -q '"via_search": false' \
   && printf '%s' "$SEARCH" | grep -q '"via_search": true'; then
    ok "     and each reports which route answered, so a count can be explained later"
else
    bad "     the sweep does not say which route answered"
fi

# --- 11 · the read-only portal ------------------------------------------------
bold "11 · the portal serves, and offers no way to write"
if ! command -v curl >/dev/null 2>&1; then
    step "curl not present — portal phase skipped, and SKIPPED IS NOT PASSED"
else
openssl ec -in issuer.pem -pubout -out issuer.pub.pem 2>/dev/null
cat > tokens.toml <<'TOKENS'
[[client]]
token = "drill-read"
roles = ["connect.read"]
TOKENS
# `--read-only`, because a portal is a reader. Without it `serve` takes the single-writer lock, and
# a page nobody writes through has no business holding it.
"$CONNECT" serve --listen 127.0.0.1:8971 --read-only --portal \
    --issuer-key issuer.pem --kid k1 --jwks issuer.pub.pem --tokens tokens.toml \
    --insecure-plaintext --policy connect-policy.toml > portal.log 2>&1 &
PORTAL_PID=$!
trap 'kill "$PORTAL_PID" 2>/dev/null' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -sf -o /dev/null -H "Authorization: Bearer drill-read" \
        "http://127.0.0.1:8971/portal" 2>/dev/null && break
    sleep 1
done
CODE="$(curl -s -o portal.html -w '%{http_code}' -H "Authorization: Bearer drill-read" \
    "http://127.0.0.1:8971/portal?as=$CONSUMER" 2>/dev/null)"
if [ "$CODE" = "200" ]; then
    ok "served the page to a caller holding connect.read"
else
    bad "the portal answered $CODE"
    tail -4 portal.log | sed 's/^/       /'
fi
UNAUTH="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8971/portal" 2>/dev/null)"
[ "$UNAUTH" = "401" ] && ok "     and refuses an unauthenticated request (401)" \
                      || bad "     an unauthenticated request got $UNAUTH, not 401"
# The design claim. A button here would be a second consent path for a decision that already has
# one, needing its own authorization model to say who may press it.
if grep -qE "<form|<button|method=\"post\"" portal.html 2>/dev/null; then
    bad "     the page offers a way to write"
else
    ok "     and the page contains no form, button or POST"
fi
# A GET with the headers dumped, not `curl -I`. HEAD is a different method and the route matches
# GET, so `-I` asks a question the portal never answers and the first version of this check read the
# 404's headers instead of the page's.
curl -s -o /dev/null -D portal.hdr -H "Authorization: Bearer drill-read" \
    "http://127.0.0.1:8971/portal" 2>/dev/null
CSP="$(tr -d '\r' < portal.hdr | grep -i '^content-security-policy:')"
if printf '%s' "$CSP" | grep -q "default-src 'none'"; then
    ok "     and ships default-src 'none' — a future edit reaching for a CDN fails in the browser"
else
    bad "     no restrictive CSP on the response"
fi
# The catalogue must be the consumer's own, and the generator must produce the reserved path.
if grep -q "transfer_funds" portal.html && grep -q "warden/needs.toml" portal.html; then
    ok "     the catalogue is rendered for $CONSUMER, and the generator writes the reserved path"
else
    bad "     the page did not render this consumer's catalogue and command"
fi
# With no consumer named there must be no rows at all — a catalogue is always somebody's.
curl -s -o unfiltered.html -H "Authorization: Bearer drill-read" \
    "http://127.0.0.1:8971/portal" 2>/dev/null
if grep -q "choose a consumer" unfiltered.html && ! grep -q "verified merge" unfiltered.html; then
    ok "     and with no consumer named it shows a picker, not an unfiltered catalogue"
else
    bad "     an unfiltered catalogue was rendered"
fi
# Silenced: bash prints "Terminated" to the drill's stderr when a job it started is killed, which
# reads as a failure at the end of a passing run.
kill "$PORTAL_PID" 2>/dev/null
wait "$PORTAL_PID" 2>/dev/null || true
trap - EXIT
fi

# --- 12 · an incremental sweep, and its state as a diff ----------------------
bold "12 · the sweep is incremental, and its answer is a reviewable file"
mkdir -p sweep-estate/r1 sweep-estate/r2 sweep-estate/r3
printf '{"mcpServers":{"a":{"command":"npx","args":["-y","@acme/pay"]}}}'   > sweep-estate/r1/.mcp.json
printf '{"mcpServers":{"b":{"command":"npx","args":["-y","@acme/pay"]}}}'   > sweep-estate/r2/.mcp.json
printf '{"mcpServers":{"c":{"command":"npx","args":["-y","@x/other"]}}}'    > sweep-estate/r3/.mcp.json
cat > sweep-shim.py <<'SWEEP'
#!/usr/bin/env python3
"""A host that dates its repositories, and records the pull requests it is asked to open."""
import base64, json, os, sys
q = json.loads(sys.stdin.read())
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.join(here, "sweep-estate")
PUSHED = {"bank/r1": 1000, "bank/r2": 2000, "bank/r3": 3000}
op = q.get("op")
if op == "repos":
    print(json.dumps({"repos": [{"name": n, "pushed_at": t} for n, t in sorted(PUSHED.items())]}))
elif op == "file":
    # The state repository is not part of the scanned estate, so `absent` for it is correct and is
    # what makes the "nothing to propose" branch reachable only once the file really is on base.
    merged = os.path.join(here, "state-merged", q["path"])
    if q["repo"] == "bank/warden-state":
        if os.path.isfile(merged):
            with open(merged, "rb") as fh:
                print(json.dumps({"content_b64": base64.b64encode(fh.read()).decode()}))
        else:
            print(json.dumps({"absent": True}))
    else:
        p = os.path.join(root, q["repo"].split("/", 1)[1], q["path"])
        if os.path.isfile(p):
            with open(p, "rb") as fh:
                print(json.dumps({"content_b64": base64.b64encode(fh.read()).decode()}))
        else:
            print(json.dumps({"absent": True}))
elif op == "open_pr":
    st = os.path.join(here, "sweep-prs.json")
    try:
        prs = json.load(open(st))
    except Exception:
        prs = {}
    b = q["branch"]
    if b in prs:
        print(json.dumps({"request_id": prs[b], "url": "u/" + prs[b], "created": False}))
    else:
        n = str(700 + len(prs) + 1)
        prs[b] = n
        json.dump(prs, open(st, "w"))
        json.dump(q, open(os.path.join(here, f"sweep-pr-{n}.json"), "w"))
        print(json.dumps({"request_id": n, "url": "u/" + n, "created": True}))
else:
    sys.exit(1)
SWEEP
SWEEP_ARGS=(--shim "python3 $WORK/sweep-shim.py" --shim-label gh)
FULL="$("$CONNECT" inventory --org bank "${SWEEP_ARGS[@]}" --quiet --out inv-full.json 2>&1)"
WM="$(printf '%s' "$FULL" | grep -oE 'watermark  [0-9]+' | awk '{print $2}')"
if [ "$WM" = "3000" ]; then
    ok "a full sweep reports the newest push as the watermark ($WM)"
else
    bad "the watermark was '$WM', expected 3000"
fi
INC="$("$CONNECT" inventory --org bank "${SWEEP_ARGS[@]}" --quiet --since 2000 2>&1)"
SK="$(printf '%s' "$INC" | grep -oE 'skipped    [0-9]+' | awk '{print $2}')"
[ "$SK" = "2" ] && ok "     --since 2000 skipped 2 of 3 — the point of the cursor" \
                || bad "     --since 2000 skipped '$SK', expected 2"
# The one that a unit test cannot reach: the watermark must advance PAST what was skipped, or a
# quiet repository is re-read on every sweep forever.
IWM="$(printf '%s' "$INC" | grep -oE 'watermark  [0-9]+' | awk '{print $2}')"
[ "$IWM" = "3000" ] && ok "     and still reports 3000 — the watermark passes what it skipped" \
                    || bad "     the incremental watermark was '$IWM', expected 3000"

# The state file, as a pull request.
S1="$("$CONNECT" inventory --org bank "${SWEEP_ARGS[@]}" --quiet --state-repo bank/warden-state 2>&1)"
if printf '%s' "$S1" | grep -qE "state      pull req [0-9]+ opened"; then
    ok "     the sweep opened a pull request with its state"
else
    bad "     no state pull request was opened"
    printf '%s\n' "$S1" | tail -4 | sed 's/^/       /'
fi
SPR="$(ls sweep-pr-*.json 2>/dev/null | head -1)"
if [ -n "$SPR" ]; then
    python3 - "$SPR" > state.toml <<'DEC'
import base64, json, sys
q = json.load(open(sys.argv[1]))
print(base64.b64decode(q["files"][0]["content_b64"]).decode(), end="")
DEC
    # One file, so a removal is a removed line. Per-server files could not express a disappearance:
    # the write op is a PUT and there is no delete.
    FILES="$(python3 -c "import json,sys; print(len(json.load(open('$SPR'))['files']))")"
    [ "$FILES" = "1" ] && ok "     as ONE file, so a server disappearing is a removed line" \
                       || bad "     the PR carried $FILES files; a delete cannot be expressed"
    if grep -q 'callers = \["bank/r1", "bank/r2"\]' state.toml; then
        ok "     with callers sorted, so an unchanged estate re-renders byte for byte"
    else
        bad "     callers are not deterministically ordered"
        sed 's/^/       /' state.toml | head -8
    fi
    grep -q "not what anybody approved" state.toml \
        && ok "     and the file says it is derived data that grants nothing" \
        || bad "     the file does not say what it is"
    # Merge it, then re-sweep: an unchanged estate must propose nothing at all.
    mkdir -p state-merged/discovery && cp state.toml state-merged/discovery/inventory.toml
    S2="$("$CONNECT" inventory --org bank "${SWEEP_ARGS[@]}" --quiet --state-repo bank/warden-state 2>&1)"
    if printf '%s' "$S2" | grep -q "unchanged on main"; then
        ok "     and once merged, a re-sweep proposes nothing"
    else
        bad "     a re-sweep of an unchanged estate proposed again"
        printf '%s\n' "$S2" | tail -4 | sed 's/^/       /'
    fi
fi

# --- 13 · zones come from the estate, not from the repository ----------------
bold "13 · an unmapped repository is refused, not guessed into a zone"
cat > zones.toml <<'ZM'
[[repo]]
name = "bank/r1"
zone = "internal.drill"
service = "ITAM-0001"
ZM
ZOUT="$("$CONNECT" inventory promote --from inv-full.json --target "npx -y @acme/pay" \
    --owner human:payments-owner@org --zone internal.drill --by human:drill@org \
    --surface warden/surface.json --zone-map zones.toml --tools get_balance \
    --justify "zone map, fail closed" 2>&1)"
if printf '%s' "$ZOUT" | grep -q "is not in the zone map"; then
    ok "bank/r2 has no row, so it is refused rather than put in a catch-all zone"
else
    bad "an unmapped repository was given a zone anyway"
    printf '%s\n' "$ZOUT" | tail -4 | sed 's/^/       /'
fi
if printf '%s' "$ZOUT" | grep -q "zone internal.drill  service ITAM-0001"; then
    ok "     and a mapped one carries its zone and service from the map"
else
    bad "     the mapped repository did not take its zone from the map"
fi

# --- 14 · the receipt, and what never goes back ------------------------------
bold "14 · a receipt goes back to the repository; the contract never does"
CID="$("$CONNECT" contracts --json 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['cid'] if d else '')" 2>/dev/null)"
if [ -z "$CID" ]; then
    bad "no contract exists to write a receipt for"
else
    mkdir -p receipts state-merged
    "$CONNECT" receipt "$CID" --out receipts >/dev/null 2>&1
    RC="receipts/$CID.toml"
    if [ -f "$RC" ]; then
        ok "rendered a receipt for $CID"
    else
        bad "no receipt was written"
    fi
    # The property this whole design turns on. A signed contract in git is a bearer grant valid
    # until its expiry however the registry changes afterwards, and git cannot express "withdrawn":
    # a deletion is another commit and the blob stays reachable.
    if grep -qE "eyJ|BEGIN [A-Z]+ KEY|BEGIN CERTIFICATE" "$RC" 2>/dev/null; then
        bad "     the receipt carries signed or key material"
    else
        ok "     and it carries no JWS and no key — it grants nothing"
    fi
    grep -q "carries no signature and no key" "$RC" && ok "     and says so, for whoever reads the repo" \
                                                    || bad "     it does not say what it is"
    # Where an auditor should actually look: the pull request where consent happened.
    #
    # Checked against a contract that HAS merge evidence. A key-signed approval records none — the
    # signature is the evidence — so asserting a merge on whichever cid sorts first tested nothing
    # about the receipt and failed on a contract behaving correctly.
    #
    # And checked with grep, not tomllib: this drill's python may predate 3.11, and the first version
    # swallowed the ImportError with 2>/dev/null and reported it as "the receipt does not point at
    # the consent" — a check that cannot run must never render as a finding about the code.
    MERGED_CID="$("$CONNECT" contracts --json 2>/dev/null | python3 -c "
import json,sys
for c in json.load(sys.stdin):
    if c['approval'].get('merges'):
        print(c['cid']); break" 2>/dev/null)"
    if [ -z "$MERGED_CID" ]; then
        bad "     no contract in this estate was settled by a merge, so this cannot be checked"
    else
        "$CONNECT" receipt "$MERGED_CID" --out receipts >/dev/null 2>&1
        MR="receipts/$MERGED_CID.toml"
        MISSING=""
        for field in repo sha request_id author approvers; do
            grep -qE "^${field} *= *(\"[^\"]+\"|\[\"[^\"]+\")" "$MR" || MISSING="$MISSING $field"
        done
        if [ -z "$MISSING" ]; then
            ok "     and for a merge-settled one, names repo, sha, request, author and approvers"
        else
            bad "     the receipt's merge evidence is missing:$MISSING"
            sed -n '/approval.merge/,$p' "$MR" | head -10 | sed 's/^/       /'
        fi
    fi

    # As a pull request, with the same two properties every other write path here needs.
    R1="$("$CONNECT" receipt "$CID" --repo bank/recon-bot --base main \
        --shim "python3 $WORK/sweep-shim.py" --shim-label gh 2>&1)"
    if printf '%s' "$R1" | grep -qE "pull req [0-9]+ opened"; then
        ok "     opened a pull request carrying it"
    else
        bad "     no receipt pull request was opened"
        printf '%s\n' "$R1" | tail -3 | sed 's/^/       /'
    fi
    # Merge it, then re-run: nothing to propose.
    RPR="$(ls sweep-pr-*.json 2>/dev/null | tail -1)"
    if [ -n "$RPR" ]; then
        python3 - "$RPR" <<'DEC'
import base64, json, os, sys
q = json.load(open(sys.argv[1]))
f = q["files"][0]
dest = os.path.join("state-merged", f["path"])
os.makedirs(os.path.dirname(dest), exist_ok=True)
b = f["content_b64"]
open(dest, "wb").write(base64.b64decode(b + "=" * (-len(b) % 4)))
DEC
        R2="$("$CONNECT" receipt "$CID" --repo bank/warden-state --base main \
            --shim "python3 $WORK/sweep-shim.py" --shim-label gh 2>&1)"
        if printf '%s' "$R2" | grep -q "unchanged on main"; then
            ok "     and once merged, a re-run proposes nothing"
        else
            bad "     a re-run proposed the same receipt again"
            printf '%s\n' "$R2" | tail -3 | sed 's/^/       /'
        fi
    fi
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
