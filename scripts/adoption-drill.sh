#!/usr/bin/env bash
# The adoption drill: from "we have no idea what we have" to a signed contract.
#
#     scripts/adoption-drill.sh
#
# ## Why this exists
#
# It runs the whole adoption path in one go, because that is the claim that matters and every part
# of it was previously demonstrated separately:
#
#     inventory  ->  promote  ->  proposal  ->  reviewed merge  ->  contract
#
# No offer manifests, no needs manifests, no per-team pipelines, no attestation, no KMS, and nothing
# asked of the thirty teams whose repositories were scanned. One repository takes a pull request; its
# merge is the consent.
#
# ## What it proves
#
#   1  a scan finds servers nobody registered, and the repositories that consume them;
#   2  `inventory promote` registers both sides and writes the proposal a PR will carry — one
#      command instead of forty by hand;
#   3  **a promoted server with no known surface refuses to be contracted.** Nothing was probed, so
#      nothing knows what tools exist, and minting on a consumer's wish list would be inventing
#      evidence. The refusal names WC-3010;
#   4  supply the surface and the same merge mints — so the refusal was about missing evidence, not
#      a broken path;
#   5  the pull request is raised by this system and is IDEMPOTENT — a second run finds the one
#      already open rather than queueing a duplicate, and the protocol has no merge op at all, so
#      the approval can only ever be the human's;
#   6  the contract records the derived ids and the merge, and the ids are `urn:` not `spiffe://`,
#      so a discovered row can never masquerade as an attested party.
#
# Phase 3 is the one worth having. A tool that promoted a discovered server straight into a
# contractable party would be manufacturing a surface out of what somebody asked for.
#
# Requires: cargo (built binaries), python3, openssl.
# Exit 0 the path works · 1 it does not · 2 setup.

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

OWNER="human:priya@bank.com"
TARGET="npx -y @acme/mcp-payments"
MEDIATOR="warden:mediator:adoption-drill"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

bold "adoption drill"
step "work dir  $WORK"

cat > connect-policy.toml <<'POLICY'
default = "require_approval"
version = "adoption-drill@v1"

[[zone]]
id = "internal.discovered"
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
reason = "the merge is the approval"
POLICY

openssl ecparam -name prime256v1 -genkey -noout -out i.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in i.tmp -out issuer.pem 2>/dev/null
rm -f i.tmp

# --- an estate nobody has inventoried ----------------------------------------
mkdir -p estate/bank-recon-bot estate/bank-ledger-ui/.vscode
cat > estate/bank-recon-bot/.mcp.json <<CFG
{"mcpServers": {"payments": {"command": "npx", "args": ["-y", "@acme/mcp-payments"]}}}
CFG
cat > estate/bank-ledger-ui/.vscode/mcp.json <<CFG
{"servers": {"payments-mcp": {"command": "npx", "args": ["-y", "@acme/mcp-payments"]}}}
CFG

cat > shim.py <<'SHIM'
#!/usr/bin/env python3
"""A stand-in source host: repositories from ./estate, and a merge approved by WC_APPROVER."""
import base64, json, os, sys
q = json.loads(sys.stdin.read())
op = q.get("op")
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "estate")
if op == "repos":
    names = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)))
    print(json.dumps({"repos": [f"bank/{n.removeprefix('bank-')}" for n in names]}))
elif op == "file":
    repo = q["repo"].split("/", 1)[1]
    path = os.path.join(root, f"bank-{repo}", q["path"])
    if os.path.isfile(path):
        with open(path, "rb") as fh:
            print(json.dumps({"content_b64": base64.b64encode(fh.read()).decode()}))
    else:
        print(json.dumps({"absent": True}))
elif op == "open_pr":
    # Records the request and answers idempotently, keyed by branch — the property that matters.
    state = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prs.json")
    try:
        prs = json.load(open(state))
    except Exception:
        prs = {}
    branch = q["branch"]
    if branch in prs:
        print(json.dumps({"request_id": prs[branch], "url": f"https://stub/pull/{prs[branch]}",
                          "created": False}))
    else:
        num = str(400 + len(prs) + 1)
        prs[branch] = num
        json.dump(prs, open(state, "w"))
        with open(os.path.join(os.path.dirname(state), f"pr-{num}.json"), "w") as fh:
            json.dump(q, fh, indent=2)
        print(json.dumps({"request_id": num, "url": f"https://stub/pull/{num}",
                          "created": True}))
elif op == "merge_evidence":
    print(json.dumps({"merged": True, "ref": "refs/heads/main", "protected": True,
                      "request_id": "77", "author": "dev@bank.com",
                      "approvers": [os.environ.get("WC_APPROVER", "priya@bank.com")]}))
else:
    sys.exit(2)
SHIM

SHIM_ARG=(--shim "python3 $WORK/shim.py" --shim-label gh)

# --- 1 · what have we got? ---------------------------------------------------
bold "1 · scan"
SCAN="$("$CONNECT" inventory "${SHIM_ARG[@]}" --org bank --out inventory.json 2>/dev/null)"
if printf '%s' "$SCAN" | grep -q "1 distinct server"; then
    ok "found one server, declared by two repositories under two different names"
    printf '%s' "$SCAN" | grep -E "^  (scanned|found)" | sed 's/^/     /'
else
    bad "the scan did not find the expected server"
    printf '%s\n' "$SCAN" | sed 's/^/       /' | head -10
    bold "DRILL FAILED"; exit 1
fi

# --- 2 · promote --------------------------------------------------------------
bold "2 · promote, with no surface"
PROMO="$("$CONNECT" inventory promote --from inventory.json --target "$TARGET" \
    --owner "$OWNER" --zone internal.discovered --by "$OWNER" --activate \
    --proposals warden/contracts --tools get_balance \
    --justify "APAC reconciliation needs end-of-day balances" --ticket CHG-4471 2>&1)"
if printf '%s' "$PROMO" | grep -q "urn:wc:mcp:"; then
    ok "registered the server and both consumers, and wrote the proposals"
    printf '%s' "$PROMO" | grep -E "server|consumer|proposal|surface" | sed 's/^/     /' | head -7
else
    bad "promotion did not register the discovered server"
    printf '%s\n' "$PROMO" | sed 's/^/       /' | head -12
    bold "DRILL FAILED"; exit 1
fi
COUNT="$(ls warden/contracts/*.toml 2>/dev/null | wc -l | tr -d ' ')"
[ "$COUNT" = "2" ] && ok "     two proposals, one per consuming repository" \
                   || bad "     wrote $COUNT proposals, expected 2"
printf '%s' "$PROMO" | grep -q "urn:wc:repo:bank-recon-bot" \
    && ok "     consumer ids name the repository that declared it" \
    || bad "     consumer ids do not name their repository"

# --- 3 · the refusal that matters --------------------------------------------
bold "3 · apply, with no surface known"
# Nothing was probed. Minting a contract for `get_balance` here would be inventing evidence out of
# what a consumer asked for, so it must refuse — and name why.
APPLY="$("$CONNECT" proposals apply --dir warden/contracts \
    --repo bank/warden-contracts --sha aaa "${SHIM_ARG[@]}" \
    --mediator "$MEDIATOR" --issuer-key issuer.pem --kid k1 --by "$OWNER" 2>&1)"
RC=$?
# Three outcomes, not two. An earlier version reported "a contract was minted" for a run that had
# refused for an unrelated reason — a false report about the control under test, which is worse than
# either real outcome.
if printf '%s' "$APPLY" | grep -q "^minted"; then
    bad "a contract was minted for tools nobody has evidence exist"
    printf '%s\n' "$APPLY" | sed 's/^/       /' | head -8
elif printf '%s' "$APPLY" | grep -qE "WC-3010|not a subset|subset of"; then
    ok "refused (exit $RC) — a surface nobody has seen cannot be contracted"
    printf '%s' "$APPLY" | grep -m1 -oE "WC-3010.{0,88}" | sed 's/^/       /'
else
    bad "refused (exit $RC), but not for the missing surface — this phase tested nothing"
    printf '%s\n' "$APPLY" | sed 's/^/       /' | head -8
fi

# --- 4 · supply the surface, same merge --------------------------------------
bold "4 · the owner supplies the surface"
printf '{"tools":[{"name":"get_balance","description":"Read an account balance."}]}' > surface.json
REPROMO="$("$CONNECT" inventory promote --from inventory.json --target "$TARGET" \
    --owner "$OWNER" --zone internal.discovered --by "$OWNER" --activate \
    --surface surface.json --proposals warden/contracts --tools get_balance \
    --justify "APAC reconciliation needs end-of-day balances" --ticket CHG-4471 2>&1)"
printf '%s' "$REPROMO" | grep -q "1 item(s) declared" \
    && ok "re-promoted with a declared surface" \
    || bad "the surface was not recorded: $(printf '%s' "$REPROMO" | grep -m1 surface)"

APPLY2="$("$CONNECT" proposals apply --dir warden/contracts \
    --repo bank/warden-contracts --sha bbb "${SHIM_ARG[@]}" \
    --mediator "$MEDIATOR" --issuer-key issuer.pem --kid k1 --by "$OWNER" 2>&1)"
RC2=$?
MINTED="$(printf '%s' "$APPLY2" | grep -c "^minted")"
if [ "$RC2" -eq 0 ] && [ "$MINTED" -ge 1 ]; then
    ok "     and the same merge minted $MINTED contract(s)"
    printf '%s' "$APPLY2" | grep -E "^minted|^  surface|^  ticket" | sed 's/^/       /' | head -6
else
    bad "     the merge did not mint after the surface was supplied (exit $RC2)"
    printf '%s\n' "$APPLY2" | sed 's/^/       /' | head -12
fi

# --- 5 · the pull request ----------------------------------------------------
bold "5 · raising the pull request"
# The trust anchor: a human reads a diff in GitHub. Nothing here can merge — there is no merge op in
# the shim protocol — so the approval is theirs.
rm -f warden/contracts/*.toml prs.json pr-*.json
PR1="$("$CONNECT" inventory promote --from inventory.json --target "$TARGET" \
    --owner "$OWNER" --zone internal.discovered --by "$OWNER" --activate \
    --surface surface.json --proposals warden/contracts --tools get_balance \
    --justify "APAC reconciliation needs end-of-day balances" --ticket CHG-4471 \
    "${SHIM_ARG[@]}" \
    --raise-pr --contracts-repo bank/warden-contracts --base main 2>&1)"
if printf '%s' "$PR1" | grep -q "pull req 401 opened"; then
    ok "opened one pull request carrying both proposals"
    printf '%s' "$PR1" | grep -E "pull req|branch|merge " | sed 's/^/     /'
else
    bad "no pull request was raised"
    printf '%s\n' "$PR1" | tail -6 | sed 's/^/       /'
fi
FILES="$(python3 -c '
import glob, json
f = sorted(glob.glob("pr-*.json"))[0]
q = json.load(open(f))
print(len(q["files"]), q["base"], q["branch"].startswith("warden/propose-"))' 2>/dev/null)"
set -- $FILES
[ "${1:-0}" = "2" ] && ok "     the PR carries 2 files, one per consumer" \
                    || bad "     the PR carries ${1:-0} files, expected 2"
[ "${2:-}" = "main" ] && ok "     against main" || bad "     base is ${2:-none}"
[ "${3:-}" = "True" ] && ok "     on a derived branch name" || bad "     branch is not derived"

# Clicked twice. A nightly scan or a second button press must not queue a duplicate.
PR2="$("$CONNECT" inventory promote --from inventory.json --target "$TARGET" \
    --owner "$OWNER" --zone internal.discovered --by "$OWNER" --activate \
    --surface surface.json --proposals warden/contracts --tools get_balance \
    --justify "APAC reconciliation needs end-of-day balances" --ticket CHG-4471 \
    "${SHIM_ARG[@]}" \
    --raise-pr --contracts-repo bank/warden-contracts --base main 2>&1)"
NPR="$(ls pr-*.json 2>/dev/null | wc -l | tr -d ' ')"
if printf '%s' "$PR2" | grep -q "already open" && [ "$NPR" = "1" ]; then
    ok "     a second run found the same pull request, and opened no other"
else
    bad "     a second run left $NPR pull request(s) — a reviewer facing duplicates reads none"
    printf '%s\n' "$PR2" | sed 's/^/       /' | head -6
fi
# And nothing in the protocol can merge.
if grep -q '"op": *"merge"' "$REPO"/crates/wc-control/src/scm.rs 2>/dev/null; then
    bad "     the shim protocol has a merge op — approval would not be the human's"
else
    ok "     and the shim protocol has no merge op, so it cannot approve its own proposal"
fi

# --- 6 · what the contract says ----------------------------------------------
bold "6 · the record"
ART="$(ls "$WARDEN_CONNECT_ROOT"/tenants/default/state/contracts/*.jws 2>/dev/null | head -1)"
if [ -n "$ART" ]; then
    python3 - "$ART" <<'PY' > rec.txt
import base64, json, sys
seg = open(sys.argv[1]).read().strip().split('.')[1]
seg += '=' * (-len(seg) % 4)
p = json.loads(base64.urlsafe_b64decode(seg))
print(p["caller"]["id"]); print(p["callee"]["id"])
print(p["approval"]["mode"]); print(p["approval"].get("by", "-"))
print(len(p["approval"].get("merges", [])))
print(p["assurance"]["posture"])
PY
    CALLER="$(sed -n 1p rec.txt)"; CALLEE="$(sed -n 2p rec.txt)"
    MODE="$(sed -n 3p rec.txt)"; BY="$(sed -n 4p rec.txt)"
    NM="$(sed -n 5p rec.txt)"; POSTURE="$(sed -n 6p rec.txt)"
    step "caller   $CALLER"
    step "callee   $CALLEE"
    case "$CALLER$CALLEE" in
        *spiffe://*) bad "a derived id was written as a spiffe:// identity" ;;
        *) ok "both ids are urn: — a discovered row cannot masquerade as an attested party" ;;
    esac
    [ "$MODE" = "human" ] && ok "mode human, approved by $BY, with $NM merge record(s)" \
                          || bad "mode is $MODE"
    # Lower-cased: the payload serialises `unattested`, and an earlier version compared against
    # `Unattested` and reported a correct posture as a failure.
    if [ "$(printf '%s' "$POSTURE" | tr 'A-Z' 'a-z')" = "unattested" ]; then
        ok "posture Unattested — correct, and the thing to fix before enforcing"
    else
        bad "posture is $POSTURE; nothing here attested anything"
    fi
else
    bad "no artifact was written"
fi

echo
if [ "$fail" -eq 0 ]; then
    bold "DRILL PASSED — scan to signed contract, with nothing asked of the scanned teams"
    cat <<'NOTE'
What this deliberately does not claim. The ids are derived, so both parties are Unattested and
enforce mode would refuse them — correct for a catalogue, and the work before enforcement. Nothing
was probed: the surface came from the owner, not from this system asking the server what it can do.
NOTE
    exit 0
fi
bold "DRILL FAILED"
exit 1
