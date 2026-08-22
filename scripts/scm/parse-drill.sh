#!/usr/bin/env bash
# Do the SCM shims read `merge_evidence` correctly?
#
#     scripts/scm/parse-drill.sh
#
# ## Why this exists
#
# `merge_evidence` decides two things nothing downstream can second-guess: who authored a merge and
# who approved it. `is_reviewed_merge` needs an approver who is **not** the author, and the keyless
# approval path needs one of those approvers to be the callee's registered owner. Both collapse if
# the two fields are read from the wrong place.
#
# That is not hypothetical. `github.sh` parsed its PR object with
#
#     sed -n 's/.*"user":{[^}]*"login":"\([^"]*\)".*/\1/p'
#
# and a real object contains **three** `"user":{` occurrences. Greedy `.*` took the last, so `author`
# came back EMPTY against a live repository — and an empty author makes every approver differ from
# it, including a self-approval. The three other wrappers had the same shape, and Azure's was worse:
# `uniqueName` appears under `createdBy` and under every reviewer, so author and approver could
# swap places outright.
#
# ## What this checks, and what it cannot
#
# It runs each host's **real** jq program — the same file the wrapper uses, not a copy — against
# fixtures whose correct answer is known, including payloads shaped to defeat greedy matching.
#
# It does **not** verify the field paths against a live host. If GitLab renames `approved_by`, these
# fixtures happily agree with the code and both are wrong together. Only a probe against a real
# tenant closes that, which is what `connect scm probe` is for.
#
# Requires: jq.
# Exit 0 every extraction is correct · 1 one is not · 2 setup.

set -uo pipefail

JQDIR="$(cd "$(dirname "$0")/jq" && pwd)"
command -v jq >/dev/null || { echo "need jq" >&2; exit 2; }

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }
fail=0

# field <json> <path>
field() { printf '%s' "$1" | jq -r "$2"; }

# expect <label> <json> <jq-path> <want>
expect() {
    local got
    got="$(field "$2" "$3")"
    if [ "$got" = "$4" ]; then
        ok "$1"
    else
        bad "$1 — got '$got', want '$4'"
    fi
}

bold "scm merge_evidence parse drill"
echo

# --- GitLab -------------------------------------------------------------------
# Adversarial on purpose: `username` appears for the author AND for two approvers, and the author's
# is FIRST. The sed version took the last match, so it reported an approver as the author.
bold "gitlab"
GL_MR='[
  {"iid": 41, "state": "opened", "target_branch": "develop",
   "author": {"username": "someone-else"}},
  {"iid": 42, "state": "merged", "target_branch": "main",
   "author": {"username": "author-dev"}}
]'
GL_AP='{"approved_by": [
  {"user": {"username": "reviewer-one"}},
  {"user": {"username": "reviewer-two"}}
]}'
GL="$(jq -n --argjson mr "$GL_MR" --argjson ap "$GL_AP" --arg prot true --arg owner_review true -f "$JQDIR/gitlab-merge.jq")"
expect "picks the MERGED request, not the first in the list" "$GL" '.request_id' "42"
expect "     target branch from the merged one"              "$GL" '.ref'        "refs/heads/main"
expect "     author from .author.username, not the last match in the payload" \
       "$GL" '.author' "author-dev"
expect "     approvers from the approvals endpoint"          "$GL" '.approvers | join(",")' "reviewer-one,reviewer-two"
expect "     protected reflects the flag passed in"          "$GL" '.protected'  "true"

# No approvals at all must be an EMPTY array. The sed version pasted into `["$approvers"]`, which
# emits `[""]` — a list containing one empty string. `is_reviewed_merge` refuses that, so it failed
# closed by luck rather than by construction.
GL_NONE="$(jq -n --argjson mr "$GL_MR" --argjson ap '{}' --arg prot false --arg owner_review false -f "$JQDIR/gitlab-merge.jq")"
expect "     no approvals is an empty array, not [\"\"]" "$GL_NONE" '.approvers | length' "0"

# Nothing merged at all.
GL_OPEN="$(jq -n --argjson mr '[{"iid":9,"state":"opened"}]' --argjson ap '{}' --arg prot true --arg owner_review true -f "$JQDIR/gitlab-merge.jq")"
expect "     an unmerged commit reports merged=false" "$GL_OPEN" '.merged' "false"

echo
# --- Bitbucket ----------------------------------------------------------------
# Adversarial: three participants, only the middle one approved. The awk state machine paired
# `"approved": true` with whichever nickname came next in the byte stream, which is not the same
# participant when the keys are ordered as Bitbucket actually orders them.
bold "bitbucket"
BB_PR='{
  "id": 77,
  "destination": {"branch": {"name": "main"}},
  "author": {"nickname": "author-dev"},
  "participants": [
    {"approved": false, "user": {"nickname": "declined-dev"}},
    {"approved": true,  "user": {"nickname": "reviewer-one"}},
    {"approved": false, "user": {"nickname": "lurker-dev"}}
  ]
}'
BB="$(jq -n --argjson pr "$BB_PR" --arg prot true --arg owner_review true -f "$JQDIR/bitbucket-merge.jq")"
expect "only the participant whose own approved flag is true" "$BB" '.approvers | join(",")' "reviewer-one"
expect "     author from .author.nickname"                    "$BB" '.author'  "author-dev"
expect "     ref built from destination.branch.name"          "$BB" '.ref'     "refs/heads/main"
expect "     request_id as a string"                          "$BB" '.request_id' "77"

# `nickname` is not always present. Falling back to display_name beats reporting an empty author,
# because an empty author makes any approver satisfy separation of duties.
BB_DN="$(jq -n --argjson pr '{"id":1,"destination":{"branch":{"name":"main"}},"author":{"display_name":"A Dev"},"participants":[{"approved":true,"user":{"display_name":"R One"}}]}' --arg prot true --arg owner_review true -f "$JQDIR/bitbucket-merge.jq")"
expect "     display_name when nickname is absent" "$BB_DN" '.author' "A Dev"

echo
# --- Azure Repos --------------------------------------------------------------
# The one that mattered most. `uniqueName` appears under createdBy and under every reviewer, and the
# sed version's greedy `.*` took the LAST — so the author could be reported as a reviewer while the
# awk picked up the creator as an approver. Author and approver swapping places is exactly what
# `is_reviewed_merge` exists to prevent.
bold "azure-repos"
AZ_PR='{
  "pullRequestId": 412,
  "targetRefName": "refs/heads/main",
  "createdBy": {"uniqueName": "author-dev@bank.com"},
  "reviewers": [
    {"vote": 10, "uniqueName": "reviewer-one@bank.com"},
    {"vote": -10, "uniqueName": "rejector@bank.com"},
    {"vote": 0,  "uniqueName": "novote@bank.com"},
    {"vote": 5,  "uniqueName": "suggestions@bank.com"}
  ]
}'
AZ="$(jq -n --argjson pr "$AZ_PR" --arg prot true --arg owner_review true -f "$JQDIR/azure-repos-merge.jq")"
expect "author from createdBy, NOT the last uniqueName in the payload" \
       "$AZ" '.author' "author-dev@bank.com"
expect "     only vote>=10 counts as an approval"  "$AZ" '.approvers | join(",")' "reviewer-one@bank.com"
expect "     a rejection is never an approval"     "$AZ" '.approvers | map(select(. == "rejector@bank.com")) | length' "0"
expect "     vote=5 (approved with suggestions) is not counted" \
       "$AZ" '.approvers | map(select(. == "suggestions@bank.com")) | length' "0"
expect "     targetRefName is not prefixed twice" "$AZ" '.ref' "refs/heads/main"

# A self-approval must be reported FAITHFULLY, so `is_reviewed_merge` can refuse it. The shim's job
# is to report, not to judge — but it has to report the same person as both, or the judgement is made
# on a lie.
AZ_SELF="$(jq -n --argjson pr '{"pullRequestId":9,"targetRefName":"refs/heads/main","createdBy":{"uniqueName":"solo@bank.com"},"reviewers":[{"vote":10,"uniqueName":"solo@bank.com"}]}' --arg prot true --arg owner_review true -f "$JQDIR/azure-repos-merge.jq")"
SELF_A="$(field "$AZ_SELF" '.author')"
SELF_R="$(field "$AZ_SELF" '.approvers | join(",")')"
if [ "$SELF_A" = "solo@bank.com" ] && [ "$SELF_R" = "solo@bank.com" ]; then
    ok "     a self-approval reports the same person as author AND approver"
    printf '       so is_reviewed_merge refuses it, which it cannot do if the two are swapped\n'
else
    bad "     a self-approval was not reported faithfully (author=$SELF_A approvers=$SELF_R)"
fi

echo
# --- owner review (W8) --------------------------------------------------------
# The field says: the ref REQUIRES approval from an owner of the changed path. Absent evidence of
# that requirement must read false, never true — an unset field defaulting to "yes" is the exact
# shape of a control that reads as configured and enforces nothing.
bold "owner review"

GL_NO="$(jq -n --argjson mr "$GL_MR" --argjson ap "$GL_AP" --arg prot true --arg owner_review false -f "$JQDIR/gitlab-merge.jq")"
expect "gitlab  carries owner_review through faithfully"  "$GL_NO" '.owner_review | tostring' "false"
BB_NO="$(jq -n --argjson pr "$BB_PR" --arg prot true --arg owner_review false -f "$JQDIR/bitbucket-merge.jq")"
expect "bitbucket carries owner_review through faithfully" "$BB_NO" '.owner_review | tostring' "false"
AZ_NO="$(jq -n --argjson pr "$AZ_PR" --arg prot true --arg owner_review false -f "$JQDIR/azure-repos-merge.jq")"
expect "azure   carries owner_review through faithfully"  "$AZ_NO" '.owner_review | tostring' "false"

# THE AZURE TRAP. A required-reviewers policy that exists, is enabled, is blocking and is scoped to
# the merged ref — and whose file patterns cover /src. It guards /src. It does not guard
# warden/offer.toml. A check that asked only "does a blocking policy exist" would call this owner
# review and be wrong in the one direction that matters.
RR=fd2167ab-b0be-447a-8ec8-39368250530e
az_owner_review() {
    jq -r --arg ref "refs/heads/main" --arg t "$RR" '
      [ .[]
        | select(.isEnabled and (.isBlocking // false))
        | select(((.type.id // "") | ascii_downcase) == $t)
        | select([ (.settings.scope // [])[] | .refName ] | index($ref))
        | select(
            [ (.settings.filenamePatterns // [])[] | ascii_downcase | ltrimstr("/") ]
            | any(. == "*" or . == "warden/*" or . == "warden/**" or startswith("warden/"))
          )
      ] | if length > 0 then "true" else "false" end'
}
pol() { printf '[{"isEnabled":%s,"isBlocking":%s,"type":{"id":"%s"},"settings":{"scope":[{"refName":"%s"}],"filenamePatterns":%s}}]' "$1" "$2" "$3" "$4" "$5"; }

got="$(pol true true "$RR" refs/heads/main '["/src/*"]' | az_owner_review)"
[ "$got" = "false" ] && ok "azure   a blocking policy over /src is NOT owner review of warden/" \
                     || bad "azure   a policy over /src was counted as guarding warden/ — got $got"
got="$(pol true true "$RR" refs/heads/main '["/warden/*"]' | az_owner_review)"
[ "$got" = "true" ]  && ok "azure   a blocking policy over /warden/* IS owner review" \
                     || bad "azure   a policy over /warden/* was not counted — got $got"
got="$(pol true false "$RR" refs/heads/main '["/warden/*"]' | az_owner_review)"
[ "$got" = "false" ] && ok "azure   a NON-BLOCKING policy suggests a reviewer, it does not require one" \
                     || bad "azure   a non-blocking policy was counted — got $got"
got="$(pol false true "$RR" refs/heads/main '["/warden/*"]' | az_owner_review)"
[ "$got" = "false" ] && ok "azure   a DISABLED policy is a comment" \
                     || bad "azure   a disabled policy was counted — got $got"
got="$(pol true true "$RR" refs/heads/develop '["/warden/*"]' | az_owner_review)"
[ "$got" = "false" ] && ok "azure   a policy scoped to another ref does not guard this one" \
                     || bad "azure   a policy on develop was counted for main — got $got"
got="$(pol true true 00000000-0000-0000-0000-000000000000 refs/heads/main '["/warden/*"]' | az_owner_review)"
[ "$got" = "false" ] && ok "azure   only the required-reviewers policy type counts" \
                     || bad "azure   some other policy type was counted — got $got"

echo
if [ "$fail" -eq 0 ]; then
    bold "EVERY EXTRACTION CORRECT"
    cat <<'NOTE'
Each host's real jq program was run — the same file the wrapper loads, not a copy of it. Duplication
is how the sed bug survived in three wrappers after being fixed in the fourth.

Still UNVERIFIED: the field paths themselves. If a host renames a field, these fixtures agree with
the code and both are wrong together. Only `connect scm probe` against a real tenant closes that.
NOTE
    exit 0
fi
bold "AT LEAST ONE EXTRACTION IS WRONG"
echo "Do not run the keyless approval path on that host: merge_evidence gates who may approve."
exit 1
