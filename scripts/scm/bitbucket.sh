#!/bin/sh
# Bitbucket Cloud shim. Requires BITBUCKET_USER and BITBUCKET_APP_PASSWORD.
# `repo` is workspace/slug, or a UUID in braces — passed through as given.
# UNVERIFIED — see README.md, and probe it before trusting it.
# CHANGED: `merge_evidence` is now parsed with jq, one field at a time, from
# scripts/scm/jq/. It used to use `sed` with greedy `.*`, which could read the author from a
# reviewer's record — and author/approver swapping places is exactly what `is_reviewed_merge`
# exists to prevent. `scripts/scm/parse-drill.sh` checks the extraction against fixtures; the
# FIELD PATHS are still unverified against a live host, so probe before trusting it.
set -eu
q=$(cat)
op=$(printf '%s' "$q" | sed -n 's/.*"op":"\([^"]*\)".*/\1/p')
repo=$(printf '%s' "$q" | sed -n 's/.*"repo":"\([^"]*\)".*/\1/p')
sha=$(printf '%s' "$q" | sed -n 's/.*"sha":"\([^"]*\)".*/\1/p')
path=$(printf '%s' "$q" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
API="https://api.bitbucket.org/2.0/repositories/$repo"
AUTH="-u ${BITBUCKET_USER}:${BITBUCKET_APP_PASSWORD}"

command -v jq >/dev/null 2>&1 || {
  echo "this shim needs jq: every field is read from its own path, and the sed version it replaced\ncould invert author and approver, which makes a self-approval read as reviewed" >&2
  exit 2
}
JQDIR="$(cd "$(dirname "$0")/jq" && pwd)"

case "$op" in
search)
  # Not implemented. `unsupported` is not the same answer as "nothing matched", and the
  # caller treats them differently: this makes it fall back to reading the reserved path per
  # repository, where an empty list would have it report an estate with no declarations.
  printf '{"unsupported":true}\n'
  ;;
file)
  # shellcheck disable=SC2086
  curl -sf $AUTH "$API/src/$sha/$path" | base64 | tr -d '\n' \
    | awk '{printf "{\"content_b64\":\"%s\"}\n", $0}'
  ;;
merge_evidence)
  # shellcheck disable=SC2086
  prs=$(curl -sf $AUTH "$API/commit/$sha/pullrequests?state=MERGED" 2>/dev/null) || prs='{}'
  [ -n "$prs" ] || prs='{}'
  id=$(printf '%s' "$prs" | jq -r '(.values // []) | first | .id // empty')
  if [ -z "$id" ]; then printf '{"merged":false,"ref":"","protected":false}\n'; exit 0; fi
  # shellcheck disable=SC2086
  pr=$(curl -sf $AUTH "$API/pullrequests/$id") || pr='{}'
  [ -n "$pr" ] || pr='{}'
  target=$(printf '%s' "$pr" | jq -r '.destination.branch.name // ""')
  # shellcheck disable=SC2086
  restrictions=$(curl -sf $AUTH "$API/branch-restrictions?pattern=$target" 2>/dev/null) || restrictions='{}'
  [ -n "$restrictions" ] || restrictions='{}'
  prot=$(printf '%s' "$restrictions" | jq -r 'if ((.values // []) | length) > 0 then "true" else "false" end')

  # RESIDUAL, recorded rather than papered over: Bitbucket Cloud has no path-scoped code owners.
  # Default reviewers are a property of the repository, so the strongest thing this host can say is
  # "a default reviewer approved" — not "the owner of warden/offer.toml approved". GitHub, GitLab
  # and Azure Repos can all scope to the path; Bitbucket Cloud cannot, and reporting parity it does
  # not have would make the weakest host look like the strongest.
  #
  # `require_default_reviewer_approvals_to_merge` with value >= 1 is the closest true statement, so
  # that is what is reported. Bitbucket Data Center does have code owners; this shim targets Cloud.
  owner_review=$(printf '%s' "$restrictions" | jq -r '
    if any((.values // [])[];
           (.kind == "require_default_reviewer_approvals_to_merge") and ((.value // 0) >= 1))
    then "true" else "false" end')

  jq -n --argjson pr "$pr" --arg prot "$prot" \
     --arg owner_review "$owner_review" -f "$JQDIR/bitbucket-merge.jq"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
