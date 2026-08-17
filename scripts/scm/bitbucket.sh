#!/bin/sh
# Bitbucket Cloud shim. Requires BITBUCKET_USER and BITBUCKET_APP_PASSWORD.
# `repo` is workspace/slug, or a UUID in braces — passed through as given.
# UNVERIFIED — see README.md, and probe it before trusting it.
set -eu
q=$(cat)
op=$(printf '%s' "$q" | sed -n 's/.*"op":"\([^"]*\)".*/\1/p')
repo=$(printf '%s' "$q" | sed -n 's/.*"repo":"\([^"]*\)".*/\1/p')
sha=$(printf '%s' "$q" | sed -n 's/.*"sha":"\([^"]*\)".*/\1/p')
path=$(printf '%s' "$q" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
API="https://api.bitbucket.org/2.0/repositories/$repo"
AUTH="-u ${BITBUCKET_USER}:${BITBUCKET_APP_PASSWORD}"

case "$op" in
file)
  # shellcheck disable=SC2086
  curl -sf $AUTH "$API/src/$sha/$path" | base64 | tr -d '\n' \
    | awk '{printf "{\"content_b64\":\"%s\"}\n", $0}'
  ;;
merge_evidence)
  # shellcheck disable=SC2086
  prs=$(curl -sf $AUTH "$API/commit/$sha/pullrequests?state=MERGED" 2>/dev/null || true)
  id=$(printf '%s' "$prs" | sed -n 's/.*"id": \([0-9]*\).*/\1/p' | head -1)
  [ -n "$id" ] || { printf '{"merged":false,"ref":"","protected":false}\n'; exit 0; }
  # shellcheck disable=SC2086
  pr=$(curl -sf $AUTH "$API/pullrequests/$id")
  target=$(printf '%s' "$pr" | sed -n 's/.*"destination":.*"branch": {"name": "\([^"]*\)".*/\1/p')
  author=$(printf '%s' "$pr" | sed -n 's/.*"author":.*"nickname": "\([^"]*\)".*/\1/p')
  approvers=$(printf '%s' "$pr" | tr '{' '\n' \
        | awk '/"approved": true/{ok=1} /nickname/{if(ok){gsub(/.*"nickname": "/,"");gsub(/".*/,"");print;ok=0}}' \
        | paste -sd'","' -)
  # shellcheck disable=SC2086
  if curl -sf $AUTH "$API/branch-restrictions?pattern=$target" 2>/dev/null | grep -q '"id"'; then
    prot=true; else prot=false; fi
  printf '{"merged":true,"ref":"refs/heads/%s","protected":%s,"request_id":"%s","author":"%s","approvers":["%s"],"merged_at":0}\n' \
    "$target" "$prot" "$id" "$author" "$approvers"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
