#!/bin/sh
# GitHub shim. Requires `gh` authenticated with repo:read.
# UNVERIFIED — see README.md, and probe it before trusting it.
set -eu
q=$(cat)
op=$(printf '%s' "$q" | sed -n 's/.*"op":"\([^"]*\)".*/\1/p')
repo=$(printf '%s' "$q" | sed -n 's/.*"repo":"\([^"]*\)".*/\1/p')
sha=$(printf '%s' "$q" | sed -n 's/.*"sha":"\([^"]*\)".*/\1/p')
path=$(printf '%s' "$q" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')

case "$op" in
file)
  # `-r .content` is already base64 from the contents API; strip newlines.
  gh api "repos/$repo/contents/$path?ref=$sha" -q .content 2>/dev/null | tr -d '\n' | \
    awk '{printf "{\"content_b64\":\"%s\"}\n", $0}'
  ;;
merge_evidence)
  pr=$(gh api "repos/$repo/commits/$sha/pulls" \
        -H "Accept: application/vnd.github+json" \
        -q '[.[] | select(.merged_at != null)][0]' 2>/dev/null)
  [ -n "$pr" ] && [ "$pr" != "null" ] || { printf '{"merged":false,"ref":"","protected":false}\n'; exit 0; }
  num=$(printf '%s' "$pr" | sed -n 's/.*"number":\([0-9]*\).*/\1/p')
  base=$(printf '%s' "$pr" | sed -n 's/.*"base":{[^}]*"ref":"\([^"]*\)".*/\1/p')
  author=$(printf '%s' "$pr" | sed -n 's/.*"user":{[^}]*"login":"\([^"]*\)".*/\1/p')
  merged_at=$(printf '%s' "$pr" | sed -n 's/.*"merged_at":"\([^"]*\)".*/\1/p')
  approvers=$(gh api "repos/$repo/pulls/$num/reviews" \
        -q '[.[] | select(.state=="APPROVED") | .user.login] | unique | join("\",\"")' 2>/dev/null || true)
  # A protected base branch is what makes the merge evidence of review.
  if gh api "repos/$repo/branches/$base/protection" >/dev/null 2>&1; then prot=true; else prot=false; fi
  ts=$(date -u -d "$merged_at" +%s 2>/dev/null || printf '0')
  printf '{"merged":true,"ref":"refs/heads/%s","protected":%s,"request_id":"%s","author":"%s","approvers":["%s"],"merged_at":%s}\n' \
    "$base" "$prot" "$num" "$author" "$approvers" "$ts"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
