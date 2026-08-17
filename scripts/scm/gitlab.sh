#!/bin/sh
# GitLab shim. Requires `glab` authenticated, or GITLAB_TOKEN for the curl fallback.
# UNVERIFIED — see README.md, and probe it before trusting it.
set -eu
q=$(cat)
op=$(printf '%s' "$q" | sed -n 's/.*"op":"\([^"]*\)".*/\1/p')
repo=$(printf '%s' "$q" | sed -n 's/.*"repo":"\([^"]*\)".*/\1/p')
sha=$(printf '%s' "$q" | sed -n 's/.*"sha":"\([^"]*\)".*/\1/p')
path=$(printf '%s' "$q" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
# GitLab wants the project path URL-encoded; the nesting is arbitrary so this must not assume depth.
enc=$(printf '%s' "$repo" | sed 's|/|%2F|g')

case "$op" in
file)
  epath=$(printf '%s' "$path" | sed 's|/|%2F|g')
  glab api "projects/$enc/repository/files/$epath?ref=$sha" -F . 2>/dev/null \
    | sed -n 's/.*"content":"\([^"]*\)".*/{"content_b64":"\1"}/p'
  ;;
merge_evidence)
  mr=$(glab api "projects/$enc/repository/commits/$sha/merge_requests" 2>/dev/null \
        | sed -n 's/.*"state":"merged".*/&/p' | head -1)
  [ -n "$mr" ] || { printf '{"merged":false,"ref":"","protected":false}\n'; exit 0; }
  iid=$(printf '%s' "$mr" | sed -n 's/.*"iid":\([0-9]*\).*/\1/p')
  target=$(printf '%s' "$mr" | sed -n 's/.*"target_branch":"\([^"]*\)".*/\1/p')
  author=$(printf '%s' "$mr" | sed -n 's/.*"author":{[^}]*"username":"\([^"]*\)".*/\1/p')
  approvers=$(glab api "projects/$enc/merge_requests/$iid/approvals" 2>/dev/null \
        | sed -n 's/.*"approved_by":\[\(.*\)\].*/\1/p' \
        | tr ',' '\n' | sed -n 's/.*"username":"\([^"]*\)".*/\1/p' | paste -sd'","' -)
  if glab api "projects/$enc/protected_branches/$target" >/dev/null 2>&1; then prot=true; else prot=false; fi
  printf '{"merged":true,"ref":"refs/heads/%s","protected":%s,"request_id":"%s","author":"%s","approvers":["%s"],"merged_at":0}\n' \
    "$target" "$prot" "$iid" "$author" "$approvers"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
