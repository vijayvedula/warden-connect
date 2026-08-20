#!/bin/sh
# GitLab shim. Requires `glab` authenticated, or GITLAB_TOKEN for the curl fallback.
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
# GitLab wants the project path URL-encoded; the nesting is arbitrary so this must not assume depth.
enc=$(printf '%s' "$repo" | sed 's|/|%2F|g')

command -v jq >/dev/null 2>&1 || {
  echo "this shim needs jq: every field is read from its own path, and the sed version it replaced\ncould invert author and approver, which makes a self-approval read as reviewed" >&2
  exit 2
}
JQDIR="$(cd "$(dirname "$0")/jq" && pwd)"

case "$op" in
file)
  epath=$(printf '%s' "$path" | sed 's|/|%2F|g')
  glab api "projects/$enc/repository/files/$epath?ref=$sha" -F . 2>/dev/null \
    | sed -n 's/.*"content":"\([^"]*\)".*/{"content_b64":"\1"}/p'
  ;;
merge_evidence)
  mr=$(glab api "projects/$enc/repository/commits/$sha/merge_requests" 2>/dev/null) || mr="[]"
  [ -n "$mr" ] || mr="[]"
  iid=$(printf '%s' "$mr" | jq -r 'map(select(.state=="merged")) | first | .iid // empty')
  if [ -z "$iid" ]; then printf '{"merged":false,"ref":"","protected":false}\n'; exit 0; fi
  ap=$(glab api "projects/$enc/merge_requests/$iid/approvals" 2>/dev/null) || ap="{}"
  [ -n "$ap" ] || ap="{}"
  target=$(printf '%s' "$mr" | jq -r 'map(select(.state=="merged")) | first | .target_branch // ""')
  if glab api "projects/$enc/protected_branches/$target" >/dev/null 2>&1; then prot=true; else prot=false; fi
  jq -n --argjson mr "$mr" --argjson ap "$ap" --arg prot "$prot" -f "$JQDIR/gitlab-merge.jq"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
