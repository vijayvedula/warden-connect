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
search)
  # Not implemented. `unsupported` is not the same answer as "nothing matched", and the
  # caller treats them differently: this makes it fall back to reading the reserved path per
  # repository, where an empty list would have it report an estate with no declarations.
  printf '{"unsupported":true}\n'
  ;;
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
  # Read once, answering both questions: is the ref guarded, and does it require approval from a
  # CODEOWNERS owner of the changed path. `code_owner_approval_required` is a GitLab Premium
  # setting; on Free it is absent, which reads as false — a tier that cannot enforce the control
  # must not report it as enforced.
  pb=$(glab api "projects/$enc/protected_branches/$target" 2>/dev/null) || pb=""
  if [ -n "$pb" ]; then
    prot=true
    owner_review=$(printf '%s' "$pb" \
      | jq -r 'if (.code_owner_approval_required // false) then "true" else "false" end')
  else
    prot=false
    owner_review=false
  fi
  jq -n --argjson mr "$mr" --argjson ap "$ap" --arg prot "$prot" \
     --arg owner_review "$owner_review" -f "$JQDIR/gitlab-merge.jq"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
