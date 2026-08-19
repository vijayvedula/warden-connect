#!/bin/sh
# GitHub shim. Requires `gh` authenticated.
#
# Three ops, and they need different permissions:
#   merge_evidence  needs ADMIN on the repo, because it reads branch protection. A repo:read token
#                   gets 404 there, the shim reports protected:false, and the contract is refused —
#                   fails closed, but reads as a policy problem rather than a token scope.
#   file            repo:read.
#   repos           read:org for private repos.
#
# `date -u -d` below is GNU-only; on macOS it silently yields merged_at 0. Run this on Linux.
#
# UNVERIFIED — see README.md, and probe it before trusting it.
set -eu
q=$(cat)
op=$(printf '%s' "$q" | sed -n 's/.*"op":"\([^"]*\)".*/\1/p')
repo=$(printf '%s' "$q" | sed -n 's/.*"repo":"\([^"]*\)".*/\1/p')
sha=$(printf '%s' "$q" | sed -n 's/.*"sha":"\([^"]*\)".*/\1/p')
path=$(printf '%s' "$q" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')

case "$op" in
file)
  # An explicit absent answer, because the inventory asks about a dozen speculative paths per
  # repository and most are legitimately missing.
  #
  # The first version piped `gh api` straight into awk, so a 404 body was wrapped as `content_b64`
  # and the shim exited 0. It failed safely only by luck — the error text is not valid base64 — and
  # it reported "not standard base64" for a file that was simply not there. A shim that answers
  # confidently when its host said no is the one failure nothing downstream can catch.
  if content=$(gh api "repos/$repo/contents/$path?ref=$sha" -q .content 2>/dev/null) \
     && [ -n "$content" ]; then
    printf '%s' "$content" | tr -d '\n' | awk '{printf "{\"content_b64\":\"%s\"}\n", $0}'
  else
    printf '{"absent":true}\n'
  fi
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
repos)
  # An org or a user. `orgs/X/repos` 404s for a user account, so try both — and note that the first
  # version of this wrapped the 404 body as a repository name and exited 0, which is a shim
  # reporting success on failure. That is the one thing a shim must never do, because nothing
  # downstream can catch it: the inventory would have scanned a repo called `{"message":"Not Found"`.
  #
  # `--paginate` matters too: an org with 400 repos returns 30 by default, and a scan of the first
  # page would report a clean estate for a large one.
  org=$(printf '%s' "$q" | sed -n 's/.*"org":"\([^"]*\)".*/\1/p')
  list=""
  for scope in orgs users; do
    if list=$(gh api --paginate "$scope/$org/repos?per_page=100" -q '.[].full_name' 2>/dev/null) \
       && [ -n "$list" ]; then
      break
    fi
    list=""
  done
  # Empty is a legitimate answer (an org with no repos this token can see) and is reported as such;
  # the CLI says "nothing to scan" rather than "found nothing", because those differ.
  printf '%s' "$list" | awk '
    BEGIN { printf "{\"repos\":[" ; n = 0 }
    /^[A-Za-z0-9._\/-]+$/ { printf "%s\"%s\"", (n++ ? "," : ""), $0 }
    END { print "]}" }'
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
