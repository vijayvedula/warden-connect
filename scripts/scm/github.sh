#!/bin/sh
# GitHub shim. Requires `gh` authenticated.
#
# Three ops, and they need different permissions:
#   merge_evidence  needs ADMIN on the repo, because it reads branch protection. A repo:read token
#                   gets 404 there, the shim reports protected:false, and the contract is refused —
#                   fails closed, but reads as a policy problem rather than a token scope.
#   file            repo:read.
#   repos           read:org for private repos.
#   open_pr         contents:write + pull-requests:write on ONE repo, and NO merge rights. There is
#                   no merge op here on purpose: a human merges, and a token that could merge its own
#                   proposals would be approving on their behalf.
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
# `org` is used by `repos` and `search`. These extractions read warden-connect's OWN query — a flat
# object it generated — not a host's API response, which is why sed is acceptable here and was not
# in `merge_evidence`. Parsing what you emitted is a different risk from parsing what you were told.
org=$(printf '%s' "$q" | sed -n 's/.*"org":"\([^"]*\)".*/\1/p')

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
  # Fields come out with jq, not sed. The first version parsed this JSON with
  #   sed -n 's/.*"user":{[^}]*"login":"\([^"]*\)".*/\1/p'
  # and a real pull-request object contains **three** `"user":{` occurrences (the PR's own, plus
  # head.user and base.user). Greedy `.*` matched the last one, which yields nothing — so `author`
  # came back EMPTY against a live repository.
  #
  # That is not a cosmetic bug. `is_reviewed_merge` requires an approver who is not the author, and
  # an empty author makes any approver satisfy it — including a self-approval. The separation-of-duties
  # check was vacuous, and it passed the probe because the answer happened to be right for a merge
  # that genuinely was reviewed by somebody else. `MergeEvidence` now refuses an unnamed author, and
  # this stops producing one.
  #
  # `merged_at` is converted by jq too, which removes the `date -u -d` GNU dependency that silently
  # yielded 0 on macOS.
  pr=$(gh api "repos/$repo/commits/$sha/pulls" \
        -H "Accept: application/vnd.github+json" \
        -q '[.[] | select(.merged_at != null)][0]
            | [ (.number|tostring),
                .base.ref,
                (.user.login // ""),
                ((.merged_at // "") | if . == "" then 0 else fromdateiso8601 end | tostring)
              ] | @tsv' 2>/dev/null) || pr=""
  if [ -z "$pr" ]; then
    printf '{"merged":false,"ref":"","protected":false}\n'
    exit 0
  fi
  num=$(printf '%s' "$pr" | cut -f1)
  base=$(printf '%s' "$pr" | cut -f2)
  author=$(printf '%s' "$pr" | cut -f3)
  ts=$(printf '%s' "$pr" | cut -f4)

  # Approvers as a JSON array straight from jq, so an empty result is `[]` and not `[""]`. The old
  # `join` produced a single empty string, which `is_reviewed_merge` had to defend against.
  approvers=$(gh api "repos/$repo/pulls/$num/reviews" \
        -q '[.[] | select(.state=="APPROVED") | .user.login] | unique' 2>/dev/null) || approvers="[]"
  [ -n "$approvers" ] || approvers="[]"
  approvers=$(printf '%s' "$approvers" | tr -d ' \n')

  # A protected base branch is what makes the merge evidence of review. Needs ADMIN on the repo: a
  # repo:read token gets 404 here and this reports false, which fails closed and reads as a policy
  # problem rather than a token scope.
  if gh api "repos/$repo/branches/$base/protection" >/dev/null 2>&1; then prot=true; else prot=false; fi

  printf '{"merged":true,"ref":"refs/heads/%s","protected":%s,"request_id":"%s","author":"%s","approvers":%s,"merged_at":%s}\n' \
    "$base" "$prot" "$num" "$author" "$approvers" "$ts"
  ;;
search)
  # Repositories containing an exact path, from the code-search index. An accelerator: the caller
  # falls back to reading the path per repository, which has no index lag and no result cap.
  #
  # `path:` is an exact match on the full path, so this only works because warden-connect reserves
  # it. The 100-per-page cap is honoured explicitly — a truncated answer reported as complete would
  # make discovery under-report silently, so `truncated` is returned and the caller re-reads.
  q=$(printf 'org:%s path:%s' "$org" "$path")
  page=1; out=""; truncated=false
  while :; do
    body=$(gh api -X GET "search/code" -f "q=$q" -f "per_page=100" -f "page=$page" 2>/dev/null) || break
    names=$(printf '%s' "$body" | jq -r '[.items[]?.repository.full_name] | unique | .[]' 2>/dev/null)
    [ -n "$names" ] && out=$(printf '%s\n%s' "$out" "$names")
    total=$(printf '%s' "$body" | jq -r '.total_count // 0')
    # GitHub's code search returns at most 1000 results however you page it.
    if [ "$total" -gt 1000 ]; then truncated=true; fi
    got=$(printf '%s' "$body" | jq -r '(.items // []) | length')
    [ "$got" -lt 100 ] && break
    page=$((page + 1))
    [ "$page" -gt 10 ] && { truncated=true; break; }
  done
  if [ "$truncated" = true ]; then
    # Refuse rather than answer partially. An accelerator that quietly drops repositories is worse
    # than one that is absent, because the caller stops falling back.
    printf '{"unsupported":true}\n'
    echo "code search returned more than it can page through; falling back to per-repo reads" >&2
    exit 0
  fi
  printf '%s' "$out" | jq -R -s 'split("\n") | map(select(length > 0)) | unique | {repos: .}'
  ;;
repos)
  # An org or a user. `orgs/X/repos` 404s for a user account, so try both — and note that the first
  # version of this wrapped the 404 body as a repository name and exited 0, which is a shim
  # reporting success on failure. That is the one thing a shim must never do, because nothing
  # downstream can catch it: the inventory would have scanned a repo called `{"message":"Not Found"`.
  #
  # `--paginate` matters too: an org with 400 repos returns 30 by default, and a scan of the first
  # page would report a clean estate for a large one.
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
open_pr)
  # The ONE write. There is deliberately no merge op: a human merges, in GitHub, and a system that
  # could merge its own proposals would be approving on somebody's behalf.
  #
  # Needs `contents:write` and `pull-requests:write` on THIS repository only, and must not be able
  # to merge. Branch protection requiring a review is what enforces that — and it is the same
  # protection `merge_evidence` reads back, so an estate that has not set it will find
  # `proposals apply` refusing the merge this produced.
  #
  # Idempotent: the branch name is derived from the content by the caller, so a button clicked twice
  # finds the open pull request rather than opening a second one. A reviewer facing forty identical
  # PRs stops reading all of them.
  base=$(printf '%s' "$q" | python3 -c 'import json,sys; print(json.load(sys.stdin)["base"])')
  branch=$(printf '%s' "$q" | python3 -c 'import json,sys; print(json.load(sys.stdin)["branch"])')
  title=$(printf '%s' "$q" | python3 -c 'import json,sys; print(json.load(sys.stdin)["title"])')
  body=$(printf '%s' "$q" | python3 -c 'import json,sys; print(json.load(sys.stdin)["body"])')

  base_sha=$(gh api "repos/$repo/git/ref/heads/$base" -q .object.sha 2>/dev/null) || base_sha=""
  [ -n "$base_sha" ] || { echo "cannot read $base on $repo" >&2; exit 1; }

  # Create the branch. Already existing is not an error: this is the second click.
  gh api "repos/$repo/git/refs" -X POST -f "ref=refs/heads/$branch" -f "sha=$base_sha" \
    >/dev/null 2>&1 || true

  # One PUT per file. An existing file needs its blob sha, or the contents API rejects the update —
  # and a proposal amended on a second run is the ordinary case, not an error.
  printf '%s' "$q" | python3 -c '
import json, sys
for f in json.load(sys.stdin)["files"]:
    print(f["path"] + "\t" + f["content_b64"])' | while IFS="$(printf "\t")" read -r path content; do
    existing=$(gh api "repos/$repo/contents/$path?ref=$branch" -q .sha 2>/dev/null) || existing=""
    if [ -n "$existing" ]; then
      gh api "repos/$repo/contents/$path" -X PUT -f "message=$title" -f "content=$content" \
        -f "branch=$branch" -f "sha=$existing" >/dev/null || exit 1
    else
      gh api "repos/$repo/contents/$path" -X PUT -f "message=$title" -f "content=$content" \
        -f "branch=$branch" >/dev/null || exit 1
    fi
  done || { echo "cannot write files to $branch" >&2; exit 1; }

  # Open it, or find the one already open for this head.
  num=$(gh api "repos/$repo/pulls" -X POST -f "title=$title" -f "body=$body" \
        -f "head=$branch" -f "base=$base" -q .number 2>/dev/null) || num=""
  created=true
  if [ -z "$num" ]; then
    created=false
    owner=${repo%%/*}
    num=$(gh api "repos/$repo/pulls?state=open&head=$owner:$branch" -q '.[0].number' 2>/dev/null) \
      || num=""
  fi
  [ -n "$num" ] && [ "$num" != "null" ] || { echo "no pull request for $branch" >&2; exit 1; }
  printf '{"request_id":"%s","url":"https://github.com/%s/pull/%s","created":%s}\n' \
    "$num" "$repo" "$num" "$created"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
