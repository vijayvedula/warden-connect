#!/bin/sh
# Azure Repos shim. Requires `az` with the azure-devops extension, AZURE_DEVOPS_EXT_PAT set.
# `repo` is org/project/repo — three parts, which is why the core never parses it.
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
org=$(printf '%s' "$repo" | cut -d/ -f1)
proj=$(printf '%s' "$repo" | cut -d/ -f2)
name=$(printf '%s' "$repo" | cut -d/ -f3-)
ORG_URL="https://dev.azure.com/$org"

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
  az repos show --repository "$name" --project "$proj" --org "$ORG_URL" >/dev/null
  # No `az` verb returns file bytes; the REST item endpoint does.
  rid=$(az repos show --repository "$name" --project "$proj" --org "$ORG_URL" --query id -o tsv)
  az rest --method get --uri \
    "$ORG_URL/$proj/_apis/git/repositories/$rid/items?path=$path&versionDescriptor.version=$sha&versionDescriptor.versionType=commit&api-version=7.1" \
    --output tsv 2>/dev/null | base64 | tr -d '\n' | awk '{printf "{\"content_b64\":\"%s\"}\n", $0}'
  ;;
merge_evidence)
  # A FAILED CALL IS NOT AN ANSWER. This was `2>/dev/null) || pr=null`, so a 401, a wrong
  # org/project/repo, or a missing extension produced the same `null` as "no completed pull
  # request" — and the shim then reported {"merged":false}. warden-connect refuses with
  # WC-1001 and sends an operator to look at their branch. Same defect as the GitHub shim
  # carried until 0b35539; the `file` verb in this file already had the lesson in a comment.
  if ! pr=$(az repos pr list --repository "$name" --project "$proj" --org "$ORG_URL" \
        --status completed --query "[?lastMergeCommit.commitId=='$sha'] | [0]" -o json 2>&1); then
    printf 'az could not list pull requests for %s\n%s\n' "$repo" "$pr" >&2
    printf 'repo must be ORG/PROJECT/REPO, and AZURE_DEVOPS_EXT_PAT must have Code (read) and Policy (read)\n' >&2
    exit 3
  fi
  [ -n "$pr" ] || pr=null
  if [ "$pr" = "null" ]; then printf '{"merged":false,"ref":"","protected":false}\n'; exit 0; fi
  target=$(printf '%s' "$pr" | jq -r '(.targetRefName // "") | sub("^refs/heads/"; "")')

  # A REVIEW policy, not any policy. This used to count any enabled policy scoped to the ref,
  # so a build-validation policy alone made the ref read as guarded — and `protected` is what
  # says a merge onto it is evidence of review. Detected by `minimumApproverCount` rather than
  # by a policy-type GUID: the behaviour is the thing being asserted, and a GUID is a second
  # spelling of it that can drift.
  if ! policies=$(az repos policy list --project "$proj" --org "$ORG_URL" -o json 2>&1); then
    printf 'az could not list branch policies for %s\n%s\n' "$proj" "$policies" >&2
    printf 'the PAT needs Policy (read)\n' >&2
    exit 3
  fi
  prot=$(printf '%s' "$policies" | jq -r --arg ref "refs/heads/$target" '
    [ .[]
      | select(.isEnabled and (.isBlocking // false))
      | select((.settings.minimumApproverCount // 0) >= 1)
      | select([ (.settings.scope // [])[] | .refName ] | index($ref))
    ] | if length > 0 then "true" else "false" end')
  jq -n --argjson pr "$pr" --arg prot "$prot" -f "$JQDIR/azure-repos-merge.jq"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
