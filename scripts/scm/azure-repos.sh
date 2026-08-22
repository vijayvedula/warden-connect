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
  pr=$(az repos pr list --repository "$name" --project "$proj" --org "$ORG_URL" \
        --status completed --query "[?lastMergeCommit.commitId=='$sha'] | [0]" -o json 2>/dev/null) || pr=null
  [ -n "$pr" ] || pr=null
  if [ "$pr" = "null" ]; then printf '{"merged":false,"ref":"","protected":false}\n'; exit 0; fi
  target=$(printf '%s' "$pr" | jq -r '(.targetRefName // "") | sub("^refs/heads/"; "")')
  # A branch policy is Azure's guard. Any enabled policy scoped to the target counts.
  pols=$(az repos policy list --project "$proj" --org "$ORG_URL" -o json 2>/dev/null) || pols='[]'
  [ -n "$pols" ] || pols='[]'
  prot=$(printf '%s' "$pols" | jq -r --arg ref "refs/heads/$target" '
    if any(.[]; .isEnabled and ([ (.settings.scope // [])[] | .refName ] | index($ref)))
    then "true" else "false" end')

  # Azure's CODEOWNERS analogue is the "Automatically included reviewers" policy, and it is the one
  # place a branch policy can be scoped to a path. Four conditions, and dropping any one of them
  # leaves a control that reads as configured and guards nothing:
  #
  #   isEnabled    — a disabled policy is a comment
  #   isBlocking   — a non-blocking policy suggests a reviewer and lets the merge through anyway
  #   scope        — scoped to the ref that was actually merged onto, not some other branch
  #   patterns     — covering the reserved paths. THIS is the trap: a required-reviewers policy on
  #                  /src guards /src. It does not guard warden/offer.toml, and a check that only
  #                  asks "does a policy exist" would call that owner review.
  #
  # Patterns are Azure's own syntax: absolute paths, `*` wildcards, `;`-separated. Only the forms
  # that demonstrably cover the reserved tree are accepted; anything cleverer is refused rather
  # than guessed, because a wrong "yes" here is the whole defect this field exists to prevent.
  RR_TYPE=fd2167ab-b0be-447a-8ec8-39368250530e
  owner_review=$(printf '%s' "$pols" | jq -r --arg ref "refs/heads/$target" --arg t "$RR_TYPE" '
    [ .[]
      | select(.isEnabled and (.isBlocking // false))
      | select(((.type.id // "") | ascii_downcase) == $t)
      | select([ (.settings.scope // [])[] | .refName ] | index($ref))
      | select(
          [ (.settings.filenamePatterns // [])[] | ascii_downcase | ltrimstr("/") ]
          | any(. == "*" or . == "warden/*" or . == "warden/**" or startswith("warden/"))
        )
    ] | if length > 0 then "true" else "false" end')

  jq -n --argjson pr "$pr" --arg prot "$prot" \
     --arg owner_review "$owner_review" -f "$JQDIR/azure-repos-merge.jq"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
