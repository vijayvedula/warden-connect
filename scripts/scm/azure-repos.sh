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
  if az repos policy list --project "$proj" --org "$ORG_URL" \
        --query "[?isEnabled && settings.scope[?refName=='refs/heads/$target']] | length(@)" -o tsv 2>/dev/null \
        | grep -qv '^0$'; then prot=true; else prot=false; fi
  jq -n --argjson pr "$pr" --arg prot "$prot" -f "$JQDIR/azure-repos-merge.jq"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
