#!/bin/sh
# Azure Repos shim. Requires `az` with the azure-devops extension, AZURE_DEVOPS_EXT_PAT set.
# `repo` is org/project/repo — three parts, which is why the core never parses it.
# UNVERIFIED — see README.md, and probe it before trusting it.
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

case "$op" in
file)
  az repos show --repository "$name" --project "$proj" --org "$ORG_URL" >/dev/null
  # No `az` verb returns file bytes; the REST item endpoint does.
  rid=$(az repos show --repository "$name" --project "$proj" --org "$ORG_URL" --query id -o tsv)
  az rest --method get --uri \
    "$ORG_URL/$proj/_apis/git/repositories/$rid/items?path=$path&versionDescriptor.version=$sha&versionDescriptor.versionType=commit&api-version=7.1" \
    --output tsv 2>/dev/null | base64 | tr -d '\n' | awk '{printf "{\"content_b64\":\"%s\"}\n", $0}'
  ;;
merge_evidence)
  # Reviewer vote >= 10 is an approval in Azure DevOps.
  pr=$(az repos pr list --repository "$name" --project "$proj" --org "$ORG_URL" \
        --status completed --query "[?lastMergeCommit.commitId=='$sha'] | [0]" -o json 2>/dev/null)
  [ -n "$pr" ] && [ "$pr" != "null" ] || { printf '{"merged":false,"ref":"","protected":false}\n'; exit 0; }
  id=$(printf '%s' "$pr" | sed -n 's/.*"pullRequestId": \([0-9]*\).*/\1/p')
  target=$(printf '%s' "$pr" | sed -n 's|.*"targetRefName": "refs/heads/\([^"]*\)".*|\1|p')
  author=$(printf '%s' "$pr" | sed -n 's/.*"createdBy":.*"uniqueName": "\([^"]*\)".*/\1/p')
  approvers=$(printf '%s' "$pr" | tr '{' '\n' \
        | awk '/"vote": (10|5)/{ok=1} /uniqueName/{if(ok){gsub(/.*"uniqueName": "/,"");gsub(/".*/,"");print;ok=0}}' \
        | paste -sd'","' -)
  # A branch policy is Azure's guard. Any enabled policy on the target counts.
  if az repos policy list --project "$proj" --org "$ORG_URL" \
        --query "[?isEnabled && settings.scope[?refName=='refs/heads/$target']] | length(@)" -o tsv 2>/dev/null \
        | grep -qv '^0$'; then prot=true; else prot=false; fi
  printf '{"merged":true,"ref":"refs/heads/%s","protected":%s,"request_id":"%s","author":"%s","approvers":["%s"],"merged_at":0}\n' \
    "$target" "$prot" "$id" "$author" "$approvers"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
