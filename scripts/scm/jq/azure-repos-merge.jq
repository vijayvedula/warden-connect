# Azure Repos: a single completed PR object -> protocol JSON.
#
# Inputs: $pr (object), $prot ("true"/"false").
#
# The most dangerous of the three to parse loosely. `uniqueName` appears under `createdBy` AND under
# every entry of `reviewers`, and the `sed` version's greedy `.*` took the last one — so `author`
# could be a reviewer while `approvers` picked up the creator. That inversion makes a self-approved
# pull request satisfy separation of duties.
#
# `vote >= 10` only. Azure's 5 is "approved with suggestions", which the previous version counted;
# a qualified yes is not the consent a contract ceiling should rest on, so this is deliberately
# stricter than what it replaced.
{
  merged: true,
  # Already fully qualified in Azure's payload — not prefixed again.
  ref: ($pr.targetRefName // ""),
  protected: ($prot == "true"),
  request_id: (($pr.pullRequestId // 0) | tostring),
  author: ($pr.createdBy.uniqueName // ""),
  approvers: [ (($pr.reviewers // [])[] | select(.vote >= 10) | .uniqueName // empty) ],
  merged_at: 0
}
