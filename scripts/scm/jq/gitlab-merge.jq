# GitLab: commits/:sha/merge_requests  +  merge_requests/:iid/approvals -> protocol JSON.
#
# Inputs: $mr (array), $ap (object), $prot ("true"/"false").
#
# Every field comes from its own path. The version this replaced used `sed` with greedy `.*`, so
# `author` matched the LAST "username" anywhere in the payload — usually a reviewer, not the author.
# `is_reviewed_merge` requires an approver who is not the author, so inverting the two makes a
# self-approved merge read as reviewed.
($mr | map(select(.state == "merged")) | first) as $m
| if $m == null then
    { merged: false, ref: "", protected: false }
  else
    {
      merged: true,
      ref: ("refs/heads/" + ($m.target_branch // "")),
      protected: ($prot == "true"),
      request_id: (($m.iid // 0) | tostring),
      author: ($m.author.username // ""),
      # `approved_by[].user.username` — the approvals endpoint, not the MR body.
      approvers: [ (($ap.approved_by // [])[] | .user.username // empty) ],
      merged_at: 0,
      base_sha: ($m.diff_refs.base_sha // "")
    }
  end
