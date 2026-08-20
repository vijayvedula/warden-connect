# Bitbucket: a single pullrequests/:id object -> protocol JSON.
#
# Inputs: $pr (object), $prot ("true"/"false").
#
# `participants[] | select(.approved == true)` rather than an awk state machine over `{`-split
# lines. That machine paired "approved": true with whichever nickname followed it, which is not
# necessarily the same participant.
{
  merged: true,
  ref: ("refs/heads/" + ($pr.destination.branch.name // "")),
  protected: ($prot == "true"),
  request_id: (($pr.id // 0) | tostring),
  # `nickname` is not always present; `display_name` is the documented fallback.
  author: ($pr.author.nickname // $pr.author.display_name // ""),
  approvers: [
    (($pr.participants // [])[]
     | select(.approved == true)
     | .user.nickname // .user.display_name // empty)
  ],
  merged_at: 0
}
