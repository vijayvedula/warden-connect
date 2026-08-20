# Source-host shims

Each script answers the protocol in `crates/wc-control/src/scm.rs`. Four reads and one write —
and one of the reads is optional, which the protocol makes explicit rather than leaving to a
convention:

```
stdin   {"op":"merge_evidence","repo":"…","sha":"…"}
stdout  {"merged":true,"ref":"refs/heads/main","protected":true,
         "request_id":"214","author":"…","approvers":["…"],"merged_at":0}

stdin   {"op":"file","repo":"…","sha":"…","path":"warden/offer.toml"}
stdout  {"content_b64":"…"}          # STANDARD base64, not base64url
stdout  {"absent":true}              # not there — an ANSWER, not a failure

stdin   {"op":"repos","org":"bank"}
stdout  {"repos":["bank/recon-bot","bank/payments-mcp"]}

stdin   {"op":"search","org":"bank","path":"warden/offer.toml"}
stdout  {"repos":["bank/payments-mcp"]}
stdout  {"unsupported":true}          # cannot answer — NOT the same as "nothing matched"

stdin   {"op":"open_pr","repo":"…","base":"main","branch":"warden/propose-…",
         "title":"…","body":"…","files":[{"path":"…","content_b64":"…"}]}
stdout  {"request_id":"412","url":"https://…/pull/412","created":true}
```

## `unsupported` is not an empty list

`search` is an accelerator. Where a host has a code-search index, one query per reserved path
replaces a read per repository — two calls instead of two per repo. Where it has none, or cannot
answer *completely*, it must say `unsupported`, and the caller falls back to reading the reserved
paths per repository.

Answering `{"repos":[]}` when the index was truncated or absent would report an estate with no
declarations at all, and the caller would believe it. That is why the two answers are different
words: an accelerator that gives up quietly is worse than one that is missing, because nothing
falls back.

`github.sh` refuses partially: GitHub's code search caps at 1000 results however you page it, so
past that it returns `unsupported` and lets the crawl do the work.

## `absent` is an answer, and it matters

A missing file is `{"absent":true}`, never an error and never a confident wrong answer. The first
GitHub wrapper piped `gh api` straight into `awk`, so a 404 body was wrapped as `content_b64` and
the shim exited 0 — it failed safely only by luck, because error text is not valid base64. The same
bug in the `repos` op wrapped a 404 as a repository *name*.

That distinction is load-bearing above this layer: `file_if_present` propagates every failure except
an explicit absence, because a scan with an expired token must report a failure rather than an estate
with no MCP servers in it. "I looked and found nothing" and "I could not look" must never render the
same.

## There is no merge op, deliberately

`open_pr` is the only write, and the token it needs is `contents:write` +
`pull-requests:write` on **one** repository with **no merge rights**. A human merges, in the tool
they already use, and that merge is the consent `merge_evidence` later reads back. A system that
could merge its own proposals would be approving on somebody's behalf, so the capability is absent
rather than merely unused.

Branch protection requiring a review is what enforces it. An estate that has not set it will find
`connect proposals apply` refusing the very merge this produced — which is the right way round.

## Verification status, per script and per op

| Script | `merge_evidence` | `file` | `repos` | `search` | `open_pr` |
|---|---|---|---|---|---|
| `github.sh` | **verified** against a live repo | **verified** | **verified** | UNVERIFIED | **verified** |
| `gitlab.sh` | parse-checked | UNVERIFIED | not implemented | `unsupported` | not implemented |
| `azure-repos.sh` | parse-checked | UNVERIFIED | not implemented | `unsupported` | not implemented |
| `bitbucket.sh` | parse-checked | UNVERIFIED | not implemented | `unsupported` | not implemented |

**parse-checked** is weaker than verified and stronger than nothing. `merge_evidence` for those
three is now read with `jq`, one field at a time, from `scripts/scm/jq/<host>-merge.jq`, and
`scripts/scm/parse-drill.sh` runs each host's real program against fixtures shaped to defeat the
greedy matching the previous `sed` versions used. The **field paths** are still unverified: if a
host renames `approved_by`, the fixtures agree with the code and both are wrong together. Only
`connect scm probe` against a real tenant closes that.

`unsupported` is a legitimate implementation of `search`, not a gap — the caller falls back.

All four `github.sh` ops have now been run against a live repository, including the write:
`open_pr` opened a real pull request, and `merge_evidence` read that merge back.

**The owner refusal is verified against that same real merge**, which is the strongest form the test
takes: one merge, approved by `anupari14`, minted a contract when the callee's registered owner was
`anupari14` and was **refused** when the owner was `vijayvedula`. Same host, same shim, same
approver, same commit — only the registered owner differed, so the refusal can only have come from
the owner check.

Two claims about `merge_evidence` remain stub-only for GitHub, and both because branch protection
prevents producing the input: an **unreviewed** merge, and a **self-approved** one. GitHub will not
let an author approve their own pull request, so the self-approval case is unreachable there by
construction — which is why `is_reviewed_merge` refuses an unnamed author regardless of what the
shim reports, and why hosts that *do* permit self-approval need their wrappers probed before use.

**Verifying `github.sh` found a bug the whole design rests on.** The first version parsed
pull-request JSON with

```sh
sed -n 's/.*"user":{[^}]*"login":"\([^"]*\)".*/\1/p'
```

and a real pull-request object carries **three** `"user":{` occurrences — the PR's own, plus
`head.user` and `base.user`. Greedy `.*` matched the last, which yields nothing, so `author` came
back **empty** against a live repository.

That is not cosmetic. `is_reviewed_merge` requires an approver who is not the author, and an empty
author makes every approver satisfy it — a self-approved merge would have read as reviewed. The
probe *passed*, because the merge it was pointed at genuinely had been reviewed by somebody else:
the check had stopped checking and the answer was right by luck.

Two fixes, and both were needed. Fields now come out through `jq` rather than `sed`, which also
removed a `date -u -d` GNU dependency that silently yielded `merged_at: 0` on macOS. And
`MergeEvidence::is_reviewed_merge` refuses an **unnamed** author outright, because an empty author is
*unknown*, not *nobody* — that half does not depend on any shim being right.

The lesson for the three unverified scripts: **do not parse JSON with `sed`.** Two of the three still
do.

`connect scm probe` exists for this. Run it against a commit you already know the answer for,
before trusting a shim with anything:

```sh
connect scm probe --shim "./scripts/scm/github.sh" --label gh \
  --repo bank/payments-mcp --sha 05e9bde \
  --expect-ref refs/heads/main --expect-protected --expect-approver s.iyer
```

A shim that has not been probed is a shim nobody has run.

## Why the answer is trusted at all

A signing shim cannot lie — cryptography catches it. **An SCM shim can**: its answer is just JSON,
and one that returns `{"merged":true}` mints a contract on fabricated evidence. So a shim is a
trusted component, deployed on the control-plane host by the platform team with the same care as
the plane's own configuration. Never consumer-supplied, never fetched at request time.

## Vocabulary, normalised

| Concept | GitHub | GitLab | Azure Repos | Bitbucket |
|---|---|---|---|---|
| review unit | Pull Request | Merge Request | Pull Request | Pull Request |
| approval | review state `APPROVED` | approval | reviewer vote ≥ 10 | `approved: true` |
| branch guard | protection / ruleset | protected branch | branch policy | branch restriction |
| repo identity | `org/repo` | `group/…/project` | `org/project/repo` | `workspace/slug` |

`repo` is opaque and is never parsed by the core — three of those four are not two-part paths.
