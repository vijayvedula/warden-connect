# Source-host shims

Each script answers the protocol in `crates/wc-control/src/scm.rs`. Three reads and one write:

```
stdin   {"op":"merge_evidence","repo":"…","sha":"…"}
stdout  {"merged":true,"ref":"refs/heads/main","protected":true,
         "request_id":"214","author":"…","approvers":["…"],"merged_at":0}

stdin   {"op":"file","repo":"…","sha":"…","path":"warden/offer.toml"}
stdout  {"content_b64":"…"}          # STANDARD base64, not base64url
stdout  {"absent":true}              # not there — an ANSWER, not a failure

stdin   {"op":"repos","org":"bank"}
stdout  {"repos":["bank/recon-bot","bank/payments-mcp"]}

stdin   {"op":"open_pr","repo":"…","base":"main","branch":"warden/propose-…",
         "title":"…","body":"…","files":[{"path":"…","content_b64":"…"}]}
stdout  {"request_id":"412","url":"https://…/pull/412","created":true}
```

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

## These are UNVERIFIED

They are written from each vendor's API documentation and **have never been run against a real
tenant**. That is precisely the position `docs/limitations.md` records for anything not backed by
an executed script — and the class the four wrong SPIRE commands came from.

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
