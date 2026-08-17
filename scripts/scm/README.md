# Source-host shims

Each script answers the two-verb protocol in `crates/wc-control/src/scm.rs`:

```
stdin   {"op":"merge_evidence","repo":"…","sha":"…"}
stdout  {"merged":true,"ref":"refs/heads/main","protected":true,
         "request_id":"214","author":"…","approvers":["…"],"merged_at":0}

stdin   {"op":"file","repo":"…","sha":"…","path":"warden/offer.toml"}
stdout  {"content_b64":"…"}          # STANDARD base64, not base64url
```

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
