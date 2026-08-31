# Setting up GitHub as a source host

warden-connect never talks to GitHub itself. It writes a JSON query to an
operator-supplied shim on stdin and reads one JSON object back on stdout. The
shim is [`scripts/scm/github.sh`](../../scripts/scm/github.sh), and it drives
the `gh` CLI.

That indirection is the point: the credential stays with the operator, and the
control plane holds no source-host token.

## What you need

| | |
|---|---|
| `gh`, authenticated | `gh auth status` must succeed as the user the shim runs as |
| GNU `date` | The shim uses `date -u -d`. On macOS that silently yields `merged_at 0`, so **run this on Linux** |
| A shim path | Passed per command as `--shim "sh scripts/scm/github.sh" --shim-label gh` |

## Token scopes, per operation

The shim answers five operations and they do not need the same rights. Grant
the least that covers the operations you actually use.

| Op | Needs | Why |
|---|---|---|
| `file` | `repo:read` | Reads a reserved path at a commit |
| `repos` | `read:org` | Lists an org's repositories. Only for private repos |
| `search` | `repo:read` | Code-search accelerator. Optional — see below |
| `merge_evidence` | **admin** on the repo | It reads branch protection. A `repo:read` token gets 404 there, the shim reports `protected:false`, and the contract is refused. That fails closed, but it reads as a policy problem rather than a scope problem |
| `open_pr` | `contents:write` + `pull-requests:write` on **one** repo | Opens the proposal PR |

**`open_pr` must not be able to merge.** There is no merge operation in the shim
protocol at all, so the shim cannot merge even if its token could. A human
merges, and a token that could merge its own proposals would be approving on
their behalf.

## Probe before you trust it

The shim is a script on your machine, so nothing about it is guaranteed until
it answers. `scm probe` runs it against a repository you already know the
answers for and compares.

```sh
connect scm probe \
  --shim "sh scripts/scm/github.sh" --label gh \
  --repo your-org/a-repo --sha <a merged commit sha> \
  --expect-ref refs/heads/main \
  --expect-protected \
  --expect-approver some-login \
  --expect-file warden/offer.toml
```

Each `--expect-*` is checked against what the shim actually returned. `--timeout`
bounds the call. Probe before the first real run, and after any change to `gh`
auth or the shim.

Note the flag name: `scm probe` takes `--label`, while every other command below
takes `--shim-label`.

## The reserved paths

Discovery reads these four paths and nothing else. It probes nothing: no port
scans, no endpoint calls, no fetching what a repository has not published.

| Path | Written by | Meaning |
|---|---|---|
| `warden/offer.toml` | provider | this repo provides capability |
| `warden/needs.toml` | consumer | this repo consumes capability |
| `warden/surface.json` | provider | the declared surface, as captured |
| `warden/contracts/<cid>.toml` | control plane | a receipt, never a JWS |

## The flow

```
inventory  →  promote  →  pull request  →  reviewed merge  →  proposals apply  →  receipt
```

**1 · Sweep the org.** Reads reserved paths across repositories and reports what
it found.

```sh
connect inventory --shim "sh scripts/scm/github.sh" --shim-label gh \
  --org your-org --out inventory.json
```

`--paths` overrides which reserved paths are read. `--declared` and `--since`
narrow the sweep. The output reports a watermark and `repos_skipped`, so a
partial sweep never reads as complete coverage.

**2 · Promote what you want to govern.** Registers the parties and writes one
proposal per consuming repository.

```sh
connect inventory promote --from inventory.json --target <server id> \
  --owner human:you@org --zone internal.discovered \
  --tools get_balance --justify "why this connection" --ticket CHG-4471 \
  --proposals warden/contracts --activate \
  --raise-pr --contracts-repo your-org/connect-contracts --base main \
  --shim "sh scripts/scm/github.sh" --shim-label gh
```

Without `--raise-pr` it writes the proposal files and tells you to raise the
pull request yourself. `--raise-pr` is idempotent, keyed by branch: a second run
finds the pull request it already opened rather than opening another.

**3 · A human reviews and merges.** This is the approval. Nothing in the shim
protocol can do it.

**4 · Apply what was merged.** Reads the merge evidence, checks it, and mints.

```sh
connect proposals apply --dir warden/contracts \
  --repo your-org/connect-contracts --sha <merge sha> \
  --shim "sh scripts/scm/github.sh" --shim-label gh \
  --mediator warden:mediator:edge-1 --issuer-key issuer.pem --kid k1 \
  --by human:you@org
```

It refuses rather than inventing evidence. A proposal for a tool on a surface
nothing has captured is refused, and the refusal names why.

**5 · Write the receipt back.** `connect receipt --cid <cid> --repo … --base main`
puts `warden/contracts/<cid>.toml` in the repository. A receipt is
human-readable and digest-bound. **The signed JWS is never committed.**

## Approval, and who counts

`connect-policy.toml` decides whether a contract needs a human at all, and which
role. A rule carrying `approver_role = "security.architect"` means a merge
approval only satisfies it when the approving login maps to that role in the
approver registry — a merge names source-host logins, and without the mapping
nothing connects the two.

Approval is read at the merge's **base commit**, never at the head, so a pull
request that adds its own author to the approver list is not approvable by that
author. A host that does not report a base commit refuses (`WC-3025`) rather
than falling back to the head.

## Two limits worth knowing

| Limit | Behaviour |
|---|---|
| GitHub code search caps at 1000 results however you page it | Past that the shim returns `unsupported`, and the caller falls back to reading reserved paths per repository. It never returns an empty list it cannot stand behind |
| A missing file is an answer | `{"absent":true}`, never an error. Most speculative paths are legitimately missing |

## Other hosts

GitLab, Azure Repos and Bitbucket shims ship in
[`scripts/scm/`](../../scripts/scm/). Merge parsing is at parity; the `repos`
and `open_pr` operations are GitHub-only. Only the GitHub path has been
exercised end to end against a live host, so read the others as templates and
probe them first. The protocol they answer is documented in
[`scripts/scm/README.md`](../../scripts/scm/README.md).
