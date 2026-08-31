# Guides

Task-shaped instructions. The design documents are one level up.

| Guide | For |
|---|---|
| [install.md](install.md) | Installing an enforcement point from release artifacts — Envoy, Kong, or the inline mediator |

## Source-host walkthroughs

Each takes two repositories from empty to a verified contract. Same shape
throughout: set the estate up once, then contract one connection per pair.
Every command names the directory it runs from and the identity that runs it.

| Host | Guide | Status |
|---|---|---|
| GitHub | [github.md](github.md) | Exercised end to end against a live host |
| Azure Repos | [azure-repos.md](azure-repos.md) | **Template.** Shim field paths unverified against a live tenant — probe first |
| Bitbucket Cloud | [bitbucket.md](bitbucket.md) | **Template.** Shim field paths unverified against a live tenant — probe first |

Three accounts appear throughout, set as shell variables in the identifiers
step: `$PROVIDER_LOGIN` and `$CONSUMER_LOGIN` own a repository each and approve
on their own side, and `$AUTHOR_LOGIN` commits and opens the pull requests. The
author must never be an approver — that is what the merge-consent check tests.

The shim protocol all three answer is in
[`scripts/scm/README.md`](../../scripts/scm/README.md).
