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
| GitHub | [github.html](github.html) | Walked end to end against a live host |
| Azure Repos | [azure-repos.html](azure-repos.html) | **Template.** Shim field paths unverified against a live tenant — probe first |
| Bitbucket Cloud | [bitbucket.html](bitbucket.html) | **Template.** Shim field paths unverified against a live tenant — probe first |

**These are HTML, and GitHub shows HTML as source rather than rendering it.**
Clone the repository and open the file in a browser, or use the "raw" view. Each
is self-contained — no network, no assets, one stylesheet inlined.

Three accounts appear throughout, set as shell variables in the identifiers
step: `$PROVIDER_LOGIN` and `$CONSUMER_LOGIN` own a repository each and approve
on their own side, and `$AUTHOR_LOGIN` commits and opens the pull requests. The
author must never be an approver — that is what the merge-consent check tests.

The shim protocol all three answer is in
[`scripts/scm/README.md`](../../scripts/scm/README.md).
