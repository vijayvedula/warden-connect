# Guides

Task-shaped instructions. The design documents are one level up.

| Guide | For |
|---|---|
| [end-to-end.md](end-to-end.md) | **Start here.** Two empty repositories to a contracted call refused at a real gateway — accounts, keys, policy, offer and need, both approval paths, then enforcement at Envoy, Kong or the inline mediator |
| [install.md](install.md) | Installing an enforcement point from release artifacts, without a checkout |

The walkthrough uses GitHub as the source host. Shims for GitLab, Azure Repos
and Bitbucket ship in [`scripts/scm/`](../../scripts/scm/) and answer the same
protocol, documented in [`scripts/scm/README.md`](../../scripts/scm/README.md).
Only the GitHub path has been exercised end to end against a live host — read
the others as templates and run `connect scm probe` against them first.
