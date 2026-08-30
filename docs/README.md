# Documentation

| Document | What it is |
|---|---|
| [pitch.html](pitch.html) | Animated walkthrough, 2:36, twelve slides. Open in a browser |
| [contract-and-enforcement.html](contract-and-enforcement.html) | Animated explainer: how a contract and an enforcement point work together |
| [explainer.html](explainer.html) | Slide deck: the problem, the model, the lifecycle, the capabilities |
| [pitch-storyboard.html](pitch-storyboard.html) | Shot list for a generative cut of the pitch |
| [install.md](install.md) | Installing an enforcement point from release artifacts |
| [07-hld.md](07-hld.md) | High-level design |
| [08-lld.md](08-lld.md) | Low-level design, crate by crate |
| [DRILL.md](DRILL.md) | How the system was built, module by module |
| [production-readiness.md](production-readiness.md) | What is closed and what is open |
| [use-cases/](use-cases/) | Ten use cases, one file each |

## The model

warden-connect decides whether a connection may **exist**. A policy engine in
the call path decides whether each **call** on that connection may proceed. That
engine is optional: `wc-mediator` builds standalone by default and enforces
contract, surface pin and revocation without one.

```
effective = contract.surface ∩ token.scope ∩ policy_decision
```

| Term | Owned by | Decided |
|---|---|---|
| `contract.surface` | warden-connect | at issuance |
| `token.scope` | the policy engine | at authentication |
| `policy_decision` | the policy engine | per call |
| `effective` | the policy engine | per call |

The interface is two signed artifacts and one identifier (`cid`).

## The declarative interface

| Path | Written by | Meaning |
|---|---|---|
| `warden/offer.toml` | provider | what this repo provides, and to whom |
| `warden/needs.toml` | consumer | what this repo consumes |
| `warden/surface.json` | provider | the declared surface, as captured |
| `warden/contracts/<cid>.toml` | control plane | a receipt. Never a signed JWS |

A reviewed merge is the approval. Four source hosts are supported, each through
an operator-supplied shim in [`scripts/scm/`](../scripts/scm):

| Host | Shim |
|---|---|
| GitHub | `scripts/scm/github.sh` |
| GitLab | `scripts/scm/gitlab.sh` |
| Azure Repos | `scripts/scm/azure-repos.sh` |
| Bitbucket | `scripts/scm/bitbucket.sh` |

## Use cases

| | Use case | Stage |
|---|---|---|
| UC-01 | [Register and admit an agent](use-cases/UC-01-register-and-admit-an-agent.md) | ① → ② |
| UC-02 | [Onboard a tool server](use-cases/UC-02-onboard-a-tool-server.md) | ① → ② |
| UC-03 | [Mediated capability discovery](use-cases/UC-03-mediated-capability-discovery.md) | ① |
| UC-04 | [Establish a connection](use-cases/UC-04-establish-a-connection.md) | ② |
| UC-05 | [Cross-organisation federation](use-cases/UC-05-cross-organisation-federation.md) | ③ |
| UC-06 | [Surface drift](use-cases/UC-06-surface-drift.md) | ② → ③ |
| UC-07 | [Emergency quarantine](use-cases/UC-07-emergency-quarantine.md) | ② |
| UC-08 | [Shadow estate detection](use-cases/UC-08-shadow-estate-detection.md) | ① |
| UC-09 | [Renewal, review, offboarding](use-cases/UC-09-renewal-review-offboarding.md) | ② → ③ |
| UC-10 | [Regulatory register and evidence](use-cases/UC-10-regulatory-register-and-evidence.md) | ③ |

## Diagrams

Committed as SVG with the Mermaid source beside each one:

```
docs/diagrams/hld-1.mmd            docs/use-cases/diagrams/uc-01.mmd
docs/diagrams/hld-1.svg            docs/use-cases/diagrams/uc-01.svg
```

| Location | Count |
|---|---|
| `docs/diagrams/` | 6 |
| `docs/use-cases/diagrams/` | 10 |

The documents reference the images rather than using ```` ```mermaid ```` fences,
because GitHub overlays a pan/zoom control cluster on every fence it renders and
there is no document-level way to suppress it
([github/community#178929](https://github.com/orgs/community/discussions/178929)).
Review the `.mmd`; the `.svg` is marked `linguist-generated`.

Regenerate after editing a `.mmd`:

```sh
scripts/render-diagrams.sh
```

That script is the only part of the toolchain that needs Node. CI never runs it.

## Note on this rewrite

`docs/` was rebuilt on 2026-08-21. The previous set — capability matrices,
journey maps, threat model, limitations, production readiness, key custody,
runbook, deployment, observability, operations, releasing, conformance,
prerequisites, physical architecture, twelve-factor, identity-without-SPIRE and
the earlier HTML explainers — is in git history at `3f30697`.
