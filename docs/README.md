# Documentation

| Document | What it is |
|---|---|
| [explainer.html](explainer.html) | **Start here.** A 21-slide self-building deck: the problem, the model, the lifecycle, the capabilities. Open it in a browser |
| [07-hld.md](07-hld.md) | High-level design — the plane split, the contract, the algebra, the trust model |
| [08-lld.md](08-lld.md) | Low-level design — every crate, every module, every check, the build order |
| [use-cases/](use-cases/) | Ten use cases, one file each, with a sequence diagram per use case |

## The one-paragraph version

warden-connect decides whether a connection between two parties may **exist**.
warden decides whether each **call** on that connection may proceed. The
interface between them is two signed artifacts and one identifier (`cid`).
A contract is a **ceiling, never a grant**:

```
effective = contract.surface ∩ token.scope ∩ policy_decision
```

warden-connect owns `contract.surface`, the terms and the `cid`. warden owns
`token.scope` and `policy_decision`, and computes the intersection.

## The declarative interface

| Path | Written by | Meaning |
|---|---|---|
| `warden/offer.toml` | provider | this repo provides capability |
| `warden/needs.toml` | consumer | this repo consumes capability |
| `warden/surface.json` | provider | the declared surface, as captured |
| `warden/contracts/<cid>.toml` | control plane | a receipt — never a signed JWS |

A reviewed merge is the approval. Supported on GitHub, Azure DevOps and
Bitbucket — same paths, same flow.

## Use cases at a glance

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

## Note on this rewrite

`docs/` was rebuilt on 2026-08-21. The previous set — capability matrices,
journey maps, threat model, limitations, production readiness, key custody,
runbook, deployment, observability, operations, releasing, conformance,
prerequisites, physical architecture, twelve-factor, identity-without-SPIRE, and
the HTML/video explainer estate — is preserved in full at
`~/aisec/backups/warden-connect-docs-20260821/` and in git history at `3f30697`.
