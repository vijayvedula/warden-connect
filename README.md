# warden-connect

**The connection control plane for AI agents.**

A policy engine decides whether an agent may take *an action*. warden-connect decides
whether two parties may be *connected at all*, and bounds what that connection can
ever carry. One is per-call authorisation. The other is the standing relationship the
calls happen inside.

> **Beta.** Not independently audited, and no hardening pass has been run. What this does
> not do is stated in [docs/07-hld.md §7.13](docs/07-hld.md) (open questions) and
> [docs/08-lld.md §8.16b](docs/08-lld.md) (deliberately not built). The detailed
> limitations and production-readiness registers were retired in the 2026-08-21 docs
> rewrite and live in git history at `3f30697`.

---

## The walkthrough, slide by slide

Twelve slides. Under each one, the problem it addresses, and a **Reference** line
into the design documents, the use cases and the end-to-end guide.

### 1 · Title

<img src="docs/slides/slide-01.png" alt="Title slide: warden-connect, the connection control plane for AI agents. Envoy, Kong, inline mediator." width="100%">

Connections between agents and tools are created with no record of who
approved them and no limit on what they can carry.

**Reference** · [HLD](docs/07-hld.md) · [LLD](docs/08-lld.md) · [end-to-end guide](docs/guides/end-to-end.md)

### 2 · The token only names a service

<img src="docs/slides/slide-02.png" alt="A bearer token addressed to one service, next to that server's full tool catalogue. Nothing links the token to individual tools." width="100%">

A bearer token has an audience of one service and carries no list of tools.
`tools/list` returns the server's whole catalogue, so every tool the token
reaches is callable, and nothing records a decision about any individual one.

**Reference** · [HLD §7.1 Scope and context](docs/07-hld.md#71-scope-and-context) · [LLD §8.6.4 the catalogue filter](docs/08-lld.md#864-filter--the-catalogue) · [UC-03 · Mediated capability discovery](docs/use-cases/UC-03-mediated-capability-discovery.md)

### 3 · The same defect, repeated

<img src="docs/slides/slide-03.png" alt="The estate as a graph of agents and tools, every edge an unrecorded connection." width="100%">

The estate is a graph assembled at runtime, not a pair. Every edge has the same
missing record, and nothing enumerates which connections exist.

**Reference** · [HLD §7.1 Scope and context](docs/07-hld.md#71-scope-and-context) · [LLD §8.5.11 inventory](docs/08-lld.md#8511-offer-need-pipeline-scm-proposal-receipt-inventory) · [UC-08 · Shadow estate detection](docs/use-cases/UC-08-shadow-estate-detection.md)

### 4 · Two separate questions

<img src="docs/slides/slide-04.png" alt="Two questions side by side: may this connection exist, answered by warden-connect, and may this call proceed, answered by a policy engine." width="100%">

Per-call authorisation answers whether a call may proceed. Nothing answers
whether the two parties should be connected at all, so that question is never
put.

**Reference** · [HLD §7.6 Two policies, two moments](docs/07-hld.md#two-policies-two-moments) · [HLD §7.7 Integration with a policy engine](docs/07-hld.md#77-integration-with-a-policy-engine) · [LLD §8.5.5 may this contract exist?](docs/08-lld.md#855-cpolicy--may-this-contract-exist)

### 5 · Each side declares in its own repository

<img src="docs/slides/slide-05.png" alt="Two lanes: the provider merges warden/offer.toml, the consumer merges warden/needs.toml, and the control plane folds them into a contract." width="100%">

A connection is normally created by the side that wants it. The party being
called holds no artifact showing that it agreed, and an approval asserted by a
pipeline can be fabricated.

**Reference** · [HLD §7.6 Reserved paths](docs/07-hld.md#reserved-paths) · [LLD §8.5.11 offer, need, scm, authority](docs/08-lld.md#8511-offer-need-pipeline-scm-proposal-receipt-inventory) · [UC-01 · Register an agent](docs/use-cases/UC-01-register-and-admit-an-agent.md) · [UC-02 · Onboard a tool server](docs/use-cases/UC-02-onboard-a-tool-server.md) · [guide §07–§10](docs/guides/end-to-end.md)

### 6 · Three dispositions

<img src="docs/slides/slide-06.png" alt="The three dispositions: granted, needs approval, and refused." width="100%">

Approving every request by hand does not scale, and approving none removes the
decision. A request for something that was never offered has to be
distinguishable from one that is only waiting for an answer.

**Reference** · [LLD §8.5.11 Disposition](docs/08-lld.md#8511-offer-need-pipeline-scm-proposal-receipt-inventory) · [LLD §8.7.2 Issuance](docs/08-lld.md#872-issuance--issuance-authority) · [UC-04 · Establish a connection](docs/use-cases/UC-04-establish-a-connection.md) · [guide §12–§13](docs/guides/end-to-end.md)

### 7 · The contract is stored in three places

<img src="docs/slides/slide-07.png" alt="The contract in three locations: the repository receipt, the control plane, and the enforcement point, where only the last expires." width="100%">

A contract held only in the control plane cannot be enforced while that plane is
unreachable. One held only at the edge cannot be withdrawn.

**Reference** · [LLD §8.8 Storage](docs/08-lld.md#88-storage) · [LLD §8.9.3 Receipts](docs/08-lld.md#893-receipts) · [LLD §8.5.8 containment and distribution](docs/08-lld.md#858-contain-dist-caep--containment) · [HLD §7.11 Non-functional requirements](docs/07-hld.md#711-non-functional-requirements)

### 8 · A contract sets a limit, not a grant

<img src="docs/slides/slide-08.png" alt="The narrowing algebra: effective equals contract surface intersected with token scope and the policy decision." width="100%">

A contract that is forged, over-broad, or issued by a compromised control plane
must not be able to widen what an agent is already permitted to do.

**Reference** · [HLD §7.4 The algebra](docs/07-hld.md#the-algebra) · [LLD §8.7.1 The narrowing algebra](docs/08-lld.md#871-the-narrowing-algebra) · [HLD §7.7 Integration with a policy engine](docs/07-hld.md#77-integration-with-a-policy-engine)

### 9 · Three places to run the check

<img src="docs/slides/slide-09.png" alt="The three enforcement points compared by network cost and by what each can verify about the caller." width="100%">

Enforcement has to fit the topology that already exists, and the caller's
identity is not equally provable at every point in it. A decision reimplemented
per proxy would let the answers diverge.

**Reference** · [HLD §7.9 Deployment topologies](docs/07-hld.md#79-deployment-topologies) · [LLD §8.6b.2 The two bindings](docs/08-lld.md#86b2-the-two-bindings) · [LLD §8.6b.1 The three layers](docs/08-lld.md#86b1-the-three-layers) · [install guide](docs/guides/install.md)

### 10 · The refusal, at three points

<img src="docs/slides/slide-10.png" alt="The same refusal produced at Envoy, at Kong and at the inline mediator." width="100%">

A refusal has to be identical wherever it is enforced, and a tool outside the
contract must not appear in the catalogue the model is given.

**Reference** · [HLD §7.4 Verification — the 14 gates](docs/07-hld.md#verification--fail-closed-at-every-step) · [LLD §8.6.4 the catalogue filter](docs/08-lld.md#864-filter--the-catalogue) · [UC-04 · Establish a connection](docs/use-cases/UC-04-establish-a-connection.md) · [guide §16–§17](docs/guides/end-to-end.md)

### 11 · One revocation reaches every enforcement point

<img src="docs/slides/slide-11.png" alt="One signed revocation reaching every enforcement point, and the hash-chained decision trail." width="100%">

Withdrawing access has to reach every enforcement point, including ones that do
not answer. The record of what was decided has to be checkable by someone who
does not trust the system that wrote it.

**Reference** · [LLD §8.5.8 the revocation feed](docs/08-lld.md#858-contain-dist-caep--containment) · [LLD §8.5.9 the evidence chain](docs/08-lld.md#859-chain-evidence-sink-export-rekor--evidence) · [UC-07 · Emergency quarantine](docs/use-cases/UC-07-emergency-quarantine.md) · [UC-06 · Surface drift](docs/use-cases/UC-06-surface-drift.md) · [UC-10 · Regulatory register and evidence](docs/use-cases/UC-10-regulatory-register-and-evidence.md)

### 12 · Each part has one job

<img src="docs/slides/slide-12.png" alt="The three planes: Git holds the request and receipt, the control plane decides and signs, the enforcement point verifies and enforces." width="100%">

Enforcement has to continue while the control plane is offline, and a
compromised control plane must not be able to manufacture authority.

**Reference** · [HLD §7.2 Architecture overview](docs/07-hld.md#72-architecture-overview) · [LLD §8.3 Crate layout](docs/08-lld.md#83-crate-and-repository-layout) · [HLD §7.8 Trust and threat model](docs/07-hld.md#78-trust-and-threat-model) · [LLD §8.19 The three claims](docs/08-lld.md#819-the-three-claims-this-design-has-to-keep)

## Layout

| Crate | What it is |
|---|---|
| `wc-core` | The artifact. Canonicalisation (`wcs1`), the contract format, signing and verification, the error taxonomy. No HTTP, no async, no filesystem assumptions — embeddable. |
| `wc-control` | The control plane. Registry, admission, approvals, evidence chain, keyring and rotation, screening, attestation, revocation, HTTP API. |
| `wc-cli` | `connect` — everything the API does, from a terminal. |
| `wc-mediator` | The enforcing half: contract cache, surface filter, ceilings, peer identity, JWKS-backed issuer trust. Ships `connect-mediate`. |
| `wc-e2e` | The pyramid above unit tests: e2e, failure injection, property, attestation interop. |

Rust 2021, MSRV 1.89. **No async runtime, no ORM, no database, no ML runtime** — and
that is asserted by [`deny.toml`](deny.toml) rather than promised in prose. Clocks are
injected everywhere, so nothing in the test suite depends on the wall clock.

## Build

```sh
cargo build --workspace          # no external checkout needed
cargo test --workspace           # 1,439 tests
cargo clippy --workspace --all-targets
cargo deny check
./scripts/dep-count.sh           # dependency ceilings, asserted
```

Nothing outside this repository is required to build or test it. The optional
`warden-proxy` feature is the only thing that pulls in a policy engine, and it is off
by default.

## Try it out

[**docs/guides/end-to-end.md**](docs/guides/end-to-end.md) takes two empty
repositories to a contracted call that a real gateway refuses. Every command
names the directory it runs from and the account that runs it.

It uses **GitHub** as the source host, and covers all three enforcement points —
pick one at §14:

| Section | Enforcement point | What it needs |
|---|---|---|
| §14 · Path A | inline mediator — `connect-mediate` | nothing beyond the binaries |
| §15 · Path B | Envoy — `wc-extproc` | Envoy, and mesh certificates |
| §15b · Path C | Kong — `libwc_kong.so` | Docker, and the library built for Kong's container |

Sections §00–§08 stand the estate up once: three accounts, keys, policy,
registration, branch protection, and a shim probe. §09–§13 fill the two
repositories and contract a connection, by the pre-granted path and then the
gated one. §16–§19 prove it, with eight refusals and where each comes from.

Shims for GitLab, Azure Repos and Bitbucket ship in
[`scripts/scm/`](scripts/scm/) and answer the same protocol, but only the GitHub
path has been walked against a live host.

Installing an enforcement point from release artifacts, without a checkout, and
running the control plane behind a TLS-terminating proxy, are in
[docs/guides/install.md](docs/guides/install.md).

`connect --help` is the full CLI surface: registration and attestation, the
connect loop, estate queries (`posture`, `blast-radius`, `discover`), keys and
rotation, air-gapped bundles, CAEP shared signals, evidence export (CSV, JSON,
DORA, CPS 230, OSCAL, BOM), and `serve`.

## Documentation

| | |
|---|---|
| [docs/guides/](docs/guides/) | **Start here.** The end-to-end walkthrough, and installing an enforcement point |
| [docs/07-hld.md](docs/07-hld.md) | High-level design — the plane split, the artifact, the algebra, the trust and threat model, the adoption ladder |
| [docs/08-lld.md](docs/08-lld.md) | Low-level design — every crate, every module, every check, the error taxonomy, the build order |
| [docs/use-cases/](docs/use-cases/) | Ten use cases, one file each, with a sequence diagram per use case |
| [sdk/python/](sdk/python) · [examples/](examples) | A dependency-free client for the control-plane API, and three runnable examples |
| [SECURITY.md](.github/SECURITY.md) | Reporting a vulnerability; what is in and out of scope |

> `docs/` was rebuilt on 2026-08-21. The previous set — capability matrices, journey maps,
> threat model, limitations, production readiness, key custody, runbook, deployment,
> observability, operations, releasing, conformance, prerequisites, physical architecture,
> twelve-factor, and the HTML/video explainer estate — is preserved in git history at
> `3f30697`. Comments throughout the source still cite those paths.

## Conformance

The contract format is meant to be a candidate standard, not a product format: **any
implementation may mint a contract, and a contract is valid iff a conforming verifier
accepts it.** `fixtures/contracts/` is the test vector set — nineteen artifacts and an
`expected.json` naming the `WC-*` code a conforming verifier must produce for each,
including alg confusion, `alg: none`, HMAC substitution, a tampered payload, a
superset surface and a wrong audience.

```sh
scripts/conformance.sh ./my-verifier          # your implementation
scripts/conformance.sh                         # ours, as a self-check
```

Fifteen vectors any verifier can run; four need a mediator (an authenticated peer, a
presented surface, a revocation feed) and are reported as **deferred** rather than passed —
counting them would tell you you had covered nineteen checks when you had covered fifteen.
`fixtures/contracts/README.md` has the calling convention and the version policy.

If your verifier and this one disagree on any vector, one of us has a bug — and that is
a more useful conversation than a specification document.

## Licence

[FSL-1.1-ALv2](LICENSE) — Functional Source License, converting to
[Apache 2.0](LICENSE-APACHE) two years after each release. Use it, run it, modify it;
do not ship a competing product with it until the conversion date.
