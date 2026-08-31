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

## The problem

An enterprise agent estate is not agent-to-tool. It is agent → agent → tool → agent,
across teams, vendors and jurisdictions, assembled at runtime by whoever wrote the
prompt. Every hop is a new trust decision that nobody made:

```
     user ──▶ orchestrator ──▶ research agent ──▶ vendor agent ──▶ payments MCP
                    │                 │                                  │
                    └──▶ ledger MCP   └──▶ another org's agent ──────────┘
```

Per-call authorisation answers *"may this call proceed?"*. It cannot answer:

- Which of these parties are allowed to talk to each other **at all**?
- Who approved that, when, and against what justification?
- What is the **most** this connection could ever do, even if the policy engine is
  misconfigured, the token is over-scoped and the agent is compromised?
- When something goes wrong, **what else** did that party reach?

A connection with no ceiling is an unbounded connection. That is the gap.

## The model

Two enforcement layers, and the relationship between them is the whole design:

```
effective = contract.surface  ∩  token.scope  ∩  policy_decision
```

**A contract is a ceiling, never a grant.** It can only ever narrow. A contract naming
`transfer_funds` does not permit `transfer_funds` — it permits *at most* that, and
the policy engine and the token's scope both still have to agree. This is what makes
the artifact safe to hand to a party you do not fully trust: the worst a forged or
over-broad contract can do is fail to widen anything.

Contracts are **signed JWS artifacts** (`warden-connection+jws`), verified by the
mediator against the issuer's keys — not looked up in a database it trusts. A
compromised control plane can *withhold* a contract, which fails closed. It cannot
manufacture one.

## Running with a policy engine

Coupling is **two signed artifacts and one identifier (`cid`)** — never a shared
library. `wc-mediator` builds **standalone by default**: connection enforcement with
no policy engine deployed at all. The `warden-proxy` build feature adds the decorator
topology, compiling the mediator into an existing proxy so per-action policy applies
in the same process.

```
  agent ──stdio──▶ proxy (per-action policy) ──▶ MediatedUpstream ──▶ real MCP server
                                                 (contract, surface filter, terms)
```

One process, no extra hop. Run it in front of whichever policy engine you have, or
none.

---

## The walkthrough, slide by slide

The two-and-a-half minute film runs twelve slides. Each is below: the claim as
the film states it, what that claim means in the implementation, and a
**Reference** line into the design documents, the use cases and the walkthrough.
If you arrived here from the video, those links are where each slide is
specified in full.

### 1 · Title — reachable is not approved

*contracts that limit what an agent may reach, enforced on every call*
· Envoy · Kong · inline mediator

The whole argument in one line. Everything after it is evidence.

**Reference** · [HLD](docs/07-hld.md) — the design in one document · [end-to-end guide](docs/guides/end-to-end.md) — walk it yourself

### 2 · The token only names a service

> The token only names a service. It says nothing about which tools the agent may use.
> The server offers every tool that it has — all of them available to anyone the token lets through.
> Being able to reach it is not the same as approval. Nobody ever decided that this agent may call `transfer_funds`.

A bearer token addressed to `payments-mcp` is an answer to *which service*. The
MCP server then advertises its full catalogue, and the model can attempt any of
it. Nothing in that exchange records a decision about `transfer_funds`
specifically. Reachability has quietly become authorisation.

**Reference** · [HLD §7.1 Scope and context](docs/07-hld.md#71-scope-and-context) · [LLD §8.6.4 the catalogue filter](docs/08-lld.md#864-filter--the-catalogue) · [UC-03 · Mediated capability discovery](docs/use-cases/UC-03-mediated-capability-discovery.md)

### 3 · The same defect, N times

> Nothing in the estate can answer these questions. There is no record of who approved any of these connections.

The estate is not agent-to-tool. It is agent → agent → tool → agent, assembled
at runtime. Each hop repeats the same gap, so the missing record is not one
oversight but a property of how the estate is wired.

**Reference** · [HLD §7.1 Scope and context](docs/07-hld.md#71-scope-and-context) · [LLD §8.5.11 inventory](docs/08-lld.md#8511-offer-need-pipeline-scm-proposal-receipt-inventory) · [UC-08 · Shadow estate detection](docs/use-cases/UC-08-shadow-estate-detection.md)

### 4 · These are two separate questions

> These are two separate questions. warden-connect answers the first one on its own. The second one is already well solved.

| Question | Answered by | When |
|---|---|---|
| May these two parties be connected at all? | warden-connect | at issuance, once |
| May *this call* proceed? | a policy engine | per call |

Conflating them is why the first goes unanswered: per-call authorisation is
mature, so the standing relationship is assumed rather than decided.

**Reference** · [HLD §7.6 Two policies, two moments](docs/07-hld.md#two-policies-two-moments) · [HLD §7.7 Integration with a policy engine](docs/07-hld.md#77-integration-with-a-policy-engine) · [LLD §8.5.5 may this contract exist?](docs/08-lld.md#855-cpolicy--may-this-contract-exist)

### 5 · Each side writes what it wants, in its own repository

> Each side writes what it wants in its own repository. The provider lists what it offers; the consumer lists what it needs.
> Neither side reviews the other's pull request. The offer is published first, and it waits until a matching need arrives.
> The source host confirms the merge, not the pipeline. A pipeline can claim anything about a commit, so the host is asked directly.

Two lanes, two repositories, two reviews. The provider writes
`warden/offer.toml`; the consumer writes `warden/needs.toml`. Neither party can
produce a contract alone, and neither needs a signing key — consent is a merge
each side approved in its own repository.

The last line is the load-bearing one. Merge evidence is read from the source
host through an operator-supplied shim, never taken from CI, because a pipeline
can assert anything about a commit. Approval is read at the merge's **base
commit**, so a pull request that adds its own author to the approver list is not
approvable by that author.

**Reference** · [HLD §7.6 Reserved paths](docs/07-hld.md#reserved-paths) · [LLD §8.5.11 offer, need, scm, authority](docs/08-lld.md#8511-offer-need-pipeline-scm-proposal-receipt-inventory) · [UC-01 · Register an agent](docs/use-cases/UC-01-register-and-admit-an-agent.md) · [UC-02 · Onboard a tool server](docs/use-cases/UC-02-onboard-a-tool-server.md) · [guide §07–§10](docs/guides/end-to-end.md)

### 6 · Three dispositions

> Most requests never need a person to approve them. The provider already approved this whole class of consumer in a reviewed commit.
> Some requests do need someone to approve them. Nothing is issued until the owner answers, even if only one item needs approval.
> Some requests cannot be approved by anyone. The provider never offered these tools to this consumer, so approval would not help.

| Disposition | Offer term | What happens |
|---|---|---|
| `Grant` | `pre_granted` | mints on apply — the gated path never runs |
| `NeedsApproval` | `named_consumer` | parks as a pending request until the provider merges an approval |
| `Refused` | not offered | returns the diff; approval is not the missing ingredient |

Refusals outrank gating: one gated item holds the whole need, and one refused
item refuses it.

**Reference** · [LLD §8.5.11 Disposition](docs/08-lld.md#8511-offer-need-pipeline-scm-proposal-receipt-inventory) · [LLD §8.7.2 Issuance](docs/08-lld.md#872-issuance--issuance-authority) · [UC-04 · Establish a connection](docs/use-cases/UC-04-establish-a-connection.md) · [guide §12–§13](docs/guides/end-to-end.md)

### 7 · The contract is stored in three places

> The contract is then stored in three places. Each place keeps something different, and that is deliberate.
> Only the copy at the edge expires. Because it expires it must be refreshed, and a revocation arrives with it.

| Where | What it holds | Expires |
|---|---|---|
| The repository | a receipt, `warden/contracts/<cid>.toml` — human-readable, grants nothing | no |
| The control plane | the signed artifact and the event log that produced it | no |
| The enforcement point | the artifact it verifies against, held in memory | **yes** |

The expiry is the containment mechanism, not an inconvenience. Because the edge
copy must be refreshed, the refresh is a channel — the revocation feed arrives
on it. An enforcement point that cannot refresh refuses once `max_stale` passes.

**Reference** · [LLD §8.8 Storage](docs/08-lld.md#88-storage) · [LLD §8.9.3 Receipts](docs/08-lld.md#893-receipts) · [LLD §8.5.8 containment and distribution](docs/08-lld.md#858-contain-dist-caep--containment) · [HLD §7.11 Non-functional requirements](docs/07-hld.md#711-non-functional-requirements)

### 8 · A contract sets a limit, never a grant

> A contract sets a limit. It never grants access. It can only reduce what an agent is already allowed to do.
> warden-connect enforces the limit on its own. A policy engine is optional; if you deploy one, it narrows the limit further, per call.

```
effective = contract.surface  ∩  token.scope  ∩  policy_decision
```

Every operator narrows. There is no widening operator anywhere in the algebra,
and the property tests assert it: `meet(a,b) ≤ a` and `meet(a,b) ≤ b`, always.
That is what makes the artifact safe to hand to a party you do not fully trust —
the worst a forged or over-broad contract can do is fail to widen anything.

**Reference** · [HLD §7.4 The algebra](docs/07-hld.md#the-algebra) · [LLD §8.7.1 The narrowing algebra](docs/08-lld.md#871-the-narrowing-algebra) · [HLD §7.7 Integration with a policy engine](docs/07-hld.md#77-integration-with-a-policy-engine)

### 9 · Three places to run the check

> There are three places to run the check. All three use exactly the same decision code.
> Where you run it changes what it costs — one network call, no network call, or inside the agent's own process.
> They differ in what they can prove about the caller. Envoy and Kong verify the caller; the mediator is simply told who it is.

| Enforcement point | Cost | Caller identity |
|---|---|---|
| Envoy (`wc-extproc`) | 1 loopback gRPC hop | verified — XFCC, origin-checked |
| Kong (`libwc_kong.so`) | none — in the nginx worker | verified — peer certificate URI SAN, or XFCC |
| Inline mediator (`connect-mediate`) | none — the agent's own process | **configured, not proven** |

The decision core is one crate, `wc-gateway`. Each binding is transport only: it
gathers evidence and moves bytes, and holds no policy. That is why the third
column can differ while the verdict cannot.

**Reference** · [HLD §7.9 Deployment topologies](docs/07-hld.md#79-deployment-topologies) · [LLD §8.6b.2 The two bindings](docs/08-lld.md#86b2-the-two-bindings) · [LLD §8.6b.1 The three layers](docs/08-lld.md#86b1-the-three-layers) · [install guide](docs/guides/install.md)

### 10 · The refusal, three ways

> Envoy blocks the call at the network hop.
> Kong blocks the call inside the nginx worker.
> The mediator blocks it in the agent's own process.
> The result is the same in all three, because the code is the same.

An uncontracted tool is refused before it reaches the server, at whichever point
is in the path. The agent never sees the tool either: `tools/list` is filtered
to the contracted surface before the catalogue reaches the model, so it cannot
be talked into attempting what it was never offered.

**Reference** · [HLD §7.4 Verification — the 14 gates](docs/07-hld.md#verification--fail-closed-at-every-step) · [LLD §8.6.4 the catalogue filter](docs/08-lld.md#864-filter--the-catalogue) · [UC-04 · Establish a connection](docs/use-cases/UC-04-establish-a-connection.md) · [guide §16–§17](docs/guides/end-to-end.md)

### 11 · One revocation reaches every enforcement point

> One revocation reaches every enforcement point. Every decision is written to a record that cannot be edited unnoticed.

Quarantine writes a signed revocation feed and fans out with an acknowledgement
deadline. A point that does not acknowledge is reported as **not confirmed** —
never assumed benign. Each enforcement point writes its own decision trail, and
each row carries the hash of the row before it, so an edit anywhere invalidates
every row after it. `connect evidence verify` finds the first break.

**Reference** · [LLD §8.5.8 the revocation feed](docs/08-lld.md#858-contain-dist-caep--containment) · [LLD §8.5.9 the evidence chain](docs/08-lld.md#859-chain-evidence-sink-export-rekor--evidence) · [UC-07 · Emergency quarantine](docs/use-cases/UC-07-emergency-quarantine.md) · [UC-06 · Surface drift](docs/use-cases/UC-06-surface-drift.md) · [UC-10 · Regulatory register and evidence](docs/use-cases/UC-10-regulatory-register-and-evidence.md)

### 12 · Each part has one job

> Each part of the system has one job. Git records what was asked for, the control plane decides, the edge enforces.
> Everything that crosses a boundary is signed. A contract, a revocation and a receipt move between them. No secret is shared.
> Every decision is written down. The edge records each call; the plane records each change to a contract.

Three planes, three signed artifacts between them, and no shared secret. The
control plane can be entirely offline and the edge still enforces against what
it holds. A compromised control plane can *withhold* a contract, which fails
closed — it cannot manufacture one, because contracts are verified against
issuer keys rather than looked up in a database the enforcement point trusts.


---

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

## Try it

```sh
# 1 · an issuer key, and the two parties
connect keys new --kid k-2026-01 --out .keys      # prints the openssl command
connect register server --endpoint https://payments.internal/mcp \
    --owner human:vijay --zone internal.payments --surface payments-surface.json
connect register agent --card recon-agent.json --owner human:vijay \
    --zone internal.apac-ops

# 2 · ask for a connection, and approve it
connect request --from spiffe://org/ns/agents/sa/recon --to spiffe://org/ns/tools/sa/payments \
    --tools get_balance,list_transactions --justify "nightly reconciliation" --ttl 30d \
    --issuer-key .keys/k-2026-01.pem --kid k-2026-01
connect approve <req-id> --by human:vijay --approver-key .keys/approver.pem \
    --issuer-key .keys/k-2026-01.pem --kid k-2026-01

# 3 · verify the artifact the way a third party would
connect verify contract.jws --jwks jwks.json --mediator-id warden:mediator:apac-ops \
    --issuer-id https://connect.internal

# 4 · enforce it, inline, in front of the real server
connect-mediate --upstream "python payments_mcp.py" \
    --mediator-id warden:mediator:apac-ops --issuer-id https://connect.internal \
    --caller spiffe://org/ns/agents/sa/recon --callee spiffe://org/ns/tools/sa/payments \
    --jwks-url https://connect.internal/v1/jwks.json \
    --contracts https://connect.internal --token "$MEDIATOR_TOKEN"
```

`connect --help` is the full surface: registration and attestation, the connect loop,
estate queries (`posture`, `blast-radius`, `discover`), keys and rotation, air-gapped
bundles, CAEP shared signals, evidence export (CSV, JSON, DORA, CPS 230, OSCAL, BOM),
and `serve`.

## Running the control plane

```sh
connect serve --listen 0.0.0.0:8787 --issuer-key .keys/k-2026-01.pem --kid k-2026-01 \
    --behind-tls-proxy --trusted-proxy 10.0.1.5 \
    --tokens tokens.toml --approvers approvers.toml
```

`serve` speaks **plain HTTP on purpose** — every supported topology terminates TLS at an ALB,
an Ingress, HAProxy or Front Door. So a non-loopback listener **refuses to start**
unless you say how TLS is handled, and with `--behind-tls-proxy` every authenticated
request must carry `x-forwarded-proto: https` from an address you named. A request that
reaches the port directly, bypassing the ingress, is refused rather than trusted.

Signing keys have a **delegated form** everywhere they have a PEM form
([docs/08-lld.md §8.12.1](docs/08-lld.md)): `--signer COMMAND` reads a base64url
signing input on stdin and writes a base64url signature on stdout, so the private key
can live in an HSM, a smartcard or a KMS and never reach this process.
`--require-external-signing` refuses to start if any key would be read from local disk.

## Documentation

| | |
|---|---|
| [docs/07-hld.md](docs/07-hld.md) | **Start here.** High-level design — the plane split, the artifact, the algebra, the trust and threat model, the adoption ladder |
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
