# warden-connect

**The connection control plane for AI agents.**

Warden core decides whether an agent may take *an action*. warden-connect decides
whether two parties may be *connected at all*, and bounds what that connection can
ever carry. One is per-call authorisation. The other is the standing relationship the
calls happen inside.

> **Beta.** Not independently audited. See
> [docs/production-readiness.md](docs/production-readiness.md) — it is a list of what is
> missing, written before anyone asked.

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
Warden core's policy and the token's scope both still have to agree. This is what makes
the artifact safe to hand to a party you do not fully trust: the worst a forged or
over-broad contract can do is fail to widen anything.

Contracts are **signed JWS artifacts** (`warden-connection+jws`), verified by the
mediator against the issuer's keys — not looked up in a database it trusts. A
compromised control plane can *withhold* a contract, which fails closed. It cannot
manufacture one.

## How the family couples

Warden core, warden-connect, warden-delegate and warden-trace are coupled by **two
signed artifacts and one identifier (`cid`)** — never by a shared library. Only
`wc-mediator` links Warden core, because it compiles *into* the proxy. Every other
crate is independently adoptable: you can run this in front of someone else's policy
engine.

```
  agent ──stdio──▶ Warden core Gateway ──▶ MediatedUpstream ──▶ real MCP server
                   (per-action policy)     (contract, filter, ceilings)
```

One process, no extra hop.

---

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
cargo build --workspace          # needs ../warden checked out beside this repo
cargo test --workspace           # 958 tests
cargo clippy --workspace --all-targets
cargo deny check
./scripts/dep-count.sh           # dependency ceilings, asserted
```

Warden core is a **path dependency** at `../warden` by design (§8.3) — the deployment
model is that the mediator compiles into the proxy. CI checks out both side by side.

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
connect verify contract.jws --jwks jwks.json --mediator-id warden:mediator:apac-ops

# 4 · enforce it, inline, in front of the real server
connect-mediate --upstream "python payments_mcp.py" \
    --mediator-id warden:mediator:apac-ops \
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

`serve` speaks **plain HTTP on purpose** — every topology in
[docs/physical-architecture.md](docs/physical-architecture.md) terminates TLS at an ALB,
an Ingress, HAProxy or Front Door. So a non-loopback listener **refuses to start**
unless you say how TLS is handled, and with `--behind-tls-proxy` every authenticated
request must carry `x-forwarded-proto: https` from an address you named. A request that
reaches the port directly, bypassing the ingress, is refused rather than trusted.

Signing keys have a **delegated form** everywhere they have a PEM form
([docs/key-custody.md](docs/key-custody.md)): `--signer COMMAND` reads a base64url
signing input on stdin and writes a base64url signature on stdout, so the private key
can live in an HSM, a smartcard or a KMS and never reach this process.
`--require-external-signing` refuses to start if any key would be read from local disk.

## Documentation

| | |
|---|---|
| [docs/07-hld.md](docs/07-hld.md) | High-level design — the two-layer model, the artifact, the family |
| [docs/08-lld.md](docs/08-lld.md) | Low-level design — every module, every check, the build order |
| [docs/physical-architecture.md](docs/physical-architecture.md) | Four deployment variants: on-prem VMs, Kubernetes, AWS, Azure |
| [docs/key-custody.md](docs/key-custody.md) | Six signing operations, and which key loss is unrecoverable |
| [docs/twelve-factor.md](docs/twelve-factor.md) | Config, state, logs, disposability — and where this deviates |
| [docs/observability.md](docs/observability.md) | Every metric family, the four alerts as PromQL, and what the telemetry cannot answer |
| [docs/operations.md](docs/operations.md) | Backup, restore, the quarterly drill, and why retention deletes nothing |
| [docs/production-readiness.md](docs/production-readiness.md) | What is not ready, in priority order |
| [DRILL.md](DRILL.md) | How this was built, module by module |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability; what is in and out of scope |

## Conformance

The contract format is meant to be a candidate standard, not a product format: **any
implementation may mint a contract, and a contract is valid iff a conforming verifier
accepts it.** `fixtures/contracts/` is the test vector set — nineteen artifacts and an
`expected.json` naming the `WC-*` code a conforming verifier must produce for each,
including alg confusion, `alg: none`, HMAC substitution, a tampered payload, a
superset surface and a wrong audience.

```sh
connect verify fixtures/contracts/valid-es256.jws \
    --jwks your-issuer-keys.json --mediator-id warden:mediator:apac-ops
```

If your verifier and this one disagree on any vector, one of us has a bug — and that is
a more useful conversation than a specification document.

## Licence

[FSL-1.1-ALv2](LICENSE) — Functional Source License, converting to
[Apache 2.0](LICENSE-APACHE) two years after each release. Use it, run it, modify it;
do not ship a competing product with it until the conversion date.
