# 8 · warden-connect — Low-Level Design

> Every crate, every module, every check, and the order they were built in.
> Section numbers are load-bearing: source files cite them in their `//!`
> headers (`registry.rs` says §8.5.3, `gate.rs` says §8.6.1). Renumbering breaks
> those references.

| | |
|---|---|
| **Version** | v0.2.0 · Rust 2021 · MSRV 1.89 |
| **Scale** | 7 crates · 73 modules · 82 error codes · 1,439 tests |
| **Companion** | [07-hld.md](07-hld.md) for the model · [use-cases/](use-cases/) for the flows |

---

## 8.1 How to read this document

| Rule | What it means |
|---|---|
| A contract is a ceiling, never a grant | Every algorithm here narrows or refuses. Nothing widens. Code that widens is a bug, whatever it was for |
| Fail closed, and name the dependency that failed | A control that degrades to "allow" on a dependency failure is the defect class this system produces. Every dependency has a code in §8.11 |
| Configured is not enforced | A flag parsed and never read, a role required and never checked, a gate that passes with its body deleted. §8.15 exists because of these |

---

## 8.2 Design constraints

| Constraint | Consequence |
|---|---|
| Asymmetric signatures only | No HMAC anywhere. `ALG_NOT_ASYMMETRIC` (`WC-3101`) rejects at parse |
| Locally-derived input may only narrow | The narrowing algebra in §8.7.1 is total; there is no widening operator |
| No async runtime | Threads and blocking I/O. No `tokio`, no `async fn` in any **embeddable** crate — see below |
| Dependency ceilings | `scripts/dep-count.sh` fails CI when a crate exceeds its budget |
| Deterministic canonical form | `wc-core::canon` (`wcs1`), depth-bounded at 32 |
| Errors carry codes, not prose | `WcError { code, detail, source }`; the code is the contract |

### The async-runtime constraint, stated precisely

The ban used to read "no `async fn` in any crate". The `ext_proc` verifier needs
a gRPC server, so the rule is narrowed rather than left false.

The ban protects one property. `wc-core` and its dependents are linked into
processes this project does not own: an existing proxy under the `warden-proxy`
feature, a provider's Python server through a PyO3 wheel, a gateway filter in
someone's data path. A crate that brings its own runtime cannot be embedded
there, and inside a host that already has one it is a second runtime.

| | Embeddable crates (`crates/*`) | Daemons (`daemon/*`) |
|---|---|---|
| Linked into a process it does not own | yes | no |
| Owns its own `main` | no | yes |
| Async runtime | **banned** — `deny.toml`, and `dep-count.sh` greps `cargo tree --workspace` | permitted |
| Gated by | dependency ceilings + the ban list | its own `dep-count.sh` clause |

`daemon/` is excluded from the workspace, which keeps `cargo tree --workspace`
answering the question the ban is about. `dep-count.sh` also runs `cargo tree
--invert tokio` against each daemon and fails if a `warden-connect-*` crate
appears — a runtime crossing back into the embeddable surface. Verified by
adding `tokio` to `wc-gateway` and watching both clauses fire.

---

## 8.3 Crate and repository layout

```
warden-connect/
├── crates/
│   ├── wc-core/          shared types, the artifact, the codes  (10 modules)
│   ├── wc-control/       the control plane                      (39 modules)
│   ├── wc-mediator/      the data plane                         (13 modules)
│   ├── wc-gateway/       the PEP decision core + shared wiring    (4 modules)
│   ├── wc-kong/          C ABI over wc-gateway, for LuaJIT FFI    (3 modules)
│   ├── wc-cli/           the `connect` binary                     (3 modules)
│   └── wc-e2e/           end-to-end and property tests
├── daemon/
│   └── wc-extproc/       Envoy ext_proc binding. OUTSIDE the workspace (§8.2)
├── docs/                 this document, the HLD, the use cases, the explainer
├── fixtures/contracts/   conformance vectors
├── scripts/              drills, dependency ceilings, SCM shims
├── connect-policy.toml   may this contract exist?
└── screen-rules.toml     declared-surface screening ruleset (§8.7.4)
```

**Dependency direction is strictly one-way:**

<img src="diagrams/lld-1.svg" alt="Crate dependency direction — one way, and the mediator never depends on the control plane" width="100%">

`wc-mediator` does **not** depend on `wc-control`. That is what lets it run
standalone, and what stops a control-plane compromise from reaching the data
plane through a linked library.

---

## 8.4 Module inventory

### `wc-core` — 10 modules

| Module | Responsibility |
|---|---|
| `contract` | The connection contract: surface, terms, registry record, JWS sign/verify |
| `canon` | `wcs1` canonical surface serialisation and pinning; depth-bounded |
| `error` | The `WC-*` taxonomy — 82 codes — and `WcError` |
| `model` | Identifiers, entities, pins, `Lifecycle`, `Posture` |
| `zone` | The zone lattice: structure, ordering, zone-pair resolution |
| `obs` | Labelled metrics and structured decision logs |
| `proc` | `spawn_piped` — the one way this workspace spawns a child with piped stdio |
| `thresholds` | The §8.10.3 latency ceilings, in one place |
| `util` | Canonical JSON, hashing |
| `lib` | Re-exports |

`proc` exists because creating a pipe and marking it close-on-exec are two steps,
not one. A thread that forks in between inherits a sibling's pipe ends, and the
thread waiting on the real child waits for a writer that will never write. The
symptom misleads: a shim that exited 0 having printed its verdict is recorded as
"no answer within 20s". `spawn_piped` holds a process-wide lock across the
spawn, and all three spawn sites use it.

### `wc-control` — 39 modules

| Module | Responsibility | §  |
|---|---|---|
| `store` | Append-only event log with an in-memory projection | 8.5.2 |
| `lock` | The single-writer lock | 8.5.2 |
| `registry` | The registry write path | 8.5.3 |
| `admission` | The admission pipeline | 8.5.4 |
| `attest` | Real attestation verifiers for admission stages 1, 3, 4 | 8.5.4 |
| `screen` | Declared-surface injection screening | 8.7.4 |
| `cpolicy` | Connection policy — may this contract exist? | 8.5.5 |
| `issuance` | Request → approval → mint | 8.7.2 |
| `authority` | Who is entitled to say a connection was approved | 8.7.2 |
| `broker` | Mediated capability discovery | 8.5.6 |
| `assurance` | Re-attestation scheduling, drift classification, posture | 8.5.7 |
| `contain` | Signed revocation feed, fan-out, ACK deadlines | 8.5.8 |
| `dist` | Which mediators hold the current contract set | 8.5.8 |
| `federate` | Trust chains, partner resolution, monotonic narrowing | 8.5.11 |
| `chain` | The tamper-evident evidence chain and its signed anchors | 8.5.9 |
| `evidence` | Facade: lifecycle events → chain → sinks | 8.5.9 |
| `sink` | Evidence sinks: format × transport × filter × delivery | 8.5.9 |
| `export` | Regulatory registers and control evidence | 8.5.9 |
| `rekor` | Transparency-log inclusion, verified offline (RFC 6962 §2.1.1) | 8.5.9 |
| `backup` | Backup, restore and retention for the system of record | 8.8 |
| `api` | The control-plane HTTP surface | 8.5.10 |
| `http` | A minimal HTTP/1.1 server | 8.5.10 |
| `portal` | The read-only portal (`connect serve --portal`) | 8.5.10 |
| `offer` | What a provider makes available, and to whom | W1 |
| `need` | What a consumer asks for, and whether an offer permits it | W2 |
| `pipeline` | Which pipeline is asking, and may it speak for this asset? | W3 |
| `scm` | Asking a source host what was merged, via an operator-supplied shim | W4 |
| `proposal` | A contract proposal, reviewed as a pull request | W6 |
| `receipt` | What goes back to a repository, and what never does | W6 |
| `inventory` | What MCP servers an organisation has, read from its repositories | W7 |
| `keys` | The issuer keyring and its rotation lifecycle | 8.12.1 |
| `custody` | Which key signs what, and the rules that keep them apart | 8.12.1 |
| `signer` | External signers: keys this process does not hold | 8.12.1 |
| `bundle` | Air-gapped contract bundles | 8.9.4 |
| `caep` | CAEP ingest: acting on signals from other people's systems | 8.5.8 |
| `tenant` | Validated tenant ids, per-tenant roots, isolation | 8.13 |
| `obs` | The §8.14 metric families, and where each number comes from | 8.14 |
| `bench` | Performance gates | 8.10.3 |
| `lib` | Composition root |

### `wc-mediator` — 13 modules

| Module | Responsibility | § |
|---|---|---|
| `gate` | The inline mediator, as an `Upstream` decorator | 8.6.1 |
| `cache` | The contract cache and revocation set | 8.6.2 |
| `jwks` | Issuer keys from a published key set, so rotation is not a deployment | 8.6.3 |
| `filter` | Catalogue filtering | 8.6.4 |
| `peer` | Where peer identity actually comes from | 8.6.6 |
| `drain` | What happens to in-flight work when a revocation lands | 8.6.5 |
| `evidence` | The decision trail an enforcement point writes, and the hash chain over it | 8.5.9 |
| `client` | Pull a contract set from the control plane, acknowledge it | 8.6.2 |
| `upstream` | The two transports: a spawned stdio child, or a remote server over Streamable HTTP | 8.6.7 |
| `mcp` | The few MCP shapes the mediation path needs | 8.9.1 |
| `rpc` | JSON-RPC 2.0 — the wire format MCP uses over stdio | 8.9.1 |
| `obs` | Decision log and the metric families the mediator owns | 8.14 |
| `lib` | Composition root |

Two notes on placement:

* `peer` also owns `spiffe_from_cert_pem`, a dependency-free DER walk to a
  certificate's URI SAN. It lives in the identity module rather than in the
  binding that needed it, because a security-critical parser buried in a binding
  is a parser that escapes review. §8.6b.4.
* `evidence` writes a local file rather than speaking a SIEM protocol. `wc-kong`
  is a cdylib inside an nginx worker and §8.2 forbids an async runtime there, so
  an HTTP client with retries and backpressure has no home. `ocsf://siem` in
  `terms.evidence.sink` means *point a shipper at the file*.

### `wc-gateway` — 4 modules

The PEP decision core. Sync and transport-free on purpose; the `dep-count.sh`
ceiling is what stops an async runtime arriving through this door (§8.2).

| Module | Responsibility | § |
|---|---|---|
| `lib` | `Filter`, `Verdict`, `BodyMode`, `BodyAction`, `PinLedger`, `FilterCfg` | 8.6b.1 |
| `adapter` | What every binding needs so that no binding reimplements it | 8.6b.1 |
| `contracts` | `ContractSet`, `Resolved`, the staleness bound, the shadowed-contract warning | 8.6b.1 |
| `routes` | Route key → callee. One table serves Envoy's cluster and Kong's service | 8.6b.2 |

### `wc-kong` — 3 modules

| Module | Responsibility | § |
|---|---|---|
| `abi` | The eleven `extern "C"` symbols, every one panic-isolated | 8.6b.3 |
| `config` | `Config`, `Handle`, `Peer`, `IdentitySource`, `ModeCfg` | 8.6b.4 |
| `lib` | The `panic = abort` build guard, and the crate's re-exports | 8.6b.3 |

Ships with `include/wc_kong.h` (hand-written, tested against the Rust) and
`lua/kong/plugins/warden-connect/` (`handler`, `schema`, `wcffi`).

### `daemon/wc-extproc`

Outside the workspace, because it owns `main` and may carry tokio (§8.2). One
module: `main.rs`, holding the `ext_proc` service. The contract-set and route
handling used to live here and was lifted into `wc-gateway::contracts` and
`::routes` when a second binding needed it.

---

## 8.5 Control-plane modules

### 8.5.1 Composition

`wc-control::lib` is a composition root and nothing else. Every module takes its
dependencies as parameters; none reaches for a global. That is what makes 1,439
tests possible without a running service.

### 8.5.2 `store` and `lock` — the system of record

**`store`** is an append-only event log with an in-memory projection. Events are
the truth; the projection is a cache that can always be rebuilt by replay.

Every event struct carries `#[serde(default)]` on fields added after the fact.
Without it, replaying an old log against new code panics — and the log is the
one thing that must survive every upgrade.

**`lock`** is the single-writer lock. Only one process may write the registry at
a time; readers never take it.

> **The macOS `flock` race.** `acquire` retries 8 times with backoff (~63 ms
> total) because on macOS a `flock` taken immediately after a release **on the
> same inode** can transiently return `EWOULDBLOCK`. A minimal probe ran 20,000
> cycles clean in isolation and blocked within one run under load. Set
> `WARDEN_CONNECT_TRACE_LOCKS` to a file path for pid + inode traces — a path,
> not stdout, because cargo captures stdout per test. Code: `WC-8003`.

Commands that only read — `need check`, `entities` — **must not take the writer
lock**. A source-scanning guard test enforces this.

### 8.5.3 `registry` — the write path

Every transition is validated before it is written:

| Guard | Code |
|---|---|
| Entity exists | `WC-2001` |
| Entity is not a duplicate | `WC-2002` |
| The transition is legal for the current lifecycle | `WC-2003` |
| The entity is not quarantined | `WC-2004` |
| The identifier is well-formed | `WC-2005` |

Quarantine is terminal. There is no transition out of it; clearing requires a
fresh admission that creates a new record.

### 8.5.4 `admission` and `attest` — the pipeline

Five stages, each fail-closed, in this order:

<img src="diagrams/lld-2.svg" alt="The five admission stages, each fail-closed, with the code each refusal produces" width="100%">

Order matters: the surface is captured **before** it is screened, and screened
**before** it is pinned. Pinning unscreened text would make the pin an assertion
that the text was reviewed when it was not.

`attest` holds the real verifiers for stages 1, 3 and 4. A verified OIDC token
satisfies the **identity stage only** and does not reach `Attested`; provenance
and surface capture are separate stages with separate evidence.

### 8.5.5 `cpolicy` — may this contract exist?

Distinct from per-call policy in every dimension: different question, different
moment, different owner.

| | |
|---|---|
| Inputs | zone pair, tier, requested surface, data classes, jurisdictions, requester authority |
| Output | a `Disposition` |
| Assurance bars | declared per zone, including `max_delegation_depth` |
| Two stanzas apply | terms narrow by `min` — the tighter wins, never the more recent |

### 8.5.6 `broker` — discovery

Returns capability **summaries** only: no endpoints, no credentials, no full
schemas. An empty result is deliberately indistinguishable from "exists but not
visible to you" (`WC-2021` asker not attested).

Throttling **truncates and never refuses**: overflow returns `truncated: true`
with an empty tail. `WC-2020 DISCOVERY_THROTTLED` is reserved and unreachable by
design — a status that changes when a caller crosses a threshold is itself the
enumeration signal throttling exists to deny.

### 8.5.7 `assurance` — the loop

Re-attestation on a tier-derived interval; drift classified benign or material
(§8.7.5); posture scored from denial patterns fed back from the data plane.
Material drift suspends every contract referencing the pin (`WC-5002`).

### 8.5.8 `contain`, `dist`, `caep` — containment

| Module | Does |
|---|---|
| `contain` | Writes the signed revocation feed and fans out to every mediator with an acknowledgement deadline. A mediator that does not acknowledge produces `WC-6003` — **not confirmed**, reported as such, never assumed benign |
| `dist` | Tracks which mediators hold the current contract set |
| `caep` | Ingests signals from other people's systems, refusing signals from parties not authorised to send them (`WC-2035`) |

### 8.5.9 `chain`, `evidence`, `sink`, `export`, `rekor` — evidence

| Module | Does |
|---|---|
| `chain` | An append-only hash chain with periodically signed anchors. Its value is that an auditor can verify it **without trusting the plane that wrote it**. It must never move to a database — a queryable chain that requires trusting the query engine is not evidence |
| `evidence` | Facade from lifecycle events to chain to sinks |
| `sink` | Composes format × transport × filter × delivery. A **blocking** sink that is unavailable refuses the call (`WC-7001`), configurable per contract via `terms.evidence.delivery` |
| `export` | Produces DORA, CPS230, OSCAL, OCSF and CSV, always with an explicit exceptions section rather than a silent omission. A broken chain refuses the export (`WC-7003`) |
| `rekor` | Transparency-log inclusion, verified offline |

Enforcement points write their own trail through `wc-mediator::evidence` (§8.4).
Appending JSON lines gives an operator a log, not evidence: anyone who can write
the file can rewrite it. Each row carries the hash of the row before it, so an
edit anywhere invalidates every row after, and `verify` finds the first break.

### 8.5.10 `api`, `http`, `portal` — the surfaces

| Module | Does |
|---|---|
| `http` | A minimal HTTP/1.1 server — no framework, which is what keeps the dependency budget |
| `api` | The control-plane surface |
| `portal` | **Read-only** and server-rendered: catalogue, shadow usage, pending requests, blast radius, evidence lookup by `cid`, and a command generator that emits the CLI line rather than performing the action |

The portal has no write path and no session state. Discovery in the browser,
execution in the CLI.

### 8.5.11 `offer`, `need`, `pipeline`, `scm`, `proposal`, `receipt`, `inventory`

The GitOps path — waves W1 to W7.

| Module | Reads / writes | Does |
|---|---|---|
| `offer` | `warden/offer.toml` | What a provider makes available, and to whom. `TermApproval` is `PreGranted` or `NamedConsumer` |
| `need` | `warden/needs.toml` | What a consumer asks for; returns a `Disposition` |
| `pipeline` | — | Whether the calling pipeline may speak for this asset |
| `scm` | the source host | What was merged, through an operator-supplied shim, with per-host `jq` extractors loaded by `jq -f` and never copied inline |
| `receipt` | `warden/contracts/<cid>.toml` | What goes back to the repository. **Never a JWS** |
| `inventory` | reserved paths | Sweeps repositories. Probes nothing. Reports `watermark` and `repos_skipped` so a partial sweep never reads as complete coverage |

```rust
pub enum Disposition {
    Grant(Box<Matched>),
    NeedsApproval(Box<Gated>),
    Refused(Vec<ItemRefusal>),
}
```

Refusals outrank gating; one gated item holds the whole need. The accessors
`granted()`, `refusals()` and `gated()` are **consuming** — the borrowing
versions dangled on temporaries.

**Who may approve (W8).** `authority` holds `ApprovalBlock` — the `[approval]`
key in both manifests, naming who may approve a change to them:

```toml
[approval]
approvers = ["s.iyer", "p.rao"]
min       = 2
```

| Rule | Detail |
|---|---|
| Read at the **base commit**, never the head | A pull request that adds its own author to the list must not be approvable by that author. `MergeEvidence.base_sha` is what makes that readable; a host that does not report one refuses (`WC-3025`) rather than falling back to the head |
| Quorum counts declared approvers only | `WC-3026` |
| No `[approval]` key at base | Nobody has declared yet — the registry owner stands in for that one merge. `MergeApproval.bootstrap` records it, so an estate migrating onto declared approvers can watch the count go to zero (W8.4) |
| `approvers = []` at base | Somebody wrote "nobody" — refuse. An instruction, not a gap |
| The fallback never widens | It supplies a list where there was none. A declared list that excludes the owner still excludes them |

**Approver drift (W8.6).** `Offer` holds the `[approval]` block it was published
with, and `approval_digest()` reduces it to a stable value — sorted, lower-cased,
`human:` stripped, `min` folded in. Reordering is not drift; adding, removing or
changing `min` is.

Drift is reported, not refused: the base-commit read already means moving the
list takes a merge the previous list approved. What was missing was the trace —
an auditor could not tell the approver set had moved. `store::NeedRecord` and
the `need.declared` event give the consumer side the same record.
`offer::approval_digest` is one free function used by both sides, because two
implementations of "has the approver set moved" would drift apart.

| | Offer | Need |
|---|---|---|
| Held in | `Projection.offers` | `Projection.needs` |
| Conflict rule | highest version wins | last write wins — a needs manifest has no version |
| Compared at | `offer publish` | `need apply` |

**Distinct approvers (W8.5).** `require_distinct_approvers` on the zone
assurance bar refuses a contract whose two sides were approved by the same human
(`WC-3027`).

| | `dual_control` | `require_distinct_approvers` |
|---|---|---|
| Asks for | two approvers on one side | the provider's approver and the consumer's to be different people |
| Default | per zone | off inside a zone, on for `partner` and `public` |

One approval each is normal; the point is that nobody decides alone that A may
call B. `strictest` ORs it. Break-glass sets it false explicitly, having no
merges at all. The check sits **above** the `owner_merge_approves` early return:
below it, opting into merge consent would silently opt out of distinctness.

---

## 8.6 Data plane — `wc-mediator`

### 8.6.1 `gate` — the decorator

The mediator is an `Upstream` decorator, not a proxy of its own. Standalone by
default; the `warden-proxy` feature compiles it into an existing proxy so
per-action policy applies in the same process, with no extra hop.

The 14 verification gates are §7.4 of the HLD, implemented in
`wc-core::contract` and driven from here. Every one is fail-closed, except
posture in observe mode, which admits and logs.

### 8.6.2 `cache` and `client`

The contract cache and revocation set are held in memory. `client` pulls a
contract set from the control plane and acknowledges it — the acknowledgement is
what `contain` waits for. **No network call happens on the hot path**; the cache
is the hot path.

### 8.6.3 `jwks`

Issuer keys are pulled from a published key set so rotation is not a deployment.
Both EC and **RSA** branches are implemented; the RSA branch yields its `alg`
and falls through to the shared verification tail. GitHub's OIDC JWKS is
RSA-only, so skipping RSA made it unreachable.

### 8.6.4 `filter` — the catalogue

`tools/list` is filtered down to `surface.tools` before the response reaches the
agent, so **the model never sees the tool it is not contracted for** and cannot
be talked into attempting it. A catalogue that cannot be filtered is refused
(`WC-4007`).

### 8.6.5 `drain`

`drain` decides what happens to in-flight work when a revocation lands — `drain`
or `abort`, per policy.

**Rate, concurrency and spend ceilings were removed.** `ceiling.rs` is deleted
and `WC-4003`, `WC-4004` and `WC-4005` are unreachable. They are retired rather
than deleted from the taxonomy, because a code is a stable contract and removing
one makes old evidence unreadable.

Counters live in one process. A contract saying `max_calls_per_hour = 10`
admitted ten **per nginx worker per node**, so the number an owner signed was
never the number in force. Measured: a 3-per-hour contract executed three calls
in one process and nine across three, in the same hour.

| Fix considered | Why it failed |
|---|---|
| Redefine the term as per-instance | The owner signed a fleet number, not a per-instance one |
| Divide the budget across instances | Instances come and go; 3 across 4 workers is 0 (deny everything) or 1 (12 in force) |
| A shared counter on the hot path | §7.11 forbids it outright |

Envoy and Kong both rate-limit properly, and traffic shaping belongs in a proxy.
This component claims **one axis** — which capabilities a caller may reach on a
callee — and enforces it exactly.

The fields stay in `Terms` for one more version: `ContractPayload` carries
`deny_unknown_fields`, so deleting them would make every already-signed artifact
fail to verify. They cannot be set on a new contract, and a binding that loads a
legacy artifact carrying one **says so at startup**.

### 8.6.6 `peer`

Peer identity comes from the established transport — mTLS or SVID — never from a
header. A header claiming peer identity is rejected (`WC-4020`). This is what
makes gates 6 and 7 meaningful.

### 8.6.7 `upstream` — the two transports

The mediator decorates an `Upstream`, and there are two implementations. Both
sit behind the same `MediatedUpstream`, so the 14 gates and the catalogue filter
are the same code on either path. The transport decides where the server lives,
not what is enforced.

| | flag | topology |
|---|---|---|
| `StdioUpstream` | `--upstream CMD` | the MCP server is spawned as a child; one agent, one server, one sidecar |
| `HttpUpstream` | `--upstream-url URL` | the MCP server is remote, over MCP Streamable HTTP; the common shape once a team wraps an existing API |

`HttpUpstream` POSTs one JSON-RPC frame per request. `application/json` is one
frame; `text/event-stream` is parsed by `sse_frame_for`:

| Detail | Why it matters |
|---|---|
| `data:` lines are joined with a **newline**, per the spec, not concatenated | The two differ when a token is split across lines: joining correctly yields invalid JSON, and concatenation would silently reassemble a frame the server never sent |
| Frames are matched on `id` | A server may interleave progress notifications ahead of the answer. A notification carries no `id`, so taking the first frame would report a progress event as the result of a `tools/call` |
| `Mcp-Session-Id` from `initialize` is echoed on every later request | A stateful server rejects everything after `initialize` without it |

Two configuration refusals, both at startup:

| Refusal | Why |
|---|---|
| `--upstream` and `--upstream-url` together | Two upstreams is two beliefs about what is being mediated. Picking one by precedence would mediate a server the operator did not point at |
| Plaintext `http://` to anything but loopback, without `--upstream-allow-plaintext` | The mediator's decisions are worth no more than the channel carrying them. The opt-out exists for a sidecar proxy that terminates TLS on the same host |

`--upstream-header 'Name: value'` (repeatable) forwards a header, typically an
`Authorization` for the provider's own gateway. The split is on the **first**
colon, because values contain colons. A name carrying whitespace or a control
character is refused, since sending it verbatim would inject a second header
line.

`scripts/http-mode-drill.sh` runs a contract, the surface pin and the surface
ceiling against a real HTTP MCP server in **enforce** mode: over
`application/json`, then over `text/event-stream` with the result behind a
progress notification, then against a server that requires the session id.

---

## 8.6b Enforcement-point bindings

Two proxies run the same decision. The split that makes that possible, and the
parts of it that are easy to get wrong, are here.

### 8.6b.1 The three layers

| Layer | Crate | Holds |
|---|---|---|
| **Decision** | `wc-gateway::Filter` | every verdict. `on_request` → `Verdict`, `on_response_headers` → `BodyMode`, `on_response_body` → `BodyAction` |
| **Shared wiring** | `wc-gateway::adapter`, `::contracts`, `::routes` | the parts that must be *identical* across bindings, not merely similar |
| **Binding** | `daemon/wc-extproc`, `crates/wc-kong` | transport. Gathers evidence, moves bytes, holds no policy |

`wc-gateway` did not survive a second binding unchanged. Four things moved into
`adapter`, each because it was about to be written twice:

| Lifted into `adapter` | Why it cannot be per-binding |
|---|---|
| `refusal_frame` | an agent must see the same refusal whichever PEP refused it |
| `placeholder_callee` | the "no contract" path must not become a second way to say it |
| `parse_request_frame` | **refusing a JSON-RPC batch is a security property.** A binding that parsed the frame itself would pass every test it wrote and stop enforcing whenever a client batched |
| `caller_from_tls` / `caller_from_xfcc` | where identity comes from is not a per-binding opinion |

`set_binding` has the same shape: `contracts` and `routes` were lifted out of
the Envoy daemon still saying `wc-extproc:` in four diagnostics, which would
have sent a Kong operator to a binary they do not run.

### 8.6b.2 The two bindings

| | `wc-extproc` (Envoy) | `wc-kong` (Kong) |
|---|---|---|
| Mechanism | gRPC `ext_proc` service, own process | `cdylib` loaded by LuaJIT FFI, in the nginx worker |
| Hops added | 1 (loopback gRPC) | 0 |
| Identity | XFCC, origin-checked | peer certificate URI SAN, or XFCC |
| Route key | `xds.cluster_name` / `xds.route_name` | `kong.router.get_service().name` / `get_route().name` |
| Buffering decided at | **response** headers, via `mode_override` | **request** phase, via `enable_buffering()` |
| Async runtime | tokio, allowed because it owns `main` | none — the ceiling in `dep-count.sh` forbids it |

One route table serves both: Kong's *service* name occupies the `cluster` column
of `routes.toml`, because it is the same slot.

**Buffering is the one place Kong is the better shape.** Envoy honours
`mode_override` only from a header phase, so the filter cannot know whether to
buffer until the response headers arrive — by which time the request body that
said "this is a catalogue" is gone. Kong decides before it proxies, so
`wc_on_request` answers `WC_BUFFER` from the request frame.

### 8.6b.3 The C ABI

Eleven symbols, verified present in the built library by the ABI suite.
Configuration and peer evidence cross as JSON, not `#[repr(C)]` structs: a
struct layout must be kept in step with a hand-written `ffi.cdef`, and a field
added on one side is a silent misread on the other.

| Symbol | Returns |
|---|---|
| `wc_init(cfg_json)` | handle, or `NULL` with the reason. Refuses to start on bad config |
| `wc_free`, `wc_contract_count`, `wc_version` | lifecycle |
| `wc_stream_new(handle, peer_json)`, `wc_stream_free` | a stream. **Never `NULL` for "no contract"** — that is a verdict, not an error |
| `wc_on_request` | `FORWARD` \| `REFUSE` \| `BUFFER` |
| `wc_on_response_headers` | `BUFFER` \| `SKIP` \| `REFUSE` |
| `wc_on_response_body` | `PASS` \| `REWRITE` \| `REFUSE` |
| `wc_refusal(code, detail)` | the frame for the one case the plugin must answer alone |
| `wc_out_free` | Rust allocates every buffer; Lua never frees Rust memory |

Rules, all of them fail-closed:

| Rule | Why |
|---|---|
| every entry point wrapped in `catch_unwind` | a panic unwinding into LuaJIT is undefined behaviour |
| `#[cfg(panic = "abort")] compile_error!` | under `panic = abort` the boundary silently is not there and a panic takes the worker down. A safety argument that evaporates on a profile switch is not one |
| a null pointer is `WC_ERR_BADARG`, never a dereference | Lua can and will pass one |
| every negative return means refuse | there is no path in `handler.lua` that forwards a frame the library did not approve |
| a worker that cannot start exits **503**, not 200 | no library verdict exists; a JSON-RPC refusal would be claiming one |

`wc_refusal` exists because a caught panic leaves no verdict body and the client
is still owed an answer. Without it Lua would carry a hardcoded JSON string — a
second refusal format that nothing keeps in step.

### 8.6b.4 The peer, and what is not in it

`Peer` carries evidence, never an assertion. There is no `caller` field: a field
in which Lua states an identity is a field in which anything reaching Lua states
an identity.

| `identity` | Evidence | Gate |
|---|---|---|
| `tls` | `ssl_client_raw_cert` | `ssl_client_verify` must be exactly `SUCCESS` |
| `xfcc` | the header | `remote` must match `mesh_origin` |

Required, with no default, and **configuring both is a startup error.** Falling
back from one source to the other is worse than guessing: it means whoever can
suppress one source selects the other.

`spiffe_from_cert_pem` (`wc_mediator::peer`) is a dependency-free DER walk to the
URI SAN. It verifies nothing, and that is the safety argument: the chain, expiry
and CA are the terminator's job, so a mis-parse yields a *wrong* identity, which
resolves to no contract, and cannot yield a forged one. Exactly one `spiffe://`
URI is accepted; zero is not an SVID, and more than one would let the holder
pick which identity to be.

| Detail | Why the test exists |
|---|---|
| `extnValue` is the **last** element of the extension | The optional `critical` BOOLEAN sits between the OID and the value, so a fixed index reads the boolean on any certificate that marks its SAN critical |
| indefinite length (`0x30 0x80`) is refused | It is legal BER and never legal DER. Accepting it means parsing a structure the verifier upstream never agreed to |

### 8.6b.5 Why there is no ceiling here

There was one, and it is gone. `Registry` counted per process, so
`max_calls_per_hour = 10` admitted up to 40 across four nginx workers on one
node. Kong made the operator acknowledge the multiplier with a scope setting,
which turned a silent wrong number into a stated one and left it wrong. Every
fix failed on something structural (§8.6.5), so rate, concurrency and spend were
removed as a capability.

### 8.6b.6 What each test layer can and cannot reach

| Layer | Reaches | Cannot reach |
|---|---|---|
| `wc-gateway` unit + `tests/pin.rs` | every verdict, gate 8 against a minted contract | anything about a transport |
| `wc-kong` ABI tests (39) | null handling, ownership, panic isolation, the header matching the Rust | whether Lua calls it correctly |
| Lua suite (18, LuaJIT) | the real handler against the real cdylib, Kong stubbed; the `cdef` against the header | Kong's own phase restrictions |
| `scripts/kong-drill.sh` (14) | real Kong, real mTLS, curl as the client, the `.so` built **for the container** | a cluster |

The layers are not redundant. The drill earned its place immediately:
`kong.response.set_raw_body` is `body_filter`-only, so every catalogue returned
`An unexpected error occurred`. The stub had accepted the call in any phase, so
the Lua suite was green; it now models the restriction.

The container build is itself a phase. A glibc or architecture mismatch is a
class of failure no test on the build host can reach, and this repository is
developed on macOS while Kong runs Linux.

### 8.6b.7 Known limits

| Limit | Status |
|---|---|
| several contracts per `(caller, callee)` | supported. Resolution picks by **tool**, a catalogue shows the union and must satisfy every pin, and two contracts claiming one tool is a conflict reported at load and refused at the call |
| hot reload | **built.** `contracts_url` + `token` refresh on a background OS thread per worker, so the contract set and the revocation feed arrive together. Not a Lua timer: `ControlPlaneClient` is blocking, and a blocking fetch from `ngx.timer` stalls the worker's event loop. The spawn happens on the first request in each worker, **after nginx forks** — a thread created before the fork does not survive into the child, so building the handle in Kong's `init` phase would produce workers whose refresher is not running. Without a URL a worker holds what it loaded and says so at startup; expiry is then the only containment |
| `no_pin` exists | for a staged rollout only. Gate 8 is not optional, which is why the flag is spelled out rather than looking like a tuning knob |
| rate, concurrency and spend | **removed as a capability** (§8.6.5). Set volume limits on the proxy |

---

## 8.7 Algorithms

### 8.7.1 The narrowing algebra

```
meet(a, b).surface        = a.surface ∩ b.surface
meet(a, b).max_depth      = min(a.max_depth, b.max_depth)
meet(a, b).data_classes   = a.data_classes ∩ b.data_classes
meet(a, b).jurisdictions  = a.jurisdictions ∩ b.jurisdictions
meet(a, b).exp            = min(a.exp, b.exp)
```

`meet` is commutative, associative and idempotent. The property tests assert all
three plus the one that matters: `meet(a,b) ≤ a` and `meet(a,b) ≤ b`, always.
**There is no `join`.**

### 8.7.2 Issuance — `issuance`, `authority`

```
request → cpolicy → Disposition
  Grant          → mint
  NeedsApproval  → park as PendingRequest, await approval
  Refused        → return the diff
```

`PendingRequest` carries `owner_must_approve` and `owner_merge_approves`, both
`#[serde(default)]` so an old event log still replays.

Approval by merge is the keyless path: the provider approves by merging a pull
request, with no key ceremony. The choke point that keeps it honest is:

```rust
fn merge_evidence_cannot_stand_in_for(
    pending: &PendingRequest,
    approval: &ApprovalRef,
) -> Result<()>
```

| Rule | Detail |
|---|---|
| A merge cannot satisfy a request that requires a role holder | unless `owner_merge_approves` was explicitly opted into |
| The owner is re-read from the registry | at **approval** time, not at request time |
| `ApprovalFile` binds by digest *and* restates the parties, items and TTL in words | so a human reviewing the pull request sees what they are approving without computing a hash |
| Break-glass (`WC-6004`, outside policy) sets `owner_must_approve: false` | visibly, in code, rather than by omission |

### 8.7.3 Admission — see §8.5.4

### 8.7.4 Screening — `screen`

Declared-surface text is screened against `screen-rules.toml` for
instruction-injection shapes, at admission and again at every re-attestation,
because the text can change under a stable endpoint. Blocking is `WC-1005`, and
the finding quotes the offending text — "blocked" without a trigger is
unactionable.

### 8.7.5 Drift classification — `assurance`

| Change | Class |
|---|---|
| Documentation typo | benign |
| Tool added **outside** the contracted surface | benign |
| Contracted tool's description changed | **material** |
| Contracted tool's parameters changed | **material** |
| New exfiltration-shaped instruction | **material** |
| Endpoint moved | **material** |

Benign drift auto-updates the pin under standing policy. Material drift suspends
every dependent contract (`WC-5002`) and notifies owners with the diff.

### 8.7.6 Federation narrowing — `federate`

Every federated term is `min`-intersected with the superior's. A subordinate
statement that would widen is rejected with `WC-2033`. Anchors that go stale
stop new issuance (`WC-2034`) while existing contracts run to `exp`.

### 8.7.7 Canonicalisation — `wc-core::canon`

`wcs1`: deterministic key ordering, no insignificant whitespace, depth bounded at
32. Two implementations must agree byte-for-byte or the pin is meaningless
across them. `connect canon` exposes it for conformance.

---

## 8.8 Storage

| Store | Shape | Durability |
|---|---|---|
| Event log | Append-only, one file per tenant | The system of record |
| Projection | In-memory, rebuilt by replay | Disposable |
| Evidence chain | Append-only hash chain + signed anchors | Never deleted, never relocated to a database |
| Contract set | Distributed to mediators, cached in memory | Rebuilt from the log |

`backup` covers backup, restore and retention. **Retention retires; it never
deletes** — the regulatory clock outlives the entity.

---

## 8.9 Wire formats

### 8.9.1 MCP and JSON-RPC

`rpc` implements JSON-RPC 2.0 over stdio. `mcp` implements only the shapes the
mediation path needs: `initialize`, `tools/list`, `tools/call`. A malformed frame
is `WC-4008`.

### 8.9.2 The contract JWS

`application/warden-connection+jws`. Asymmetric only. Size-bounded (`WC-3121`);
unknown schema versions refused (`WC-3120`).

### 8.9.3 Receipts

TOML at `warden/contracts/<cid>.toml`. Human-readable, digest-bound, and
**never** the signed artifact.

### 8.9.4 Air-gapped bundles — `bundle`

`bundle export` / `bundle verify` move a contract set across an air gap without a
network path between the planes.

Two fixes worth recording:

| Defect | Fix |
|---|---|
| The artifacts directory was spelled twice — `base/artifacts` in `TenantPaths`, `state/contracts` in `Store`. Each side was self-consistent, so every test that built both from its own helper agreed with itself. Only a real tenant disagreed, and `bundle export` reported zero contracts on an estate that had them | Derived once, in `tenant::TenantPaths`, from the state root plus `store::ARTIFACT_DIR`. The test asserts the path against a real `Store` write, not a second literal |
| A missing artifact was a warning printed *after* the file was written, exit 0. An air-gap transfer would ship a bundle short of live contracts and be told it worked | **A missing artifact refuses.** A bundle that omits a live contract addressed to that mediator is not a smaller bundle, it is a wrong one |

---

## 8.10 Concurrency and the latency budget

### 8.10.1 Threading

No async runtime. Threads and blocking I/O. The control plane is single-writer
(§8.5.2); the data plane is lock-free on the hot path because the cache is
read-mostly.

### 8.10.2 The hot path

Contract verification performs **no network call**. Everything gates 1–14 need is
either in the contract, in the cache, or already established by the transport.

### 8.10.3 Ceilings — `thresholds`, `bench`

Latency ceilings live in one place (`wc-core::thresholds`) and are asserted by
`bench` as gates, not as reports. A benchmark that only prints a number does not
fail a regression.

---

## 8.11 Error taxonomy

82 codes. The family is the triage:

| Family | Range | Domain |
|---|---|---|
| Admission | `WC-1001`–`WC-1010` | Identity, provenance, screening, pinning, tiering |
| Registry | `WC-2001`–`WC-2005` | Existence, duplication, transitions, quarantine |
| Zones & discovery | `WC-2011`–`WC-2021` | Zone pairs, throttling, attestation |
| Federation | `WC-2030`–`WC-2035` | Anchors, chains, expiry, widening, signals |
| Issuance | `WC-3001`–`WC-3015` | Subsets, policy, preconditions, TTL, widening, caps |
| Approval | `WC-3020`–`WC-3027` | Roles, staleness, dual control, signatures, owner, declared approvers, cross-side distinctness |
| Renewal | `WC-3030`–`WC-3033` | Posture, re-attestation, ended contracts, withdrawal |
| **Mediation** | `WC-3101`–`WC-3121` | The 14 verification gates |
| Runtime | `WC-4001`–`WC-4020` | No contract, uncontracted tool, egress, frames, peer headers. `WC-4003`–`WC-4005` are retired ceilings (§8.6.5) |
| Assurance | `WC-5001`–`WC-5030` | Re-attestation, drift, credentials, blast-radius truncation |
| Containment | `WC-6001`–`WC-6004` | Dual control, feed, acknowledgement, break-glass |
| Evidence | `WC-7001`–`WC-7020` | Sinks, chain, export, PDP |
| Platform | `WC-8001`–`WC-8004` | Policy, tenant, lock, config |

Every code carries a fail direction. `Code::fail_direction` and `is_fail_closed`
are an exhaustive match — adding a code without deciding its direction does not
compile.

Eleven codes ship reserved: defined and never emitted, each marked `RESERVED:` in
`error.rs`. `scripts/code-emission.sh` fails CI when a code is neither emitted
nor marked.

---

## 8.12 Security implementation

### 8.12.1 Keys — `keys`, `custody`, `signer`

Six signing operations, each with its own key: issuer, anchor, revocation,
approver, second approver, bundle. `custody` enforces which key signs what and
the rules that keep them apart.

| Control | Detail |
|---|---|
| Every key flag has a delegated partner | `--signer COMMAND` runs an operator-supplied command — stdin is the base64url signing input, stdout is the signature — so the process never holds the key. Two guard tests enforce the pairing across every command that accepts a key |
| `--require-external-signing` | Refuses to start if any key is on local disk. Deliberately satisfiable: a delegated key passes, so the posture is not a way to refuse everything |
| The unrecoverable loss | The anchor key. Move it first |

### 8.12.2 What never leaves

| Never | Where enforced |
|---|---|
| A signed JWS in a repository | `receipt` — receipts only |
| A credential minted by this system | There is no credential path |
| The evidence chain in a database | §8.8, by design |
| A peer identity taken from a header | `peer` (`WC-4020`) |

### 8.12.3 The `open_pr` token

Needs `contents:write` and `pull-requests:write` on one repository, and **must
not be able to merge**. There is no merge operation in the shim protocol, so the
shim cannot merge even if its token could.

---

## 8.13 Configuration

Resolved after the command is known and before flags are checked, because which
keys apply depends on the command. `--config FILE` is explicit; otherwise
`connect.toml` beside the process is used if present.

**Absent is fine. Present and broken is a startup failure** (`WC-8004`) — a file
that exists was written on purpose.

`tenant` validates tenant ids before any path is built, because a tenant id is a
path component.

### 8.13.1 The Kong plugin's configuration

Passed as JSON to `wc_init` and validated there, not in Lua. `schema.lua` catches
a shape error at `kong config` time; it is not a second validator and defaults
nothing the library does not default.

| Key | Required | Note |
|---|---|---|
| `contracts` | ✓ | paths to `*.jws`. Empty is a startup error, because a filter with no contract set denies everything while looking healthy |
| `routes` | ✓ | path to `routes.toml`. A table that maps nothing is a startup error for the same reason |
| `identity` | ✓ | `tls` \| `xfcc`. **No default** — §8.6b.4 |
| `mesh_origin` | with `xfcc` | leading `/` means a unix socket, otherwise an address. Setting it with `identity = "tls"` is an error, not a precedence rule |
| `issuer_pub` + `kid`, or `jwks_file`, or `jwks_url` | one of | issuer keys |
| `mediator_id`, `issuer_id` | ✓ | who the contracts must be addressed to, and from which plane |
| `contracts_url` + `token` | together | hot reload. A URL without a token is refused, because a set no revocation can reach is worse than no set |
| `refresh_secs`, `max_stale` | | refresh period, and the seconds a worker may run on an unrefreshed set before every call is refused |
| `evidence_path`, `evidence_delivery` | | the decision trail. Must contain `%w` when `worker_processes > 1` — each worker keeps its own chain |
| `mode` | | `enforce` (default) \| `observe` |
| `pin_max_age` | | seconds; `0` means no bound |
| `any_zone`, `no_pin` | | both default false. `no_pin` is for a staged rollout only |
| `library_path` | | absolute path to `libwc_kong.so`, or a name for the dynamic loader |

`workers` is **not** a configuration key. The handler reads `ngx.worker.count()`;
asking an operator to restate nginx's own number is asking them to get it wrong.

---

## 8.14 Observability, operations, compatibility

Metric families are declared once in `wc-core::obs` and populated by
`wc-control::obs` and `wc-mediator::obs`. Each family documents **where its
number comes from**, so a dashboard showing zero can be told apart from a metric
nobody increments.

Decision logs carry `cid` as the correlation root, which lets a policy-engine
audit row, a mediator decision and a control-plane lifecycle event be joined
later.

---

## 8.15 Test strategy

| Layer | What it proves | Where |
|---|---|---|
| Unit | Each module's guards fire | `crates/*/src/*.rs` |
| Property | `meet` narrows, always | `wc-e2e/tests/property.rs` |
| Conformance | Fixture vectors verify identically | `fixtures/contracts/` |
| End-to-end | The whole loop, including federation | `wc-e2e/tests/` |
| Drills | 15 scripted drills in `scripts/`, plus `scripts/scm/parse-drill.sh`. Ten of them and `parse-drill` run in GitHub CI; `adoption`, `inventory`, `proposal`, `rotation` and `scale` are run on demand | `scripts/` |
| **ABI** | Null handling, ownership, panic isolation, and the C header matching the Rust it describes | `wc-kong/tests/abi.rs` |
| **Lua** | The real Kong handler against the real cdylib, with Kong stubbed | `wc-kong/lua/spec/`, LuaJIT |
| **Real proxy** | Envoy and Kong, real mTLS, the library built for the container | `scripts/envoy-drill.sh`, `scripts/kong-drill.sh` |
| **Mutation** | That the tests would notice | `scripts/gate-mutation-check.sh`, in CI |

Four rules this repository learned the hard way:

| Rule | What happened |
|---|---|
| Three statements of one ABI can disagree | Rust declares the C surface, `include/wc_kong.h` describes it, `wcffi.lua`'s `cdef` restates it. A disagreement is not a crash — it is Lua reading a field at the wrong offset. `tests/abi.rs` compares the header against the Rust; `spec/abi_spec.lua` compares the `cdef` against the header |
| A stub more permissive than the host is a green suite and a broken plugin | When a drill finds something a stub allowed, the stub is what needs the fix |
| Mutation testing is not optional | It has exposed a drill phase that passed with its guard deleted and a redundant sort in `receipt.rs`. If a mutant survives, the test is decorative |
| A number in a table is not executable | The Lua suite said 19 against 18 cases; the Kong drill said 11 after four phases were added. `scripts/doc-claims.sh` checks the counted claims above against the tree |

`cargo test --workspace` aborts at the first failing crate. Use `--no-fail-fast`.

### Known flake

SCM shim tests fail under parallel load — near one run in two on a shared
runner, against 2 in 55 locally. Because `cargo test` runs before the drills, it
was stopping the drills from executing at all.

| Cause | Status |
|---|---|
| A shim that exits 127 races the parent's write to its stdin | **Fixed.** Returning on the write error made one misconfiguration report two diagnoses: `WC-8004 ... not executable` when the write won, `WC-1001 ... cannot write the query` when it lost. A broken pipe there means the child exited; it now falls through to the exit-status classification. Pinned by a test that repeats the case 64 times |
| `a_ref_the_host_disagrees_with_is_an_error_not_a_downgrade` under 8-thread contention | **Open**, roughly 3 runs in 25. The failing detail has not been captured — it reproduces on a loaded machine, not an idle one |

---

## 8.16 Build order

| Wave | Delivered |
|---|---|
| 1 | `offer` — what a provider makes available |
| 2 | `need` — what a consumer asks for, and the `Disposition` |
| 3 | `pipeline` — may this pipeline speak for this asset |
| 4 | `scm` — what was merged, via the shim |
| 5 | Keyless approval by merge, and the choke point |
| 6 | `proposal`, `receipt`, `dist` |
| 7 | `inventory`, `portal` |
| 8 | E5 — `wc-gateway` and the Envoy `ext_proc` binding |
| 9 | E6 — the Kong binding: `wc-gateway` shared surface, `wc-kong` C ABI, `spiffe_from_cert_pem`, the Lua plugin, the Kong drill |

## 8.16b Deliberately not built: a database adapter

The event log and the evidence chain are files on purpose. A database would make
them queryable and destroy the property that makes them evidence: that they can
be verified by someone who does not trust the system that wrote them. Permanent
decision, not a backlog item.

---

## 8.17 Resolved HLD open questions

| Q | Resolution |
|---|---|
| Q1 · Where does approval authority live? | `authority`, resolved at approval time from the registry (§8.7.2) |
| Q2 · Can a provider approve without holding a key? | Yes — approval by merge, with `merge_evidence_cannot_stand_in_for` as the choke point |
| Q3 · How does discovery scale to thousands of repositories? | Reserved paths, read not probed, with a reported watermark (§8.5.11) |
| Q4 · One policy or two? | Two. `connect-policy.toml` gates existence; the policy engine gates calls (§8.5.5) |

---

## 8.18 Traceability

| Use case | Primary modules | Codes |
|---|---|---|
| [UC-01](use-cases/UC-01-register-and-admit-an-agent.md) | `admission`, `attest`, `screen`, `registry` | `WC-1001`–`WC-1010` |
| [UC-02](use-cases/UC-02-onboard-a-tool-server.md) | `admission`, `canon`, `screen` | `WC-1002`, `WC-1005`, `WC-1010` |
| [UC-03](use-cases/UC-03-mediated-capability-discovery.md) | `broker` | `WC-2021` (throttling truncates, see §8.5.6) |
| [UC-04](use-cases/UC-04-establish-a-connection.md) | `issuance`, `cpolicy`, `authority`, `gate`, `filter` | `WC-3010`–`WC-3121`, `WC-4001`, `WC-4002` |
| [UC-05](use-cases/UC-05-cross-organisation-federation.md) | `federate` | `WC-2030`–`WC-2035` |
| [UC-06](use-cases/UC-06-surface-drift.md) | `assurance`, `canon`, `screen` | `WC-5002`, `WC-3108` (a failed re-attestation reports as `Posture::Degraded`, not `WC-5001`) |
| [UC-07](use-cases/UC-07-emergency-quarantine.md) | `contain`, `dist`, `caep` | `WC-6001`–`WC-6004`, `WC-5030` |
| [UC-08](use-cases/UC-08-shadow-estate-detection.md) | `inventory`, `portal` | `WC-2001`, `WC-4001` |
| [UC-09](use-cases/UC-09-renewal-review-offboarding.md) | `issuance`, `assurance`, `backup` | `WC-3032`, `WC-3033` (degraded posture denies in `cpolicy` with its own reason, not `WC-3030`/`WC-3031`) |
| [UC-10](use-cases/UC-10-regulatory-register-and-evidence.md) | `export`, `chain`, `rekor` | `WC-7001`–`WC-7010` |

---

## 8.19 The three claims this design has to keep

| # | Claim | What breaks without it |
|---|---|---|
| 1 | A contract can only narrow | If any path widens authority, the artifact is unsafe to hand to a party you do not fully trust, and the premise fails |
| 2 | A compromised control plane cannot manufacture a contract | Verification is against issuer keys, never against a database the mediator trusts |
| 3 | The evidence is verifiable by someone who does not trust us | The moment the chain requires trusting the plane that wrote it, it stops being evidence and becomes a claim |

Every design decision above is downstream of one of these three.
