# 8 · warden-connect — Low-Level Design

> Status: design, implementation-ready. Companion to
> [07-hld.md](07-hld.md), which decides *what* the components are. This document
> decides *how they are built*: crate layout, module boundaries, concrete types
> and signatures, exact algorithms, storage records, wire formats, error codes,
> latency budgets, and the test suite that proves each of them.
>
> Everything here is grounded in the shipped Warden core tree
> (`../../warden/src/*.rs`, Rust 2021, MSRV 1.89) — reuse claims name real
> modules and real functions.
>
> **§8.17 resolves all seven HLD open questions.** They are decisions now, not
> questions.

---

## 8.1 How to read this document

| Section | Answers |
|---|---|
| 8.2–8.4 | Constraints, crate layout, module inventory |
| 8.5 | Every control-plane module: types, signatures, behaviour |
| 8.6 | The data-plane mediator, as an `Upstream` decorator over unmodified Warden core |
| 8.7 | The nine algorithms that carry the design's weight (pseudocode) |
| 8.8 | Storage records and sizing |
| 8.9 | Wire formats — contract, MCP/A2A framing, feeds, bundles |
| 8.10 | Concurrency, latency budget, and how p99 < 5 ms is actually met |
| 8.11 | Error taxonomy — 70 codes, each with a fail direction and a metric |
| 8.12 | Key management, crypto choices, input limits |
| 8.13 | Config and env reference |
| 8.14 | Observability |
| 8.15 | Test strategy, conformance vectors, performance gates |
| 8.16 | Build order: module × phase, with acceptance criteria |
| 8.17 | Resolved HLD open questions |
| 8.18 | Traceability: capability → module → function → test |

Naming convention throughout: `wc` = warden-connect, `cid` = connection id,
`wcs1` = the canonical surface serialisation version 1.

---

## 8.2 Design constraints inherited from Warden core

These are not preferences; they are the properties that make the family
deployable, and warden-connect does not get to break them.

| Constraint | Consequence for this design |
|---|---|
| **Thin dependency tree** — Warden core keeps to `serde`, `serde_json`, `sha2`, `hex`, `toml`, `jsonwebtoken` 10.4 `rust_crypto`, `base64`, `ureq`, `libc`, and so do we | No async runtime, no ORM, no graph database, no ML runtime. New deps must be justified per-crate in §8.3. Today: `wc-core` resolves to 30 crates, `wc-control` to 61. |
| **No async** — thread-per-request, `Arc<Gateway>` shared state (`http.rs::serve`) | Control plane is a synchronous threaded HTTP server; the sentinel is a worker-thread pool, not a task executor. |
| **File-backed durable state** — hash-chained JSONL (`audit.rs`), signed feeds (`revocation.rs`), JSON snapshots (`budget.rs`) | The registry and contract store are **append-only event logs with in-memory projections** (§8.8), not a SQL schema. A SQL backend is an optional P4 adapter behind a trait, never the default. |
| **Asymmetric-only signatures** (`identity.rs` `ASYMMETRIC_ALGS`) | Contracts are ES256/ES384/EdDSA/PS256/RS256. An HMAC-signed contract is rejected before any other check — algorithm confusion is structurally excluded. |
| **Fail closed with a named reason** | Every rejection path returns a `WC-*` code (§8.11); no boolean-only failures, no silent allow. |
| **Verify a carried artifact; never look up on the hot path** | Contract verification does zero network I/O. Distribution is out-of-band (§8.9.4). |
| **12-factor config** (`docs/twelve-factor.md`) | Everything via `WARDEN_CONNECT_*` env, TOML file, or flag — flags override file overrides env (core's precedence). |
| **`util::{canonical_json, sha256_hex, sha256_bytes, now_unix}`** | Reused verbatim; canonical JSON is already specified and fuzzed in core. |

**Deliberately not built** (to keep this honest about scope): no service mesh, no
gRPC surface, no distributed consensus (single-writer control plane with
replicated readers through P3), no ML classifier in surface screening, no payload
inspection.

---

## 8.3 Crate and repository layout

A Cargo workspace, so that the data plane can be compiled *into* the Warden proxy
with no extra network hop, while the control plane stays a separate binary.

```
warden-connect/
├─ Cargo.toml                  # [workspace] members
├─ crates/
│  ├─ wc-core/                 # shared types + crypto + canon; no I/O policy
│  │  └─ src/{lib,model,canon,contract,zone,error,util}.rs
│  ├─ wc-control/              # the control plane (lib)
│  │  └─ src/{lib,store,registry,admission,screen,broker,cpolicy,
│  │           sentinel,evidence,export,federate,api,tenant}.rs
│  ├─ wc-mediator/             # the data plane (lib, linked into warden proxy)
│  │  └─ src/{lib,cache,gate,filter,ceiling,peer,drain}.rs
│  └─ wc-cli/                  # the `connect` binary
│     └─ src/main.rs
├─ fixtures/
│  ├─ contracts/               # conformance vectors (§8.15.3)
│  ├─ surfaces/                # canonicalisation vectors
│  └─ screening/               # labelled screening corpus
├─ fuzz/fuzz_targets/          # 5 targets (§8.15.2)
├─ connect.toml                # control-plane config example
├─ connect-policy.toml         # connection policy example
└─ docs/                       # 01..08 + SVG
```

### Dependency budget

| Crate | Depends on | Added third-party |
|---|---|---|
| `wc-core` | `serde`, `serde_json`, `sha2`, `hex`, `jsonwebtoken`, `base64` | **`unicode-normalization`** (NFC for `wcs1`) — the only new primitive that cannot be hand-rolled safely |
| `wc-control` | `wc-core`, `toml`, `ureq`, `libc` | none |
| `wc-mediator` | `wc-core`, **`warden`** | none |
| `wc-cli` | all of the above | none |

### No dependency on Warden core, except where the deployment model demands it

**Only `wc-mediator` links `warden`**, and there the coupling is not a choice: it
compiles *into* the shipped proxy so the data plane adds no second hop (§8.10). If
you run the mediator you run Warden core, by construction.

Everywhere else, warden-connect is standalone. Three reasons, in order of weight:

1. **The contract verifier is a conformance implementation.** §7.4 makes
   `connect verify <contract>` the ground truth for a candidate standard. A
   reference verifier that requires linking the vendor's product is not a
   reference verifier — a partner org or a competing platform must be able to
   check a `warden-connection+jws` with one small crate.
2. **Adoption is any-subset.** A team may run Warden core plus `warden-trace` and
   substitute something else for `connect`; another may take `connect` alone for
   the register and the kill switch. The family's interface is deliberately **two
   signed artifacts and one identifier** (§7.7), so a code dependency between
   members would contradict the stated architecture.
3. **Independent release cadence and a one-crate SBOM** for adopters who only
   want the connection layer.

The primitives both projects need — canonical JSON and SHA-256 — are ~30 lines,
vendored into `wc_core::util` and **behaviourally identical on purpose**:
compatibility is held by shared golden vectors (`fixtures/`), which is checked
rather than assumed. When a third family member needs the same primitives, extract
them into a neutral crate then; not before, because duplicating thirty lines twice
is cheaper than getting a crate boundary wrong across four repositories.

What this costs is **code** leverage, not **design** leverage. The evidence chain,
sink semantics, revocation feed format and policy idiom are all reimplemented to
Warden core's proven design, in its idiom, with its operational model — and with
format compatibility as a tested contract. §8.4 marks which modules link core
and which do not; doc 04 §4.10 carries the corrected leverage ledger.

### Binaries and how the mediator ships

| Artifact | What it is |
|---|---|
| `connect` | Control-plane CLI + server (`connect serve`). One binary, subcommand tree per §8.5.11. |
| `connect mediate` | The inline mediator: composes **unmodified** Warden core's `Gateway` with an `Upstream` decorator (§8.6.1). One process, no extra hop — this is how §8.10's latency budget is met, and it requires no change to Warden core. |
| *(none)* | The mediator is **optional**. A control-plane-only deployment gives the register, pins, drift detection and exports — the P0 wedge — with no data-plane component at all (§7.9). Enforcement is what requires a mediator. |

---

## 8.4 Module inventory

Rough sizes are implementation estimates, for sequencing — not targets.

| Module | Responsibility | LOC | Phase | Relationship to Warden core |
|---|---|---|---|---|
| `wc-core::model` | `Entity`, `Contract`, `Zone`, `Approval`, `PostureEvent`, ids, serde | 450 | P0 | — |
| `wc-core::canon` | `wcs1` canonicalisation + pinning (§8.7.1) | 400 | P0 | vendored primitives, byte-compatible |
| `wc-core::contract` | Mint / verify `warden-connection+jws` (§8.7.2) | 600 | P1 | `jsonwebtoken` directly; same asymmetric-only stance |
| `wc-core::zone` | Zone lattice, assurance bars, zone-pair resolution | 220 | P4 (stub P1) | — |
| `wc-core::error` | `WcError` + the `WC-*` code table (§8.11) | 260 | P0 | — |
| `wc-control::store` | Append-only logs, projections, single-writer lock, compaction | 600 | P0 | same file discipline as `audit.rs` |
| `wc-control::registry` | Entity CRUD, lifecycle state machine, pins, indexes | 480 | P0 | — |
| `wc-control::admission` | 7-stage admission pipeline, tier derivation (§8.7.3) | 900 | P0/P2 | independent |
| `wc-control::screen` | Declared-surface injection screening (§8.7.4) | 1540 | P2 | — |
| `wc-control::broker` | Capability index, mediated discovery, anti-enumeration | 380 | P1 | — |
| `wc-control::cpolicy` | `connect-policy.toml`: parse, evaluate, lint, dry-run | 1100 | P1 | condition algebra reimplemented to match `policy.rs` syntax exactly |
| `wc-control::sentinel` | Re-attest scheduler, drift classify, posture score, blast radius | 780 | P2/P3 | — |
| `wc-control::evidence` | Lifecycle chain, anchors, OCSF/CAEP sinks | 850 | P0 | same formats as `audit`/`anchor`/`sink`/`ocsf`, held by golden vectors |
| `wc-control::export` | DORA / CPS 230 / OSCAL / CSV / CycloneDX registers | 520 | P4 | — |
| `wc-control::federate` | OpenID-Federation trust chains, partner resolution | 460 | P4 | OIDC discovery reimplemented |
| `wc-control::api` | HTTP/1.1 surface, authn, idempotency, rate limits | 900 | P0→ | same shape as `http.rs`/`authzen.rs` |
| `wc-control::tenant` | Per-tenant roots: store, keys, policy, chain | 240 | P4 | — |
| `wc-mediator::cache` | Contract snapshot cache, revocation set, COW swap | 320 | P1 | **links `revocation::RevocationSet`** |
| `wc-mediator::gate` | `Upstream` decorator: the 11 verification steps | 420 | P1 | **links `warden::{Gateway, Upstream}`** — no core changes |
| `wc-mediator::filter` | `tools/list` filtering, surface allowlist | 260 | P1 | **links `mcp.rs`** |
| `wc-mediator::ceiling` | Rate / spend / fan-out / concurrency ceilings | 300 | P1/P3 | **links `budget.rs`** |
| `wc-mediator::peer` | Peer identity from mTLS / SVID / mesh socket | 340 | P1 | **links `dpop.rs`** |
| `wc-mediator::drain` | Drain vs abort on revocation | 180 | P3 | **links `control.rs`** pause/drain |
| `wc-cli::main` | Command tree, exit codes, output formats | 900 | P0→ | core CLI conventions |

Total ≈ 13 kLOC of new Rust, of which the P0 wedge (`model`, `canon`, `error`,
`util`, `store`, `registry`, `admission`, `evidence`, `api` subset, `cli` subset)
is ≈ 4.5 kLOC. **Bold** entries are the only ones that link Warden core, and they
are all in `wc-mediator` — which is compiled into the proxy by design (§8.3).

---

## 8.5 Control-plane modules

### 8.5.1 `wc-core::model` — the domain types

```rust
/// A registry entity: an agent, an MCP tool server, or an A2A agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub id: EntityId,                  // "spiffe://…" | "urn:wc:…"
    pub kind: Kind,                    // Agent | McpServer | A2aAgent
    pub owner: HumanRef,               // required; no owner => cannot be Active
    pub service: Option<String>,
    pub tier: Tier,                    // 1..=4, derived at admission
    pub zone: ZoneId,
    pub pin: Pin,                      // wcs1 surface pin (§8.7.1)
    pub provenance: Vec<ProvRef>,
    pub posture: Posture,              // Attested | Degraded | Unattested | Quarantined
    pub posture_score: u8,             // 0..=100 (§8.7.6)
    pub lifecycle: Lifecycle,          // Pending | Active | Suspended | Retired
    pub data_classes: Vec<String>,
    pub jurisdictions: Vec<String>,
    pub endpoint: Option<String>,      // servers only; never returned by discovery
    pub reattest_every: u32,           // seconds, from tier
    pub reattested_at: u64,
    pub created_at: u64,
    pub updated_at: u64,
    pub schema: u16,                   // record schema version
}

/// The pinned surface. `manifest` covers the whole declared surface;
/// `tools` carries a per-item hash so drift can be localised (§8.7.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pin {
    pub alg: String,                        // "wcs1"
    pub manifest: String,                   // "sha256:…" over the whole wcs1 doc
    pub items: BTreeMap<String, String>,    // item name -> "sha256:…"
    pub pinned_at: u64,
}

impl Pin {
    /// Digest over exactly the contracted subset — the value a contract carries.
    /// Additive change outside the subset cannot move it.
    pub fn surface_digest(&self, names: &[String]) -> Result<String, WcError>;
}
```

`EntityId`, `Cid`, `Jti`, `HumanRef` and `ZoneId` are newtypes over `String` with
validating constructors (charset, length ≤ 512, no control characters). Parsing
identifiers is a security boundary, so it happens exactly once, at the edge.

**Lifecycle state machine** — the only legal transitions:

| From → To | Trigger | Guard |
|---|---|---|
| — → `Pending` | `POST /v1/entities` | schema valid |
| `Pending` → `Active` | admission pass | owner present, posture ≠ Quarantined, tier confirmed |
| `Pending` → *dropped* | admission fail (enforce mode) | — |
| `Active` → `Suspended` | material drift, failed re-attestation, owner departure | — |
| `Suspended` → `Active` | re-admission pass | full pipeline re-run |
| `Active`/`Suspended` → `Quarantined` | `POST /v1/quarantine`, CAEP signal | — |
| `Quarantined` → `Pending` | explicit clear + **full re-admission** | dual control |
| any → `Retired` | offboarding | contracts revoked first |

`Quarantined → Active` does not exist. That is invariant 6 from the HLD expressed
as unreachable code, which is the only way an invariant survives contact with a
roadmap.

### 8.5.2 `wc-control::store` — append-only logs with in-memory projections

One design decision, and it is load-bearing: **the store is an event log, not a
mutable table.** The registry's current state is a projection. This gives
point-in-time `as_of` exports (UC-10) and tamper-evidence for free, and it matches
core's file discipline.

```rust
/// A typed append-only JSONL log with an exclusive-writer lock and O(1) append.
pub struct Log<T: Serialize + DeserializeOwned> { /* file, lock, seq, path */ }

impl<T> Log<T> {
    pub fn open(path: &Path) -> Result<Self, WcError>;   // flock(LOCK_EX|LOCK_NB)
    pub fn append(&mut self, rec: &T) -> Result<u64, WcError>;  // -> seq
    pub fn replay(path: &Path) -> Result<Vec<(u64, T)>, WcError>;
    pub fn replay_until(path: &Path, ts: u64) -> Result<Vec<(u64, T)>, WcError>;
    pub fn rotate(&mut self, max_bytes: u64) -> Result<(), WcError>;
}

/// Everything the control plane knows, rebuilt from the logs at startup.
pub struct Projection {
    pub entities: HashMap<EntityId, Entity>,
    pub contracts: HashMap<Cid, ContractRecord>,
    pub by_caller: HashMap<EntityId, HashSet<Cid>>,   // blast radius, forward
    pub by_callee: HashMap<EntityId, HashSet<Cid>>,   // blast radius, reverse
    pub by_pin: HashMap<String, HashSet<Cid>>,        // drift fan-out, O(1)
    pub capabilities: CapabilityIndex,                // broker
    pub expiring: BinaryHeap<Reverse<(u64, Cid)>>,    // sentinel expiry watch
}

impl Projection {
    pub fn rebuild(root: &Path) -> Result<Self, WcError>;
    pub fn apply(&mut self, ev: &Event) -> Result<(), WcError>;  // pure, total
    pub fn as_of(root: &Path, ts: u64) -> Result<Self, WcError>;
}
```

Rules that keep this safe:

- `apply` is **pure and total** — no I/O, no panics, unknown event kinds are
  recorded as `unapplied` and counted, never dropped silently. This is what makes
  forward-compatible schema evolution possible (§8.14.4).
- **Single writer.** `flock` on `wc.lock`; a second writer fails fast with
  `WC-8003` rather than interleaving. HA is active/standby with the lock as the
  election primitive (P4 adds an optional Postgres advisory-lock adapter behind
  `trait Store`).
- **Durability.** `append` writes then `fdatasync` for issuance and quarantine
  events; posture and discovery events batch-sync every 64 records or 200 ms.
  Losing a discovery log line is acceptable; losing a mint record is not.
- **Compaction.** At `rotate`, a `snapshot.json` of the projection plus the
  segment boundary is written; startup loads the newest snapshot and replays the
  tail. Startup at 10⁵ contracts: snapshot load ≈ 180 ms, tail replay ≈ 20 ms.
- The lifecycle **evidence** chain (`audit.rs`) is separate from the state log and
  is never compacted. State can be rebuilt; evidence must not be rewritable.

### 8.5.3 `wc-control::registry`

```rust
pub struct Registry<'a> { proj: &'a mut Projection, log: &'a mut Log<Event> }

impl Registry<'_> {
    pub fn put(&mut self, e: Entity, actor: &HumanRef) -> Result<Entity, WcError>;
    pub fn get(&self, id: &EntityId) -> Option<&Entity>;
    pub fn transition(&mut self, id: &EntityId, to: Lifecycle, why: &str)
        -> Result<(), WcError>;                       // enforces §8.5.1 table
    pub fn repin(&mut self, id: &EntityId, pin: Pin, cause: RepinCause)
        -> Result<Vec<Cid>, WcError>;                 // returns affected contracts
    pub fn set_posture(&mut self, id: &EntityId, p: Posture, score: u8)
        -> Result<(), WcError>;
}
```

There is deliberately **no `list_all` on the API surface** for agent principals
(T2.4). `connect posture` and exports enumerate; they require an operator role and
are logged as bulk reads. The absence of a list endpoint is a design artifact, so
it is asserted by a test (`api::tests::no_agent_visible_enumeration`).

### 8.5.4 `wc-control::admission` — seven stages, typed failures

```rust
pub struct AdmissionRequest {
    pub kind: Kind,
    pub id: Option<EntityId>,          // absent for servers => derived from endpoint identity
    pub card: Option<Vec<u8>>,         // A2A agent card (JWS or JSON)
    pub endpoint: Option<String>,      // MCP server
    pub attestation: Vec<Attestation>, // sigstore bundle / SLSA / in-toto
    pub owner: HumanRef,
    pub service: Option<String>,
    pub declared: Declared,            // data classes, jurisdictions, requested tier
    pub zone: ZoneId,
    pub mode: Mode,                    // Enforce | Observe
}

pub struct AdmissionOutcome {
    pub entity: Entity,
    pub findings: Vec<Finding>,        // screening + provenance findings
    pub tier_rationale: String,        // why this tier — shown to the approver
    pub stages: Vec<StageResult>,      // every stage's verdict, for evidence
}

pub fn admit(req: AdmissionRequest, ctx: &AdmissionCtx)
    -> Result<AdmissionOutcome, WcError>;
```

| Stage | Function | Fails with | Observe-mode behaviour |
|---|---|---|---|
| 1 · Identity | `verify_workload_identity` — X.509-SVID against trust bundle, or JWT-SVID via `identity::verify_token_str` with `VerifyOpts{ jwks, aud, leeway }` | `WC-1001` | admit, `posture: Unattested` |
| 2 · Surface acquisition | `fetch_surface`: MCP `initialize` + `tools/list` over `ureq` (timeout 10 s, ≤ 4 MiB, ≤ 512 tools), or card fetch | `WC-1002` | **hard fail in both modes** — nothing is pinned on trust |
| 3 · Card signature | `verify_card_jws` — detached JWS, key from operator JWKS or federation chain | `WC-1003` | admit + finding |
| 4 · Provenance | `verify_provenance` — Sigstore bundle offline verification, SLSA predicate subject digest == artifact digest, Rekor inclusion proof if `--rekor` | `WC-1004` | admit + finding |
| 5 · Screening | `screen::surface(&Surface, tier_hint)` (§8.7.4) | `WC-1005` (block class) | admit + findings |
| 6 · Tier | `derive_tier` (§8.7.3) | `WC-1006` (tier > requested ceiling) | same |
| 7 · Pin | `canon::pin(&Surface)` → `Pin`; write entity; append evidence | `WC-1007` | same |

Stage 2 being unforgiving in both modes is the sharp edge of "no register on
trust" (UC-02 A3). Every other stage degrades; the pin cannot.

### 8.5.5 `wc-control::cpolicy` — connection policy

Mirrors core's condition algebra rather than inventing one: `when = [...]`,
`{all=[]}`, `{any=[]}`, `{not=…}` and the same four operators behave identically to
Warden policy, so an operator writes one stanza style for both planes. It is
**reimplemented, not imported** — `wc-control` links no Warden core (§8.3) — and
`syntax_matches_warden_core_policy` pins the four shapes so they cannot drift apart.

Two things the spec below leaves out and the implementation had to decide. Zone
bars **combine with their trust level's floor**, so a `trust = "partner"` zone
cannot declare its way below a human approver, a 7-day ceiling and delegation depth
1, whatever its stanza says. And glob semantics follow core exactly — `prefix*`
matches any value beginning with `prefix`, *including* `prefix` itself — which is
why `internal.*` does not match bare `internal` (it does not begin with
`internal.`) while `public*` does match bare `public`.

```rust
#[derive(Deserialize)]
pub struct ConnectPolicy {
    pub default: ConnDecision,              // Allow | Deny | RequireApproval
    #[serde(default)] pub zones: Vec<ZoneDef>,
    #[serde(default)] pub rules: Vec<ConnRule>,
    #[serde(default)] pub standing: StandingLimits,   // §8.17-Q4
    pub version: String,                    // "connect-policy@v37"
}

#[derive(Deserialize)]
pub struct ConnRule {
    #[serde(default)] pub caller_zone: Option<Glob>,
    #[serde(default)] pub callee_zone: Option<Glob>,
    #[serde(default)] pub caller_tier: Option<TierMatch>,
    #[serde(default)] pub callee_tier: Option<TierMatch>,
    #[serde(default)] pub surface: Option<SurfaceMatch>,   // { write: false, max_tools: 8 }
    #[serde(default)] pub data_classes: Option<Vec<String>>,
    #[serde(default)] pub jurisdictions: Option<Vec<String>>,
    #[serde(default)] pub when: Option<Match>,             // core's tree, over conn: fields
    pub decision: ConnDecision,
    #[serde(default)] pub approver_role: Option<String>,
    #[serde(default)] pub ttl_max: Option<Duration>,
    #[serde(default)] pub terms: Option<TermsOverride>,    // caps, never raises
    #[serde(default)] pub reason: Option<String>,
}

pub struct ConnEval {
    pub decision: ConnDecision,
    pub reason: String,
    pub trace: String,             // "rule[3]/zone-bar/standing-cap" — into evidence
    pub ttl_max: u32,
    pub terms: Terms,              // intersection of rule terms and zone bar
    pub approver_role: Option<String>,
}

impl ConnectPolicy {
    pub fn evaluate(&self, req: &ConnRequest, reg: &Projection, now: u64) -> ConnEval;
    pub fn lint(&self) -> LintReport;                  // core's LintReport type
    pub fn dry_run(&self, proj: &Projection) -> DryRunReport;  // diff vs live contracts
}
```

Evaluation order — deterministic and documented, because "first match wins" is
only safe if the operator can predict the order:

1. **Structural preconditions** (not rules; cannot be overridden by any rule):
   both parties `Active`; posture ≠ `Quarantined`; `requested_surface ⊆
   callee.pin.items`; requester holds authority over the caller entity.
2. **Zone bar** for `(caller.zone, callee.zone)` — sets the *floor* on assurance
   and the *ceiling* on TTL. Unknown pair ⇒ most restrictive (`WC-2011`).
3. **First matching `[[rules]]` entry**, top to bottom.
4. **`default`** if no rule matched.
5. **Standing-policy cap** (§8.17-Q4) — can only downgrade `Allow` to
   `RequireApproval`, never upgrade.

`terms` from rules and zone bars **intersect**; a rule cannot raise a ceiling a
zone bar set. The `Terms::intersect` function is total and has a property test
asserting monotone narrowing — the algebra from §1.4 enforced in the type system's
neighbourhood.

`connect policy dry-run` replays every *live* contract against a candidate policy
and reports which would no longer be issuable. Policy changes are the most likely
cause of a self-inflicted outage, so this is a P1 deliverable, not a nicety.

### 8.5.6 `wc-control::broker` — mediated discovery

```rust
pub struct CapabilityIndex {           // built from admitted surfaces
    by_capability: HashMap<CapKey, Vec<EntityId>>,   // "payments.balance.read"
    by_jurisdiction: HashMap<String, HashSet<EntityId>>,
    tokens: HashMap<EntityId, TokenBucket>,          // per-asker query budget
}

pub struct DiscoverResult {
    pub matches: Vec<CapabilitySummary>,   // { entity_ref, capability, tier, zone, owner_team }
    pub truncated: bool,
}

pub fn discover(q: &Query, asker: &EntityId, pol: &ConnectPolicy, proj: &Projection)
    -> Result<DiscoverResult, WcError>;
```

Anti-enumeration is four concrete mechanics, not an aspiration:

1. **Eligibility filter before shaping** — candidates are dropped unless
   `pol.evaluate()` for `(asker → candidate)` would return `Allow` or
   `RequireApproval`. `Deny` candidates are indistinguishable from nonexistent.
2. **Shaped results** — `CapabilitySummary` has no endpoint, no tool schema, no
   full tool list. Reaching an endpoint requires a contract; discovery hands out
   no reachability.
3. **Token bucket per asker**: 30 queries/min, 300/day burst-limited; overflow
   returns `truncated: true` with an empty tail and emits a
   `wc.discovery.throttled` finding. Never a 4xx that confirms existence.
4. **Uniform latency** — the empty-result path is padded to the p50 of the
   non-empty path (±jitter) so timing does not leak existence. Cheap, and it
   closes the only side channel the shaping leaves open.

`CapKey` is derived at admission from tool names, descriptions and declared
capability tags via a deterministic normalisation (lowercase, dot-segmented,
stop-words removed). It is a search key, never an authority key.

### 8.5.7 `wc-control::sentinel` — scheduler, drift, posture, blast radius

```rust
pub struct Sentinel {
    workers: usize,                       // default: min(8, cores)
    queue: Mutex<BinaryHeap<Reverse<Task>>>,   // (due_at, kind, target)
    cfg: SentinelCfg,
}

pub enum TaskKind { Reattest, ExpiryWarn(u32), CredExpiry, PostureRescore, FederationRefresh }

impl Sentinel {
    pub fn tick(&self, now: u64, ctx: &mut Ctx) -> TickReport;      // pull due tasks, run
    pub fn reattest(&self, id: &EntityId, ctx: &mut Ctx) -> Result<Reattestation, WcError>;
    pub fn classify_drift(&self, old: &Pin, new: &Pin, contracts: &[ContractRecord])
        -> DriftVerdict;                                            // §8.7.5
    pub fn score(&self, e: &Entity, sig: &Signals) -> u8;           // §8.7.6
    pub fn blast_radius(&self, id: &EntityId, depth: u8, proj: &Projection) -> BlastReport;
}
```

Scheduling detail that matters operationally: `due_at` carries **±10% jitter**
seeded from `sha256(entity_id)` so 10⁴ entities admitted by the same CI run do not
re-attest in the same second. Tier 1 interval is 1 h (NFR); tier 4 is 7 d.
Re-attestation is rate-limited per callee endpoint (max 1 concurrent, 4/min) so the
sentinel cannot become a denial-of-service against a tool server it is
supposedly protecting.

### 8.5.8 `wc-control::evidence` — the reuse showpiece

```rust
pub struct Evidence {
    chain: warden::audit::AuditLog,        // hash-chained JSONL, verbatim reuse
    sinks: Vec<warden::sink::Sink>,        // OCSF / CAEP × file / webhook × filter × delivery
    ocsf_path: Option<String>,
}

pub struct LifecycleEvent {
    pub kind: EventKind,       // Register|Admit|Deny|Discover|Request|Approve|Mint|Renew
                               // |Revoke|Drift|Repin|Reattest|Quarantine|Ack|Export|BreakGlass
    pub cid: Option<Cid>,
    pub contract_jti: Option<Jti>,
    pub entities: Vec<EntityId>,
    pub actor: Actor,          // Human | Service | Sentinel
    pub decision: &'static str,
    pub reason: String,
    pub policy_version: String,
    pub detail: Value,         // kind-specific, redacted via warden::redact
}

impl Evidence {
    pub fn append(&mut self, ev: &LifecycleEvent) -> Result<warden::audit::Entry, WcError>;
    pub fn ship_blocking(&self, ev: &LifecycleEvent) -> Result<(), WcError>;  // no mint without evidence
    pub fn verify(root: &Path) -> Result<ChainReport, WcError>;               // `connect audit verify`
}
```

`LifecycleEvent` maps onto core's `audit::Entry` by carrying connect fields in the
existing `args`/`matched` shape plus **three new hashed columns** (`cid`,
`contract_jti`, `policy_version`). This is a change to core's `Entry` struct and
its `row_hash` input — an additive, versioned change, gated as described in
§8.14.4. It must be additive-and-hashed: a `cid` that is recorded but not folded
into `row_hash` is a `cid` an attacker can rewrite, which would defeat the whole
correlation-root claim.

OCSF mapping (via `warden::ocsf::event`):

| Lifecycle kind | OCSF class | `activity_id` | Severity |
|---|---|---|---|
| Register / Admit | Entity Management (3004) | Create | Informational |
| Deny (admission) | Detection Finding (2004) | Create | Medium |
| Discover | API Activity (6003) | Read | Informational |
| Mint / Renew | Entity Management (3004) | Update | Informational |
| Approve / Deny (contract) | Account Change (3001) | — | Low |
| Drift (material) | Detection Finding (2004) | Create | **High** |
| Quarantine | Detection Finding (2004) + CAEP SET | Create | **Critical** |
| Ack / non-Ack | Application Lifecycle (6002) | — | Low / High |
| Export | API Activity (6003) | Read | Informational |

### 8.5.9 `wc-control::export`

Generators are pure functions from a point-in-time projection to bytes, so they
are trivially testable and reproducible:

```rust
pub fn dora_register(p: &Projection, as_of: u64) -> Result<Vec<Csv>, WcError>;   // RT.01–RT.07 shaped rows
pub fn cps230_register(p: &Projection, as_of: u64) -> Result<Vec<Csv>, WcError>;
pub fn oscal_component(p: &Projection, as_of: u64) -> Result<Value, WcError>;    // component-definition
pub fn cyclonedx_bom(e: &Entity) -> Result<Value, WcError>;                      // 1.6, surface BOM
pub fn exceptions(p: &Projection) -> Vec<Exception>;                             // never silently omit
```

Every export embeds `{ as_of, chain_head_seq, chain_head_hash, anchor_ref }`, so
`connect audit verify --export <file>` proves the export matches a signed
checkpoint. And every export carries the `exceptions` section (UC-10 A1) — the
register that declares its own gaps is the one that survives an audit.

### 8.5.10 `wc-control::api`

Built on core's `http.rs` threaded server. Authn is a Warden session token
(`identity::verify_token_str`) carrying roles; every mutating call requires an
`Idempotency-Key` (stored 24 h, keyed on `sha256(key ‖ body)`).

| Method & path | Role | Idem | Success | Notable errors |
|---|---|---|---|---|
| `POST /v1/entities` | `connect.register` | yes | 201 `Entity` | 1001–1007, 2002 |
| `GET /v1/entities/{id}` | `connect.read` | — | 200 | 2001 |
| `POST /v1/discover` | agent SVID or `connect.read` | — | 200 `DiscoverResult` | 2020 (throttled) |
| `POST /v1/connections` | `connect.request` | yes | 202 `ConnRequest` \| 201 contract (standing) | 3010–3015 |
| `POST /v1/connections/{cid}/approve` \| `/deny` | rule's `approver_role` | yes | 200 | 3020–3023 |
| `GET /v1/connections/{cid}` | `connect.read` | — | 200 | 3001 |
| `POST /v1/connections/{cid}/renew` \| `/revoke` | `connect.request` / `connect.admin` | yes | 200 | 3030–3032 |
| `POST /v1/quarantine` | `connect.secops` (dual control at tier 1) | yes | 202 `QuarantineReport` | 6001–6004 |
| `GET /v1/posture?drift&expiring&unattested&shadow` | `connect.read` | — | 200 (cursor paged) | — |
| `GET /v1/blast-radius/{id}?depth=` | `connect.read` | — | 200 | 5030 |
| `GET /v1/mediators/{mid}/contracts?since=` | mediator SVID | — | 200 `ContractSetDelta` | 4001 |
| `POST /v1/mediators/{mid}/ack` | mediator SVID | — | 204 | 6003 |
| `GET /v1/jwks.json` | public | — | 200 | — |
| `GET /v1/export?format=&as_of=` | `connect.compliance` | — | 200 (streamed) | 7010 |
| `POST /access/v1/evaluation` | `connect.read` | — | 200 AuthZEN | 7020 |
| `GET /metrics`, `GET /healthz`, `GET /readyz` | local | — | 200 | — |

Approval bodies carry a **detached JWS signed by the approver's key** (reusing
core's `approval_sig.rs` pattern), so an approval is a signed artifact rather than
a database row an operator with SQL access can forge.

### 8.5.11 `wc-cli` — command tree and exit codes

The HLD's CLI (§7.6) plus the operator verbs the LLD needs:

```sh
connect serve            --config connect.toml
connect register agent   --card … --attest … --owner … [--observe]
connect register server  --endpoint … --tier … --zone … [--insecure-skip-provenance]
connect discover         --capability … --as … [--jurisdiction …]
connect request | approve | deny | contracts {list,show,renew,revoke}
connect quarantine <party> --reason … [--drain|--abort] [--confirm-blast-radius]
connect posture          [--drift|--expiring|--unattested|--shadow] [--json]
connect blast-radius <id> [--depth N]
connect export           --format dora|cps230|oscal|ocsf|csv|bom --as-of …
connect verify           <contract.jws> [--mediator-id …] [--pins pins.json]
connect audit verify     [--export <file>]
connect canon            <surface.json>          # print the wcs1 doc + pin
connect screen           <surface.json>          # screening report, exit 5 on block
connect policy           lint | dry-run | show
connect keys             init | rotate | jwks
connect bundle           export --mediator … --out bundle.wcb   # air-gapped
connect bench            [--verify|--filter|--mint]              # perf gates
```

| Exit | Meaning |
|---|---|
| 0 | success |
| 1 | operational error (I/O, network, config) |
| 2 | usage error |
| 3 | policy decision: denied |
| 4 | verification failed (contract, chain, provenance) |
| 5 | screening block / material drift |
| 6 | approval required and not granted (non-interactive) |

Distinguishing 3 / 4 / 5 matters: CI needs to tell "you asked for too much" from
"this artifact is not trustworthy" from "this surface looks poisoned" without
scraping stderr.

---

## 8.6 Data plane — `wc-mediator`

### 8.6.1 Integration without modifying Warden core

The mediator needs to see three things on the wire: the `initialize` handshake, the
`tools/list` response, and each `tools/call`. Warden core already routes all three
through one public trait, so **no change to Warden core is required**:

```rust
// warden/src/upstream.rs — already public
pub trait Upstream {
    fn request(&mut self, req: &Request) -> Response;
    fn notify(&mut self, _req: &Request) {}
}
```

`Gateway::new` takes a `Box<dyn Upstream + Send>`, and `gateway.rs` forwards through
it at `:348` (`initialize`), `:351` (every non-`tools/call` method, so `tools/list`,
`resources/list`, `prompts/list`) and `:929` (an allowed `tools/call`). So the
mediator is an **`Upstream` decorator** wrapping the real upstream:

```rust
/// Wraps the real upstream so the connection is verified, the catalogue is
/// filtered, and ceilings are applied — with no change to Warden core.
pub struct MediatedUpstream {
    inner: Box<dyn Upstream + Send>,
    cache: Arc<Cache>,
    cfg: GateCfg,
    conn: Option<Admitted>,
}

impl Upstream for MediatedUpstream {
    fn request(&mut self, req: &Request) -> Response {
        match req.method.as_str() {
            "initialize"    => self.on_initialize(req),     // verify contract, pin presented surface
            "tools/list"
            | "resources/list"
            | "prompts/list" => self.filter_catalog(req),   // reduce to the contracted surface
            "tools/call"     => self.authorize_call(req),   // allowlist + ceilings
            _                => self.inner.request(req),
        }
    }
}
```

`connect mediate` is then a binary that composes Warden's `Gateway` with this
decorator — one process, no extra hop, no fork, no cargo feature in someone else's
repository. The dependency direction is one-way (`wc-mediator → warden`), which
also avoids the circular dependency an in-core trait would have created: core would
define the trait, `wc-mediator` would implement it, and core's *binary* would then
need `wc-mediator` to wire it up.

**This is the property that keeps warden-connect off anyone else's critical path.**
Enforcement ships against unmodified Warden core, today.

#### The one thing the decorator does not get, and the optional patch that would

For `tools/call`, the decorator runs *after* Warden's action policy rather than
before. The uncontracted call is still blocked — the decorator returns a tool error
instead of forwarding — but two details are imperfect:

| Imperfection | Consequence |
|---|---|
| Denial is attributed at the upstream layer | Core's audit row reads `allow` / forwarded, with the connection denial recorded separately by connect. Reconstructing "why" needs both records rather than one. |
| Core's per-run budget reserves before forwarding | An uncontracted call consumes a budget unit it never used. |

Neither weakens the security property; both muddy the evidence. So a small
**optional** upstream patch stays worth proposing to Warden core — but as a P2
improvement, not a prerequisite:

```rust
// warden/src/gateway.rs — proposed, optional
pub trait ConnectionGate: Send + Sync {
    fn authorize_call(&self, tool: &str, args: &Value) -> Result<CallCtx, GateDenial>;
}
impl Gateway {
    pub fn set_connection_gate(&mut self, gate: Box<dyn ConnectionGate>);
}
```

Called in `dispatch` after the revocation check and **before** `policy.evaluate`, it
buys exactly two things: correct ordering (an uncontracted tool never reaches policy
evaluation or the budget) and `CallCtx` carrying `cid` + `contract_jti` into
`audit::Accountability`, so every action row inherits the correlation root in core's
own hashed chain (T7.7). That second one is what makes `warden-trace` exact rather
than heuristic, so it is worth having — later, and only if core wants it.

Fail-closed default, in both designs: **if a contract source is configured but no
gate can be constructed, the mediator refuses to start.** A mediator that silently
degrades to pass-through is worse than no mediator, because the estate believes it
is protected.

### 8.6.2 `wc-mediator::cache` — copy-on-write snapshots

```rust
pub struct Snapshot {
    pub set_hash: String,                          // hash of the whole set, for ACKs
    pub seq: u64,
    pub by_pair: HashMap<(EntityId, EntityId), Arc<VerifiedContract>>,
    pub by_cid: HashMap<Cid, Arc<VerifiedContract>>,
    pub issuer_keys: JwkSet,
}

pub struct Cache {
    live: RwLock<Arc<Snapshot>>,                   // readers clone an Arc; never block on refresh
    revocations: Mutex<warden::revocation::RevocationSet>,
    refresh: Duration,                             // default 5 s
}

/// A contract whose signature has already been verified once, with the
/// per-connection derived state precomputed.
pub struct VerifiedContract {
    pub payload: Contract,
    pub tools: HashSet<String>,                    // O(1) allowlist
    pub resources: Vec<GlobPattern>,
    pub verified_at: u64,
    pub jti: Jti,
}
```

Refresh runs on a background thread: fetch `ContractSetDelta`, verify each new
contract's JWS **once**, build a new `Snapshot`, swap the `Arc`. Steady-state
verification cost on the connection path is therefore a hash-map lookup, not an
ECDSA verify — which is the trick that makes the latency budget comfortable rather
than tight (§8.10).

Revocation refresh reuses `RevocationSet::refresh()` verbatim, with two new event
kinds appended to core's `"jti" | "agent" | "human"`:

| kind | subject | Effect |
|---|---|---|
| `cid` | connection id | that connection dies |
| `party` | entity id | every contract naming it as caller or callee dies |

Both are signed ES256 events on the existing feed, so core's "unsigned events are
rejected and alerted" property carries over for free.

### 8.6.3 `wc-mediator::gate` — the eleven checks

The HLD lists ten; implementation adds the token-binding check (§8.17-Q7). Order
is chosen so that the cheapest and most decisive checks run first, and so no
expensive work happens for a contract that is already dead.

```rust
pub fn verify(
    c: &VerifiedContract,
    peer: &PeerIdentity,
    presented: &Pin,
    token: Option<&warden::identity::VerifiedToken>,
    cfg: &GateCfg,
    now: u64,
) -> Result<Admitted, GateDenial>
```

| # | Check | Cost | Denial |
|---|---|---|---|
| 1 | `alg` ∈ asymmetric set (before any signature work) | ~0 | `WC-3101` |
| 2 | JWS verified against issuer JWKS by `kid` (once, at cache build) | ~70 µs cold, 0 warm | `WC-3102` |
| 3 | `nbf ≤ now < exp`, no grace | ~0 | `WC-3103` |
| 4 | `aud == cfg.mediator_id` | ~0 | `WC-3104` |
| 5 | `jti`, `cid`, both parties ∉ revocation set | ~0 | `WC-3105` |
| 6 | `peer.caller == contract.caller.id` (authenticated identity) | ~0 | `WC-3106` |
| 7 | `peer.callee == contract.callee.id` | ~0 | `WC-3107` |
| 8 | `presented.surface_digest(contract.surface.tools) == contract.callee.surface_digest` **and** `presented.manifest == contract.callee.manifest` unless `allow_additive` | ~5 µs | `WC-3108` + DRIFT |
| 9 | `assurance.posture == Attested` (or observe override, logged) | ~0 | `WC-3109` |
| 10 | `zone_pair(caller.zone, callee.zone)` permitted locally | ~0 | `WC-3110` |
| 11 | Token binding: if the session token carries `wcid`, it equals `cid`; else bind by pair | ~0 | `WC-3111` |

Check 8 is where the per-item pin pays off. With a whole-manifest hash only, a
tool server adding an unrelated tool breaks every contract it has — operators
learn to ignore drift alerts, and the control dies of noise. With
`surface_digest` over the contracted subset, an additive change outside the
contracted surface is *structurally* benign: the digest does not move, the
connection stands, and the change is still recorded and re-screened at the
registry level. Precision comes from the data model, not from a classifier.

### 8.6.4 `wc-mediator::filter` — catalogue filtering

```rust
pub fn filter_tools_list(conn: &Admitted, resp: &mut Value) -> FilterStat;
```

Rules, each of which exists because its absence is a bypass:

1. Retain a tool only if `conn.tools.contains(name)`. Unknown shapes (no `name`,
   non-object entries) are **dropped**, not passed.
2. On any structural surprise (`result.tools` absent or not an array) → replace
   with an **empty array**, count `wc.filter.failclosed`, and log. An
   unfilterable catalogue is an empty catalogue.
3. `nextCursor` from the upstream is dropped unless every page is filtered; a
   paginated catalogue is fully drained (bounded at 512 tools) before responding.
4. `resources/list` and `prompts/list` filter against `surface.resources` glob
   patterns and `surface.prompts`. Prompts are an injection vector too, and an
   unfiltered `prompts/list` reintroduces exactly the exposure `tools/list`
   filtering removes.
5. The filtered-out set is recorded once per connection (not per call), with
   counts, so operators can see the ratchet from "23 tools exposed" to "2".

**Invariant asserted by test:** for any upstream response and any contract, the
set of tool names visible to the agent is a subset of `contract.surface.tools`.
This is the single most valuable line of the product (uncontracted tools never
enter model context), so it gets a property test over generated catalogues plus a
fuzz target.

### 8.6.5 `wc-mediator::ceiling`

Extends `warden::budget::Budget` (which already does atomic
compare-and-increment persisted to a JSON file — the check-then-increment race is
already closed there) with time-windowed and cost-shaped counters:

```rust
pub struct Ceilings {
    calls: SlidingWindow,        // max_calls_per_hour, 60 × 1-minute buckets
    spend: DayCounter,           // max_spend_usd_per_day, durable
    concurrent: AtomicU32,       // max_concurrent, RAII guard
    fanout: AtomicU32,           // downstream connections opened by this cid
}

impl Ceilings {
    pub fn reserve(&self, cid: &Cid, cost: Option<f64>) -> Result<Guard, WcError>;
}
```

Persisted per `cid` under `.warden/connect/ceilings/<cid>.json` on the same
single-writer discipline as `budget.rs`, so a proxy restart does not reset a
ceiling — the bypass core explicitly closed with its durable budget file.

Breach behaviour: deny the call, keep the contract valid, notify the owner, emit
an OCSF finding. A rate breach is a signal, not a compromise; revoking the
contract on breach converts a noisy neighbour into an outage.

### 8.6.6 `wc-mediator::peer` — where identity actually comes from

Peer identity is never taken from a claim in the request body. Three trusted
sources, in precedence order:

| Mode | Source | Trust basis |
|---|---|---|
| `mtls` | X.509-SVID from the completed TLS handshake (SAN URI) | The handshake |
| `spire` | SPIFFE Workload API over a local UDS | Kernel-verified local socket + SPIRE attestation |
| `mesh` | A allowlisted header (`x-forwarded-client-cert`) **only** when the connection arrives over a configured local socket from the mesh sidecar | Local socket + mesh mTLS (§8.17-Q6) |
| `jwt-svid` | JWT-SVID + DPoP proof via `warden::dpop::verify_proof` | Signed token + holder-key proof |

In `mesh` mode the header is honoured only from `127.0.0.1`/UDS with a
`--mesh-socket` match; from any other origin it is ignored and logged as a
spoofing attempt (`WC-4020`). Header-based identity that is trusted from anywhere
is not identity.

### 8.6.7 `wc-mediator::drain`

Reuses core's pause/drain model (`control.rs`, `http.rs::request_shutdown`).
On a revocation naming a live connection:

| Config | In-flight calls | New calls | Bound |
|---|---|---|---|
| `--on-revoke=drain` (default for non-security revocations) | allowed to complete | refused | `--drain-timeout`, default 10 s, then abort |
| `--on-revoke=abort` (default for quarantine) | connection closed, JSON-RPC error to the agent | refused | immediate |
| ambiguous / unparsable config | **abort** | refused | — |

The ACK to the control plane carries `{ mediator_id, set_hash, revoked_cids,
in_flight_aborted, ts }` and is signed with the mediator's SVID key, so
"contained" is an attested claim rather than an HTTP 200.

---

## 8.7 Algorithms

### 8.7.1 A1 · `wcs1` canonical surface serialisation and pinning

This resolves HLD open question 2. The pin is only as good as its canonical form,
and a noisy pin trains operators to ignore drift alerts — so the normalisation is
specified precisely, versioned, and fuzzed.

```
wcs1_document(surface, kind, entity_id) -> String
  1  REJECT if bytes > 4 MiB, items > 512, JSON depth > 32       (WC-1010)
  2  PROJECT each item to the allowlisted fields only:
       mcp_tools:  name, description, inputSchema, outputSchema,
                   annotations{title, readOnlyHint, destructiveHint,
                               idempotentHint, openWorldHint}
       a2a_card:   name, version, description, skills[{id,name,description,
                   inputModes,outputModes,tags}], securitySchemes, url
     Everything else (server version banners, `_meta`, vendor extensions,
     timestamps) is DROPPED — it is not part of what the model reads.
  3  NORMALISE every string:
       a. Unicode NFC
       b. CRLF/CR -> LF
       c. strip trailing whitespace per line; strip leading/trailing blank lines
       d. collapse runs of space/tab/NBSP(U+00A0) to a single space
       e. PRESERVE case, punctuation, zero-width chars (U+200B-U+200F,
          U+FEFF) and bidi controls (U+202A-U+202E, U+2066-U+2069)
  4  ORDER: items sorted by `name` (UTF-8 byte order); object keys lexicographic
     byte order; arrays order-preserved EXCEPT JSON-Schema `required` and `enum`,
     which are sorted (their order carries no meaning)
  5  DROP null and absent optional fields; numbers via serde_json shortest
     round-trip
  6  SERIALISE with warden::util::canonical_json over
       { "v":1, "kind":kind, "entity":entity_id, "items":[…] }

pin(surface) -> Pin
  doc        = wcs1_document(...)
  manifest   = "sha256:" ‖ sha256_hex(doc)
  items[n]   = "sha256:" ‖ sha256_hex(canonical_json(projected_item_n))
```

Two decisions inside step 3 deserve their reasoning:

- **Zero-width and bidi characters are preserved, not stripped.** Stripping them
  would make an invisible-instruction attack *invisible to the pin too* — the
  poisoned and clean surfaces would hash identically. They stay in the hash (so
  they move the pin) and are flagged as a block-class finding by `screen` (§8.7.4).
  Normalisation must never launder an attack.
- **Whitespace and formatting are normalised** because reformatting a manifest is
  a real, frequent, benign event. Every drift alert an operator dismisses costs
  some of the control's credibility; the ones that fire must mean something.

**Algorithm versioning.** The pin carries `alg: "wcs1"`. A future `wcs2` does not
retroactively create drift: on upgrade the sentinel computes both, and if `wcs1`
matches while `wcs2` differs it performs a **silent shadow re-pin** and records a
`repin{cause: AlgUpgrade}` event with no suspension. Migration noise is a design
problem, and the design solves it once rather than in each operator's runbook.

Property tests: key-order permutation invariance; whitespace-reformat invariance;
idempotence (`pin(pin_doc)` stable); **sensitivity** — a single inserted U+200B,
one changed word in a description, or a swapped `required` member must all move
the hash.

### 8.7.2 A2 · Contract mint

```
mint(req, eval, entities, keys, now) -> Jws
  1  ASSERT structural preconditions again at mint time (not just at request
     time): both parties Active, posture != Quarantined,
     req.tools ⊆ callee.pin.items.keys()                             (WC-3012)
  2  ASSERT eval.decision == Allow, and if approval was required, that a valid
     approver JWS exists whose `policy_version` == current policy version.
     A policy change between approval and mint invalidates the approval.  (WC-3021)
  3  ttl = min(req.ttl, eval.ttl_max, zone_bar.ttl_max, ISSUER_MAX_TTL=30d)
  4  terms = Terms::intersect(req.terms, eval.terms, zone_bar.terms)   // narrowing only
  5  cid = "conn_" ‖ hex(sha256(caller ‖ callee ‖ sorted(tools) ‖ nonce))[..8]
     jti = "cx_" ‖ 128 bits from getrandom
  6  aud = each mediator on the path (one contract per mediator; never a
     multi-audience contract — see A2 in the HLD threat table)
  7  payload = { typ, cid, iss, aud, jti, iat, nbf, exp,
                 caller{id, card|pin, zone, tier},
                 callee{id, manifest, surface_digest, zone, tier},
                 surface, terms, assurance, approval, policy_version, schema:1 }
  8  sign ES256 with the tenant's current issuer key; header{alg, kid, typ}
  9  evidence.ship_blocking(Mint) if any blocking sink configured        (WC-7001)
 10  store contract record; index by_caller/by_callee/by_pin/expiring
 11  enqueue distribution to each `aud` mediator
```

Step 6 — one contract per mediator — is what makes replay across mediators
impossible rather than merely detectable. Step 9 orders evidence *before*
issuance: in a regulated estate, an authority that exists without a durable record
of its creation is exactly the gap the audit finds.

### 8.7.3 A3 · Tier derivation

Deterministic, explainable, and printed with its rationale, because a tier that
nobody can explain gets argued rather than applied.

```
derive_tier(declared, surface, zone) -> (Tier, rationale)
  base = max over declared.data_classes:
           restricted|pii|phi|pci -> 1 ; confidential -> 2 ; internal -> 3 ; public -> 4
  cap  = max over surface capability classes:
           money_movement|infra_destructive|identity_admin|code_exec -> 1
           external_send|data_export|write_persistent              -> 2
           read_sensitive                                          -> 3
           read_public                                             -> 4
  tier = min(base, cap)                      // most sensitive dimension wins
  escalate one step (toward 1) if any:
    zone.trust == external
    surface contains an unbounded/wildcard item
    declared.jurisdictions crosses a data-residency boundary
  clamp to 1..=4; tier <= 2 => human approval; tier == 1 => dual control
```

Capability classes come from a maintained keyword→class map applied to tool names,
descriptions and annotations (`destructiveHint`, `readOnlyHint` are respected but
never trusted alone — they are the callee's self-assessment). Unmapped tools
default to class 2, not 4: an unclassified capability is treated as significant
until someone classifies it.

### 8.7.4 A4 · Declared-surface injection screening

This resolves HLD open question 3: screening gates admission only for
high-precision detector classes; everything else flags. Two verdict classes,
different powers.

| ID | Detector | Class | Rationale |
|---|---|---|---|
| S1 | Zero-width chars, bidi overrides, RTL/LTR embedding in any item text | **block** | No legitimate tool description needs invisible characters. Near-zero false-positive rate. |
| S2 | Homoglyph/script mixing in `name`, or a name within edit-distance 1 of an existing registered tool from a different entity | **block** | Cross-server shadowing / typosquatting |
| S3 | Base64/hex blob > 64 chars, `data:` URI, or HTML comment inside a description | **block** | Payload smuggling into model context |
| S4 | Egress-shaped instruction: a secret noun and a hand-over verb co-occurring **within one sentence** — env vars, file contents, credentials, keys, prior messages or "the full conversation" directed into an argument | **block** | The canonical tool-poisoning exfiltration primitive. The sentence boundary is what makes it precise enough to block: "reads your SSH config" is documentation, "pass the contents of `~/.ssh/id_rsa` in the query field" is an attack. A full stop only ends a sentence when whitespace follows, or dotted paths (`.env`, `~/.aws/credentials`) are shredded and the detector silently never fires |
| S5 | Model-directed override phrasing: "ignore previous/above", "system prompt", "do not tell the user", "before calling any other tool", "instead of using" | flag (score 30 each) | Legitimate imperative text exists; not precise enough to block |
| S6 | Cross-entity reference: description names another server, tool or endpoint | flag (40) | Legitimate in orchestration tools |
| S7 | Parameter-shape abuse: free-text param documented as receiving conversation/context; secret-shaped param name (`token`, `key`, `password`) that is not `secret: true` | flag (35) | Common in badly-designed-but-honest tools |
| S8 | Outliers: description > 2 KiB, > 24 params, > 8 nested schema levels | flag (15) | Weak signal, useful in aggregate |

```
screen(surface, tier_hint) -> Report
  findings = run S1..S8 over every item's name/description/params/annotations
  if any block-class finding:
      verdict = Block                             (WC-1005)
  else:
      score = Σ flag weights, capped per item at 100
      verdict = match (score, tier_hint):
          (s, t) if s >= 60 && t <= 2 => Block
          (s, _) if s >= 60           => EscalateTier
          (s, _) if s >= 25           => Flag
          _                           => Pass
```

Operational discipline that makes this deployable rather than merely
defensible:

- **Approval is by pinned item hash.** An AppSec engineer can accept a flagged
  description once; the acceptance is keyed on `items[name] = sha256:…` with the
  approver and ticket recorded. It survives re-attestation and lapses the moment
  the text changes. The false-positive tax is paid once per text, not once per
  scan.
- **Calibration gate.** The block classes ship only after achieving **precision ≥
  0.98** on `fixtures/screening/` (target ≥ 400 labelled items: real MCP servers
  from the public ecosystem plus curated attack samples). Recall is measured and
  reported, never used as a release gate — a screener that blocks legitimate tools
  gets switched off, and a switched-off control has zero recall.
  The gate is mechanical, not procedural: `ScreenRules.calibrated` is what permits
  the blocking classes to block, it ships `false`, and a test asserts it stays
  `false` while the corpus is under target. Uncalibrated, `S1`–`S4` still run and
  still report; they simply cannot decide.
- **A report states what executed.** `Report` carries `ran`, `skipped` (with a
  reason per detector) and `softened` (why the verdict is weaker than the
  detectors asked for). Two of the three brakes on blocking — mode, and
  calibration — would otherwise be indistinguishable from a clean surface, which
  is the failure mode this whole control exists to avoid. Disabling every blocking
  detector while declaring `calibrated = true` is rejected at load.
- **Detector powers are not configurable.** Phrase lists live in the TOML because
  attack phrasing moves faster than releases. Which detectors may block does not:
  it is fixed in code, so no ruleset can promote `S5` to blocking.
- **Modes.** `screen.mode = observe | flag | enforce`, default `flag` at P2 and
  `enforce` at P3, per zone. External zones enforce first.
- Detector rules live in a versioned TOML (`screen-rules.toml`) with a
  `ruleset_version` recorded on every finding, so a re-screen result is
  attributable to a ruleset rather than to a mystery.

### 8.7.5 A5 · Drift classification

Mostly structural, thanks to per-item pins — which is what keeps the noise low.

```
classify(old: Pin, new: Pin, contracts: [ContractRecord]) -> DriftVerdict
  contracted = ⋃ c.surface.tools for c in contracts
  removed    = old.items.keys - new.items.keys
  added      = new.items.keys - old.items.keys
  changed    = { k : old.items[k] != new.items[k] }

  MATERIAL if any of:
     removed  ∩ contracted ≠ ∅                     // a contracted tool vanished
     changed  ∩ contracted ≠ ∅                     // contracted semantics moved
     endpoint or transport changed
     card/manifest signature now invalid, or provenance no longer verifies
     re-screen of new/changed text yields a block-class finding
  BENIGN otherwise:
     added ∖ contracted            -> record, re-screen, do NOT suspend
     changed ∖ contracted          -> record, re-screen, do NOT suspend
     dropped-field-only difference -> auto-repin (AlgUpgrade / MetadataOnly)

  MATERIAL  -> suspend every cid in proj.by_pin[old.manifest]        (O(1) lookup)
               notify owners with the semantic diff
               posture: Attested -> Degraded
               re-approval re-runs the full admission pipeline (F1)
  BENIGN    -> auto-repin under standing policy; record Repin event
  Either way: emit OCSF, append to chain, count wc.drift.{material,benign}
```

Repeated benign drift is itself a signal: > 3 benign drifts in 7 days shortens
`reattest_every` by half and adds 10 to the posture penalty. A party that
constantly changes shape is a party to watch, even when each individual change is
harmless.

### 8.7.6 A6 · Posture score

```
score(entity, signals) -> u8
  s = 100
  s -= 30 if identity unverifiable at last re-attestation
  s -= 25 if provenance missing/unverifiable
  s -= 20 if any open material-drift finding
  s -=  8 per benign drift in the last 7 days           (cap 24)
  s -= 15 if reattest overdue by > 1 interval;  -= 30 if > 3 intervals
  s -= 20 if owner orphaned (IdP leaver, unreassigned)
  s -= 10 if a credential/cert expires within 7 days;   -= 25 if expired
  s -= min(20, 2 × denied_action_rate_percentile/10)     // fed back from core
  s -=  5 per open flag-class screening finding          (cap 15)
  clamp 0..=100

  state = if entity.posture == Quarantined { Quarantined }
          else if unverified_identity_or_provenance     { Unattested }
          else if s >= 85 { Attested } else { Degraded }
```

Consequences by state: `Attested` → normal; `Degraded` → **no renewal, no new
contracts**, existing contracts run to `exp`; `Unattested` → not connectable in
enforce mode; `Quarantined` → everything revoked.

**A low score never triggers automatic quarantine.** Auto-quarantine on a computed
score hands any attacker who can nudge the inputs — a burst of denied actions, a
few noisy drifts — an estate-wide denial-of-service primitive. Quarantine stays a
human or signed-CAEP decision. Degradation is automatic; containment is
authorised.

### 8.7.7 A7 · Quarantine fan-out and the sub-60-second claim

```
quarantine(party, reason, actor) -> QuarantineReport
  t0  registry.transition(party -> Quarantined)                     ~5 ms
      (dual control required at tier 1: two distinct approver JWS)
  t1  revocation::append(feed, key, "party", party, now)            ~15 ms (fdatasync)
  t2  for each affected cid: append kind="cid"                      ~0.1 ms each
  t3  fan-out push to N mediators: 8 worker threads, ureq, 2 s
      timeout, 3 attempts, exponential backoff + jitter
  t4  collect signed ACKs {mediator_id, set_hash, revoked, aborted}
  t5  blast_radius(party) as of t0                                  ~20 ms @ 10^5
  t6  emit CAEP SET via warden::sink (transmitter)                  ~50 ms
  t7  append every step to the chain; ship OCSF
      report = { confirmed[], unconfirmed[], bounded_by_poll_interval }
```

| Path | Latency | Why |
|---|---|---|
| Push ACK received (p50) | ~1.2 s | one round trip |
| Push ACK received (p95, N=200 mediators) | ~6 s | 8 threads × 200 targets × ~250 ms |
| Push failed, mediator healthy | ≤ poll interval (default **5 s**) + verify | the mediator pulls the delta itself |
| Mediator unreachable/partitioned | **not confirmed**, reported as such | it fails closed at its next contract check; worst case bounded by cache `exp` |

The NFR (< 60 s estate-wide) has ~10× headroom on the push path, and the
worst-case bound is a *stated* function of the poll interval rather than a hope.
`unconfirmed` is a first-class field in the report — the HLD's "never assumed
contained" made structural.

### 8.7.8 A8 · Blast radius

```
blast_radius(id, max_depth, proj) -> BlastReport
  forward:  BFS over by_caller[e] -> contract.callee, depth <= max_depth (default 3)
  reverse:  BFS over by_callee[e] -> contract.caller
  annotate each node with tier, zone, data_classes, owner, service
  cut set = contracts that would be revoked
  impacted business services = ⋃ node.service   // what the change-manager asks
  cost: O(V+E); 10^4 nodes / 10^5 edges => < 25 ms, adjacency already in memory
```

Reported both as JSON and as a service-level summary, because the SecOps analyst
about to quarantine something needs "these 3 business services stop" more than a
list of 400 entity ids (UC-07 A2).

### 8.7.9 A9 · Contract set distribution

```
mediator loop (every `refresh`, default 5 s):
  GET /v1/mediators/{mid}/contracts?since={seq}     (mTLS with mediator SVID)
  -> { seq, set_hash, added:[jws…], removed:[cid…], full: bool }
  verify each added JWS once; build new Snapshot; swap Arc
  POST /v1/mediators/{mid}/ack { set_hash, seq, applied_at }   // signed
control plane:
  tracks per-mediator {seq, set_hash, last_ack}; a mediator whose ack lags
  > 3 intervals is surfaced in `connect posture` as an unconfirmed enforcement
  point — a visibility gap is itself a finding
```

Push is an optimisation on top of this pull loop (a webhook that says "refresh
now"), never a substitute. Systems built on push alone fail silently when the push
fails; systems built on pull fail visibly and slowly.

---

## 8.8 Storage

### 8.8.1 On-disk layout

```
$WARDEN_CONNECT_ROOT/                    # default /var/lib/warden-connect
├─ wc.lock                               # flock, single-writer election
├─ tenants/<tenant>/
│  ├─ state/
│  │  ├─ events-000001.jsonl             # the state log (rotated at 256 MiB)
│  │  ├─ snapshot-000042.json            # projection snapshot + segment boundary
│  │  └─ idempotency.jsonl               # 24 h key -> response hash
│  ├─ evidence/
│  │  ├─ chain.jsonl                     # warden::audit hash chain (never compacted)
│  │  ├─ anchor.jsonl                    # warden::anchor signed checkpoints
│  │  └─ ocsf.jsonl                      # local OCSF mirror
│  ├─ contracts/<cid>.jws                # the signed artifacts, as issued
│  ├─ revocations.jsonl                  # signed feed (warden::revocation format)
│  ├─ keys/  issuer-<kid>.pem            # 0600; or PKCS#11/KMS URI
│  └─ policy/  connect-policy@v37.toml   # every version retained
```

### 8.8.2 State event records

One record shape, discriminated by `kind`; all records carry `{seq, ts, actor,
tenant, schema}`.

| kind | Payload |
|---|---|
| `entity.put` | full `Entity` |
| `entity.transition` | `{id, from, to, why}` |
| `entity.repin` | `{id, old_pin, new_pin, cause, diff}` |
| `entity.posture` | `{id, posture, score, signals}` |
| `contract.request` | `{req_id, from, to, tools, justify, ttl, eval}` |
| `contract.approve` \| `.deny` | `{req_id, approver, approver_jws, ticket, policy_version}` |
| `contract.mint` | `{cid, jti, jws_sha256, aud[], exp, surface, terms}` |
| `contract.revoke` | `{cid, reason, actor}` |
| `contract.suspend` | `{cid, cause: Drift \| Reattest \| Owner}` |
| `discovery.query` | `{asker, capability, filters, result_count}` (short retention) |
| `mediator.ack` | `{mediator_id, set_hash, seq, revoked, aborted}` |
| `quarantine.order` | `{party, reason, actor, dual_control[]}` |

`jws_sha256` rather than the JWS itself keeps the state log compact; the artifact
lives in `contracts/<cid>.jws` and its integrity is provable against the log.

### 8.8.3 Sizing at the NFR (10⁴ entities, 10⁵ contracts per tenant)

| Structure | Per item | Total | Note |
|---|---|---|---|
| `Entity` in memory | ~1.4 KB | ~14 MB | with pins for ~40 items each |
| `ContractRecord` | ~1.1 KB | ~110 MB | payload + indexes |
| `by_caller`/`by_callee`/`by_pin` | ~48 B/edge | ~10 MB | |
| `CapabilityIndex` | — | ~12 MB | |
| **Resident total** | | **~150 MB** | comfortable; the whole graph is in memory, which is why blast radius is a 25 ms query rather than a batch job |
| State log, 1 year | ~700 B/event | ~2–6 GB | compacted via snapshots |
| Evidence chain, 7 years | ~900 B/event | ~20–60 GB | never compacted; WORM/object-store target |

The optional P4 SQL adapter (`trait Store`) exists for estates that need
multi-writer HA or already have a managed Postgres; the file backend remains the
default and the reference implementation because it has one operational failure
mode instead of ten.

---

## 8.9 Wire formats

### 8.9.1 The contract JWS

Header: `{ "alg": "ES256", "kid": "wc-apac-2026-03", "typ":
"warden-connection+jws" }`. Payload exactly as HLD §7.4 plus three
implementation-required fields:

| Field | Type | Why it is added here |
|---|---|---|
| `callee.surface_digest` | `"sha256:…"` | digest over the *contracted* items only, enabling check 8's precision (§8.6.3) |
| `schema` | `u16` | contract schema version; a verifier that does not know the version **rejects** (`WC-3120`) rather than guessing |
| `terms.evidence.sink_id` | `string` | which configured sink satisfies a `blocking` obligation |

Size: a 2-tool contract serialises to ~1.1 KB; the 512-tool worst case is ~24 KB.
Verifiers cap payloads at 64 KiB (`WC-3121`).

### 8.9.2 MCP framing

```jsonc
// initialize (agent -> mediator)
{ "jsonrpc":"2.0", "id":1, "method":"initialize",
  "params": { "protocolVersion":"…", "capabilities":{…},
              "_meta": { "warden": { "cid":"conn_7f3a91c4",
                                     "contract":"eyJhbGciOi…" } } } }  // contract optional (§8.17-Q1)
```

- `_meta.warden.cid` selects the contract when pre-distributed; `contract` is the
  agent-carried fallback. A carried contract is verified with the *same* function
  and the same eleven checks — the carrying path grants no leniency.
- Denials return a JSON-RPC error, not a tool error, at `initialize` time:
  `{ "code": -32001, "message": "BLOCKED by warden-connect: WC-3108 surface pin
  mismatch", "data": { "code":"WC-3108", "cid":"…" } }`. Machine-readable,
  human-legible, greppable — matching core's `BLOCKED by Warden:` convention so
  existing runbooks and log parsers keep working.
- `tools/call` denials use core's existing `tool_error_result` path so agents
  handle them as they already do.

### 8.9.3 A2A framing

Contract in `X-Warden-Connection: <jws>` (or `_meta` for JSON-RPC-over-HTTP
transports); the callee's agent card is fetched at connection setup, canonicalised
and compared to the pin. Skills are filtered exactly as tools are.

### 8.9.4 Feeds and bundles

| Artifact | Format |
|---|---|
| Revocation feed | JSONL of ES256 JWTs, `{kind, sub, ts}` — core's format, new kinds `cid`/`party` |
| Contract set delta | `{seq, set_hash, added[jws], removed[cid], full}` over mTLS |
| CAEP SET | RFC 8417 SET via `warden::sink` transmitter; `session-revoked`, `credential-change`, plus a `connection-revoked` subject type |
| Air-gapped bundle (`.wcb`) | `{ bundle_jws, contracts[jws], jwks, revocations[], issued_at, exp }` — one signed envelope, expiry hard, verified by the same code path |

---

## 8.10 Concurrency and the latency budget

### 8.10.1 Threading

| Component | Model |
|---|---|
| `connect serve` | thread-per-request (core's `http.rs`), `Arc<ControlPlane>`; writes serialised behind one `Mutex<Writer>`; reads from an `Arc<Projection>` swapped copy-on-write |
| Sentinel | `min(8, cores)` workers pulling a due-time heap; per-endpoint concurrency 1 |
| Distribution | 8 workers, bounded queue 4096, drop-oldest with a counter (never unbounded — a slow mediator must not exhaust control-plane memory) |
| Mediator | inherits the proxy's thread-per-request; one background refresh thread; readers take `Arc<Snapshot>` clones and never block on refresh |

Lock discipline: `Projection` write lock is held only for `apply`, never across
I/O. Ceiling counters are atomics, not mutexes. There is no lock ordering problem
to reason about because no path takes two locks.

### 8.10.2 Connection-establishment budget (target p99 < 5 ms added)

| Step | Cost | Notes |
|---|---|---|
| Peer identity | **0** | from the completed TLS handshake / local SVID |
| Contract lookup by pair or `cid` | ~1 µs | `HashMap` on `Arc<Snapshot>` |
| Signature verify | **0 warm**, ~70 µs cold | verified once at snapshot build |
| Time / `aud` / `schema` checks | < 1 µs | |
| Revocation membership (×3) | ~300 ns | `HashSet` |
| `surface_digest` compare | ~5 µs | hash of ≤ 512 item hashes, cached per snapshot |
| Zone-pair lookup | ~200 ns | |
| Filter construction | 0 | precomputed in `VerifiedContract` |
| Evidence append (fail-safe WAL) | ~40 µs | batched fsync off the hot path |
| **Total (steady state)** | **~50 µs p50, ~0.9 ms p99** | p99 dominated by scheduler jitter, not by work |
| Cold contract (first use after refresh) | ~1.0 ms p99 | one ECDSA verify |

Two honest caveats, stated rather than buried:

1. With a **blocking** evidence sink (`delivery = "blocking"`, the regulated
   configuration), connection establishment includes a synchronous round trip to
   the sink. The budget then becomes **p99 < 25 ms**, documented as a distinct
   NFR. Trading 20 ms for "no connection without durable evidence" is the right
   trade in that estate, but it must be a declared trade.
2. A **cache miss with no cached snapshot** (cold start, control plane
   unreachable) fails closed after a single 500 ms fetch attempt. No retry storm,
   no indefinite hang: `WC-4001`.

Per-call added cost: allowlist `HashSet` lookup + ceiling atomics ≈ **5 µs** —
two orders of magnitude inside the < 1 ms NFR.

### 8.10.3 Performance gates in CI

`connect bench` asserts, on the CI reference machine, and fails the build on
regression:

| Gate | Threshold |
|---|---|
| `gate::verify` steady state | p99 ≤ 1.5 ms |
| `gate::verify` cold | p99 ≤ 3.0 ms |
| `filter_tools_list`, 256 tools | p99 ≤ 50 µs |
| `contract::mint` | p99 ≤ 20 ms |
| `blast_radius`, 10⁵ edges | p99 ≤ 40 ms |
| `Projection::rebuild`, 10⁵ contracts | ≤ 600 ms |

A latency claim in a design document that is not asserted by a test is a
marketing claim.

---

## 8.11 Error taxonomy

Every rejection has a stable code, a fail direction, and a metric. Codes are API,
so they are additive-only — never renumbered, never reused.

| Code | Meaning | Fails | HTTP / JSON-RPC |
|---|---|---|---|
| **WC-10xx admission** | | | |
| WC-1001 | Workload identity unverifiable | closed | 422 |
| WC-1002 | Surface unobtainable at handshake | closed (both modes) | 424 |
| WC-1003 | Card signature invalid | closed / observe: finding | 422 |
| WC-1004 | Provenance unverifiable | closed / observe: finding | 422 |
| WC-1005 | Screening block-class finding | closed | 422 |
| WC-1006 | Derived tier exceeds requested ceiling | closed | 409 |
| WC-1007 | Pin write failed | closed | 500 |
| WC-1008 | Owner missing or unresolvable in IdP | closed | 422 |
| WC-1010 | Surface exceeds limits (size/count/depth) | closed | 413 |
| **WC-20xx registry & discovery** | | | |
| WC-2001 | Entity not found | — | 404 |
| WC-2002 | Duplicate entity id | — | 409 |
| WC-2003 | Illegal lifecycle transition | closed | 409 |
| WC-2004 | Entity quarantined | closed | 403 |
| WC-2005 | Malformed identifier (entity id, cid, jti, owner, zone) | closed | 422 |
| WC-2011 | Unknown zone pair → most restrictive | closed | 403 |
| WC-2020 | Discovery throttled (anti-enumeration) | — | 200 truncated |
| WC-2021 | Asker not registered/attested | closed | 200 empty |
| **WC-30xx contract lifecycle** | | | |
| WC-3001 | Contract not found | — | 404 |
| WC-3010 | Requested surface ⊄ declared surface | closed | 422 + diff |
| WC-3011 | Policy denied | closed | 403 |
| WC-3012 | Precondition failed at mint | closed | 409 |
| WC-3013 | TTL exceeds zone bar | narrowed, warned | 200 |
| WC-3014 | Terms would widen a ceiling | closed | 422 |
| WC-3015 | Standing-policy cap reached → human | closed→human | 202 |
| WC-3020 | Approver lacks required role | closed | 403 |
| WC-3021 | Approval stale (policy version moved) | closed | 409 |
| WC-3022 | Dual control not satisfied | closed | 403 |
| WC-3023 | Approval signature invalid | closed | 401 |
| WC-3030 | Renewal blocked: posture degraded | closed | 409 |
| WC-3031 | Renewal blocked: re-attestation failed | closed | 409 |
| WC-3032 | Contract already revoked/expired | — | 410 |
| **WC-31xx contract verification (data plane)** | | | |
| WC-3101 | Non-asymmetric / unsupported `alg` | closed | -32001 |
| WC-3102 | Signature or issuer chain invalid | closed | -32001 |
| WC-3103 | Expired or not yet valid | closed | -32001 |
| WC-3104 | `aud` ≠ this mediator | closed | -32001 |
| WC-3105 | Revoked (`jti`/`cid`/party) | closed | -32001 |
| WC-3106 | Caller peer identity mismatch | closed | -32001 |
| WC-3107 | Callee peer identity mismatch | closed | -32001 |
| WC-3108 | Surface pin mismatch (+ DRIFT event) | closed | -32001 |
| WC-3109 | Posture not attested | closed / observe: allow+finding | -32001 |
| WC-3110 | Zone pair not permitted locally | closed | -32001 |
| WC-3111 | Token/contract binding mismatch | closed | -32001 |
| WC-3120 | Unknown contract schema version | closed | -32001 |
| WC-3121 | Contract exceeds size limit | closed | -32001 |
| **WC-40xx mediation** | | | |
| WC-4001 | No contract available (cache miss, CP unreachable) | closed | -32001 |
| WC-4002 | Uncontracted tool attempted | closed | tool error |
| WC-4003 | Rate ceiling exceeded | closed (contract stays valid) | tool error |
| WC-4004 | Spend ceiling exceeded | closed | tool error |
| WC-4005 | Concurrency / fan-out ceiling exceeded | closed | tool error |
| WC-4006 | Egress term violated (data class / jurisdiction) | closed | tool error |
| WC-4007 | Catalogue unfilterable → empty list | closed | 200 empty |
| WC-4008 | Malformed / oversized frame | closed | -32600 |
| WC-4020 | Peer identity header from untrusted origin | closed + alert | -32001 |
| **WC-50xx posture** | | | |
| WC-5001 | Re-attestation failed | degrade | — |
| WC-5002 | Material drift detected | suspend | — |
| WC-5010 | Credential expiring / expired | warn / closed | — |
| WC-5030 | Blast-radius depth limit exceeded | truncated result | 200 |
| **WC-60xx containment** | | | |
| WC-6001 | Quarantine dual control missing | closed | 403 |
| WC-6002 | Revocation feed unwritable | **closed, alarm** | 500 |
| WC-6003 | Mediator ACK not received | reported unconfirmed | 202 |
| WC-6004 | Break-glass request outside policy | closed | 403 |
| **WC-70xx evidence** | | | |
| WC-7001 | Blocking sink unavailable → no issuance | closed | 503 |
| WC-7002 | Audit chain append failed | closed | 500 |
| WC-7003 | Chain verification found a break | alarm | 200 report |
| WC-7010 | Export failed | — | 500 |
| WC-7020 | External PDP unreachable | closed | 503 |
| **WC-80xx platform** | | | |
| WC-8001 | Invalid policy → keep last-known-good | last-known-good + alarm | 422 |
| WC-8002 | Tenant unknown / cross-tenant reference | closed | 404 |
| WC-8003 | Store write lock held by another writer | closed | 503 |
| WC-8004 | Config invalid at startup | **refuse to start** | — |

Discipline that gives this teeth: every code appears in exactly one place in the
code as a `WcError` variant, is asserted by at least one test, and increments
`wc_denials_total{code}`. A code with no test does not ship.

---

## 8.12 Security implementation

### 8.12.1 Keys

| Key | Purpose | Storage | Rotation |
|---|---|---|---|
| Issuer signing key (per tenant) | signs contracts | PKCS#11 / KMS URI, or 0600 PEM | 90 d, overlapping; both `kid`s in JWKS through max TTL + 7 d |
| Anchor key | signs chain checkpoints (`anchor.rs`) | offline-capable HSM preferred | 1 y |
| Revocation key | signs feed events | separate from the issuer key | 90 d |
| Approver keys | human approval JWS | per-approver, in `approver-jwks` | per IdP lifecycle |
| Mediator SVID | mTLS + signed ACKs | SPIRE-managed, short-lived | hourly, by SPIRE |

Rotation is safe because verification is `kid`-directed and JWKS carries both
keys through the overlap; a contract signed by a retired `kid` remains verifiable
until `exp`. Compromise response is a **JWKS removal plus a bulk revocation by
`kid`** (`connect revoke --by-kid`), which is why revocation supports a
non-`cid` subject.

Key separation matters: an attacker who steals the issuer key can mint contracts,
but cannot forge the evidence chain that would show they did — the anchor key is
separate and preferably offline. That is the property that makes control-plane
compromise (threat A8) detectable rather than merely catastrophic.

### 8.12.2 Input limits (DoS bounds)

| Input | Limit | Code |
|---|---|---|
| Contract JWS | 64 KiB | WC-3121 |
| Surface document | 4 MiB, 512 items, depth 32 | WC-1010 |
| Tool description | 64 KiB per item | WC-1010 |
| JSON-RPC frame | inherits core's `jsonrpc.rs` cap | WC-4008 |
| API request body | 1 MiB | 413 |
| Discovery queries | 30/min, 300/day per asker | WC-2020 |
| Re-attestation | 1 concurrent, 4/min per endpoint | — |
| Distribution queue | 4096, drop-oldest + counter | — |

### 8.12.3 Other implementation-level defences

- **Constant-time comparison** for all hash and digest equality
  (`subtle`-style volatile compare, hand-rolled to avoid a dependency), so pin
  comparison leaks nothing by timing.
- **No contract content in error messages** returned to agents beyond the code and
  `cid`. The agent is on the untrusted side of the boundary; a verbose denial is a
  reconnaissance oracle.
- **Redaction reuse**: `warden::redact::Redactor` applied to everything written to
  evidence and exports (never to the forwarded call), so a poisoned description
  quoted in a finding cannot exfiltrate secrets into the SIEM.
- **Uniform-latency empty results** on discovery (§8.5.6).
- **`serde` deny-unknown-fields on the contract payload**, so a verifier never
  silently ignores a claim a minter thought was enforced. Silent field-dropping
  between versions is how signed-artifact systems get quietly broken.

---

## 8.13 Configuration

`connect.toml` (control plane) — flags override file overrides env, per core:

```toml
[server]
listen = "0.0.0.0:8443"
tenant = "apac"
root   = "/var/lib/warden-connect"
mode   = "enforce"                  # enforce | observe
tls    = { cert = "/tls/cp.pem", key = "/tls/cp.key", client_ca = "/tls/spiffe-ca.pem" }

[policy]
path         = "connect-policy.toml"
hot_reload   = true                 # SIGHUP; invalid => keep last-known-good (WC-8001)
pdp_url      = ""                   # AuthZEN passthrough; unreachable => deny

[identity]
mode         = "spire"              # mtls | spire | mesh | jwt-svid
trust_bundle = "/run/spire/bundle.pem"
jwks         = "/keys/idp.jwks.json"
aud          = "warden-connect:apac"
approver_jwks = "/keys/approvers.jwks.json"

[keys]
issuer     = "pkcs11:token=wc;object=issuer-2026-03"
revocation = "/keys/revoke.pem"
anchor     = "/keys/anchor.pem"

[admission]
require_provenance = true
require_card_signature = true
rekor = "https://rekor.sigstore.dev"

[screen]
mode = "flag"                       # observe | flag | enforce
rules = "screen-rules.toml"

[sentinel]
workers = 8
reattest_default = "24h"
reattest_tier1   = "1h"

[evidence]
chain  = "evidence/chain.jsonl"
anchor = { path = "evidence/anchor.jsonl", interval = 100 }

[[sink]]                            # warden::sink::load_specs shape, verbatim
name = "security-lake"
format = "ocsf"
transport = "webhook"
endpoint = "https://collector.internal/ocsf"
filter = "all"
delivery = "fail-safe"

[retention]
contracts = "7y"
discovery = "90d"
```

Mediator flags (`connect mediate`, composing unmodified Warden core):

```sh
connect mediate --upstream … --policy warden.policy.toml \
  --connect-contracts    https://connect.internal/v1/mediators/apac-ops-1 \
  --connect-issuer-jwks  /keys/connect.jwks.json \
  --mediator-id          warden:mediator:apac-ops \
  --connect-mode         enforce \
  --connect-refresh      5 \
  --on-revoke            abort \
  --connect-bundle       ./bundle.wcb        # air-gapped alternative
```

Env equivalents: `WARDEN_CONNECT_*` for every key
(`WARDEN_CONNECT_MEDIATOR_ID`, `WARDEN_CONNECT_MODE`, …). Any config error at
startup is `WC-8004`: **refuse to start**. A mediator that boots with a broken
config and passes traffic through is the worst outcome available.

---

## 8.14 Observability, operations, compatibility

### 8.14.1 Metrics (`/metrics`, Prometheus text + JSON, via `warden::obs`)

```
wc_admissions_total{result,kind,mode}
wc_entities{posture,tier,zone}
wc_discovery_queries_total{result}        wc_discovery_throttled_total
wc_contracts_active{zone_pair,tier}       wc_contracts_minted_total{approval_mode}
wc_contract_ttl_seconds_bucket            wc_contracts_expiring{window}
wc_verify_duration_seconds_bucket{path=warm|cold}
wc_denials_total{code}                    # every WC-* code
wc_filter_tools{state=exposed|hidden}     wc_filter_failclosed_total
wc_ceiling_breaches_total{kind}
wc_drift_total{class}                     wc_reattest_total{result}
wc_posture_score_bucket
wc_quarantine_duration_seconds            wc_mediator_ack_lag_seconds{mediator}
wc_chain_length  wc_anchor_age_seconds    wc_sink_failures_total{sink}
wc_standing_share                          # §8.17-Q4 cap utilisation
```

The three an operator should alert on first: `wc_filter_failclosed_total > 0`
(the filter is the crown jewel), `wc_mediator_ack_lag_seconds > 3×refresh` (an
enforcement point may be dark), `wc_anchor_age_seconds` beyond interval (evidence
is no longer externally provable).

### 8.14.2 Logs and traces

JSON logs (`--log-format json`, core's convention) with a stable field set:
`{ts, level, event, code, cid, contract_jti, caller, callee, tier, zone_pair,
policy_version, decision, reason, duration_us}`. OTel span attributes carry
`warden.cid`, `warden.contract_jti`, `warden.policy_version` — the same `cid`
`warden-trace` will later join on.

### 8.14.3 Runbook hooks

`connect posture --unconfirmed` (mediators lagging), `connect audit verify`
(chain + anchors), `connect policy dry-run` (before every policy change),
`connect bundle export` (before an air-gap window), `connect blast-radius`
(before every quarantine).

### 8.14.4 Compatibility rules

| Change | Rule |
|---|---|
| Contract payload | Additive optional claims only within `schema:1`. A new **required** claim bumps `schema`; verifiers reject unknown `schema` (`WC-3120`) rather than guessing. |
| `wcs1` | Frozen. Changes ship as `wcs2` with the shadow-re-pin migration (§8.7.1). |
| State events | New `kind`s must be ignorable by `Projection::apply` (counted as `unapplied`), so an older replica can replay a newer log without corrupting state. |
| Core `audit::Entry` | **Optional (P2), not a prerequisite.** warden-connect keeps its own chain (§8.8.1), so nothing here depends on core changing. *If* core adopts `cid`/`contract_jti`/`policy_version` in the hashed row — worth it, because it makes `warden-trace` exact rather than heuristic — that **breaks chain continuity by construction**, so it ships with a `schema:2` marker row and verifiers that switch hash inputs at that row, plus vectors for both schemas. |
| `WC-*` codes | Additive only; never renumbered or reused. |
| API | `/v1` stable; breaking changes go to `/v2` with both served through a deprecation window. |

---

## 8.15 Test strategy

### 8.15.1 Unit and property tests

| Module | Property tests |
|---|---|
| `canon` | permutation invariance · whitespace-reformat invariance · idempotence · **sensitivity** (one U+200B, one word, one reordered `required` each move the hash) · `surface_digest` unchanged by additive tools |
| `contract` | mint→verify round trip · `Terms::intersect` never widens (monotone narrowing) · TTL is `min` of all bounds · any single-bit mutation of the JWS fails verification |
| `cpolicy` | first-match determinism · rules cannot raise a zone bar · `dry_run` diff is exact |
| `filter` | **∀ upstream response, ∀ contract: visible ⊆ contract.surface.tools** |
| `store` | `apply` totality · rebuild(snapshot+tail) == rebuild(full log) · unknown kinds counted, never dropped |
| `sentinel` | drift classification decision table exhaustively · posture score monotonicity in each signal |
| `screen` | no block-class finding on the clean corpus (precision gate) |

### 8.15.2 Fuzz targets (mirroring `warden/fuzz`)

`parse_contract` · `canon_surface` · `parse_connect_policy` · `screen_text` ·
`revocation_event`. Each asserts no panic, no unbounded allocation, and — for
`parse_contract` — that no malformed input is ever accepted.

### 8.15.3 Conformance vectors — `connect verify` is the ground truth

`fixtures/contracts/` ships pairs of (artifact, expected verdict). Any
implementation claiming to mint `warden-connection+jws` must produce the exact
codes:

| Vector | Expected |
|---|---|
| `valid-es256.jws`, `valid-ed25519.jws` | Admit |
| `hmac-hs256.jws` | WC-3101 |
| `alg-none.jws` | WC-3101 |
| `unknown-kid.jws` | WC-3102 |
| `tampered-payload.jws` | WC-3102 |
| `expired.jws`, `nbf-future.jws` | WC-3103 |
| `aud-other-mediator.jws` | WC-3104 |
| `revoked-jti.jws`, `quarantined-party.jws` | WC-3105 |
| `caller-peer-mismatch.jws` | WC-3106 |
| `pin-mismatch.jws` | WC-3108 |
| `surface-superset.jws` (surface ⊄ declared) | WC-3010 at mint; WC-3108 at verify |
| `posture-unattested.jws` | WC-3109 (Admit + finding in observe) |
| `schema-99.jws` | WC-3120 |
| `oversize-70kb.jws` | WC-3121 |
| `duplicate-tool-names.jws` | WC-3010 |

Plus `fixtures/surfaces/`: for each input, the expected `wcs1` document bytes and
pin — the interoperability contract for anyone else canonicalising a surface.

### 8.15.4 End-to-end scenarios (one per use case)

| Test | Asserts |
|---|---|
| `e2e::uc01_admit_agent` | 7 stages, pin written, chain entry, OCSF emitted, **zero contracts** after registration |
| `e2e::uc02_onboard_server` | handshake capture, screening report, BOM, unreachable endpoint ⇒ nothing pinned |
| `e2e::uc03_discovery` | ineligible candidates invisible; empty result indistinguishable; throttle fires |
| `e2e::uc04_connection` | mint → distribute → verify → **`tools/list` returns 2 of 23** → `tools/call` on tool 3 denied WC-4002 → audit rows carry `cid` |
| `e2e::uc05_federation` | partner bar enforced; `max_depth=1` unraisable by the callee; egress term denies an undeclared jurisdiction |
| `e2e::uc06_drift` | contracted-tool change ⇒ suspend + notify; additive tool ⇒ no suspension, event recorded; connect-time mismatch ⇒ WC-3108 |
| `e2e::uc07_quarantine` | full fan-out < 60 s with 200 simulated mediators; one unreachable ⇒ `unconfirmed`, fails closed on next poll; blast radius as of t0 |
| `e2e::uc08_shadow` | unknown counterparty ⇒ finding in observe, refusal in enforce |
| `e2e::uc09_renewal` | usage-informed surface reduction; no owner response ⇒ lapse at `exp`; degraded posture ⇒ no renewal |
| `e2e::uc10_export` | DORA/OSCAL shapes; exceptions section present; `as_of` reconstruction verifies against an anchor |

### 8.15.5 Failure injection

Control plane killed mid-mint (no partial contract, idempotency replay works) ·
control plane down for 1 h (existing connections work to `exp`, no new
connections) · revocation feed truncated/corrupted (**deny all**, alarm) ·
blocking sink down (no issuance, `WC-7001`) · clock skew ±10 min (leeway
honoured, beyond it fails closed) · two writers racing for the store lock
(`WC-8003`, no interleaving) · mediator with a stale snapshot (fails closed on
revoked `cid` at next refresh) · disk full during append (fails closed, no
silent gap in the chain).

---

## 8.16 Build order

Each phase is shippable and independently valuable; the acceptance criteria are
the exit gates.

| Phase | Modules delivered | Acceptance criteria |
|---|---|---|
| **P0 · Observe** | `model`, `canon`, `error`, `store`, `registry`, `admission` (stages 1–2, 6–7), `evidence`, `api` (entities/posture/export-csv), `cli` (register/posture/audit/canon), mediator in observe-only (shadow detection) | 10⁴ entities registered from CI; `connect audit verify` green; shadow report non-empty on a real estate; **zero behaviour change** measured on the proxy path |
| **P1 · Contract** | `contract`, `cpolicy`, `broker`, `wc-mediator` (`cache`, `gate`, `filter`, `peer`) as an `Upstream` decorator, API connections + approvals, distribution loop | Conformance vectors 100% pass; `tools/list` filtering verified end to end **against unmodified Warden core**; `connect policy dry-run` accurate; verify p99 ≤ 1.5 ms in CI |
| **P2 · Assure** | `admission` (stages 3–5), `screen`, `sentinel` (re-attest, drift, posture); *optionally* propose core's `ConnectionGate` + hashed `cid` (§8.6.1) | Screening precision ≥ 0.98 on the labelled corpus; material drift detected ≤ tier-1 interval; drift suspension exercised in e2e |
| **P3 · Contain** | quarantine fan-out, ACK tracking, `drain`, CAEP ingest/emit, `blast_radius`, break-glass, `ceiling` (durable spend) | 200-mediator quarantine < 60 s with ACKs; unconfirmed reported; quarterly drill script in the repo |
| **P4 · Govern** | `zone` (full lattice), `federate`, `export` (DORA/CPS 230/OSCAL), `tenant`, SQL `Store` adapter, air-gapped bundles | Partner federation e2e against a second control plane; DORA register generated in < 1 h at 10⁵ contracts; cross-tenant reference returns `WC-8002` |

Dependency order that cannot be reshuffled: `canon` before `admission` (no pin, no
admission) · `contract` before `mediator` · per-item pins before `sentinel` (drift
classification depends on them) · `evidence` before everything (P0 ships it first
so no later phase has to retrofit a record). Nothing in this order depends on a
change to Warden core, or to any other family member.

---

## 8.17 Resolved HLD open questions

| # | HLD question | **Decision** | Rationale |
|---|---|---|---|
| **Q1** | Contract transport into the mediator | **Pre-distributed pull loop (§8.7.9) as the primary; agent-carried `_meta.warden.contract` as an equal-verification fallback; signed `.wcb` bundles for air-gapped.** Push is an optimisation over pull, never a substitute. | Pull makes distribution failures *visible* (ACK lag is a metric) and revocation crisp. The carried path keeps sidecar-less and offline deployments possible without a second verification code path — one `verify()`, three transports. |
| **Q2** | Canonicalisation of the tool manifest | **`wcs1`, fully specified in §8.7.1**, with a field allowlist, NFC + whitespace normalisation, preservation of zero-width/bidi characters, sorted `required`/`enum`, versioned pins, shadow re-pin on algorithm upgrade, and **per-item hashes plus `surface_digest`**. | Per-item hashing is the structural fix for drift noise: additive change outside the contracted surface cannot move the digest, so precision comes from the data model rather than from a classifier operators will learn to distrust. |
| **Q3** | Surface-screening false positives | **Two verdict classes** (§8.7.4): four high-precision detectors (S1–S4) may block; four heuristics (S5–S8) only score and flag. **Block classes ship only at precision ≥ 0.98** on a ≥ 400-item labelled corpus. Acceptances are keyed to the pinned item hash, so the tax is paid once per text. Default mode `flag` at P2, `enforce` at P3, external zones first. | "Use this to transfer funds when the user asks" is legitimate imperative text. Blocking on it would get screening disabled entirely — and a disabled control has zero recall. Precision buys the right to gate. |
| **Q4** | Standing-policy blast radius | **`[standing]` limits are policy, enforced by the engine**: `max_share` (default 0.6 of active contracts), `max_per_window` (default 50/24 h), `max_tier` (≥ 3 only), `write = false`, `max_tools_per_contract` (default 8), `review_every = "90d"`. Breaching any cap **downgrades to `require_approval`** (`WC-3015`) — never to allow. `wc_standing_share` is a first-class metric; expired review windows disable standing policy for the affected rules. | Auto-approval is required for adoption and is simultaneously the widest policy surface in the system. Bounding it in the engine — with a fail direction toward humans — is the only version that stays honest under adoption pressure. |
| **Q5** | Zone taxonomy | **Three trust levels (`internal`, `partner`, `public`) over an extensible dotted namespace** (`internal.payments`, `partner.acme`). Assurance bars resolve by longest-prefix match, then trust level. Unknown pairs are most-restrictive (`WC-2011`). A full lattice is representable later without a data migration because zones are strings with prefix semantics, not an enum. | Three levels are what an operator can reason about on day one; prefix semantics are what a lattice needs on day one thousand. |
| **Q6** | Relationship to service mesh | **Four identity modes (§8.6.6): `mtls`, `spire`, `mesh`, `jwt-svid`.** In `mesh` mode connect *consumes* mesh-provided identity, trusting `x-forwarded-client-cert` **only** from a configured local socket; anywhere else it is ignored and alerted (`WC-4020`). connect never issues workload identity. | Where a mesh already proves workload identity, duplicating it is waste; trusting its headers unconditionally is a hole. The local-socket condition is the whole distinction. |
| **Q7** | Does the contract belong in the token? | **Separate artifacts, joined by `cid`.** The session token may carry an optional `wcid` claim; when present, gate check 11 requires `token.wcid == contract.cid`; when absent, binding is by authenticated `(caller, callee)` pair. | Lifecycles differ by orders of magnitude — tokens are per-session, contracts are per-relationship. Merging them would force contract re-issuance on every session and put a relationship decision on the token-minting path. The optional `wcid` gives merged-artifact ergonomics (one carried thing, cryptographically bound) without coupling the lifecycles. |

---

## 8.18 Traceability

Capability (doc 04) → module → function → test. Abbreviated to the load-bearing
rows; the full matrix is generated by `connect policy show --traceability` from
annotations in the source, so it cannot drift from the code.

| Cap | Module::function | Test |
|---|---|---|
| T1.1 workload identity | `admission::verify_workload_identity` | `e2e::uc01_admit_agent`, `admission::tests::no_identity_denied` |
| T1.4 provenance | `admission::verify_provenance` | `admission::tests::sigstore_bundle_offline` |
| T1.5 card signature | `admission::verify_card_jws` | `fixtures/contracts` + `admission::tests::unsigned_card` |
| T2.1 registry | `registry::put`, `store::Projection` | `store::tests::rebuild_equivalence` |
| T2.2 surface pinning | `canon::pin`, `Pin::surface_digest` | `canon::props::*`, `fixtures/surfaces/*` |
| T2.3 mediated discovery | `broker::discover` | `e2e::uc03_discovery` |
| T2.4 anti-enumeration | `broker` token bucket + uniform latency | `broker::tests::empty_indistinguishable` |
| T2.5 shadow detection | `mediator::gate` observe path → `sentinel` | `e2e::uc08_shadow` |
| T3.1 mint | `contract::mint` | `contract::props::mint_verify_roundtrip` |
| T3.2 verify | `mediator::gate::verify` | **all** `fixtures/contracts/*` |
| T3.4 `tools/list` filtering | `mediator::filter::filter_tools_list` | `filter::props::visible_subset_of_surface` |
| T3.5 narrowing algebra | `Terms::intersect`, gate ordering | `cpolicy::props::never_widens` |
| T3.8 standing policy | `cpolicy::StandingLimits` | `cpolicy::tests::cap_downgrades_to_human` |
| T4.4 ceilings | `mediator::ceiling::reserve` | `ceiling::tests::durable_across_restart` |
| T4.7 latency | `gate::verify` warm path | `bench::gate_verify` (CI gate) |
| T5.1 drift | `sentinel::classify_drift` | `sentinel::tests::decision_table` |
| T5.2 screening | `screen::surface` | `screen::corpus::precision_gate` |
| T5.4 posture | `sentinel::score` | `sentinel::props::monotonic` |
| T5.6 blast radius | `sentinel::blast_radius` | `bench::blast_radius_1e5` |
| T6.1/6.2 revocation & quarantine | `evidence` + `revocation` kinds `cid`/`party` | `e2e::uc07_quarantine` |
| T6.5 drain | `mediator::drain` | `drain::tests::ambiguous_config_aborts` |
| T7.1 lifecycle audit | `evidence::append` (core `audit.rs`) | `evidence::tests::chain_across_schema_boundary` |
| T7.4 register export | `export::dora_register` | `e2e::uc10_export` |
| T7.7 `cid` correlation root | `gate::authorize_call` → `audit::Accountability` | `e2e::uc04_connection` |

---

## 8.19 The three claims this design has to keep

Everything above exists to make three sentences true in production, not in a
slide:

1. **An uncontracted tool never enters the model's context.** Enforced by
   `filter::filter_tools_list`, whose subset property is a test, whose failure
   mode is an empty catalogue, and whose bypass would require the mediator to not
   be inline — a deployment property, checked by shadow detection.
2. **A changed counterparty is a new decision.** Enforced by `wcs1` per-item pins,
   compared at every connection and on a schedule, with material change suspending
   contracts rather than updating a record.
3. **Any connection can be cut in seconds, provably.** Enforced by signed
   revocation on core's existing feed, ACK-tracked fan-out with an explicit
   `unconfirmed` set, and a fail-closed poll bound — with the cut itself recorded
   in a chain anchored outside the control plane that performed it.

If an implementation choice ever conflicts with one of those three, the
implementation choice is what changes.
