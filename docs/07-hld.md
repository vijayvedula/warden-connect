# 7 · warden-connect — High-Level Design

warden-connect decides whether a connection between two parties may **exist**.
A policy engine in the call path decides whether each **call** on that
connection may proceed. The interface between them is two signed artifacts and
one identifier.

| | |
|---|---|
| **Status** | v0.2.0 · Rust 2021 · MSRV 1.89 · 7 crates · 1,439 tests |
| **Audience** | Architects, reviewers, implementers of a competing verifier |
| **Companion** | [08-lld.md](08-lld.md) for every module and check · [use-cases/](use-cases/) for the ten flows |

## In one screen

| | |
|---|---|
| **What it decides** | May this connection exist? Not: may this call proceed |
| **The artifact** | One signed JWS, `application/warden-connection+jws`, addressed to one mediator |
| **The rule** | `per-action authority = contract.surface ∩ token.scope ∩ policy_decision` |
| **The ceiling** | A contract naming `transfer_funds` does not permit it. It permits *at most* that. No path widens |
| **The split** | Control plane at human timescale. Data plane sub-millisecond, no network call, 14 gates, all fail closed |
| **Runs alone** | `wc-mediator` builds standalone; no policy engine need be deployed |
| **Three claims** | A contract can only narrow · a compromised control plane cannot mint one · the evidence verifies without trusting us |

The rest of this document is the argument for those rows, plus the detail a
reviewer or a competing implementer needs.

## 7.1 Scope and context

A connection control plane for AI agents. Authentication answers who is calling
and authorization what they may do. Neither asks the party being *called*
whether it agreed — to this caller, these tools, these terms, until this date.

| Not | Because |
|---|---|
| A policy engine | This produces the ceiling a policy engine intersects. It evaluates no per-call policy itself |
| An identity provider | Identity arrives already proven; this binds to it |
| A service mesh | No traffic management, retries or load balancing |
| A secrets manager | No credential is minted, held or distributed here |
| A gateway product | `wc-mediator` runs standalone, or compiles into an existing proxy as a decorator |

## 7.2 Architecture overview

| Plane | Crate | Decides | Latency budget | Failure stance |
|---|---|---|---|---|
| Control | `wc-control`, `wc-cli` | May this connection exist? | Human timescale | Fail closed; a withheld contract denies |
| Data | `wc-mediator` | Is this call inside the ceiling? | Sub-millisecond, no network call | Fail closed on every gate |
| Shared | `wc-core` | The artifact, its canonical form, the 82 codes | — | — |

The control plane can be offline and the data plane still enforces against
contracts it holds. A compromised plane can withhold a contract, which fails
closed; it cannot manufacture one, because contracts are verified against issuer
keys rather than looked up in a database the mediator trusts.

The 73 modules behind those three planes are inventoried in
[LLD §8.4](08-lld.md).

## 7.3 Domain model

```
Entity (agent | mcp_server | a2a_agent)
  id            spiffe:// | urn:                        the wire identity
  owner         human:…                                 accountable, required
  tier          1..4                                    derived at admission
  zone          internal.<domain> | partner.<org> | public
  surface_hash  sha256 of the canonical card/manifest   ← the pin
  posture       attested | degraded | unattested | quarantined
  lifecycle     pending | active | suspended | retired

Contract        cid, caller→Entity, callee→Entity, surface, terms,
                assurance, approval, exp                (§7.4)

Zone            id, trust_level, assurance_bar { identity, provenance,
                ttl_max, approval, oversight, max_delegation_depth }
```

<details>
<summary>The remaining entities, and <code>Entity</code>'s other fields</summary>

```
Entity          service       business service reference
                provenance    [slsa | sigstore refs]
                data_classes  [...]        jurisdictions [...]

Approval        id, cid, approver (human), signature, ticket,
                policy_version, ts

PostureEvent    entity, kind (drift | reattest | expiry | screening |
                quarantine), diff, severity, ts

AuditEntry      the policy engine's audit row, extended with cid,
                contract_jti, entity ids, policy_version — folded
                into row_hash
```

</details>

Posture is orthogonal to lifecycle: `Attested`, `Degraded`, `Unattested`,
`Quarantined`. Quarantined is terminal until a full re-admission.

<details>
<summary>The seven invariants the registry enforces</summary>

| # | Invariant |
|---|---|
| 1 | An `Entity` with no `owner` cannot be `active` |
| 2 | A `Contract` cannot reference an entity whose posture is `quarantined` |
| 3 | `contract.surface ⊆ callee.declared_surface` at mint time |
| 4 | `contract.exp − iat ≤ zone.assurance_bar.ttl_max` |
| 5 | The presented surface hash must equal `entity.surface_hash` at connect time |
| 6 | A quarantined entity's contracts are revoked; clearing requires new admission |
| 7 | No signed JWS is ever committed to a repository. Receipts only |

</details>

## 7.4 The connection contract

The single coupling point. Media type `application/warden-connection+jws`;
asymmetric signatures only (ES256/ES384/EdDSA/PS256/RS256), which precludes
algorithm confusion.

The five blocks that make up the payload:

```
header    typ, alg          asymmetric only
identity  cid, iss, aud, jti, iat, nbf, exp
parties   caller { id, card, zone, tier }, callee { id, manifest, zone, tier }
grant     surface { tools, skills, resources }      ← the ceiling
bounds    terms, assurance, approval, policy_version
```

`aud` MUST match the mediator verifying it, and `callee.manifest` is the pin
gate 8 compares against. A complete signed example is in
[fixtures/contracts/](../fixtures/contracts/).

<details>
<summary>The full payload, every field populated</summary>

```jsonc
{
  "typ": "warden-connection+jws",
  "cid": "conn_7f3a91c4",
  "iss": "https://connect.internal/t/apac",
  "aud": "warden:mediator:apac-ops",        // MUST match this mediator
  "jti": "cx_84be…",
  "iat": 1785312000, "nbf": 1785312000, "exp": 1785398400,

  "caller": { "id": "spiffe://org/ns/agents/sa/recon-bot-7",
              "card": "sha256:9c1f…", "zone": "internal.apac-ops", "tier": 2 },
  "callee": { "id": "spiffe://org/ns/tools/sa/payments-mcp",
              "manifest": "sha256:41ab…", "zone": "internal.payments", "tier": 1 },

  "surface": { "tools": ["get_balance", "list_transactions"],
               "skills": [], "resources": ["ledger://apac/*"] },

  "terms": {
    "data_classes": ["internal"],
    "jurisdictions": ["SG", "AU"],
    "human_oversight": "required_above:10000_usd",
    "delegation": { "max_depth": 2, "attenuation": "monotonic" },
    "evidence": { "sink": "ocsf://siem", "delivery": "blocking" }
  },

  "assurance": { "attestation": ["slsa-provenance:sha256:…", "sigstore-bundle:…"],
                 "reattest_every": "24h", "posture": "attested" },

  "approval": { "by": "human:cecil@org", "jti": "apr_5d2e…",
                "ticket": "RISK-4471", "mode": "human" },

  "policy_version": "connect-policy@v37"
}
```

</details>

### Verification — fail closed at every step

```
verify(contract, peer_caller, peer_callee, presented_surface_hash)

  1. JWS signature valid against a trusted issuer key (JWKS by kid)   else WC-3102
  2. alg ∈ {ES256, ES384, EdDSA, PS256, RS256}  — no HMAC             else WC-3101
  3. nbf ≤ now < exp                                                  else WC-3103
  4. aud == this mediator id                                          else WC-3104
  5. jti ∉ revocation set; cid not revoked; parties not quarantined   else WC-3105
  6. peer_caller.identity == contract.caller.id  (authenticated)      else WC-3106
  7. peer_callee.identity == contract.callee.id                       else WC-3107
  8. presented_surface_hash == contract.callee.manifest               else WC-3108 + DRIFT
  9. assurance.posture == attested  (observe-mode override is logged) else WC-3109
 10. zone_pair(caller.zone, callee.zone) permitted locally            else WC-3110
 11. token binding matches                                            else WC-3111
 12. issuer matches the expected issuer for this tenant               else WC-3112
 13. schema version known                                             else WC-3120
 14. contract within size bound                                       else WC-3121

  → Admit; install the surface filter and terms for this connection
```

Steps 1–5 are local constant-time checks. Steps 6–7 use already-established peer
identity. Step 8 compares against a value captured during `initialize`. No
network call on the hot path.

### The algebra

```
per-action authority  =  contract.surface ∩ token.scope ∩ policy_decision
per-hop authority     =  contract.terms.delegation ⊇ delegate's attenuation
federated term        =  min(local_term, superior_term)
```

Every operator narrows. A forged or over-broad contract can only fail to widen
something.

### Conformance

`connect verify <contract>` is ground truth. Any registry may mint contracts; a
contract is valid if and only if the verifier accepts it — which makes the
artifact a candidate standard rather than a product format.

## 7.5 Key flows

Specified in full, with sequence diagrams, in [use-cases/](use-cases/).

| Flow | Use case | Summary |
|---|---|---|
| F1 · Admission | [UC-01](use-cases/UC-01-register-and-admit-an-agent.md), [UC-02](use-cases/UC-02-onboard-a-tool-server.md) | Prove identity, screen the surface, pin the hash |
| F2 · Connection establishment | [UC-04](use-cases/UC-04-establish-a-connection.md) | Offer meets need, policy disposes, a ceiling is minted and distributed |
| F3 · Drift detection | [UC-06](use-cases/UC-06-surface-drift.md) | Re-hash on an interval; material drift suspends dependent contracts |
| F4 · Quarantine | [UC-07](use-cases/UC-07-emergency-quarantine.md) | Terminal state, revoke everywhere, report non-confirmation |
| F5 · Federation | [UC-05](use-cases/UC-05-cross-organisation-federation.md) | Anchors and chains, terms narrowed by `min`, one hop only |

Two pipelines, two repositories, two reviews. Neither party can produce a
contract alone.

## 7.6 Interfaces

### CLI — 62 commands

Thirteen groups: Admission, Registry, GitOps, Issuance, Containment,
Distribution, Discovery, Federation, Keys, Evidence, Gateway, Policy, Runtime.
`connect --help` is ground truth.

<details>
<summary>All 62 commands, by group</summary>

| Group | Commands |
|---|---|
| Admission | `register agent` · `register server` · `activate` · `attest verify` · `attest surface` · `screen` |
| Registry | `entities` · `show` · `posture` · `discover` · `blast-radius` · `tenants` |
| GitOps | `offer publish` · `offer lint` · `offer list` · `offer show` · `offer status` · `need check` · `need apply` · `receipt` · `scm probe` |
| Issuance | `request` · `approve` · `deny` · `requests` · `contracts` · `breakglass` |
| Containment | `quarantine` · `unquarantine` · `revoke` |
| Distribution | `mediators` · `distribution` |
| Discovery | `inventory` · `inventory promote` · `proposals apply` |
| Federation | `federate` |
| Keys | `keys list` · `new` · `add` · `rotate` · `retire` · `jwks` · `note` |
| Evidence | `audit verify` · `evidence verify` · `evidence since` · `export` · `bundle export` · `bundle verify` · `backup` · `restore` · `retention` |
| Gateway | `gateway check` |
| Policy | `policy lint` · `policy dry-run` · `policy show` |
| Runtime | `serve` · `canon` · `verify` · `bench` · `caep ingest` · `version` |

</details>

### Reserved paths

| Path | Written by | Meaning |
|---|---|---|
| `warden/offer.toml` | provider | this repo provides capability |
| `warden/needs.toml` | consumer | this repo consumes capability |
| `warden/surface.json` | provider | the declared surface, as captured |
| `warden/contracts/<cid>.toml` | control plane | a receipt, never a JWS |

Discovery reads these paths and nothing else. The scanner probes nothing: no
port scans, no endpoint calls, no fetching what a repository has not published.

### Two policies, two moments

| | `connect-policy.toml` | the policy engine |
|---|---|---|
| Question | May this contract exist? | May this call proceed? |
| Evaluated | at issuance | per call |
| Owned by | warden-connect | whoever runs the engine |
| Inputs | zone, tier, surface, data class, jurisdiction, authority | token scope, context, action |

## 7.7 Integration with a policy engine

Coupling is two signed artifacts and one identifier, never a shared library.

| Term in `effective` | Owned by | Decided |
|---|---|---|
| `contract.surface` | warden-connect | at issuance |
| `token.scope` | the policy engine | at authentication |
| `policy_decision` | the policy engine | per call |
| `effective` | the policy engine, which computes the intersection | per call |

warden-connect owns the first set, the terms and the `cid`. It hands that
ceiling over and never learns what the engine decides inside it. Signal runs the
other way: denied-action patterns feed posture scoring, so repeated denials
degrade a party and shorten its re-attestation interval.

`wc-mediator` builds **standalone by default** — connection enforcement with no
policy engine deployed. The `warden-proxy` build feature adds the decorator
topology, compiling the mediator into an existing proxy so per-action policy
applies as well. One process, no extra hop.

## 7.8 Trust and threat model

A compromised control plane cannot mint a valid contract without the signing
keys. It can withhold, and withholding fails closed.

| Dependency unavailable | Behaviour | Code |
|---|---|---|
| Issuer JWKS unreachable | Refuse the connection | `WC-3102` |
| Revocation feed unwritable | Refuse to quarantine silently | `WC-6002` |
| A mediator does not acknowledge | Report not confirmed; it fails closed itself | `WC-6003` |
| Blocking evidence sink down | Refuse the call | `WC-7001` |
| Audit chain broken | Refuse to export | `WC-7003` |
| Registry lock held | Refuse to write | `WC-8003` |
| Policy file invalid | Refuse to start | `WC-8001` |
| Surface unobtainable at attest | Degrade posture, never pass | `WC-1002` |

The single exception is posture in observe mode, which admits with `Unattested`
and logs.

The defect this system produces is not a crash but a control that reads as
configured and does nothing — a flag parsed and never enforced, a gate deleted
with every test still green. Review targets that class, and mutation testing is
standard practice because it is what exposes it.

## 7.9 Deployment topologies

| Topology | Mediator placement | When |
|---|---|---|
| Standalone | Its own process in the path | No policy engine deployed; connection enforcement only |
| Decorator | Compiled into an existing proxy (`warden-proxy` feature) | A proxy already in the path |
| Sidecar | One mediator per agent | Enforcement at the edge |
| Observe-only | In the path, refusing nothing | Stage ① — inventory before enforcement |

Which proxy is orthogonal: the decision is one crate (`wc-gateway`) and each
proxy is a binding over it.

| Binding | Where it runs | Caller identity from | Hops added |
|---|---|---|---|
| `wc-extproc` | its own process; Envoy calls it over gRPC | `x-forwarded-client-cert`, origin-checked | 1, loopback |
| `wc-kong` | a `cdylib` in the nginx worker, driven by a Lua plugin over LuaJIT FFI | the peer certificate's URI SAN, or XFCC | 0 |

Istio and Linkerd are Envoy underneath — a deployment recipe for the first, not
a third binding ([LLD §8.6b](08-lld.md)).

Where the tool server lives is orthogonal again: a spawned stdio child
(`--upstream CMD`) or a remote server over MCP Streamable HTTP
(`--upstream-url URL`). Both sit behind the same decorator, so the gates, the
catalogue filter and the surface ceiling are identical either way
([LLD §8.6.7](08-lld.md)).

**Not built:** the mediator as an HTTP listener, which is the shared-gateway
topology. `PeerSource::{Mtls, Mesh, JwtSvid}` exists for it, but until a
listening transport constructs them peer identity comes from configuration, and
only the sidecar topology is honest (§7.13).

## 7.10 The adoption ladder

| Rung | What you get | What it costs |
|---|---|---|
| 1 · Inventory | What is being used, and by whom | A read token. No infrastructure |
| 2 · Register | Contracts issued, nothing enforced | One service, one key |
| 3 · Enforce at the gateway | Calls bounded | A mediator in the path |
| 4 · Enforce per agent | Bounded at the edge | A sidecar per agent |

Most of the value is at rungs 1 and 2. The original design started at rung 4,
which is why it could not be adopted.

## 7.11 Non-functional requirements

| Property | Target | How |
|---|---|---|
| Hot-path latency | No network call | Contracts and pins cached; verification is local |
| Availability | Data plane survives control-plane outage | Distributed contracts remain valid to `exp` |
| Integrity | Independently verifiable | Anchored hash chain; `connect audit verify` needs no trust in the plane |
| Dependency budget | Enforced in CI | `scripts/dep-count.sh` ceilings per crate |
| Determinism | Byte-identical canonical form | `wc-core::canon`, depth-bounded |
| Portability | No async runtime | Threads and blocking I/O throughout |

## 7.12 Data protection

| Rule | |
|---|---|
| Contracts carry references, never payloads | hashes, identifiers, terms |
| `terms.data_classes` and `terms.jurisdictions` | enforced as egress control |
| The evidence chain is append-only | its value is that it is independently verifiable, not that it is queryable |
| Retention deletes nothing; it retires | the regulatory clock outlives the entity |

## 7.13 Open questions

| # | Question | Stance |
|---|---|---|
| 1 | Does `terms.delegation.max_depth` bind anything today? | No. It is carried, narrowed and federated correctly, but no delegation chain exists here to measure against it |
| 2 | Are Azure Repos and Bitbucket at parity with GitHub? | Merge parsing is. `repos` and `open_pr` are GitHub-only, and only GitHub has been exercised against a live host. Read the other shims as templates |
| 3 | Cluster-scale behaviour | Unverified. Needs a real cluster |
| 4 | What happens to a contract when the basis of its approval changes? | Undesigned. See §7.14 |
| 5 | Is the mediator ready for the shared-gateway topology? | Partly. Envoy and Kong bindings are built and drilled against real proxies. The inline mediator's own listener is not |
| 6 | Do rate, concurrency and spend ceilings bind anything? | No — removed as a capability, because counters live in one process. Volume belongs to the proxy. [LLD §8.6.5](08-lld.md) |

## 7.14 Contract maintenance

Assurance watches the surface: pin it, re-check on an interval, classify benign
or material, suspend on material (§7.5 F3).

Nothing watches the consent. A contract records who approved it and on what
basis, and that basis is never revisited until `exp`. Four events change it and
none is a trigger today; the shape is the same as drift and should reuse it.

<details>
<summary>The four events, and what blocks a design</summary>

| Event | What changes | Status |
|---|---|---|
| Repo transfer | The host-designated owner changes, so who may approve changes mid-contract | undesigned |
| Approver leaver | The human who consented no longer exists. Their contracts remain valid to `exp` | partial: [UC-09](use-cases/UC-09-renewal-review-offboarding.md) A2 flags an orphaned owner, at renewal only, and only for the owner |
| Approver mover | Role or team changed, so the authority they held is gone | undesigned |
| Approver set moves without a re-apply | `[approval]` is compared at `offer publish` and `need apply`. A manifest whose approver set changes but is never re-applied is never compared | known gap |

Three questions block a design: whether a leaver's approval is void or valid to
`exp`; whether a repo transfer suspends or only degrades posture; and what the
pinned artifact is — CODEOWNERS content hash, policy id, approver identity, or
all three.

</details>

Until this exists, a contract's approval is checked once, at issuance, and never
again.
