# 7 · warden-connect — High-Level Technical Design

> Status: design. Target: a control plane plus a thin inline data-plane extension
> to the shipped Warden proxy. Diagram companion:
> [warden-connect-logical-architecture.svg](warden-connect-logical-architecture.svg).
> Implementation companion: [08-lld.md](08-lld.md) — crate layout, module
> signatures, algorithms, error codes, latency budgets and test suite.

---

## 7.1 Scope and context

**In scope.** Registry of agents and tool servers; admission and attestation;
mediated discovery; connection contract lifecycle; inline channel mediation and
surface filtering; continuous posture and drift; containment; evidence and
regulatory export; cross-org federation.

**Out of scope.** Per-action authorization (Warden core), authority attenuation
across hops (`warden-delegate`), cross-agent lineage and taint (`warden-trace`),
model/content guardrails, agent runtime, network transport security below the
channel (mesh/TLS termination — composed with, not replaced).

### System context

```
   Agent Developer   Security Architect   SecOps   Risk & Compliance   Partner Org
          │                  │               │            │                │
          └────────── control-plane API / CLI / portal ────┘        federation (OIDC-Fed)
                                   │                                       │
                        ┌──────────▼───────────────────────────────────────▼─────────┐
                        │              warden-connect CONTROL PLANE                  │
                        │  registry · admission · broker · contract · sentinel · evd │
                        └──────────┬───────────────────────────────┬─────────────────┘
        signed contracts + revocations │                           │ evidence (OCSF/CAEP/OSCAL)
                                   ┌───▼────┐                  ┌───▼────┐
                Agent ──MCP/A2A──▶ │ MEDIATOR + Warden proxy │ │ SIEM · GRC · IdP │
                                   └───┬────┘                  └────────┘
                                       │ contracted surface only
                                       ▼
                            Tool server / callee agent
```

The control plane is **off the hot path**. The data plane verifies a signed
artifact locally — the same stance that keeps Warden core's token verification
free of network calls.

---

## 7.2 Architecture overview

### Plane split

| | Control plane | Data plane |
|---|---|---|
| **Runs** | Centrally (per tenant), HA, replicated | Inline, co-located with the agent runtime — same process or sidecar alongside `warden proxy` |
| **Owns** | Registry, admission, discovery, contract issuance, posture, exports | Contract verification, peer authentication, surface filtering, ceilings, per-connection evidence |
| **Latency** | Seconds acceptable | **p99 < 5 ms added** per connection establishment; ~0 per subsequent call |
| **On failure** | New issuance stops; existing contracts remain valid to `exp` | Fail closed: no valid contract → no connection |
| **State** | Durable (registry, contracts, audit chain) | Cache of contracts + revocation set; rebuildable |

The asymmetry is deliberate: **a control-plane outage must not take the estate
down**, but it must not allow new authority either. Contracts already issued keep
working until they expire — which is why TTLs are short and expiry is hard.

### Component inventory

| Component | Responsibility | Warden core reuse |
|---|---|---|
| **registry** | Entity records for agents and servers; content-addressed cards/manifests; ownership, tier, zone, lifecycle, posture | new |
| **admission** | Verify identity, provenance, card/manifest signature; screen declared surface; derive tier; pin hashes | new (uses `identity.rs` verification primitives) |
| **broker** | Mediated capability discovery; policy-filtered results; anti-enumeration | new |
| **contract** | Mint / verify / renew / revoke `warden-connection+jws`; approval workflow; policy evaluation | new (JOSE + `policy.rs` condition engine) |
| **sentinel** | Scheduled re-attestation; drift detection & semantic diff; posture scoring; expiry watch; blast-radius | new |
| **evidence** | Lifecycle events → tamper-evident chain + anchors; OCSF/CAEP sinks; OSCAL & register exports | **`audit.rs`, `anchor.rs`, `sink.rs`, `ocsf.rs`** |
| **mediator** *(data plane)* | Peer auth, contract verification, `tools/list` filtering, surface allowlist, ceilings, zone rules, drain | **extends `gateway.rs`, `mcp.rs`, `budget.rs`, `revocation.rs`** |

Seven components; **two are largely existing code**, one is an extension of the
shipped proxy, four are new.

---

## 7.3 Domain model

```
Entity (agent | server)
  id            spiffe:// | urn:  (the wire identity)
  kind          agent | mcp_server | a2a_agent
  owner         human:…                 (accountable, required)
  service       business service ref
  tier          1..4                    (derived at admission)
  zone          internal.<domain> | partner.<org> | public
  surface_hash  sha256 of canonical card/manifest   ← the pin
  provenance    [slsa|sigstore refs]
  posture       attested | degraded | unattested | quarantined
  lifecycle     pending | active | suspended | retired
  data_classes  [...]      jurisdictions [...]

Contract  (the interface artifact — §7.4)
  cid, caller→Entity, callee→Entity, surface, terms, assurance, approval, exp

Zone
  id, trust_level, assurance_bar {identity, provenance, ttl_max, approval, oversight}

Approval
  id, cid, approver (human), signature, ticket, policy_version, ts

PostureEvent
  entity, kind (drift|reattest|expiry|screening|quarantine), diff, severity, ts

AuditEntry   (Warden core shape, extended)
  … + cid, contract_jti, entity ids, policy_version   ← folded into row_hash
```

**Key invariants**

1. An `Entity` with no `owner` cannot be `active`.
2. A `Contract` cannot reference an entity whose `posture = quarantined`.
3. `contract.surface ⊆ callee.declared_surface` at mint time — always.
4. `contract.exp − iat ≤ zone.assurance_bar.ttl_max`.
5. Presented surface hash must equal `entity.surface_hash` at connect time.
6. A quarantined entity's contracts are revoked; clearing quarantine requires a
   new admission, never a state transition.

---

## 7.4 The connection contract

The single coupling point, exactly as the session token is for Warden core.
Media type `application/warden-connection+jws`; asymmetric signatures only
(ES256/EdDSA), matching core's `ASYMMETRIC_ALGS` stance to preclude algorithm
confusion.

### Payload

```jsonc
{
  "typ": "warden-connection+jws",
  "cid": "conn_7f3a91c4",
  "iss": "https://connect.internal/t/apac",
  "aud": "warden:mediator:apac-ops",       // MUST match this mediator, else reject
  "jti": "cx_84be…",
  "iat": 1785312000, "nbf": 1785312000, "exp": 1785398400,

  "caller": { "id": "spiffe://org/ns/agents/sa/recon-bot-7",
              "card": "sha256:9c1f…", "zone": "internal.apac-ops", "tier": 2 },
  "callee": { "id": "spiffe://org/ns/tools/sa/payments-mcp",
              "manifest": "sha256:41ab…", "zone": "internal.payments", "tier": 1 },

  "surface": { "tools": ["get_balance","list_transactions"],
               "skills": [],
               "resources": ["ledger://apac/*"] },

  "terms": {
    "data_classes": ["internal"],
    "jurisdictions": ["SG","AU"],
    "max_calls_per_hour": 500,
    "max_concurrent": 8,
    "max_spend_usd_per_day": 200,
    "human_oversight": "required_above:10000_usd",
    "delegation": { "max_depth": 2, "attenuation": "monotonic" },
    "evidence": { "sink": "ocsf://siem", "delivery": "blocking" }
  },

  "assurance": { "attestation": ["slsa-provenance:sha256:…","sigstore-bundle:…"],
                 "reattest_every": "24h", "posture": "attested" },

  "approval": { "by": "human:cecil@org", "jti": "apr_5d2e…",
                "ticket": "RISK-4471", "mode": "human" },   // or "standing_policy"

  "policy_version": "connect-policy@v37"
}
```

### Verification algorithm (data plane, fail-closed at every step)

```
verify(contract, peer_caller, peer_callee, presented_surface_hash) -> Result
  1. JWS signature valid against a trusted connect issuer key (JWKS by kid)   else Deny
  2. alg ∈ {ES256, ES384, EdDSA, PS256, RS256}   (no HMAC)                    else Deny
  3. nbf ≤ now < exp                                                          else Deny
  4. aud == this mediator id                                                  else Deny
  5. jti ∉ revocation set   (and cid ∉ revoked, parties ∉ quarantined)        else Deny
  6. peer_caller.identity == contract.caller.id  (authenticated, not claimed) else Deny
  7. peer_callee.identity == contract.callee.id                               else Deny
  8. presented_surface_hash == contract.callee.manifest                       else Deny + raise DRIFT
  9. assurance.posture == "attested"  (or observe-mode override, logged)      else Deny
 10. zone_pair(caller.zone, callee.zone) permitted by local zone policy       else Deny
 --> Admit; install surface filter, ceilings and terms for this connection
```

Steps 1–5 are constant-time local checks. Steps 6–7 come from the already
established mTLS/SVID peer identity. Step 8 is a hash comparison against a value
captured during `initialize`. **No network call on the hot path.**

### The narrowing algebra

```
per-action authority  =  contract.surface  ∩  token.scope  ∩  policy_decision
per-hop authority     =  contract.terms.delegation  ⊇  delegate's attenuation   (never ⊂ violated)
```

A contract is a **ceiling**, never a grant that overrides Warden core. This is
the connection-layer statement of core's existing rule that locally-derived and
unsigned inputs may only narrow authority.

### Conformance

`connect verify <contract>` is the ground truth, exactly as `warden token verify`
is for the token spec. Any registry, platform or framework may mint contracts; a
contract is valid iff the verifier accepts it. That is what makes the artifact a
candidate standard rather than a product format.

---

## 7.5 Key flows

### F1 · Admission (UC-01 / UC-02)

```
CI ──register(card|endpoint, attestation, owner)──▶ admission
                                                     │ 1 verify workload identity (SVID / trust bundle)
                                                     │ 2 verify card signature | MCP initialize+tools/list
                                                     │ 3 verify provenance (SLSA / Sigstore / Rekor)
                                                     │ 4 screen declared surface for injection patterns
                                                     │ 5 derive tier from data classes × capability classes
                                                     │ 6 canonicalise + hash surface  → PIN
                                                     ▼
                                            registry.write(entity, posture=attested)
                                                     │
                                            evidence.append(chain) ──▶ OCSF sink
```

Failure at 1, 2, 3 or 4 → **no registration** in enforce mode; registration with
`posture: unattested` and a finding in observe mode.

### F2 · Connection establishment (UC-04)

```
developer ─request(from,to,tools,justify,ttl)──▶ contract
                                                  │ policy: zones, tiers, surface ⊆ declared,
                                                  │         data classes, jurisdictions, requester authority
                                        ┌─────────┴─────────┐
                          standing policy            human approval
                                        └─────────┬─────────┘
                                                  │ mint warden-connection+jws (cid, surface, terms, exp)
                                                  ▼
                                        distribute to mediator(s) on the path
                                                  │
runtime:  agent ──initialize──▶ mediator ─┤ verify contract (10 steps) ├─▶ callee
          agent ──tools/list──▶ mediator ─┤ FILTER to surface.tools    ├─▶ agent sees 2 tools
          agent ──tools/call──▶ mediator ─┤ surface allowlist, ceilings├─▶ Warden core policy ─▶ callee
                                                  │
                                        every action recorded with cid
```

Step **`tools/list` filtering** is the highest-leverage line in this design: an
uncontracted tool never enters the model's context, so no prompt injection can
induce a call to it. The control is structural, not probabilistic.

### F3 · Drift detection (UC-06)

```
sentinel ──(schedule | connect-time mismatch)──▶ re-fetch surface
                                                   │ canonicalise + hash
                                                   │ compare to pin ── equal ──▶ record reattest, done
                                                   │ differ
                                                   ▼
                                       semantic diff  (tools ±, description Δ, params Δ, endpoint Δ)
                                                   │ re-screen new text for injection patterns
                                                   ▼
                              classify:  benign ──▶ auto-repin under standing policy, record
                                         material ─▶ SUSPEND every contract referencing the pin
                                                   ──▶ notify owners with the diff
                                                   ──▶ re-approval re-runs admission (F1)
```

### F4 · Quarantine (UC-07)

```
secops ──quarantine(party, reason)──▶ registry: posture=quarantined (terminal)
                                        │
                                        ├─▶ contract: revoke all where party ∈ {caller, callee}
                                        ├─▶ push signed revocation events to every mediator
                                        │      mediator: refuse new · drain|abort in-flight · ACK
                                        ├─▶ emit CAEP SET  (downstream + federated partners)
                                        ├─▶ sentinel: blast-radius report as of the cut
                                        └─▶ evidence: order, revocations, ACKs, non-ACKs → chain + SIEM
```

**Unacknowledged mediators are reported as unconfirmed, never assumed
contained** — and because they fail closed on their next contract check, the
worst case is bounded by the revocation-poll interval.

### F5 · Cross-org federation (UC-05)

```
org A connect ⟷ org B connect
  1 exchange federation entity statements; verify to the agreed trust anchor
  2 resolve a specific partner agent by capability (no catalogue exchange)
  3 fetch + verify its signed card; PIN locally
  4 partner-zone assurance bar: signed card + provenance + short TTL
      + mandatory human approval + delegation.max_depth = 1
  5 mint contract; both sides hold a verifiable copy
  6 mediator enforces egress: declared data classes and jurisdictions only
```

---

## 7.6 Interfaces

### Control-plane API (OpenAPI 3.1, `/v1`)

| Method & path | Purpose |
|---|---|
| `POST /v1/entities` | Register an agent or server (admission) |
| `GET /v1/entities/{id}` | Entity record, pin, posture, provenance |
| `POST /v1/discover` | Mediated capability query (policy-filtered) |
| `POST /v1/connections` | Request a connection |
| `POST /v1/connections/{cid}/approve` \| `/deny` | Signed human decision |
| `GET /v1/connections/{cid}` | Contract + status |
| `POST /v1/connections/{cid}/renew` \| `/revoke` | Lifecycle |
| `POST /v1/quarantine` | Estate-wide containment |
| `GET /v1/posture` | Drift, expiring, unattested, shadow |
| `GET /v1/blast-radius/{id}` | Transitive reachable set |
| `GET /v1/export?format=dora\|cps230\|oscal\|ocsf\|csv&as_of=` | Register & evidence |
| `POST /access/v1/evaluation` | **AuthZEN** PDP passthrough for external policy engines |

### CLI (mirrors Warden core's verb style)

```sh
connect register agent  --card agent-card.json --attest bundle.sigstore --owner human:priya@org
connect register server --endpoint https://payments-mcp.internal --tier 1 --zone internal.payments
connect discover --capability "payments.balance.read" --as agent:recon-bot-7
connect request  --from agent:recon-bot-7 --to server:payments-mcp \
                 --tools get_balance,list_transactions --justify "APAC recon" --ttl 30d
connect approve  <req-id> --by human:cecil@org --approver-key ~/.keys/cecil.pem
connect contracts list | show <cid> | renew <cid> | revoke <cid>
connect quarantine agent:recon-bot-7 --reason "SOC-2291"
connect posture --shadow --expiring --drift
connect blast-radius agent:recon-bot-7
connect export --format dora --as-of 2026-06-30
connect verify <contract.jws>          # conformance ground truth
connect audit verify                   # prove the lifecycle record is untampered
```

### Wire (data plane)

- **MCP**: contract referenced in `initialize` params `_meta.warden.cid` and
  carried alongside the existing session token; `tools/list` responses filtered.
- **A2A**: contract presented on the invocation channel; agent card hash
  verified against the pin.
- **Peer identity**: mTLS with SPIFFE X.509-SVID, or JWT-SVID plus DPoP where
  mTLS is unavailable.
- **Revocations**: signed event feed polled/pushed to mediators (reuses core's
  `revocation.rs` format and CAEP ingest).

### Policy-as-code (`connect-policy.toml`, Warden-style, hot-reloadable)

```toml
default = "require_approval"

[[zone]]
id = "internal.apac-ops"; trust = "internal"

[[zone]]
id = "partner.acme"; trust = "external"
assurance = { identity = "required", provenance = "required",
              ttl_max = "7d", approval = "human", oversight = "required" }

# standing policy: the low-risk majority never reaches a human
[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
callee_tier = { op = "gte", value = 3 }
surface     = { write = false }
decision    = "allow"
ttl_max     = "30d"

[[rules]]
callee_tier = { op = "lte", value = 2 }
decision    = "require_approval"
approver_role = "security.architect"

[[rules]]
caller_zone = "internal.*"
callee_zone = "public.*"
decision    = "deny"
reason      = "public-zone egress requires a partner onboarding"
```

---

## 7.7 Integration with the Warden family

| Direction | Contract |
|---|---|
| **connect → Warden core** | Mediator hands core the `surface` allowlist and `terms` as additional conditions; core computes `surface ∩ token.scope ∩ policy`. Core's audit `Entry` gains `cid` and `contract_jti`, folded into `row_hash`. |
| **connect → warden-delegate** | `terms.delegation.{max_depth, attenuation}` is the envelope delegate must attenuate within. Delegate may reduce depth or scope; it can never raise either. |
| **connect → warden-trace** | `cid` is the correlation root stamped on every action, evidence row and delegation across the whole multi-agent transaction. Without it, cross-agent reconstruction is heuristic; with it, it is exact. |
| **Warden core → connect** | Denied-action patterns and ceiling breaches feed posture scoring; repeated denials degrade a party's posture and shorten its re-attestation interval. |
| **trace → connect** | Taint findings (a response influenced by untrusted content) raise the counterparty's risk signal, which can trigger re-approval. |

The interface between the four is deliberately **two artifacts and one
identifier**: the session token, the connection contract, and `cid`.

---

## 7.8 Trust and threat model

### Trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| Agent runtime ↔ mediator | mediator | **agent** (may be prompt-injected; is the thing being policed) |
| Mediator ↔ callee | mediator | **callee's declared surface and responses** |
| Control plane ↔ mediator | signed contracts and revocations | transport |
| Org ↔ partner org | own trust anchor | **everything the partner asserts** |
| Admission ↔ CI/CD | verified provenance | **self-asserted metadata** |

### Threats and controls

| # | Threat | Control | Residual |
|---|---|---|---|
| A1 | Forged connection contract | Asymmetric-only JWS, JWKS by `kid`, `aud` binding, revocation set | Issuer key compromise → key rotation + anchor detection |
| A2 | Contract replay against another mediator | `aud` per mediator, `nbf`/`exp`, `jti` tracking | Bounded by TTL |
| A3 | Peer impersonation | mTLS/SVID peer identity compared to contract claims — authenticated, never claimed | Depends on the workload-identity issuer |
| A4 | Rug-pull / tool poisoning | Pinned surface hash, connect-time comparison, scheduled re-attestation, injection screening | A change **within** a pinned description is impossible; semantic-but-unpinned changes on the callee's *behaviour* are `warden-trace`'s problem |
| A5 | Shadow endpoint bypassing the mediator | Mediator on the path is a deployment property; shadow detection finds bypass attempts; strict mode denies unknown counterparties | Requires the mediator to actually be inline — an assumption to enforce at deploy time |
| A6 | Discovery used for reconnaissance | Mediated results, no enumeration, throttling, indistinguishable empty results | Aggregation over time by a legitimate asker |
| A7 | Approval fatigue exploited | Standing policy for the low-risk majority; risk-ranked queue; requests carry full context | Human judgement remains the limit at the top tier |
| A8 | Control-plane compromise | Signed artifacts, tamper-evident chain with anchors, dual control for quarantine override, per-tenant keys | Full CP compromise is catastrophic — hence anchors are externally verifiable |
| A9 | Control-plane DoS | DP works from cache to `exp`; issuance stops but the estate keeps running | New connections blocked during outage (by design) |
| A10 | Malicious insider widening a contract | Contracts are signed and versioned; every mint carries approver and `policy_version`; widening is visible in the chain | Detection, not prevention — dual control at tier 1 |
| A11 | Delegation-depth evasion via a chain of contracts | `max_depth` enforced by delegate against the **originating** contract, not per hop | Requires `delegate` to be deployed on every hop |

### Fail-closed matrix

| Condition | Strict (default) | Observe |
|---|---|---|
| No contract | Deny connection | Allow + finding |
| Contract expired | Deny (no grace) | Deny |
| Surface hash mismatch | Deny + drift event | Allow + drift event |
| Posture `unattested` | Deny | Allow + finding |
| Posture `quarantined` | Deny | **Deny** (never overridable) |
| Control plane unreachable | Serve from cache to `exp`; no new connections | same |
| Revocation feed unreadable | Deny all (feed integrity is load-bearing) | Allow + alarm |
| Blocking evidence sink unavailable | Deny (no connection without a recorded trail) | Allow + alarm |

---

## 7.9 Deployment topologies

| Topology | Shape | When | Trade-off |
|---|---|---|---|
| **Sidecar** (preferred) | One mediator + Warden proxy per agent runtime | Matches core's MVP; surgical containment | More instances to operate |
| **Shared gateway** | One mediator fronting many agents | Simpler ops, brownfield | Concentrated trust boundary; containment relies on per-`cid` revocation rather than process isolation |
| **Egress mediator** | Dedicated mediator on the org boundary | Partner/public zone crossings | Must not be the only mediator — internal relationships still need governing |
| **Federated** | CP per org, federated trust anchors | Cross-org A2A | Trust-anchor lifecycle becomes a first-class operational concern |
| **Air-gapped** | Contracts pre-issued as signed bundles; no CP call | Regulated/offline estates | Expiry is hard; revocation depends on bundle refresh |

---

## 7.10 Non-functional requirements

| Dimension | Target | Notes |
|---|---|---|
| Added latency, connection establishment | **p99 < 5 ms** | Signature verify + set membership; no network call |
| Added latency, per subsequent call | **< 1 ms** | Surface allowlist is a set check inside core's existing dispatch |
| Contract distribution | < 5 s to all mediators | Push with poll fallback |
| Quarantine propagation | **< 60 s estate-wide**, with per-mediator ACK | The headline containment number |
| Drift detection | ≤ re-attestation interval; tier 1 ≤ 1 h | Plus every connect-time check |
| Registry scale | 10⁴ entities, 10⁵ contracts per tenant | Contract graph fits in memory for blast-radius queries |
| Control-plane availability | 99.9% | DP unaffected to `exp` |
| Data-plane availability | Inherits the agent runtime | Stateless beyond cache |
| Evidence durability | Tamper-evident + externally anchored | Reuses core `audit.rs` / `anchor.rs` |
| Retention | Contract + lifecycle history ≥ 7 years (configurable) | DORA/CPS 230 horizons |
| Multi-tenancy | Per-tenant registry, keys, policy, audit chain | Cross-tenant resolution structurally impossible |

---

## 7.11 Data protection and privacy

- The contract carries **identifiers and terms, not payloads**. No business data
  transits the control plane.
- Human identifiers (`owner`, `approval.by`) are personal data: minimised to a
  stable pseudonymous identifier plus a directory reference, and retained under
  the regulatory retention clock rather than indefinitely.
- Discovery logs record the asker and the capability question — retained for
  reconnaissance detection, with a shorter clock than contract history.
- Jurisdiction terms are enforced but not *inferred*: the declaring party asserts
  them and is accountable for the assertion, which is exactly how third-party
  attestations work today.

---

## 7.12 Build phases

| Phase | Ships | Unlocks | Rough shape |
|---|---|---|---|
| **P0 — Observe** | Registry, CLI, entity records, shadow detection from mediator observation, tamper-evident lifecycle chain, OCSF sink | Estate visibility with zero behaviour change; maturity **L1** | Registry + evidence reuse. The wedge. |
| **P1 — Contract** | Contract mint/verify/renew/revoke, request→approval workflow, standing policy, mediator surface allowlist + `tools/list` filtering | Deny-by-default topology; maturity **L2** | The core loop (UC-04). |
| **P2 — Assure** | Provenance verification, card/manifest signing, surface screening, pinning, drift detection, re-attestation, posture scoring | Rug-pull and tool-poisoning defence; maturity **L3** | The differentiated security value. |
| **P3 — Contain** | Estate-wide quarantine with ACKs, CAEP ingest/emit, blast-radius, drain semantics, break-glass | The demo moment; sub-minute MTTC | Heavy reuse of `revocation.rs`. |
| **P4 — Govern** | Zone model, cross-org federation, egress control, DORA/CPS 230/OSCAL export, multi-tenancy | Regulated-enterprise close; maturity **L4** | The commercial edge. |

P0 is deliberately the smallest possible thing that is independently valuable —
and it is mostly assembled from code Warden already ships.

---

## 7.13 Open questions

> **All seven are now resolved in [08-lld.md §8.17](08-lld.md#817-resolved-hld-open-questions).**
> They are kept here as the record of what was open at HLD stage, and of the
> leaning the LLD had to either confirm or overturn.

1. **Contract transport into the mediator.** Pre-distributed (push) versus
   agent-carried (like the session token) versus both. Agent-carried is simpler
   and matches core's "carried, not looked up" stance; pre-distributed makes
   revocation crisper. Current lean: **pre-distributed, with an agent-carried
   fallback for air-gapped and sidecar-less deployments.**
2. **Canonicalisation of the tool manifest.** The pin is only as good as the
   canonical form. Needs a specified normalisation (field ordering, whitespace,
   optional-field handling) or benign formatting changes will generate drift noise
   and train operators to ignore alerts.
3. **Surface screening false-positive rate.** Tool descriptions are legitimately
   imperative ("use this to transfer funds when the user asks"). The screening
   heuristic must be tuned against a real corpus before it can gate admission
   rather than merely flag.
4. **Standing-policy blast radius.** Auto-approval is required for adoption but
   is also the widest possible policy surface. Needs its own review cadence and
   an explicit cap on how much of the estate may be auto-approved.
5. **Zone taxonomy.** Two levels (internal/partner/public) or a full lattice with
   per-domain internal zones? Start with three; make it extensible.
6. **Relationship to service mesh.** Where a mesh already provides SPIFFE
   identity and mTLS, connect should consume rather than duplicate it. Needs a
   defined "mesh-provided identity" mode.
7. **Does the contract belong in the token?** A merged artifact is simpler for
   adopters; separate artifacts keep the lifecycles independent (tokens are
   per-session, contracts are per-relationship and much longer-lived). Current
   lean: **separate, joined by `cid`** — but this is the most consequential open
   decision for the spec.
