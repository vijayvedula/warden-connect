# B1 · Agent & Tool Estate Management

> *"know what we run"*

The domain that answers the first of the four questions with no owner: **which
parties exist at all, and who owns each of them.**

Five of the six capabilities below need no mediator and change no behaviour on the
request path. Only **B1.3** touches the data plane, and only because a shadow
endpoint is by definition absent from the registry and can therefore only be seen in
traffic. An estate that adopts B1 alone gets a truthful register with named owners
and nothing else — which is the honest description, and the reason B1 is reachable
before anyone has agreed to enforcement.

| L2 | Capability | Realised by | Component |
|---|---|---|---|
| [B1.1](#b11--agent-registry) | Agent registry | T2.1 · T1.5 · T1.1 | `admission`, `registry` |
| [B1.2](#b12--tool-server--mcp-registry) | Tool-server / MCP registry | T2.1 · T2.2 · T2.6 | `admission`, `registry` |
| [B1.3](#b13--shadow-agent--shadow-mcp-discovery) | Shadow-agent & shadow-MCP discovery | T2.5 · T7.2 | `mediator`, `assurance`, `evidence` |
| [B1.4](#b14--capability--surface-catalogue) | Capability & surface catalogue | T2.3 · T2.4 | `broker` |
| [B1.5](#b15--ownership--lifecycle-state) | Ownership & lifecycle state | T1.6 · T2.1 | `registry` |
| [B1.6](#b16--business-service-mapping) | Business-service mapping | T2.1 · T7.4 | `registry`, `evidence` |

---

## B1.1 · Agent registry

> **Outcome** — a single authoritative answer to "what agents do we run, and who owns each".
> **Owner** Head of AI Platform · **KPI** % of production agents registered with a named owner, target 100% · **Stage** ①

| Technical capability | Failure mode |
|---|---|
| **T1.1** Workload identity verification | No verifiable identity → **not registrable** |
| **T1.5** Agent-card signature verification | Unsigned or mis-signed card → **not admitted** |
| **T2.1** Agent & server registry | Registry unavailable → strict mode denies new connections |

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant CLI as connect CLI
    participant Adm as admission
    participant SPIRE as SPIFFE / SPIRE
    participant Reg as registry
    participant Ev as evidence

    Dev->>+CLI: connect register agent --card agent-card.json --owner human:priya@org
    CLI->>+Adm: card, owner, tier, zone

    Adm->>+SPIRE: verify workload identity
    SPIRE-->>-Adm: X.509-SVID spiffe://org/ns/agents/recon

    alt no verifiable workload identity
        Adm-->>CLI: reject, not registrable
        Note over Adm,CLI: T1.1 · no record is created.<br/>An unprovable agent never reaches the registry.
    else identity verified
        Adm->>Adm: verify agent-card JWS against the claimed operator key
        alt card unsigned or signed by another key
            Adm-->>CLI: reject, not admitted
        else card signature valid
            Adm->>+Reg: create entity record
            Note right of Reg: identity · owner · tier · zone<br/>card hash · lifecycle = active
            Reg-->>-Adm: agent:recon-bot-7
            Adm->>+Ev: append REGISTERED
            Ev-->>-Adm: chain head sha256:9c2e…
            Adm-->>-CLI: registered
            CLI-->>-Dev: exit 0
        end
    end
```

**What the diagram argues.** The owner is captured at the same moment as the
identity, not bolted on afterwards. That is what makes the KPI *"registered with a
named owner"* rather than merely *"registered"* — a record cannot exist without one.

---

## B1.2 · Tool-server / MCP registry

> **Outcome** — every tool server inventoried with its exposed surface and dependencies.
> **Owner** Platform Engineering · **KPI** % of MCP endpoints registered; count of unregistered endpoints observed · **Stage** ①

| Technical capability | Failure mode |
|---|---|
| **T2.1** Agent & server registry | — |
| **T2.2** Surface pinning | Presented hash ≠ pinned hash → refused, drift event raised |
| **T2.6** Surface BOM | — |

```mermaid
sequenceDiagram
    autonumber
    actor Plat as Platform Engineer
    participant CLI as connect CLI
    participant Adm as admission
    participant MCP as MCP tool server
    participant Reg as registry

    Plat->>+CLI: connect register server --endpoint https://payments-mcp.internal --tier 1
    CLI->>+Adm: endpoint, tier, zone, owner

    Adm->>+MCP: tools/list
    MCP-->>-Adm: 9 tools with names, descriptions and schemas

    Adm->>Adm: canonicalise the contracted subset, then sha256
    Note over Adm: surface_digest plus a per-tool digest,<br/>so a later diff names the tool that moved

    Adm->>+Reg: create server record with pinned digest
    Reg-->>-Adm: server:payments-mcp
    Adm->>Reg: attach CycloneDX surface BOM
    Adm-->>-CLI: registered, 9 tools pinned
    CLI-->>-Plat: surface_digest sha256:230c1f4a…
```

**What the diagram argues.** The pin is taken from the server's own `tools/list`
response, not from its documentation — so the record is what the server *actually
serves*. Every later drift check in **B5.1** is a comparison against this one
message.

---

## B1.3 · Shadow-agent & shadow-MCP discovery

> **Outcome** — unsanctioned agents and servers surfaced from live traffic, not from surveys.
> **Owner** CISO · **KPI** shadow endpoints detected per month; mean time to registration or removal · **Stage** ①

| Technical capability | Failure mode |
|---|---|
| **T2.5** Shadow-endpoint detection | Observe mode logs only. Enforce mode refuses |
| **T7.2** SIEM export | Blocking sink unavailable → connection not issued |

```mermaid
sequenceDiagram
    autonumber
    participant Agent as unregistered agent
    participant Med as mediator
    participant Reg as registry
    participant Asr as assurance
    participant Ev as evidence
    actor SecOps as CISO / SecOps

    Agent->>+Med: tools/call to https://unknown-mcp.internal
    Med->>+Reg: resolve callee endpoint
    Reg-->>-Med: no record

    alt observe mode
        Med->>Agent: forward upstream, behaviour unchanged
        Note over Med,Agent: T2.5 · log only. Nothing breaks<br/>while you find out what you have.
    else enforce mode
        Med-->>Agent: refuse, callee not registered
    end

    Med->>+Asr: observation: endpoint, caller, first-seen
    deactivate Med
    Asr->>Asr: correlate against registry and prior observations
    Asr->>+Ev: OCSF finding, shadow endpoint
    Ev-->>-Asr: emitted to SIEM
    deactivate Asr

    SecOps->>+Asr: connect posture --shadow
    Asr-->>-SecOps: 3 endpoints · first seen · calling agents · call volume
```

**What the diagram argues.** The survey is replaced by the traffic. Note that the
finding carries the *calling agent*, because the KPI is mean time to registration or
removal — and that needs a person to chase, which the caller's owner supplies.

---

## B1.4 · Capability & surface catalogue

> **Outcome** — developers find the right existing agent instead of building a fourth one.
> **Owner** Head of AI Platform · **KPI** reuse rate: connections to existing agents ÷ new agent builds · **Stage** ①

| Technical capability | Failure mode |
|---|---|
| **T2.3** Mediated discovery | Unknown asker → **empty result set**, never an error that confirms existence |
| **T2.4** Anti-enumeration | Enumeration attempt → throttled and logged as reconnaissance |

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant CLI as connect CLI
    participant Brk as broker
    participant Reg as registry
    participant Pol as connection policy

    Dev->>+CLI: connect discover --capability payments.balance.read --as agent:recon-bot-7
    CLI->>+Brk: capability query, asker identity

    Brk->>+Reg: resolve asker
    Reg-->>-Brk: zone internal.apac-ops · tier 3

    alt asker not registered
        Brk-->>CLI: empty result set
        Note over Brk,CLI: T2.3 · never an error. "Not found" and<br/>"not allowed" must be indistinguishable,<br/>or the API is an enumeration oracle.
    else asker resolved
        Brk->>+Reg: candidates advertising the capability
        Reg-->>-Brk: 6 servers
        Brk->>+Pol: filter by zone pair, tier bar, data class
        Pol-->>-Brk: 2 connectable
        Brk->>Brk: rate-limit and log the query
        Brk-->>-CLI: 2 entries with the surface each could expose
        CLI-->>-Dev: server:payments-mcp, server:ledger-mcp
    end
```

**What the diagram argues.** There is no list endpoint. The answer to a capability
question is bounded by what the asker could be *connected to*, so discovery can never
return more than governance would allow — and repeated near-miss queries become a
reconnaissance signal rather than just a throttle.

---

## B1.5 · Ownership & lifecycle state

> **Outcome** — no orphaned agents; leavers do not leave live authority behind.
> **Owner** Business service owner · **KPI** orphaned-agent count, target 0; age of oldest unreviewed record · **Stage** ②

| Technical capability | Failure mode |
|---|---|
| **T1.6** Identity lifecycle sync | Owner leaves → connections flagged, then expired |
| **T2.1** Registry lifecycle field | — |

```mermaid
sequenceDiagram
    autonumber
    participant IdP as IdP / HR system
    participant Reg as registry
    participant Asr as assurance
    actor Owner as business service owner
    participant Ct as contract

    IdP->>+Reg: SCIM deprovision, human:priya@org
    Reg->>Reg: mark owned entities owner-orphaned
    Reg-->>-IdP: ack

    Reg->>+Asr: 2 agents now without a live owner
    Asr->>+Owner: notify: reassign or retire, clock started
    deactivate Asr

    alt reassigned within the review window
        Owner->>+Reg: connect register agent --owner human:sam@org
        Reg-->>-Owner: lifecycle = active, orphan cleared
    else window elapses
        Reg->>+Ct: no renewal for contracts held by orphaned parties
        Note over Ct: T3.7 · expiry is the enforcement.<br/>Nothing is severed early — the contract<br/>simply is not renewed at exp.
        Ct-->>-Reg: contracts will lapse at exp
        Reg->>Reg: lifecycle = retiring
    end
```

**What the diagram argues.** The leaver event does not cut anything. It starts a
clock, and the *absence of renewal* does the work — so an HR feed can never cause an
outage, which is what makes it safe to wire an HR feed to a production control at
all.

---

## B1.6 · Business-service mapping

> **Outcome** — agent risk expressed in business terms, not infrastructure terms.
> **Owner** Operational Risk · **KPI** % of agents mapped to a critical business service · **Stage** ②

| Technical capability | Failure mode |
|---|---|
| **T2.1** Registry record fields | — |
| **T7.4** Regulatory register export | — |

```mermaid
sequenceDiagram
    autonumber
    actor Risk as Operational Risk
    participant CLI as connect CLI
    participant Reg as registry
    participant Ev as evidence
    actor Reg2 as Regulator

    Risk->>+CLI: map agent:recon-bot-7 to service:payments, criticality = critical
    CLI->>+Reg: set business service and criticality
    Reg-->>-CLI: record updated
    CLI-->>-Risk: mapped

    Note over Reg: The field is on the entity, so every<br/>contract the party later holds inherits<br/>a business meaning for free.

    Reg2->>+Risk: which critical operations depend on AI agents?
    Risk->>+Ev: connect export --format cps230 --as-of 2026-06-30
    Ev->>+Reg: entities, owners, criticality, contracts as at that date
    Reg-->>-Ev: resolved
    Ev-->>-Risk: register, with the evidence chain head
    deactivate Risk
```

**What the diagram argues.** Criticality is recorded once on the entity and inherited
by every relationship it later forms. That is what turns **B7.1**'s register from a
reconstruction into a query — the business meaning was captured at registration, not
assembled at audit time.

---

## What B1 does not do

It does not decide whether two parties may connect — that is **B3**, and no contract
exists at this stage. It records a provenance attestation but does not gate on it —
that is **B2.2**. And it enforces nothing on the request path unless the mediator is
deployed, which only **B1.3** requires.
