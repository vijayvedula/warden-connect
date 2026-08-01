# 2 · Why warden-connect is the need of the hour

> Status: positioning. Companion to Warden's [why-warden.md](../../warden/docs/why-warden.md).
> Regulatory timing below reflects rules in force as of mid-2026; the EU AI Act's
> high-risk phase-in has been subject to active amendment — treat specific dates
> as "verify before external use," the direction as settled.

**The compressed argument:** the industry spent 2024–25 governing what an agent
*does*. In 2026 the unit of risk moved — from a single agent calling a tool to a
**mesh of agents calling each other and calling tool servers nobody registered**.
The action boundary is a chokepoint on one hop. The connection boundary is the
chokepoint on the *topology* — and it is completely ungoverned.

---

## 2.1 The seven forcing functions

### F1 · Multi-agent stopped being an architecture diagram
Orchestrator-workers, routing, group-chat and hierarchical topologies are in
production. Relationships scale roughly with the square of agents, not linearly —
an estate of 40 agents and 25 tool servers has a five-figure space of possible
introductions. Every organisation is currently governing that space with a
combination of *deployment configuration* and *hope*. There is no register, no
owner, no expiry, and no bar to clear before two agents start talking.

### F2 · Shadow MCP is the new shadow IT — and it is faster
Standing up an MCP server is a one-line command. Developers wire agents to
community servers pulled from a registry, run locally, with no review. The
questions a CISO now cannot answer: *how many MCP servers are in our estate? who
owns them? what do they expose? which agents reach them? which of them phone
home?* Shadow IT took a decade to become a board topic. Shadow MCP took months,
because the adoption barrier is a package install and the blast radius is a tool
with production credentials.

### F3 · The attack class Warden core structurally cannot see
Tool poisoning, rug-pull updates, cross-server tool shadowing and description
line-jumping all work by **putting attacker-controlled instructions into the
declared surface** — the tool description, the parameter doc, the agent card —
which the model reads as trusted instruction text before any call is made.

> A per-call policy engine evaluates the call it is given. It cannot detect that
> the *menu* was rewritten. By the time policy runs, the injection has already
> been read.

These are integrity-of-surface problems. The controls that answer them —
content-addressed pinning, admission-time surface screening, drift detection,
re-attestation — are all **connection-layer** controls, and none of them exist in
the action layer. This is the single strongest technical argument for the
component.

### F4 · A2A turns agents into externally reachable services
Agent-to-agent protocols give agents a public-facing card, a skill catalogue and
an invocation endpoint. That makes a partner's agent a **third-party service
provider that you integrate with in an afternoon** — with none of the onboarding,
contracting, assurance or exit machinery that every regulated organisation
mandates for third-party software. Identity spoofing and rogue-agent insertion
(OWASP Agentic **T9**, **T13**) have no answer at the action layer: you cannot
authorize your way out of having been introduced to an impostor.

### F5 · Regulation now asks for exactly this artifact
Three separate regimes converged on the same demand — a **register of the things
you depend on, the terms you depend on them under, evidence of oversight, and a
demonstrated exit**:

| Regime | In force | What it demands | warden-connect artifact |
|---|---|---|---|
| **EU DORA** | since Jan 2025 | Register of Information for ICT third-party services; contractual terms; exit strategies | Registry + connection contract + revocation record |
| **APRA CPS 230** | since Jul 2025 | Material service-provider register, tiering, oversight, termination | Registry + risk tier + owner + quarantine evidence |
| **EU AI Act** | phasing through 2026–27 | High-risk system obligations: human oversight, logging, provider/deployer duties along the value chain | Oversight terms, evidence obligations, per-connection log |
| **NIS2** | transposed from Oct 2024 | Supply-chain security of direct suppliers | Admission attestation + provenance |
| **MAS agentic-AI guidance** | current | Named accountability and bounded autonomy for agentic systems | Named owner per connection + terms ceilings |

An external agent **is** a third-party service. An MCP server **is** an ICT
dependency. Nobody has been registering them. warden-connect makes the register a
by-product of how connections are made, rather than a spreadsheet reconstructed
under audit pressure — which is the difference between a control and a
compliance exercise.

### F6 · Blast radius and denial-of-wallet scale with fan-out
Unbounded agent-to-agent invocation produces recursive call storms, cost
runaways, and cascading failure across business services that were never intended
to be coupled. Per-run budgets bound one agent. Only a connection-level ceiling
bounds the *graph*.

### F7 · The containment gap in a real incident
When an agent is compromised, the required action is *"cut everything it can
reach, now, and prove when we cut it."* Today that is a hunt through deployment
config across teams. A connection registry makes it one command and one
tamper-evident record — the difference between a 4-hour and a 40-second
containment.

---

## 2.2 What breaks first, without it

| Failure | How it presents | Who owns the incident |
|---|---|---|
| Poisoned tool description on a community MCP server | Agent starts exfiltrating to an attacker endpoint "because the tool said to" | AppSec — with no evidence of when the description changed |
| Rug-pull update | Reviewed server, approved months ago, silently changes behaviour | Platform — no pin, no diff, no alert |
| Rogue/spoofed partner agent | Internal agent hands data to an impostor over A2A | Security — no counterparty verification to point to |
| Unregistered MCP server with prod credentials | Discovered during audit, not during operation | CISO — a register that does not exist |
| Recursive agent fan-out | Cost spike, upstream saturation, cascading timeouts | SRE — no connection-level ceiling |
| Regulator asks for the agent interconnect register | Weeks of manual reconstruction; gaps admitted | Risk & Compliance |

Each row is unanswerable at the action layer and routine at the connection layer.

---

## 2.3 Why *Warden* is the right vendor for this

1. **It already owns the wire.** Warden sits inline on the MCP path today. The
   channel mediator is an extension of a shipped proxy (`gateway.rs`, `mcp.rs`,
   `identity.rs`), not a new data plane to earn a place for.
2. **It already has the hard parts.** Tamper-evident hash-chained audit with
   signed anchors, CAEP/Shared-Signals revocation, OCSF sinks, fail-closed
   discipline, DPoP sender-constraint — all the primitives connection lifecycle
   needs, already built and tested.
3. **The spec flywheel extends cleanly.** Warden's strategic asset is the token
   spec. The **connection contract is its natural companion**: an open, verifiable
   artifact (`connect verify` mirroring `warden token verify`) that any registry,
   platform or framework can emit. Two specs covering identity *and* topology is
   materially more gravity than one.
4. **It resolves the buyer ≠ user tension even better than core.** Core lands on
   developer visibility. `connect` lands on something developers want *more* — a
   working catalogue that tells them which agent to call and gets them connected
   through an approval path instead of a ticket queue. Security gets the register
   as the by-product.
5. **Adoption motion is unchanged.** *Observe* (register the estate, discover
   shadow MCP, change nothing) → *Enforce* (deny-by-default topology, contracts
   required) → *Govern* (attestation bars, zone rules, automated register export).
   Identical to Warden's landing arc, which is already proven to work.

---

## 2.4 The competitive window

| Alternative | Why it does not close the gap |
|---|---|
| Platform-native registries (cloud agent catalogues, workspace tool governance) | Single-platform. Real estates run several clouds and several frameworks, and the whole point of a register is that it is *complete*. |
| Service mesh / zero-trust networking | Governs workloads, not agent semantics. A mesh will happily authorize a mutually-authenticated connection to a tool server whose description was rewritten yesterday. |
| API gateways / API management | The unit is an endpoint, not a relationship with an owner, a risk tier, an expiry and an oversight term. No concept of a capability surface or an agent card. |
| MCP registries / marketplaces | Publication and discovery, not admission control and enforcement. They tell you what exists; they do not decide who may reach it. |
| Build in-house | It is a registry *plus* an attestation pipeline *plus* an inline mediator *plus* an evidence chain *plus* regulatory export. Everyone builds the registry and stops. |

The window is open because the incumbents each own an adjacent layer and none
owns **the agent relationship as a governed object with a lifecycle**. That is
the unclaimed noun.

---

## 2.5 The sentence to lead with

> *"You have a control for what your agents do. You have no control for who they
> talk to, no list of what you actually run, and no way to prove either. Warden
> gave you the brake. warden-connect gives you the wiring diagram — enforced, and
> exportable to your regulator."*
