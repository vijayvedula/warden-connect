# 3 · warden-connect — Business Capability Matrix

> A capability model, not a feature list: **L1 domains → L2 capabilities**, each
> with the business outcome, the accountable owner, a measurable KPI, the
> adoption stage at which it lands, and its regulatory anchor.

## 3.0 How to read this

- **Stage** maps to Warden's proven adoption arc:
  **① Observe** (register and see, change nothing) → **② Enforce**
  (deny-by-default, contracts required) → **③ Govern** (assurance bars, zone
  rules, automated regulatory evidence).
- **Owner** is the *accountable* role, not the operator.
- **Reg. anchor** is indicative mapping for control-catalogue traceability, not
  legal advice.

---

## 3.1 The L1 capability map

```
warden-connect
├── B1  Agent & Tool Estate Management        "know what we run"
├── B2  Admission & Onboarding                "nothing joins unproven"
├── B3  Connection Governance                 "relationships have terms and owners"
├── B4  Exposure & Trust-Zone Management      "who may reach whom, across boundaries"
├── B5  Continuous Assurance                  "trust decays; re-earn it"
├── B6  Containment & Resilience              "cut it, fast, provably"
├── B7  Regulatory Evidence & Reporting       "hand the register over"
└── B8  Consumption & Cost Control            "bound the graph, charge it back"
```

---

## 3.2 L2 capability matrix

### B1 · Agent & Tool Estate Management

| L2 capability | Business outcome | Owner | KPI | Stage | Reg. anchor |
|---|---|---|---|---|---|
| B1.1 Agent registry | A single authoritative answer to "what agents do we run, and who owns each" | Head of AI Platform | % of production agents registered with a named owner (target 100%) | ① | CPS 230 · DORA RoI |
| B1.2 Tool-server / MCP registry | Every tool server inventoried with its exposed surface and dependencies | Platform Engineering | % of MCP endpoints registered; count of unregistered endpoints observed | ① | NIS2 · DORA |
| B1.3 Shadow-agent & shadow-MCP discovery | Unsanctioned agents and servers surfaced from live traffic, not from surveys | CISO | Shadow endpoints detected per month; mean time to registration or removal | ① | CPS 230 |
| B1.4 Capability & surface catalogue | Developers find the right existing agent instead of building a fourth one | Head of AI Platform | Reuse rate: connections to existing agents ÷ new agent builds | ① | — |
| B1.5 Ownership & lifecycle state | No orphaned agents; leavers do not leave live authority behind | Business service owner | Orphaned-agent count (target 0); age of oldest unreviewed record | ② | CPS 230 · SOX-adjacent |
| B1.6 Business-service mapping | Agent risk expressed in business terms, not infrastructure terms | Operational Risk | % of agents mapped to a critical business service | ② | CPS 230 (critical operations) |

### B2 · Admission & Onboarding

| L2 capability | Business outcome | Owner | KPI | Stage | Reg. anchor |
|---|---|---|---|---|---|
| B2.1 Identity attestation | Only cryptographically identified workloads join the estate | Security Architecture | % of registered parties with verified workload identity | ② | NIS2 · CPS 234 |
| B2.2 Build provenance verification | Supply-chain assurance for the agent and its tool servers | AppSec | % of admissions with valid SLSA/Sigstore provenance | ③ | NIS2 · EO-style SSDF expectations |
| B2.3 Declared-surface screening | Poisoned tool descriptions and cards rejected before a model ever reads them | AppSec | Injection-pattern findings per 100 admissions; false-negative rate at re-review | ② | EU AI Act (risk mgmt) |
| B2.4 Risk tiering & assurance bar | Proportionate control — a read-only reporting agent is not treated like a payments agent | Operational Risk | % of parties tiered; tier-appropriate control coverage | ② | CPS 230 tiering · EU AI Act risk class |
| B2.5 Third-party / partner agent onboarding | External agents pass a real supplier gate, in days not months | Third-Party Risk | Onboarding cycle time; % of external connections with completed due diligence | ③ | DORA · CPS 230 · NIS2 |
| B2.6 Self-service developer onboarding | A paved road: registration in minutes, not a ticket queue | Head of AI Platform | Median time from "agent exists" to "agent registered & connectable" | ① | — |

### B3 · Connection Governance

| L2 capability | Business outcome | Owner | KPI | Stage | Reg. anchor |
|---|---|---|---|---|---|
| B3.1 Connection request & approval workflow | Every relationship has a documented, human-approved justification | Security Architecture | Median approval latency; % auto-approved under standing policy | ② | EU AI Act (human oversight) |
| B3.2 Connection contracts (terms of use) | Machine-enforced equivalent of a supplier contract, per relationship | Legal / Third-Party Risk | % of active connections under a valid contract (target 100%) | ② | DORA (contractual terms) |
| B3.3 Surface scoping (least connectivity) | An agent sees and can attempt only the tools it was granted | Security Architecture | Mean tools exposed per connection vs mean granted; scope-creep rate | ② | CPS 234 (least privilege) |
| B3.4 Time-boxing & renewal | No permanent, forgotten connectivity | Business service owner | % of connections older than policy TTL (target 0); renewal-on-time rate | ② | DORA · CPS 230 |
| B3.5 Human-oversight terms | High-consequence relationships carry a standing oversight obligation | Operational Risk | % of high-tier connections with an oversight term; hold-to-decision latency | ③ | EU AI Act Art. 14-style oversight |
| B3.6 Exit & offboarding | A demonstrable, rehearsed termination path per dependency | Third-Party Risk | Time-to-terminate (drill); % of dependencies with a tested exit | ③ | DORA (exit strategy) · CPS 230 |

### B4 · Exposure & Trust-Zone Management

| L2 capability | Business outcome | Owner | KPI | Stage | Reg. anchor |
|---|---|---|---|---|---|
| B4.1 Trust-zone model | Internal / partner / public are governed differently, by design | Security Architecture | % of connections with an explicit zone pair; unclassified count (target 0) | ② | CPS 234 (segmentation) |
| B4.2 Zone-crossing control | Every boundary crossing is deliberate, higher-assurance and logged | CISO | Cross-zone connections per month, each with approval evidence | ② | NIS2 · CPS 234 |
| B4.3 Mediated discovery (anti-reconnaissance) | An agent's view of the estate is its permitted connection set — nothing more | Security Architecture | Enumeration attempts blocked; catalogue leakage incidents (target 0) | ② | — |
| B4.4 Cross-org federation | Partner agents interoperate without either side exposing a full catalogue | Head of AI Platform | Federated partners live; connections per partner | ③ | DORA · NIS2 |
| B4.5 Egress control for external agents | Data leaving to an external agent is bounded by declared data class and jurisdiction | Data Protection Officer | Cross-jurisdiction connections; policy-violating attempts blocked | ③ | GDPR/PDPA transfer rules · EU AI Act |

### B5 · Continuous Assurance

| L2 capability | Business outcome | Owner | KPI | Stage | Reg. anchor |
|---|---|---|---|---|---|
| B5.1 Surface-drift detection | A rug-pull is an alert in minutes, not an incident in months | AppSec | Mean time to detect manifest/card change; drift events per month | ② | NIS2 · EU AI Act (post-market monitoring) |
| B5.2 Scheduled re-attestation | Trust decays and must be re-earned on a clock | Platform Engineering | % of connections re-attested within SLA; stale-attestation count | ③ | CPS 230 · DORA |
| B5.3 Posture scoring | Risk-ranked view of the estate for prioritised remediation | CISO | % of estate at "attested"; count at "degraded"/"unattested" | ③ | CPS 230 |
| B5.4 Certificate / key / owner hygiene | No connection outlives its credentials or its human | Platform Engineering | Expiring-credential lead time; orphaned-owner count | ② | CPS 234 |
| B5.5 Continuous control monitoring & attestation reporting | Control effectiveness is evidenced continuously, not sampled annually | Internal Audit | % of controls with automated evidence; audit findings on agent estate | ③ | CPS 230 · SOC 2 / ISO 42001 |

### B6 · Containment & Resilience

| L2 capability | Business outcome | Owner | KPI | Stage | Reg. anchor |
|---|---|---|---|---|---|
| B6.1 Estate-wide quarantine | One command severs every connection a compromised agent holds | Security Operations | Mean time to contain (target < 60s); drill success rate | ② | CPS 234 (IR) · NIS2 (IR) |
| B6.2 Signal-driven revocation (CAEP/SSF) | Identity and risk events from the IdP automatically cut connectivity | Security Operations | % of revocations triggered automatically; signal-to-cut latency | ③ | CPS 234 |
| B6.3 Blast-radius analysis | "If this agent is compromised, what is reachable?" answered before the incident | Security Architecture | % of critical agents with a current reachability analysis | ③ | CPS 230 (severe but plausible) |
| B6.4 Graceful degradation & drain | Containment does not itself cause an outage | SRE | Failed-transaction rate during quarantine drills | ② | CPS 230 (tolerance levels) |
| B6.5 Containment evidence | The cut is provable: what, when, by whom, under which policy version | Internal Audit | % of containment actions with tamper-evident record (target 100%) | ② | DORA (incident reporting) |

### B7 · Regulatory Evidence & Reporting

| L2 capability | Business outcome | Owner | KPI | Stage | Reg. anchor |
|---|---|---|---|---|---|
| B7.1 Interconnect register export | The regulator's register is generated, not reconstructed | Risk & Compliance | Hours to produce the register (target < 1); gap findings | ③ | DORA RoI · CPS 230 register |
| B7.2 Control-evidence export (OSCAL/OCSF) | Auditors and SIEM consume machine-readable, verifiable evidence | Internal Audit | % of requested evidence served automatically | ③ | ISO 42001 · SOC 2 |
| B7.3 AI value-chain traceability | Provider/deployer roles and dependencies are documented per system | Model Risk / AI Governance | % of high-risk systems with a complete dependency map | ③ | EU AI Act |
| B7.4 Attestation of oversight | Proof that a named human authorised each material relationship | Operational Risk | % of high-tier connections with a signed human approval | ② | EU AI Act · MAS guidance |

### B8 · Consumption & Cost Control

| L2 capability | Business outcome | Owner | KPI | Stage | Reg. anchor |
|---|---|---|---|---|---|
| B8.1 Connection-level rate & fan-out ceilings | Recursive agent storms are bounded at the graph, not just per agent | SRE | Ceiling breaches per month; incidents attributed to fan-out (target 0) | ② | CPS 230 (tolerances) |
| B8.2 Spend ceilings per relationship | Denial-of-wallet has a hard stop with a named owner | FinOps | Spend variance vs ceiling; runaway events (target 0) | ② | — |
| B8.3 Chargeback & showback | Agent-to-agent consumption is attributable to a business service | FinOps | % of spend attributable to a connection and owner | ③ | — |
| B8.4 Capacity & dependency planning | Interconnect growth is a planned figure, not a surprise | Head of AI Platform | Forecast accuracy on connection growth | ③ | CPS 230 (resilience) |

---

## 3.3 Value-driver heat map

Where each domain pays back. **H** = primary driver, **M** = secondary.

| L1 domain | Risk reduction | Delivery speed | Cost control | Compliance | Revenue enablement |
|---|:--:|:--:|:--:|:--:|:--:|
| B1 Estate Management | H | **H** | M | H | M |
| B2 Admission | **H** | M | — | H | M |
| B3 Connection Governance | **H** | H | M | **H** | M |
| B4 Exposure & Zones | **H** | — | — | H | **H** *(partner integration)* |
| B5 Continuous Assurance | **H** | — | — | H | — |
| B6 Containment | **H** | — | M | H | — |
| B7 Regulatory Evidence | M | — | M | **H** | **H** *(passes customer security review)* |
| B8 Consumption & Cost | M | — | **H** | M | — |

The two rows to lead with commercially are **B3** (the only one that is
simultaneously primary on risk, compliance and speed) and **B7** (the one that
unblocks revenue by passing someone else's security review).

---

## 3.4 Capability maturity model

| Level | Name | Estate characteristic | Typical evidence |
|---|---|---|---|
| **L0** | Unknown | No inventory. Topology is deployment configuration. Connectivity is discovered during incidents. | None |
| **L1** | Visible | Every agent and tool server registered with an owner; shadow endpoints detected from live traffic. No enforcement. | Register exists but is not authoritative |
| **L2** | Contracted | Deny-by-default topology. Every connection carries a signed, time-boxed contract with a scoped surface and a named approver. | Contract per connection; approval records |
| **L3** | Assured | Admission requires attestation and provenance; drift is detected and re-attestation is scheduled; zones enforced; quarantine drilled. | Posture scores; drift alerts; drill results |
| **L4** | Federated & self-evidencing | Cross-org federation live; register, control evidence and oversight attestations generated on demand; blast-radius analysis continuous. | One-click DORA/CPS 230 register; OSCAL export |

Most organisations today are **L0**. The realistic 12-month target for a
regulated enterprise is **L3**, with **L1 reachable in a quarter** because it
requires no behaviour change from developers.

---

## 3.5 Stakeholder value summary

| Stakeholder | What they get on day one | What keeps them |
|---|---|---|
| **Agent developer** | A catalogue that answers "who can do X" and a self-service path to connect | Connections in minutes instead of a ticket queue |
| **Security Architect** | An accurate topology and a rejection point before introduction | Deny-by-default with a scoped, expiring surface |
| **AppSec** | Shadow MCP discovery and surface screening | Drift alerts on approved servers |
| **SecOps** | Blast-radius visibility | One-command, provable estate-wide quarantine |
| **Platform / SRE** | Dependency map | Fan-out ceilings and safe drain semantics |
| **Risk & Compliance** | The register they have been asked for | Generated evidence, not reconstructed evidence |
| **CISO** | An answer to "what do our agents talk to" | A defensible control story to the board and the regulator |
| **CFO / FinOps** | Consumption attributable to a relationship | Hard spend ceilings per dependency |
