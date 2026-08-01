# 5 · warden-connect — Use Case Definitions

> Ten use cases in a single template. Each states the actors, the trigger, the
> main and exception flows, the **controls exercised** (→ `04-technical-capability-matrix.md`),
> the **evidence produced**, and the **threats mitigated**.

**Template fields:** ID · Name · Primary actor · Supporting actors · Trigger ·
Preconditions · Main flow · Alternate / exception flows · Postconditions ·
Controls exercised · Evidence produced · Threats mitigated · Success measure.

**Actor glossary:** *Agent Developer* (builds/owns an agent) · *Security
Architect* (approves connections) · *AppSec Engineer* (surface & supply chain) ·
*SecOps Analyst* (containment) · *Platform Operator* (runs the plane) · *Risk &
Compliance Officer* (evidence) · *Partner Agent Operator* (external) ·
*Calling Agent* / *Callee* (non-human actors).

---

## UC-01 · Register and admit an internal agent

| Field | Detail |
|---|---|
| **Primary actor** | Agent Developer |
| **Supporting** | Admission service, CI/CD pipeline, Security Architect (tier ≥ 2 only) |
| **Trigger** | An agent is being promoted toward a non-development environment |
| **Preconditions** | Agent has a workload identity; build pipeline emits a provenance attestation; a named human owner exists |

**Main flow**
1. CI job calls `connect register agent --card agent-card.json --attest bundle.sigstore --owner human:dev@org --service payments-recon`.
2. Admission verifies the workload identity (SPIFFE SVID) against the trust bundle.
3. Admission verifies the agent-card signature and schema.
4. Admission verifies build provenance (SLSA/Sigstore) and its link to the running artifact.
5. Admission **screens the declared surface** — card description, skill text, parameter docs — for instruction-injection patterns.
6. Risk tier is derived from declared data classes and requested capability classes; tier ≥ 2 routes to a Security Architect for confirmation.
7. Card is hashed and **pinned**; the agent record is written to the registry with `posture: attested`, lifecycle `active`.
8. Registration is appended to the tamper-evident chain and emitted as OCSF.

**Alternate / exception**
- *A1 — Unverifiable provenance:* in **observe** mode the agent is admitted with `posture: unattested` and flagged; in **enforce** mode admission is denied.
- *A2 — Screening finding:* admission blocked; finding routed to AppSec with the offending text quoted.
- *A3 — No named owner:* admission denied. Ownership is non-negotiable.
- *A4 — Re-registration with a changed card:* treated as **drift**, not an update — see UC-06.

**Postconditions** — the agent exists in the registry, is discoverable to the extent policy allows, and holds **zero connections**. Registration is not connectivity.

| | |
|---|---|
| **Controls** | T1.1, T1.4, T1.5, T2.1, T2.2, T5.2, T7.1, T7.2 |
| **Evidence** | Registration record; pinned card hash; provenance reference; tier decision; approver (if any) |
| **Threats** | T13 rogue agents · T9 spoofing · T12 communication poisoning (at source) |
| **Success measure** | 100% of production agents registered with a named owner; median registration < 5 min in CI |

---

## UC-02 · Onboard an MCP tool server and pin its surface

| Field | Detail |
|---|---|
| **Primary actor** | Platform Operator (internal server) or AppSec Engineer (third-party server) |
| **Supporting** | Admission service, Third-Party Risk (external only) |
| **Trigger** | A tool server is to be made available to agents |
| **Preconditions** | Server endpoint reachable; `tools/list` obtainable; owner identified |

**Main flow**
1. `connect register server --endpoint … --owner … --tier 3 --zone internal.payments`.
2. Admission performs an MCP `initialize` + `tools/list` handshake and captures the **full declared surface**.
3. Each tool's name, description and parameter documentation is screened (T5.2) — this is where a poisoned description is caught, before any agent's model has read it.
4. Data classes and jurisdictions the server touches are declared and recorded.
5. Surface is canonicalised and **hashed**; the hash is pinned. A CycloneDX surface BOM is generated.
6. Server record written with `posture: attested`; re-attestation interval set from tier.

**Alternate / exception**
- *A1 — Third-party server:* additionally requires a completed supplier record; admitted at `zone: partner`, and the higher zone bar applies to every future connection.
- *A2 — Surface too large / wildcard tools:* admission requires an explicit scoping justification; unbounded surfaces are refused at tier ≥ 2.
- *A3 — Server unreachable at handshake:* registration fails; nothing is pinned. There is no "register on trust."

| | |
|---|---|
| **Controls** | T2.1, T2.2, T2.6, T5.2, T7.1 |
| **Evidence** | Pinned manifest hash; surface BOM; screening report; supplier reference |
| **Threats** | Tool poisoning · rug-pull (baseline established) · T2 tool misuse |
| **Success measure** | 0 unregistered MCP endpoints observed in production traffic |

---

## UC-03 · Mediated capability discovery

| Field | Detail |
|---|---|
| **Primary actor** | Calling Agent (or its developer, at design time) |
| **Supporting** | Discovery broker |
| **Trigger** | An agent or developer needs a capability it does not itself have |
| **Preconditions** | Asker is registered and attested |

**Main flow**
1. Asker submits a **capability question**: `connect discover --capability "payments.balance.read" --as agent:recon-bot-7 --jurisdiction SG`.
2. Broker resolves candidate entries from the registry.
3. Broker filters to entries the asker is **policy-eligible to connect to** — zone rules, tier compatibility, data class, jurisdiction.
4. Broker returns capability summaries only — no endpoints, no credentials, no full tool schemas.
5. Query is logged with the asker identity.

**Alternate / exception**
- *A1 — No eligible entries:* an empty result is returned. It is never distinguishable from "exists but you may not see it" — the broker does not confirm existence.
- *A2 — Enumeration pattern detected:* broad or repeated scanning is throttled and raised as a reconnaissance finding.

**Postconditions** — the asker knows a capability exists and may request a connection (UC-04). It still cannot reach anything.

| | |
|---|---|
| **Controls** | T2.3, T2.4, T7.1 |
| **Evidence** | Discovery query log per asker |
| **Threats** | Reconnaissance · T3 privilege compromise (lateral discovery) |
| **Success measure** | 0 catalogue-leakage findings; developer capability-find time under 2 minutes |

---

## UC-04 · Establish an internal agent → tool-server connection

The core loop. Everything else supports this.

| Field | Detail |
|---|---|
| **Primary actor** | Agent Developer |
| **Supporting** | Contract service, Security Architect (approval), Channel mediator |
| **Trigger** | A discovered capability is required by a real workload |
| **Preconditions** | Both parties registered and attested; caller has a valid Warden session token |

**Main flow**
1. `connect request --from agent:recon-bot-7 --to server:payments-mcp --tools get_balance,list_transactions --justify "APAC daily reconciliation" --ttl 30d`.
2. Connection policy evaluates: zone pair, tier compatibility, requested surface vs the callee's declared surface, data classes, jurisdictions, requester's authority.
3. **Decision:** auto-approve under standing policy (low tier, same zone, read-only), or route to a Security Architect with the full request context.
4. On approval, a **connection contract** is minted: `cid`, caller, callee, pinned hashes, `surface`, `terms` (rate, spend, oversight, delegation depth, evidence), `assurance`, `approval`, `exp`.
5. Contract is distributed to the mediator(s) on the path.
6. At runtime the mediator verifies the contract, verifies both peer identities, checks the presented card/manifest hashes against the pins, and establishes the channel.
7. The mediator **filters `tools/list`** down to `surface.tools` — the agent's model never sees `wire_funds`, so it can never be manipulated into attempting it.
8. Each subsequent `tools/call` is enforced by **Warden core** inside the surface: `effective = surface ∩ token.scope ∩ policy`.
9. Every action is recorded with `cid` as the correlation root.

**Alternate / exception**
- *A1 — Requested surface exceeds the callee's declared surface:* rejected at request time with a precise diff.
- *A2 — Cross-zone request:* escalated to the zone-crossing path (UC-05).
- *A3 — Approval not granted within SLA:* request expires; nothing is provisioned.
- *A4 — Hash mismatch at connect time:* connection refused, drift raised (UC-06).
- *A5 — Contract expired mid-workload:* the connection stops. Renewal is UC-09; there is no implicit grace.
- *A6 — Ceiling breach (rate/spend/fan-out):* deny, notify owner, keep the contract valid.

| | |
|---|---|
| **Controls** | T3.1–T3.8, T4.1, T4.4, T4.7, T7.1, T7.7 |
| **Evidence** | Signed contract; approval record with approver and ticket; per-connection lifecycle events; per-action Warden audit rows carrying `cid` |
| **Threats** | T2 tool misuse · T3 privilege compromise · T10 HITL fatigue (approve the relationship, not each call) |
| **Success measure** | 100% of production connections contracted; median request-to-connected < 1 business day; mean exposed tools per connection trending down |

---

## UC-05 · Cross-organisation (partner) agent federation

| Field | Detail |
|---|---|
| **Primary actor** | Head of AI Platform / Third-Party Risk |
| **Supporting** | Partner Agent Operator, Security Architect, DPO |
| **Trigger** | A business process requires an internal agent to invoke a partner's agent (or vice versa) |
| **Preconditions** | Partner organisation onboarded as a supplier; a federation trust anchor is agreed |

**Main flow**
1. Federation established: partner's registry entity statement verified against the agreed trust anchor; a trust chain is built.
2. Partner agent resolved through federation — its signed card is fetched and **pinned locally**. Neither side exposes a full catalogue.
3. Elevated admission bar applies for `zone: partner`: signed card mandatory, provenance mandatory, short `reattest_every`, mandatory human approval, mandatory data-class and jurisdiction declaration.
4. DPO reviews declared data classes and cross-border jurisdictions.
5. Contract minted with a short TTL, tight ceilings, an explicit oversight term, and `delegation.max_depth: 1` — a partner agent may not sub-delegate onward.
6. Mediator enforces egress control: only declared data classes may cross, only to declared jurisdictions.
7. The connection appears in the third-party register with its termination path recorded.

**Alternate / exception**
- *A1 — Partner card changes:* connection suspended immediately; re-approval required. External drift is treated more severely than internal.
- *A2 — Federation anchor rotation:* connections continue to `exp` but no new contracts are issued until the anchor is re-verified.
- *A3 — Partner requests deeper delegation:* denied by construction; `max_depth` cannot be raised by the callee.
- *A4 — Exit triggered (contract ends, breach, insolvency):* `connect revoke --party partner:*` executes the tested exit and produces the evidence.

| | |
|---|---|
| **Controls** | T1.2, T1.5, T4.2, T4.5, T5.3, T7.4, T7.6 |
| **Evidence** | Federation trust chain; partner supplier record; contract; DPO review; exit drill record |
| **Threats** | T9 spoofing · T13 rogue agents · T12 communication poisoning · cross-border data exposure |
| **Success measure** | Partner onboarding cycle time in days; 100% of external connections with tested exit |

---

## UC-06 · Detect and respond to surface drift (rug-pull)

The use case that most clearly cannot be served at the action layer.

| Field | Detail |
|---|---|
| **Primary actor** | Sentinel (automated) |
| **Supporting** | AppSec Engineer, agent owner |
| **Trigger** | Scheduled re-attestation, or a hash mismatch at connect time |
| **Preconditions** | A pinned card/manifest hash exists |

**Main flow**
1. Sentinel re-fetches the callee's declared surface on its interval.
2. Canonicalise and hash; compare against the pin.
3. On mismatch, compute a **semantic diff**: tools added/removed, descriptions changed, parameters changed, endpoints changed.
4. Re-run injection screening against the new text.
5. Classify: *benign* (docs typo, additive tool outside the contracted surface) vs *material* (contracted tool's description or parameters changed; new exfiltration-shaped instruction; endpoint moved).
6. **Material drift → every contract referencing that pin is suspended immediately.** Owners are notified with the diff.
7. Re-approval re-runs admission; on approval a new pin and new contracts are issued.

**Alternate / exception**
- *A1 — Drift detected at connect time (before the scheduled check):* the connection is refused on the spot; the same flow runs.
- *A2 — Benign drift under standing policy:* pin auto-updated, event recorded, no suspension.
- *A3 — Repeated drift from one party:* posture degraded; the party's tier is escalated and its re-attestation interval shortened.

| | |
|---|---|
| **Controls** | T2.2, T5.1, T5.2, T5.3, T5.4, T6.1 |
| **Evidence** | Old and new hashes; semantic diff; screening result; suspension and re-approval records |
| **Threats** | Tool poisoning · rug-pull · cross-server shadowing · T12 · T11 |
| **Success measure** | Mean time to detect material drift < re-attestation interval (target ≤ 1 h for tier 1); 0 undetected contracted-surface changes |

---

## UC-07 · Emergency quarantine of a compromised agent

| Field | Detail |
|---|---|
| **Primary actor** | SecOps Analyst |
| **Supporting** | Control plane, all mediators, IdP (signal source) |
| **Trigger** | Compromise indication — SOC detection, CAEP `session-revoked`, anomalous fan-out, owner report |
| **Preconditions** | The party is in the registry (which is exactly why UC-01/02 are mandatory) |

**Main flow**
1. `connect quarantine agent:recon-bot-7 --reason "SOC-2291 credential theft"`.
2. Registry state → `quarantined` (a terminal state until explicitly cleared).
3. Revocation of every contract where the party is caller **or** callee, propagated to all mediators as signed events.
4. Mediators refuse new connections and apply drain policy (`drain` or `abort`) to in-flight calls.
5. A CAEP signed SET is emitted so downstream systems and partners cut their own sessions.
6. Blast-radius report generated: everything the party could reach, and everything that could reach it, at the moment of quarantine.
7. Every step appended to the tamper-evident chain and shipped to the SIEM.

**Alternate / exception**
- *A1 — A mediator is unreachable:* it is treated as **not confirmed**; strict mode means it will itself fail closed on its next contract check. Non-confirmation is reported, never assumed benign.
- *A2 — Quarantine would break a critical business service:* the decision is surfaced with the impacted service list, but containment is not silently downgraded — an override is an explicit, dual-controlled, logged act.
- *A3 — Clearing quarantine:* requires full re-admission (UC-01), not a state flip.

| | |
|---|---|
| **Controls** | T6.1, T6.2, T6.3, T6.4, T6.5, T5.6, T7.1, T7.2 |
| **Evidence** | Quarantine order with reason and operator; per-contract revocation records; propagation confirmations; blast-radius report; emitted SETs |
| **Threats** | T13 rogue agents · T3 privilege compromise · T4 resource overload · T8 repudiation |
| **Success measure** | Mean time to contain < 60 s estate-wide; quarterly drill pass rate 100% |

---

## UC-08 · Shadow agent / shadow MCP detection

| Field | Detail |
|---|---|
| **Primary actor** | Sentinel (automated) |
| **Supporting** | CISO, agent owner, Platform Operator |
| **Trigger** | An observed connection attempt whose caller, callee or both are unregistered |
| **Preconditions** | Mediators deployed on the paths in scope (may be observe-only) |

**Main flow**
1. Mediator observes an attempt referencing an unknown identity or endpoint.
2. **Observe mode:** allow, record, and raise a finding with the observed surface, the endpoint and the inferred owner (from workload identity / namespace / repo).
3. Findings aggregate into a shadow-estate view ranked by risk signals — external endpoint, write-capable tools, sensitive data classes.
4. Owner is contacted with a one-command remediation path: register (UC-01/02) or decommission.
5. **Enforce mode:** the attempt is refused and the finding is raised as an incident.

**Alternate / exception**
- *A1 — Owner cannot be inferred:* the finding escalates to the platform team with the network and identity context captured.
- *A2 — Endpoint is external and unapproved:* treated as an egress incident immediately, regardless of mode.

| | |
|---|---|
| **Controls** | T2.5, T2.1, T4.5, T7.2 |
| **Evidence** | Finding with observed endpoint, surface, timestamps, inferred owner |
| **Threats** | T13 rogue agents · supply chain · unmanaged egress |
| **Success measure** | Shadow endpoints detected per month trending to 0; mean time to registration-or-removal < 14 days |

---

## UC-09 · Renewal, review and offboarding

| Field | Detail |
|---|---|
| **Primary actor** | Business service owner / agent owner |
| **Supporting** | Sentinel, Security Architect |
| **Trigger** | Contract approaching `exp`; periodic access review; agent decommissioned; owner departs |
| **Preconditions** | An active contract exists |

**Main flow**
1. Sentinel notifies the owner ahead of expiry with **actual usage** for the period: tools actually called, volume, spend, denied attempts.
2. Owner elects renew / renew-with-reduced-surface / terminate.
3. Renewal re-runs admission checks — identity, provenance, pin, screening. It is a re-decision, not an extension.
4. Usage-informed **surface reduction** is proposed automatically: tools granted but never called are dropped by default.
5. New contract minted, or the connection lapses at `exp`.
6. On termination the record is retained for the regulatory retention period with a demonstrable exit path.

**Alternate / exception**
- *A1 — No owner response:* the contract lapses at `exp`. Silence terminates; it never renews.
- *A2 — Owner has left the organisation:* connection flagged as orphaned; the business service owner must reassign or it lapses.
- *A3 — Re-attestation fails at renewal:* no renewal; the connection lapses on schedule.

| | |
|---|---|
| **Controls** | T3.7, T5.3, T5.5, T1.6, T7.1 |
| **Evidence** | Renewal decision with usage report; surface-reduction diff; termination record |
| **Threats** | Standing-privilege accumulation · orphaned authority · T3 |
| **Success measure** | 0 connections past TTL; % of renewals with reduced surface (the least-connectivity ratchet) |

---

## UC-10 · Regulatory register and evidence export

| Field | Detail |
|---|---|
| **Primary actor** | Risk & Compliance Officer |
| **Supporting** | Internal Audit, external regulator or auditor |
| **Trigger** | Periodic filing, audit request, incident report, or customer security review |
| **Preconditions** | Registry and contract history populated |

**Main flow**
1. `connect export --format dora --as-of 2026-06-30` (also `cps230`, `oscal`, `ocsf`, `csv`).
2. The export enumerates every internal and external dependency: party, owner, business service, criticality tier, jurisdictions, data classes, contract terms, approval record, exit path, incident history.
3. External agents appear as ICT third-party service providers with contractual terms drawn from the connection contract itself.
4. Point-in-time integrity is provable: the export references audit-chain anchors, so it is verifiable rather than merely asserted.
5. Control evidence exports in OSCAL for the GRC platform; findings and lifecycle events in OCSF for the SIEM.

**Alternate / exception**
- *A1 — Gaps present (unregistered or unattested parties):* the export includes an explicit exceptions section rather than silently omitting them. An incomplete register that says so is defensible; one that pretends is not.
- *A2 — Historical as-of query:* reconstructed from the contract history and verified against anchors.

| | |
|---|---|
| **Controls** | T7.1, T7.2, T7.4, T2.1, T2.6 |
| **Evidence** | The export itself, with anchor references and an exceptions section |
| **Threats** | T8 repudiation · regulatory finding |
| **Success measure** | Register produced in < 1 hour; 0 material gaps at audit |

---

## 5.11 Coverage summary

| Use case | B-capabilities (doc 3) | Stage | Primary persona |
|---|---|---|---|
| UC-01 Register & admit agent | B1.1, B2.1–B2.4, B2.6 | ① → ② | Agent Developer |
| UC-02 Onboard tool server | B1.2, B2.3, B2.5 | ① → ② | Platform Operator / AppSec |
| UC-03 Mediated discovery | B1.4, B4.3 | ① | Agent Developer |
| UC-04 Establish connection | B3.1–B3.3, B8.1, B8.2 | ② | Agent Developer |
| UC-05 Partner federation | B2.5, B4.2, B4.4, B4.5, B3.6 | ③ | Third-Party Risk |
| UC-06 Drift detection | B5.1, B5.2, B5.3 | ② → ③ | AppSec |
| UC-07 Quarantine | B6.1–B6.5 | ② | SecOps |
| UC-08 Shadow detection | B1.3, B1.5 | ① | CISO |
| UC-09 Renewal & offboarding | B3.4, B3.6, B5.4, B5.5 | ② → ③ | Service owner |
| UC-10 Register export | B7.1–B7.4 | ③ | Risk & Compliance |

Note the stage column: **UC-01, UC-02, UC-03 and UC-08 all land in stage ①** and
require no behaviour change from any developer. That is the wedge — the estate
becomes visible before anything becomes enforced.
