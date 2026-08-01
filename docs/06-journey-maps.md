# 6 · warden-connect — Journey Maps

> Five personas, end to end. Each map runs **stage → goal → today's reality →
> with warden-connect → touchpoint → evidence produced → metric**, followed by
> the emotional arc, the moments that matter, and the friction budget.
>
> The design rule these maps enforce: **the developer journey must get faster,
> or the security journey never happens.**

---

## J1 · Agent Developer — "I need my agent to talk to the payments service"

**Persona:** Priya, senior engineer on the reconciliation team. Ships weekly.
Measures success in merged PRs, not controls. Will route around anything that
costs more than an afternoon.
**Goal:** get a reconciliation agent reading balances from the payments MCP
server, in production, this sprint.

| Stage | Goal | Today | With warden-connect | Touchpoint | Evidence produced | Metric |
|---|---|---|---|---|---|---|
| **1 Discover** | Find something that can read balances | Ask in Slack; get three contradictory answers; two teams point at each other | `connect discover --capability "payments.balance.read"` returns eligible providers with owners | CLI / portal | Discovery query logged | Capability-find time: **days → < 2 min** |
| **2 Register** | Get her agent known to the platform | No such step exists; she just deploys | CI step registers the agent with its card, provenance and owner | CI pipeline | Registration record, pinned card | Registration time **< 5 min**, zero manual steps |
| **3 Request** | Get permission to connect | Raises a ticket; unclear approver; asked for a threat model she has never written | `connect request --tools get_balance,list_transactions --justify …`; policy answers instantly whether it is auto-approved | CLI | Connection request with justification | Request effort: **hours → 1 command** |
| **4 Approve** | Wait | 2–3 weeks; chased in standups | Read-only same-zone auto-approves in seconds; higher tiers route to a named architect with full context pre-attached | Slack / portal | Signed approval, ticket ref | Median approval: **~14 days → < 1 day** (auto-approvals: seconds) |
| **5 Connect** | Make the call work | Copy an endpoint and a shared credential from a wiki page | Contract distributed automatically; the mediator is already on the path; her MCP client points at Warden as it already did | none — it just works | Contract `cid`, connection established | Config changes required: **0** |
| **6 Build** | Iterate | Every tool the server exposes is visible; easy to call the wrong one by accident | `tools/list` shows exactly the two contracted tools — narrower surface, less to reason about, fewer accidents | runtime | Per-action rows carrying `cid` | Accidental out-of-scope calls: **→ 0** |
| **7 Operate** | Keep it healthy | Finds out about breakage from a failing job | Owner alerts on drift, ceiling approach, and upcoming expiry | Slack / email | Drift and ceiling events | Mean time to know: **hours → minutes** |
| **8 Renew** | Keep it running | Nothing expires, so nothing is reviewed | 30-day notice with real usage; one-click renew, with unused tools dropped by default | portal | Renewal decision + surface diff | Renewals with reduced surface: **target > 60%** |

**Emotional arc:** *frustrated* (1–4 today: opaque, slow, gatekept) → *relieved*
(5–6: it works and the surface is small) → *in control* (7–8: told before it
breaks).

**Moments that matter**
1. **Stage 1 → 2.** If discovery does not immediately return something useful,
   she goes back to Slack and the whole model collapses. Discovery must be *the
   fastest way to find a capability*, not merely the sanctioned one.
2. **Stage 4.** Auto-approval under standing policy for the low-risk majority is
   the single feature that decides adoption. If every connection needs a human,
   this becomes the ticket queue it replaced.
3. **Stage 5.** Zero config change. The moment she has to edit a deployment
   manifest to satisfy a security tool, adoption becomes a negotiation.

**Friction budget:** *net negative*. She should spend **less** total time than
today — a registration step she does not perform manually, traded against weeks
of waiting she no longer does.

---

## J2 · Security Architect — "Should these two be introduced?"

**Persona:** Cecil, security architect covering four business units. Reviews
40–60 requests a month across all technologies. Optimises for *defensible
decisions at volume*.
**Goal:** approve safe connections in minutes and spend real attention only on
the ones that deserve it.

| Stage | Goal | Today | With warden-connect | Touchpoint | Evidence | Metric |
|---|---|---|---|---|---|---|
| **1 Intake** | Understand what is being asked | A ticket saying "need access to payments API" | A structured request: both parties, tiers, zones, exact tool surface, data classes, jurisdictions, provenance status, justification | Portal / Slack | Request record | Clarification round-trips: **3 → 0** |
| **2 Triage** | Spend attention where it matters | Everything looks the same; reviews by arrival order | Risk-ranked queue; the low-risk majority never reaches him at all | Portal | Auto-approval records | Human-reviewed share: **100% → ~20%** |
| **3 Assess** | Judge the actual exposure | Guesswork — no way to know what the server really exposes | Screened surface, pinned manifest, provenance status, and the callee's existing connection graph, all in the request | Portal | Screening + posture snapshot | Time per review: **~45 → ~5 min** |
| **4 Shape** | Reduce rather than reject | Binary approve/deny; rejection means an argument | Counter-offer: narrower tool set, shorter TTL, tighter ceilings, oversight term added | Portal | Contract terms as approved | Share shaped rather than rejected: **target > 50%** |
| **5 Decide** | Make it stick | Approval lives in a ticket; enforcement is somebody else's problem | Approval **is** the enforcement — the signed contract is the mechanism | Portal + signing key | Signed approval bound to `cid` | Approval-to-enforcement gap: **weeks → 0** |
| **6 Assure** | Know it stayed true | No feedback loop; approvals decay silently | Drift alerts on anything he approved; usage reports at renewal | Slack | Drift events, usage reports | Approved-then-drifted detected: **100%** |
| **7 Review** | Defend the portfolio | Reconstructs from tickets when asked | Live view of every connection he approved, with current posture | Portal | Portfolio view | Audit prep: **days → minutes** |

**Emotional arc:** *overwhelmed* (1–2 today) → *equipped* (3–4: the facts arrive
with the request) → *confident* (5–6: decisions are enforced and monitored, not
filed).

**Moments that matter**
1. **Stage 2.** Standing policy is what makes the role survivable. Approving the
   *relationship* rather than every call is the direct answer to human-in-the-loop
   fatigue (OWASP T10) — and reviewer fatigue is itself an attack surface.
2. **Stage 5.** The approval and the enforcement artifact must be the same
   object. Every security process that separates them decays.
3. **Stage 6.** Being told when something he approved changed is what converts
   this from a gate into a control.

**Friction budget:** *strongly negative*. Fewer reviews, better inputs, shorter
each.

---

## J3 · SecOps Analyst — "Contain it now, prove it later"

**Persona:** Sam, on-call SOC analyst. 03:00. An agent is exfiltrating.
**Goal:** stop the bleeding in seconds, and be able to prove exactly what was
cut and when.

| Stage | Goal | Today | With warden-connect | Touchpoint | Evidence | Metric |
|---|---|---|---|---|---|---|
| **1 Detect** | Know something is wrong | SIEM alert on an odd egress destination | Same alert, plus the agent identity, its `cid` set and its owner already attached | SIEM | Correlated finding | Triage context: **minutes → immediate** |
| **2 Scope** | Know what it can reach | Ask three teams; grep deployment repos; guess | `connect blast-radius agent:x` returns the transitive reachable set | CLI | Blast-radius report | Scoping: **hours → seconds** |
| **3 Contain** | Cut it | Scale the deployment to zero and hope nothing else holds its credentials | `connect quarantine agent:x` — every contract revoked, all mediators, inbound and outbound | CLI | Quarantine order + per-contract revocations | MTTC: **hours → < 60 s** |
| **4 Verify** | Confirm the cut landed | No way to confirm; watch the SIEM and hope | Propagation confirmations per mediator; unconfirmed mediators reported explicitly and fail closed themselves | CLI / portal | Propagation report | Containment confidence: **assumed → proven** |
| **5 Notify** | Tell everyone downstream | Manual emails to partners | Signed CAEP SETs emitted; federated partners cut their own sessions | automatic | Emitted SETs | Downstream notification: **hours → seconds** |
| **6 Investigate** | Reconstruct what happened | Stitch logs from N systems, incomplete | Every action carries `cid`; `warden-trace` reconstructs the multi-agent lineage | trace | Correlated lineage | Reconstruction: **days → same shift** |
| **7 Report** | Meet the reporting clock | Scramble; timings approximate | Tamper-evident timeline with anchors — defensible to the minute | Export | Anchored incident timeline | Regulatory report inside the window: **100%** |
| **8 Restore** | Bring it back safely | Redeploy and hope | Clearing quarantine requires full re-admission — you cannot restore a party you have not re-proved | CLI | Re-admission record | Re-compromise on restore: **0** |

**Emotional arc:** *alarmed* (1) → *powerful* (2–3: one command, whole estate) →
*trusted* (4–7: the record defends itself).

**Moments that matter**
1. **Stage 3.** One verb, whole estate, under a minute. This is the demo moment —
   it is what a CISO buys.
2. **Stage 4.** Explicit non-confirmation. A containment tool that silently
   assumes success is worse than none, because it manufactures false confidence.
3. **Stage 8.** Re-admission on restore closes the loop that most incident
   processes leave open.

**Friction budget:** *hugely negative* on the paths that matter, and deliberately
**positive** on restore — restoring should be harder than cutting.

---

## J4 · Risk & Compliance Officer — "Show me the register"

**Persona:** Anika, operational risk lead. Owns the CPS 230 / DORA response.
Has been asking for an agent inventory for three quarters.
**Goal:** produce a complete, defensible register and evidence of oversight,
without a project.

| Stage | Goal | Today | With warden-connect | Touchpoint | Evidence | Metric |
|---|---|---|---|---|---|---|
| **1 Inventory** | Know the dependency population | A spreadsheet built from a survey, stale on arrival | The registry is the inventory, and it is maintained as a by-product of connecting | Portal | Live registry | Inventory freshness: **quarterly → live** |
| **2 Classify** | Tier by criticality | Manual, inconsistent across teams | Tier derived at admission from data classes and capability classes, mapped to business service | Portal | Tier decisions | Tiered coverage: **partial → 100%** |
| **3 Contract** | Evidence the terms | Contracts exist for vendors; nothing at all for internal agent relationships | Every connection carries machine-readable terms — surface, ceilings, oversight, exit | Portal | Connection contracts | Dependencies under documented terms: **→ 100%** |
| **4 Oversee** | Evidence human oversight | Screenshots of ticket approvals | Signed approvals cryptographically bound to the connection | Export | Signed approval records | Oversight evidence: **assertion → proof** |
| **5 Monitor** | Show ongoing control | Annual sample-based review | Continuous posture, drift and re-attestation records | Portal | Posture history | Control evidence: **sampled → continuous** |
| **6 Exit** | Prove termination is possible | Never tested for agents | Quarantine drills are the exit test, and they produce a record | Export | Drill records | Dependencies with tested exit: **→ 100%** |
| **7 Report** | File it | 3-week reconstruction project per cycle | `connect export --format dora --as-of …`, with an explicit exceptions section | CLI / portal | Register + anchor references | Time to produce: **weeks → < 1 hour** |
| **8 Defend** | Withstand challenge | "We believe this is complete" | Anchored, verifiable, point-in-time — and honest about gaps | Audit meeting | Verifiable export | Material audit findings: **→ 0** |

**Emotional arc:** *resigned* (1–2 today: she has stopped expecting an accurate
answer) → *surprised* (3–5: the artifacts already exist) → *confident* (7–8: she
can defend it, including the gaps).

**Moments that matter**
1. **Stage 1.** The register being a by-product rather than a project is the
   whole proposition. A register that must be maintained is a register that will
   be stale.
2. **Stage 7 (A1 in UC-10).** The explicit exceptions section. An export that
   declares its gaps is defensible; one that quietly omits them destroys trust in
   the entire artifact the first time an auditor finds one.
3. **Stage 8.** Verifiability — she is not asking to be believed.

**Friction budget:** *near zero ongoing*. She consumes; she does not maintain.

---

## J5 · Partner Agent Operator — "Integrate with them without exposing ourselves"

**Persona:** Marcus, platform lead at a fintech whose agent must serve a bank's
agent. His deal depends on passing the bank's security review.
**Goal:** get connected quickly without handing over his catalogue or accepting
unbounded obligations.

| Stage | Goal | Today | With warden-connect | Touchpoint | Evidence | Metric |
|---|---|---|---|---|---|---|
| **1 Qualify** | Learn the bar | A 300-row spreadsheet questionnaire | A published assurance bar for `zone: partner`: signed card, provenance, TTL, oversight | Docs | — | Time to understand requirements: **weeks → an afternoon** |
| **2 Prepare** | Meet it | Bespoke evidence per customer | Sign the card, ship provenance from the existing pipeline, declare data classes | CI | Signed card, provenance | Prep: **weeks → days** |
| **3 Federate** | Establish trust | Exchange API keys over email | Federation trust anchor exchanged once; entity statements verified both ways | Portal | Trust chain | One-time setup, reusable per relationship |
| **4 Scope** | Expose only what is needed | Expose the whole API and hope | Only the contracted skills are resolvable; the rest of his catalogue is invisible | Contract | Contract surface | Surface exposed: **whole API → contracted skills** |
| **5 Operate** | Serve traffic | Unpredictable volume, unclear liability | Ceilings and terms are explicit and mutual, and `max_depth: 1` blocks onward sub-delegation | Runtime | Per-connection metering | Volume surprises: **→ 0** |
| **6 Change** | Ship updates | Breaks the customer silently | Card change is detected as drift and re-approved through a defined path | Portal | Drift + re-approval | Silent breakage: **→ 0** |
| **7 Renew / exit** | Keep or end it cleanly | Perpetual, forgotten integrations | Time-boxed by construction; exit is a tested, evidenced path | Portal | Renewal / termination | Orphaned integrations: **→ 0** |

**Emotional arc:** *defensive* (1–2: another customer questionnaire) →
*reassured* (3–4: he is not exposing his catalogue) → *cooperative* (5–7:
obligations are bounded and symmetric).

**Moments that matter**
1. **Stage 1.** A *published, machine-checkable* bar converts security review
   from negotiation into conformance. That is precisely the sell-through motion
   in Warden's core thesis — the vendor adopts it to pass their customer's review.
2. **Stage 4.** Neither side exposes a catalogue. Federation without disclosure
   is what makes cross-org adoption politically possible.
3. **Stage 6.** A defined change path. Without one, partners route around the
   control and ship silently — which is the rug-pull risk arriving through the
   front door.

**Friction budget:** *positive but bounded and reusable* — real work once, then
amortised across every future customer that speaks the same contract.

---

## 6.6 Cross-journey design principles

Extracted from the moments-that-matter above; these are the acceptance criteria
for the product, not aspirations.

| # | Principle | Fails if |
|---|---|---|
| 1 | **The developer path must be faster than the unsanctioned path** | Registration adds manual steps, or discovery returns nothing useful |
| 2 | **Approve relationships, not calls** | Every action prompts a human; reviewer fatigue becomes the vulnerability (T10) |
| 3 | **Approval and enforcement are the same artifact** | Approvals live in a ticket system while enforcement lives in config |
| 4 | **Silence terminates, it never renews** | Expiry has a grace period, or unreviewed contracts roll forward |
| 5 | **Non-confirmation is reported, never assumed** | Quarantine reports success without per-mediator confirmation |
| 6 | **Gaps are declared, not omitted** | An export hides unregistered parties and an auditor finds one |
| 7 | **Restoring is harder than cutting** | Quarantine can be cleared with a state flip instead of re-admission |
| 8 | **Evidence is a by-product, never a project** | Anyone has to maintain the register by hand |
