# warden-connect

> **The connection control plane for AI agents.**
> Warden decides whether an action may happen. **warden-connect decides whether
> the relationship that enables it may exist at all.**

Status: **built, pre-1.0**. The design set below defined it; the code implements it
and [production-readiness.md](production-readiness.md) is the honest list of what
still stands between here and a release. Start at the
[repository README](../README.md) if you want to run it rather than read it.

Companion to the Warden core docs (`../../warden/docs/`) — this set defines the
first of three new family members: `warden-connect`, `warden-delegate`,
`warden-trace`.

---

## The family, in one table

| Component | Boundary it owns | The question it answers | Primary artifact |
|---|---|---|---|
| **Warden** (core) | **Action** — agent → tool call | *May this call happen, and who is accountable?* | Signed session token → allow / deny / hold + audit entry |
| **warden-connect** | **Relationship** — agent ↔ agent, agent ↔ tool server | *May these two parties connect at all, and on what terms?* | **Signed connection contract** (`cid`) |
| **warden-delegate** | **Authority** — what crosses a hop | *How much power flows across this handoff, and can it only shrink?* | Attenuated delegation / transaction token |
| **warden-trace** | **Evidence** — across all hops | *What actually happened end to end, and what influenced it?* | Federated, tamper-evident lineage graph |

Warden core is the **brake**. `connect` is the **admission gate and the wiring
diagram**. `delegate` is the **power-of-attorney**. `trace` is the **black-box
recorder, joined up across agents**.

---

## Deliverables in this set

| # | Document | What it gives you |
|---|---|---|
| 1 | [01-capability.md](01-capability.md) | Capability definition — what warden-connect is, its principles, and its explicit non-goals |
| 2 | [02-why-now.md](02-why-now.md) | Why this is the need of the hour — forcing functions, cost of inaction, why Warden is positioned to build it |
| 3 | [03-business-capability-matrix.md](03-business-capability-matrix.md) | L1/L2 business capability model, owners, KPIs, maturity stages, regulatory anchors |
| 4 | [04-technical-capability-matrix.md](04-technical-capability-matrix.md) | Technical capabilities → mechanism → standard → interface → enforcement point → failure mode → status |
| 5 | [05-use-cases.md](05-use-cases.md) | Ten formal use-case definitions with flows, controls exercised, evidence produced, threats mitigated |
| 6 | [06-journey-maps.md](06-journey-maps.md) | Five persona journey maps with pain-today vs with-connect, moments that matter, friction budget |
| 7 | [07-hld.md](07-hld.md) | High-level technical design — components, domain model, contract schema, flows, APIs, threat model, topologies, NFRs, phasing |
| 8 | [08-lld.md](08-lld.md) | Low-level design — crate layout, module signatures, algorithms, storage records, wire formats, error codes, latency budgets, test suite, resolved open questions |
| 9 | [warden-connect-logical-architecture.svg](warden-connect-logical-architecture.svg) | Logical architecture diagram (same visual language as `warden-logical-architecture.svg`) |
| — | [explainer/](explainer/) | Twelve self-contained HTML pages: a capability hub, one per use case, and the adoption ladder. A *rendering* of 05 and 08 for sharing, not a second specification |
| — | [explainer/video/](explainer/video/) | Five animated journey explainers, one per persona in 06. 1080p, 53 s each |

Written after the build, and downstream of what the code turned out to need:

| Document | What it gives you |
|---|---|
| [physical-architecture.md](physical-architecture.md) | Four deployment variants — on-prem VMs, on-prem Kubernetes, AWS, Azure — with topologies, a cross-variant mapping table, and the gaps that shape the design |
| [key-custody.md](key-custody.md) | The six signing operations, which key loss is unrecoverable and which is merely an outage, and why the revocation key is the odd one out |
| [twelve-factor.md](twelve-factor.md) | Config, state, logs, disposability — and the two places this deliberately deviates, including the one where §1 of the LLD overstates what exists |
| [observability.md](observability.md) | The §8.14 families as emitted, the four alerts this design implies written as PromQL with runbooks, and the questions the telemetry deliberately cannot answer |
| [operations.md](operations.md) | Backup, restore and the quarterly drill; what losing each file costs, and why retention on a hash-linked chain is segment retirement rather than deletion |
| [production-readiness.md](production-readiness.md) | Nineteen items in P0/P1/P2 plus a hardening pass, in working order. Written before anyone asked |

Read them in order; 01 and 02 are the positioning, 03–06 are the product
definition, 07–09 are the build. 07 decides *what* the components are; 08 decides
*how* they are built — and resolves every open question 07 left standing.

`explainer/` is downstream of all of it. If a page disagrees with 05, 06 or 08,
the design documents are right and the page needs regenerating — the generator in
`explainer/src/` exists so that is one command rather than twelve edits.

---

## The one-liner

> **warden-connect is a mediated registry and admission gateway for AI agents and
> tool servers: nothing is discoverable until it is attested, nothing is
> reachable without a signed, time-boxed connection contract, and any connection
> can be cut in seconds when trust changes.**

The coupling point — the thing that makes it portable, and the strategic asset —
is the **connection contract**: one signed document that says *this caller may
reach this callee, over exactly this surface, under these terms, until this
time.* Warden core enforces per-action **inside** that envelope; `delegate`
attenuates authority **within** it; `trace` correlates evidence **by** it.

Same design stance as Warden core: **carried, not looked up** — verify a signed
artifact on the hot path, keep the graph resolution upstream.

---

## The single most important sentence

Warden core stops a bad call. warden-connect **stops the relationship that makes
the bad call possible** — it moves the control left, from exploitation to
reconnaissance and initial access. An agent cannot be induced to misuse a tool
server it was never introduced to.
