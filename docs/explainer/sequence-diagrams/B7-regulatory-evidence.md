# B7 · Regulatory Evidence & Reporting

> *"hand the register over"*

The domain with the least novel machinery and the clearest test: a regulator asks a
question, and the answer is either **generated** or **reconstructed**. Everything here
turns on that verb.

Nothing in B7 collects new data. Every field it exports was recorded by B1 at
registration, B2 at admission, B3 at approval or B6 at containment — B7 is a set of
queries and shapes over an existing chain. Which is why its KPIs are measured in
*hours to produce* rather than in coverage.

| L2 | Capability | Realised by | Component |
|---|---|---|---|
| [B7.1](#b71--interconnect-register-export) | Interconnect register export | T7.4 | `evidence`, `registry` |
| [B7.2](#b72--control-evidence-export-oscalocsf) | Control-evidence export | T7.2 · T7.4 | `evidence` |
| [B7.3](#b73--ai-value-chain-traceability) | AI value-chain traceability | T2.6 · T7.7 | `registry`, `evidence` |
| [B7.4](#b74--attestation-of-oversight) | Attestation of oversight | T3.1 · T7.1 | `contract`, `evidence` |

---

## B7.1 · Interconnect register export

> **Outcome** — the regulator's register is generated, not reconstructed.
> **Owner** Risk & Compliance · **KPI** hours to produce the register, target < 1; gap findings · **Stage** ③

| Technical capability | Failure mode |
|---|---|
| **T7.4** Regulatory register export | — |

```mermaid
sequenceDiagram
    autonumber
    actor Reg8 as Regulator
    actor RC as Risk & Compliance
    participant Ev as evidence
    participant Reg as registry

    Reg8->>RC: register of ICT interconnections, as at 30 June
    RC->>+Ev: connect export --format dora --as-of 2026-06-30

    Ev->>+Reg: entities, owners, criticality, zones as at that instant
    Reg-->>-Ev: resolved from the chain, not from current state
    Note over Ev,Reg: as_of replays the hash chain to a point<br/>in time. "What was true in June" is a<br/>different question from "what is true now",<br/>and only one of them is being asked.

    Ev->>Ev: shape into the DORA Register of Information
    Ev-->>-RC: register · 412 rows · chain head at that date · signature

    RC->>Reg8: register, with the evidence head it was generated from

    Note over RC,Reg8: The head makes the export checkable.<br/>A regulator can ask for the same query<br/>again in a year and get a byte-identical<br/>answer, which a spreadsheet cannot offer.
```

**What the diagram argues.** `as_of` is the whole capability. Exporting *current*
state is easy and answers the wrong question — the register is always retrospective,
and reconstructing June's estate from July's database is exactly the manual work the
control exists to remove.

---

## B7.2 · Control-evidence export (OSCAL / OCSF)

> **Outcome** — auditors and SIEM consume machine-readable, verifiable evidence.
> **Owner** Internal Audit · **KPI** % of requested evidence served automatically · **Stage** ③

| Technical capability | Failure mode |
|---|---|
| **T7.2** SIEM export | Blocking sink unavailable → connection not issued |
| **T7.4** Register export | — |

```mermaid
sequenceDiagram
    autonumber
    actor Audit as Internal Audit
    participant Ev as evidence
    participant SIEM as SIEM
    participant GRC as GRC platform

    par continuous, as events occur
        Ev->>SIEM: OCSF activity and finding events, streamed
    and on request, per control
        Audit->>+Ev: OSCAL assessment results for CC6.1, this quarter
        Ev->>Ev: select lifecycle events implementing the control
        Ev-->>-Audit: OSCAL, every observation citing a chain offset
    end

    Audit->>+Ev: connect audit verify --from 2026-04-01 --to 2026-06-30
    Ev->>Ev: recompute hashes, check checkpoint signatures
    Ev-->>-Audit: intact · 41 checkpoints · no gaps

    Audit->>GRC: import
    Note over Audit,GRC: Each observation cites an offset, so a<br/>reviewer can verify one row without<br/>trusting the export as a whole. That is<br/>the difference between evidence and a report.
```

**What the diagram argues.** Two channels with different tempos and the same source.
The SIEM stream is continuous and lossy-tolerant; the OSCAL export is on demand and
must be exact. Both read the same chain, so a SIEM alert and an audit observation
about the same event cite the same offset.

---

## B7.3 · AI value-chain traceability

> **Outcome** — provider/deployer roles and dependencies documented per system.
> **Owner** Model Risk / AI Governance · **KPI** % of high-risk systems with a complete dependency map · **Stage** ③

| Technical capability | Failure mode |
|---|---|
| **T2.6** Surface BOM | — |
| **T7.7** Correlation root for `warden-trace` | Missing `cid` → action recorded as uncorrelated and **flagged** |

```mermaid
sequenceDiagram
    autonumber
    actor MR as Model Risk
    participant Reg as registry
    participant Ev as evidence
    participant Trace as warden-trace

    MR->>+Reg: dependency map for system:credit-decisioning
    Reg->>Reg: walk the contract graph, collect surface BOMs
    Reg-->>-MR: 6 agents · 4 tool servers · 2 external providers<br/>each with its role — provider or deployer

    MR->>+Ev: for each dependency, the evidence of its admission
    Ev-->>-MR: provenance, screening findings, approval signatures

    MR->>+Trace: what did this system actually do last quarter
    Trace->>Trace: query by cid
    Trace-->>-MR: actions, correlated to the relationship that permitted them

    Note over Trace,MR: T7.7 · the cid stamped at mint time is the<br/>join key. Without it, "which relationship<br/>allowed this action" is a reconstruction —<br/>which is why an uncorrelated action is<br/>flagged rather than merely logged.
```

**What the diagram argues.** The dependency map and the behaviour record are joined
by one identifier issued at contract-mint time. The EU AI Act asks a deployer to
document its value chain; a graph of *declared* dependencies is a document, while a
graph joined to what actually executed is evidence.

---

## B7.4 · Attestation of oversight

> **Outcome** — proof that a named human authorised each material relationship.
> **Owner** Operational Risk · **KPI** % of high-tier connections with a signed human approval · **Stage** ②

| Technical capability | Failure mode |
|---|---|
| **T3.1** Contract minting | Any policy miss → no contract issued |
| **T7.1** Connection-lifecycle audit | Chain break detected on verify → alert |

```mermaid
sequenceDiagram
    autonumber
    actor OR as Operational Risk
    participant Ev as evidence
    participant Ct as contract

    OR->>+Ev: every tier-1 relationship live in Q2, with its human approval
    Ev->>+Ct: resolve contracts, extract the embedded approval
    Ct-->>-Ev: 38 contracts, each carrying a detached signature

    loop per contract
        Ev->>Ev: verify the approval signature against the approver key at that time
        Note over Ev: "at that time" matters. Verifying against<br/>today's JWKS would fail for a rotated key<br/>and wrongly report an unapproved contract.
    end

    alt every signature verifies
        Ev-->>-OR: 38 of 38 · approver, key id, timestamp, policy version
    else a signature does not verify
        Ev--)OR: named, with the reason — this is a finding, not a rounding error
    end

    Note over OR: The claim is not "an approval was recorded".<br/>It is "a specific key signed this specific<br/>request", which survives an operator with<br/>database access.
```

**What the diagram argues.** Historical key resolution is the subtle requirement. An
approval signed in April by a key rotated in May is still a valid approval — verifying
it needs the key set as it stood in April, which is why the chain records key ids and
not just signatures.

---

## What B7 does not do

It does not judge compliance. Every export here states what happened and proves the
statement has not been altered — whether that satisfies DORA, CPS 230 or the AI Act is
a determination made by people, on evidence this domain makes cheap to produce.
