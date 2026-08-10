# B3 · Connection Governance

> *"relationships have terms and owners"*

The centre of the system. B1 said what exists, B2 said what may exist — B3 is where a
**relationship** acquires terms, an owner, an expiry and a signature, and becomes the
artifact everything downstream reads.

One idea runs through all six capabilities and is worth stating before the diagrams:
**a contract is a ceiling, never a grant.** Holding one does not authorise a call. It
bounds what a call could possibly be, and the bound composes with token scope and
policy by intersection — so no contract can widen anything.

| L2 | Capability | Realised by | Component |
|---|---|---|---|
| [B3.1](#b31--connection-request--approval-workflow) | Request & approval workflow | T3.1 · T3.8 · T7.1 | `contract`, `evidence` |
| [B3.2](#b32--connection-contracts-terms-of-use) | Connection contracts | T3.1 · T3.2 · T3.6 | `contract`, `mediator` |
| [B3.3](#b33--surface-scoping-least-connectivity) | Surface scoping | T3.3 · T3.4 · T3.5 | `mediator` |
| [B3.4](#b34--time-boxing--renewal) | Time-boxing & renewal | T3.7 | `contract` |
| [B3.5](#b35--human-oversight-terms) | Human-oversight terms | T3.6 | `mediator`, Warden core |
| [B3.6](#b36--exit--offboarding) | Exit & offboarding | T6.1 · T3.7 | `contract`, `mediator` |

---

## B3.1 · Connection request & approval workflow

> **Outcome** — every relationship has a documented, human-approved justification.
> **Owner** Security Architecture · **KPI** median approval latency; % auto-approved under standing policy · **Stage** ②

| Technical capability | Failure mode |
|---|---|
| **T3.1** Contract minting | Any policy miss → **no contract issued** |
| **T3.8** Standing-policy auto-approval | Ambiguity → escalate to a human, never auto-allow |
| **T7.1** Connection-lifecycle audit | Chain break detected on verify → alert |

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant Ct as contract
    participant Pol as connection policy
    participant Reg as registry
    actor Appr as named approver
    participant Ev as evidence

    Dev->>+Ct: connect request --from agent:recon --to server:payments<br/>--tools get_balance,list_transactions --justify "APAC recon" --ttl 30d
    Ct->>+Reg: resolve both parties, tiers, zones, posture
    Reg-->>-Ct: caller tier 3 internal · callee tier 1 internal · both attested
    Ct->>+Pol: evaluate standing policy
    Pol-->>-Ct: write surface none, same zone, callee tier 1

    alt standing policy satisfies the bar
        Ct->>Ct: mint without a human
    else bar not met or ambiguous
        Ct->>+Appr: req_7f3c, with justification, surface and both postures
        Appr->>Appr: review the relationship, not the calls
        alt rejected
            Appr-->>Ct: reject
            Ct->>Ev: append REQUEST_REJECTED
            Ct-->>Dev: no contract issued
        else approved
            Appr-->>-Ct: detached signature over req_7f3c, key kid=vijay-1
        end
    end

    Ct->>Ct: mint warden-connection+jws, embed the approval signature
    Ct->>+Ev: append MINTED, cid conn_1a9b
    Ev-->>-Ct: chain head
    Ct-->>-Dev: conn_1a9b, exp +30d
```

**What the diagram argues.** The approval is a **detached signature carried inside
the contract**, not a row in a workflow table. An operator with database access can
alter a ticketing system. They cannot forge a signature over a request they do not
hold the key for — which is what makes the approval itself the enforcement rather
than a record of an intention to enforce.

---

## B3.2 · Connection contracts (terms of use)

> **Outcome** — a machine-enforced equivalent of a supplier contract, per relationship.
> **Owner** Legal / Third-Party Risk · **KPI** % of active connections under a valid contract, target 100% · **Stage** ②

| Technical capability | Failure mode |
|---|---|
| **T3.1** Contract minting | Any policy miss → no contract issued |
| **T3.2** Contract verification | Any failure → connection refused, **fail-closed** |
| **T3.6** Terms enforcement | Condition false → deny or hold |

```mermaid
sequenceDiagram
    autonumber
    participant Agent as agent
    participant Med as mediator
    participant JWKS as issuer JWKS
    participant Rev as revocation feed
    participant Svc as callee

    Agent->>+Med: connect, presenting contract.jws
    Med->>+JWKS: resolve issuer key by kid
    JWKS-->>-Med: public key

    Med->>Med: 1 signature · 2 issuer chain · 3 exp and nbf
    Med->>Med: 4 wire identities match caller and callee
    Med->>Med: 5 pinned surface hash still current
    Med->>+Rev: 6 revocation status for this cid
    Rev-->>-Med: not revoked
    Med->>Med: 7 posture of both parties still acceptable

    alt any single check fails
        Med-->>Agent: refused
        Note over Med,Agent: T3.2 · fail-closed. There is no<br/>partial acceptance — eleven checks,<br/>all must pass, and this is the<br/>conformance ground truth for anyone<br/>implementing the checks elsewhere.
    else all checks pass
        Med->>+Svc: establish upstream
        Svc-->>-Med: ready
        Med-->>-Agent: connected, bounded by the contract surface
    end
```

**What the diagram argues.** Verification is local. Signature, expiry, hash
comparison and set membership — no network call to a policy server on the hot path,
which is why the target is p99 under 5 ms and why a control-plane outage does not
stop traffic that already holds a valid contract.

---

## B3.3 · Surface scoping (least connectivity)

> **Outcome** — an agent sees and can attempt only the tools it was granted.
> **Owner** Security Architecture · **KPI** mean tools exposed per connection vs mean granted; scope-creep rate · **Stage** ②

| Technical capability | Failure mode |
|---|---|
| **T3.3** Surface allowlist enforcement | Uncontracted call → blocked **before upstream** |
| **T3.4** `tools/list` surface filtering | Filter failure → return an **empty list**, fail-closed |
| **T3.5** Narrowing algebra | Attempted widening is **structurally impossible**, not merely denied |

```mermaid
sequenceDiagram
    autonumber
    participant Agent as agent
    participant Med as mediator
    participant Svc as callee

    Agent->>+Med: tools/list
    Med->>+Svc: tools/list
    Svc-->>-Med: 9 tools
    Med->>Med: intersect with contract surface
    Med-->>-Agent: 2 tools
    Note over Med,Agent: T3.4 · the other 7 never enter the<br/>model's context. This is prevention,<br/>not detection — the agent cannot be<br/>persuaded to call a tool it cannot see.

    Agent->>+Med: tools/call get_balance
    Med->>Med: in the allowlist
    Med->>+Svc: forward
    Svc-->>-Med: result
    Med-->>-Agent: result

    Agent->>+Med: tools/call wire_funds
    Med->>Med: not in the contract surface
    Med-->>-Agent: WC-4002 refused
    Note over Med,Svc: T3.3 · the upstream is never spoken to.<br/>The callee logs zero executions, which is<br/>the negative assertion the test suite checks.

    Note over Med: effective = contract.surface ∩ token.scope ∩ policy<br/>Removing any term narrows the set. No term can widen it.
```

**What the diagram argues.** Two different mechanisms, deliberately. Filtering
`tools/list` means the wrong tool is never *offered*. The allowlist means it is never
*executed* even if the agent asks anyway. The first is what actually prevents
accidents — the second is what survives an agent that has been told to try.

---

## B3.4 · Time-boxing & renewal

> **Outcome** — no permanent, forgotten connectivity.
> **Owner** Business service owner · **KPI** % of connections older than policy TTL, target 0; renewal-on-time rate · **Stage** ②

| Technical capability | Failure mode |
|---|---|
| **T3.7** Time-boxing & renewal | Expired → refused. **No grace period by default** |

```mermaid
sequenceDiagram
    autonumber
    participant Asr as assurance
    actor Owner as business service owner
    participant Ct as contract
    participant Adm as admission
    participant Med as mediator

    Asr->>Owner: conn_1a9b expires in 7 days, still in use, 1.2k calls last week

    alt renewed
        Owner->>+Ct: connect renew conn_1a9b
        Ct->>+Adm: re-run admission checks on both parties
        Adm-->>-Ct: caller now unattested, provenance stale
        alt re-admission fails
            Ct-->>Owner: not renewed, posture degraded
            Note over Ct,Owner: T5.3 · renewal is where posture decay<br/>becomes visible. A party that stopped<br/>meeting the bar loses connectivity at exp,<br/>not at the moment it degraded.
        else re-admission passes
            Ct-->>Owner: renewed, exp +30d
        end
        deactivate Ct
    else not renewed
        Note over Owner,Med: nothing happens until exp
    end

    Med->>Med: at exp, contract no longer verifies
    Med--)Med: subsequent connections refused, no grace period
```

**What the diagram argues.** Expiry is the enforcement, and it is passive. Nothing
watches the clock and cuts a connection — the contract simply stops verifying. That
makes the control impossible to fail open: a control plane that is down cannot renew,
and not renewing is the safe direction.

---

## B3.5 · Human-oversight terms

> **Outcome** — high-consequence relationships carry a standing oversight obligation.
> **Owner** Operational Risk · **KPI** % of high-tier connections with an oversight term; hold-to-decision latency · **Stage** ③

| Technical capability | Failure mode |
|---|---|
| **T3.6** Terms enforcement | Condition false → **deny or hold** |

```mermaid
sequenceDiagram
    autonumber
    participant Agent as agent
    participant Med as mediator
    participant Core as Warden core policy
    actor Human as named overseer
    participant Svc as callee

    Agent->>+Med: tools/call initiate_payment, amount 250000
    Med->>Med: tool is in the contract surface
    Med->>+Core: evaluate terms — oversight_threshold, data class, jurisdiction
    Core->>Core: arg:amount exceeds the contract's oversight threshold
    Core-->>-Med: HOLD, not DENY

    Med->>+Human: held action, cid conn_1a9b, full argument set
    Note over Med,Human: T3.6 · the hold is the oversight.<br/>EU AI Act Article 14 asks for a human who<br/>can intervene — an alert after the fact<br/>is not intervention.

    alt approved within the hold window
        Human-->>Med: release
        Med->>+Svc: forward
        Svc-->>-Med: result
        Med-->>Agent: result
    else rejected or window elapses
        Human-->>-Med: reject
        Med-->>-Agent: denied, recorded against the cid
    end
```

**What the diagram argues.** The oversight term lives in the contract but is
evaluated by Warden core per call, against the actual argument values. That is the
division the whole system rests on: **warden-connect bounds the relationship, Warden
core decides the action** — and a hold is an action decision, so it belongs to core.

---

## B3.6 · Exit & offboarding

> **Outcome** — a demonstrable, rehearsed termination path per dependency.
> **Owner** Third-Party Risk · **KPI** time-to-terminate in a drill; % of dependencies with a tested exit · **Stage** ③

| Technical capability | Failure mode |
|---|---|
| **T6.1** Contract revocation | Revocation feed unreadable → strict mode denies all, fail-closed |
| **T3.7** Time-boxing | Expired → refused, no grace period |

```mermaid
sequenceDiagram
    autonumber
    actor TPR as Third-Party Risk
    participant Ct as contract
    participant Med1 as mediator A
    participant Med2 as mediator B
    participant Ev as evidence

    TPR->>+Ct: exit drill — terminate every dependency on partner:acme
    Ct->>Ct: resolve contracts held by the party, inbound and outbound
    Ct-->>TPR: 6 contracts across 2 mediators

    par propagate to every mediator
        Ct->>+Med1: revoke 4 cids
        Med1-->>-Ct: applied, confirmed
    and
        Ct->>+Med2: revoke 2 cids
        Med2-->>-Ct: applied, confirmed
    end

    alt a mediator does not confirm
        Ct->>Ct: mark unconfirmed, that mediator fails closed locally
        Note over Ct: T6.2 · parties not yet confirmed are<br/>treated as denied. A drill that reported<br/>success here would be measuring nothing.
    end

    Ct->>+Ev: append EXIT_DRILL with elapsed time and per-mediator outcome
    Ev-->>-Ct: chain head
    deactivate Ct
    Ct-->>TPR: terminated in 38s, 2 of 2 mediators confirmed
```

**What the diagram argues.** The exit path is the quarantine verb pointed at a
partner rather than an incident, which is why it can be *rehearsed*. DORA asks for a
tested exit strategy — a drill that produces a timed, signed record of every
dependency severed is that test, and it costs one command.

---

## What B3 does not do

It does not decide whether an individual call proceeds — that is Warden core, reading
the contract as an outer bound. And it does not detect that a surface has changed
under a live contract: the contract pins a hash, but noticing the hash has moved is
**B5.1**.
