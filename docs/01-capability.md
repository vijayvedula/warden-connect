# 1 · warden-connect — Capability Definition

> Status: design. Defines the capability, its principles, its interface artifact,
> and its explicit non-goals.

## 1.1 One-liner

**warden-connect is the connection control plane for AI agents** — a mediated
registry and admission gateway that decides **which agents and tool servers may
connect to each other, over what surface, on what terms, and for how long** —
and that severs any connection the moment trust changes.

## 1.2 The gap it closes

Warden core is an excellent answer to *"may this call happen?"* It assumes the
call has arrived — that the agent is already wired to an upstream MCP server, and
that the server is the one it claims to be. Everything before that first
`tools/call` is currently out of scope:

| Question asked before any action | Owned by Warden core today? |
|---|---|
| Which agents and tool servers do we actually run? | ✗ no inventory |
| Is this counterparty who it claims to be? | ~ partially (token `aud`/wire identity, one hop) |
| Was this agent/server built from attested, provenanced artifacts? | ✗ |
| Has the tool surface changed since it was approved? | ✗ (tool descriptions are trusted at read time) |
| May agent A talk to agent B *at all*? | ✗ (topology is a deployment accident) |
| What may agent A even *see* in the catalog? | ✗ (discovery is unmediated) |
| Is this an internal, partner, or public counterparty — and does that change the bar? | ✗ (no trust zones) |
| Can we cut every connection to a rogue agent in seconds? | ~ per-process pause only |
| Can we hand a regulator the register of agent interconnects? | ✗ |

Every row above is a **connection-layer** question. No amount of per-call policy
answers them, because by the time policy runs the relationship already exists and
the untrusted surface has already been read into the model's context.

## 1.3 What warden-connect is — six pillars

### P1 · Registry — the authoritative agent & tool estate
A content-addressed catalogue of every agent and every MCP/A2A endpoint in the
estate: identity, owner, business service, risk tier, data classification,
jurisdiction, lifecycle state, and the **pinned hash** of its A2A **agent card**
or MCP **tool manifest**. This is the inventory that does not exist today — and,
not incidentally, the artifact three regulators now ask for by name.

### P2 · Admission — nothing joins the estate unattested
Registration is not self-service assertion; it is an **admission decision**. A
party is admitted only if it presents:
- a verifiable workload identity (SPIFFE SVID / cloud workload identity / mTLS cert),
- a signed, schema-valid agent card or tool manifest,
- build provenance for the artifact behind it (SLSA / in-toto / Sigstore bundle),
- a named human owner and an approved risk tier.

Admission also **statically inspects the declared surface** — tool names,
descriptions, parameter docs, skill definitions — for the instruction-injection
patterns that make tool poisoning work. A description is untrusted input that the
model will read as instructions; it is screened *before* it can ever be read.

### P3 · Mediated discovery — you see only what you may connect to
Agents do not enumerate a global catalogue. They ask the broker a **capability
question** ("who can settle a payment in SG?") and receive only entries their
policy already permits them to connect to. Enumeration is not a feature; it is
reconnaissance. This is the pillar that denies the attacker's first move.

### P4 · Connection contracts — the terms, signed and time-boxed
A connection is not a network fact; it is an **agreement**. `connect` mints a
signed **connection contract** binding caller ↔ callee to an exact surface
(tool/skill/resource allowlist) plus terms: data classes, jurisdictions, rate and
spend ceilings, human-oversight thresholds, maximum delegation depth, evidence
obligations, and an expiry. It carries the approving human and the change ticket.
This is the interface artifact — see §1.4.

### P5 · Channel mediation — the data-plane enforcement point
On the wire, `connect` terminates and re-establishes the channel: mutual
authentication (SPIFFE/mTLS, sender-constrained tokens), contract verification,
**surface filtering** — the `tools/list` response an agent receives is reduced to
the contracted surface, so uncontracted tools never enter the model's context at
all — and fan-out, rate and spend ceilings. Zone crossings (internal → partner →
public) are explicit, and each has its own assurance bar.

### P6 · Continuous posture & containment
Trust is not established once. `connect` re-attests on a schedule, watches for
**drift** (card changed, manifest hash moved, provenance expired, certificate
rotated, owner left), and treats drift as a **new connection decision, not a
silent update**. It consumes and emits Shared-Signals/CAEP events so
`quarantine agent:rogue-9` cuts every connection that agent holds — in seconds,
across the estate — and records the cut as evidence.

## 1.4 The interface: the connection contract

Warden core's genius is that its only coupling point is one signed token.
warden-connect follows the same stance with one signed contract.

```jsonc
{
  "typ": "warden-connection+jws",
  "cid": "conn_7f3a91c4",                  // connection id — also the trace correlation root
  "iss": "https://connect.internal",
  "iat": 1785312000, "nbf": 1785312000, "exp": 1785398400,   // trust is time-boxed

  "caller": {
    "id":   "spiffe://org/ns/agents/sa/recon-bot-7",
    "card": "sha256:9c1f…",                // pinned A2A agent card
    "zone": "internal.apac-ops"
  },
  "callee": {
    "id":       "spiffe://org/ns/tools/sa/payments-mcp",
    "manifest": "sha256:41ab…",            // pinned MCP tool manifest
    "zone":     "internal.payments"
  },

  "surface": {                              // what may even be ATTEMPTED
    "tools":     ["get_balance", "list_transactions"],
    "skills":    [],                        // A2A skills when the callee is an agent
    "resources": ["ledger://apac/*"]
  },

  "terms": {
    "data_classes":   ["internal"],
    "jurisdictions":  ["SG", "AU"],
    "max_calls_per_hour": 500,
    "max_spend_usd_per_day": 200,
    "human_oversight": "required_above:10000_usd",
    "delegation": { "max_depth": 2, "attenuation": "monotonic" },   // → warden-delegate
    "evidence":   { "sink": "ocsf://siem", "delivery": "blocking" } // → warden-trace
  },

  "assurance": {
    "attestation":    ["slsa-provenance:sha256:…", "sigstore-bundle:…"],
    "reattest_every": "24h",
    "posture":        "attested"
  },

  "approval":       { "by": "human:cecil@org", "jti": "apr_5d2e…", "ticket": "RISK-4471" },
  "policy_version": "connect-policy@v37"
}
```

**Verification is fail-closed on any miss:** signature and issuer trust chain;
`exp`/`nbf`; caller and callee wire identities equal to the claimed identities;
presented card/manifest hash equal to the pinned hash; posture ≠ `quarantined`;
contract not revoked.

**The narrowing algebra.** A contract can only ever reduce authority:

```
effective_authority = contract.surface  ∩  token.scope  ∩  policy_decision
```

A connection contract can never permit a call Warden core would otherwise deny.
This is the connection-layer restatement of Warden's existing rule that
locally-derived inputs may only narrow, never widen.

## 1.5 Core principles

1. **Reachability is a grant, not a default.** The topology is deny-by-default.
   Unregistered means undiscoverable; undiscoverable means unreachable.
2. **A connection may only narrow.** See the algebra above. `connect` is
   additive to control, never to permission.
3. **Identity before introduction.** No unattested party is discoverable, and no
   unverified party is connectable — one hop or ten.
4. **The surface is pinned, not described.** Cards and manifests are
   content-addressed. A changed description is a *changed counterparty*.
5. **Trust is time-boxed.** Contracts expire by construction; renewal is
   re-attestation, not a rubber stamp. There is no permanent connection.
6. **Disconnection is a first-class operation.** Quarantine is a verb, it is
   estate-wide, it takes seconds, and it fails closed.
7. **Discovery is mediated.** No enumeration. An agent's view of the estate is
   exactly its permitted connection set — nothing is leaked to reconnaissance.
8. **Fail closed, everywhere.** Unknown counterparty, unverifiable attestation,
   expired contract, or (in strict mode) an unreachable control plane → no
   connection. Degraded modes are explicit and documented, never implicit.

## 1.6 What warden-connect is *not*

| Not this | Because |
|---|---|
| A network firewall or service mesh | It operates on **agent semantics** (cards, skills, tools, manifests), not IP/port/SNI. It *composes with* mesh mTLS and SPIFFE rather than replacing them — the mesh proves workload identity; `connect` decides whether that workload may be introduced to another. |
| A replacement for Warden core policy | `connect` gates the relationship; Warden gates each action inside it. Neither substitutes for the other, and `connect` never widens a Warden decision. |
| A prompt/content filter or guardrail model | It screens *declared surfaces* (tool descriptions, cards) at admission. Runtime content inspection is a different control and a different product. |
| An agent runtime or orchestrator | It has no opinion on how agents are built or scheduled. |
| A data-loss-prevention engine | It enforces declared data-class terms on a connection; it does not classify payloads. |
| A general API gateway | Its unit of governance is the *agent relationship and its exposed capability surface*, with a human owner, an expiry, and an evidence obligation attached. |

## 1.7 How it composes with the family

```
                        warden-connect  (control plane)
                     registry · admission · broker · contract · sentinel
                                        │
                       signed connection contract (cid, surface, terms)
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        ▼                               ▼                               ▼
  Warden core                    warden-delegate                 warden-trace
  enforces each action           attenuates authority            correlates evidence
  INSIDE contract.surface        WITHIN terms.delegation         BY contract.cid
```

- **→ Warden core** receives `surface` as an outer bound and `terms` as extra
  conditions; it intersects them with the session token's `scope`.
- **→ warden-delegate** receives `terms.delegation` (`max_depth`,
  `attenuation: monotonic`) as the envelope inside which authority may be passed
  on — and never expanded.
- **→ warden-trace** receives `cid` as the **correlation root**, which is what
  makes a multi-agent transaction reconstructable as one lineage instead of N
  disconnected audit files.

## 1.8 Enforcement points

| Point | Runs where | Enforces |
|---|---|---|
| **Admission gate** | Control plane, at registration/renewal | Attestation, card/manifest validity, surface screening, ownership, risk tier |
| **Discovery broker** | Control plane, per query | Mediated visibility; no enumeration |
| **Contract minting** | Control plane, per request | Policy, approvals, terms, TTL |
| **Channel mediator** | **Data plane**, in the connection path (co-located with the Warden proxy) | mTLS/SPIFFE, contract verification, surface filtering of `tools/list`, fan-out & rate ceilings, zone rules |
| **Sentinel** | Control plane, continuous | Re-attestation, drift, expiry, CAEP-driven quarantine |

The data-plane component is deliberately thin and sits exactly where Warden's
proxy already sits — which is why this is an extension of a shipped product
rather than a new one.
