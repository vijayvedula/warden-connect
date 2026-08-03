# 4 · warden-connect — Technical Capability Matrix

> Format follows Warden's [standards.md](../../warden/docs/standards.md): each
> capability maps to a **mechanism**, the **standard** it rides on, the
> **interface** that exposes it, the **enforcement point**, its **failure mode**,
> and a build **status**.
>
> Status: `[x]` designed & specified · `[~]` partial / depends on a Warden core
> primitive that already exists · `[ ]` roadmap.
> Enforcement point: **CP** = control plane · **DP** = data plane (inline) ·
> **CP/DP** = decided in CP, enforced in DP.

---

## T1 · Identity & attestation

| Capability | Mechanism | Standards | Interface | Point | Failure mode | Status |
|---|---|---|---|---|---|---|
| T1.1 Workload identity verification | Verify caller/callee SVID or workload credential before any introduction | **SPIFFE/SPIRE** (X.509-SVID, JWT-SVID), cloud workload identity | `--trust-bundle`, `connect register --identity` | CP/DP | No verifiable identity → **not registrable, not connectable** | `[~]` reuses `identity.rs` JWT path |
| T1.2 Mutual channel authentication | mTLS on the connection path; peer identity bound to the contract's `caller`/`callee` | **mTLS**, **RFC 8705** (mTLS-bound tokens) | `connect mediate --mtls` | DP | Peer mismatch → connection refused before first frame | `[ ]` |
| T1.3 Sender-constrained tokens | Session tokens bound to a holder key, so a stolen token is unusable off-channel | **RFC 9449 DPoP**, **RFC 7800**, RFC 7638 thumbprint | `DPoP` header | DP | Missing/invalid proof → 401, no forward | `[x]` shipped in Warden `dpop.rs` |
| T1.4 Build provenance verification | Verify signed provenance for the artifact behind an agent or tool server | **SLSA**, **in-toto**, **Sigstore** bundle / Rekor inclusion | `connect register --attest bundle.sigstore` | CP | Unverifiable provenance → admission denied (or `posture: unattested` in observe mode) | `[ ]` |
| T1.5 Agent-card signature verification | The A2A agent card must be signed by the claimed operator | **A2A agent card**, JWS, **OpenID Federation** entity statements (cross-org) | `connect register agent --card` | CP | Unsigned/mis-signed card → not admitted | `[ ]` |
| T1.6 Identity lifecycle sync | Joiner/mover/leaver for agent identities and their human owners | **SCIM 2.0**, IdP events | control-plane webhook | CP | Owner leaves → connections flagged, then expired | `[ ]` |

## T2 · Registry & discovery

| Capability | Mechanism | Standards | Interface | Point | Failure mode | Status |
|---|---|---|---|---|---|---|
| T2.1 Agent & server registry | Content-addressed records: identity, owner, tier, zone, card/manifest hash, lifecycle state | JSON Schema; **CycloneDX** for the surface BOM | `connect register …`, `GET /v1/entities` | CP | Registry unavailable → strict mode denies new connections; existing contracts remain valid until `exp` | `[ ]` |
| T2.2 Surface pinning | Store `sha256` of the tool manifest / agent card at admission; compare on every connect | content addressing | automatic; `connect show <id>` | CP/DP | Presented hash ≠ pinned hash → connection refused, drift event raised | `[ ]` |
| T2.3 Mediated discovery / capability query | Broker answers a capability question with only the entries the asker may connect to | MCP `tools/list` semantics; A2A skill discovery | `connect discover --capability` | CP | Unknown asker → empty result set (never an error that confirms existence) | `[ ]` |
| T2.4 Anti-enumeration | No global list endpoint for agent principals; results are policy-filtered and rate-limited | — | — | CP | Enumeration attempt → throttled + logged as reconnaissance | `[ ]` |
| T2.5 Shadow-endpoint detection | Correlate observed connection attempts against the registry; unknown endpoints become findings | OCSF finding events | `connect posture --shadow` | DP → CP | Observe mode: log only. Enforce mode: refuse | `[ ]` |
| T2.6 Surface BOM | Machine-readable bill of materials of everything a party exposes and depends on | **CycloneDX 1.6** (ML-BOM/SBOM) | `connect export --bom` | CP | — | `[ ]` |

## T3 · Connection contract

| Capability | Mechanism | Standards | Interface | Point | Failure mode | Status |
|---|---|---|---|---|---|---|
| T3.1 Contract minting | Sign a `warden-connection+jws` binding caller, callee, surface, terms, assurance, approval, TTL | **JWS/JOSE**, ES256/EdDSA (asymmetric-only) | `connect request` → `connect approve` | CP | Any policy miss → no contract issued | `[ ]` |
| T3.2 Contract verification | Verify signature, issuer chain, `exp`/`nbf`, wire identities, pinned hashes, revocation, posture | JOSE; JWKS | `connect verify <contract>` (the conformance ground truth) | DP | Any failure → connection refused, fail-closed | `[ ]` |
| T3.3 Surface allowlist enforcement | Only contracted tools/skills/resources may be attempted | MCP, A2A | automatic | DP | Uncontracted call → blocked before upstream | `[~]` extends Warden `policy.rs` |
| T3.4 **`tools/list` surface filtering** | The catalogue returned to the agent is reduced to the contracted surface, so uncontracted tools never enter model context | MCP `tools/list` | automatic | DP | Filter failure → return empty list (fail-closed) | `[~]` extends Warden `mcp.rs` |
| T3.5 Narrowing algebra | `effective = contract.surface ∩ token.scope ∩ policy` — a contract can never widen | Warden narrowing rule | automatic | DP | Attempted widening is structurally impossible, not merely denied | `[x]` principle already in core |
| T3.6 Terms enforcement | Data class, jurisdiction, oversight threshold, delegation depth as evaluable conditions | Warden `when` conditions (`arg:`/`subject:`/`env:`/`resource:`) | contract `terms` | DP | Condition false → deny or hold | `[~]` extends `policy.rs` |
| T3.7 Time-boxing & renewal | Contracts expire; renewal re-runs admission checks | JOSE `exp` | `connect renew <cid>` | CP/DP | Expired → refused; no grace period by default | `[ ]` |
| T3.8 Standing-policy auto-approval | Low-risk, same-zone, read-only connections issued without a human in the loop | policy-as-code | `connect-policy.toml` | CP | Ambiguity → escalate to human, never auto-allow | `[ ]` |

## T4 · Channel mediation (data plane)

| Capability | Mechanism | Standards | Interface | Point | Failure mode | Status |
|---|---|---|---|---|---|---|
| T4.1 Inline mediator | Terminates the agent-side channel, verifies the contract, re-establishes to the callee | **MCP** stdio + Streamable-HTTP; **A2A** transport | `connect mediate`, composing an unmodified `warden` gateway | DP | Mediator down → no connection (fail-closed) | `[~]` `Upstream` decorator, no core change |
| T4.2 Zone-crossing enforcement | Internal / partner / public zone pairs, each with an assurance bar | policy-as-code | `connect-policy.toml` zones | DP | Unclassified pair → treated as most-restrictive | `[ ]` |
| T4.3 Fan-out & recursion limits | Cap concurrent downstream connections and delegation depth per contract | contract `terms`, `delegation.max_depth` | contract | DP | Limit hit → deny + alert (protects against call storms) | `[ ]` |
| T4.4 Rate & spend ceilings | Per-connection call-rate and cost ceilings, durable across restarts | Warden budget model | contract `terms` | DP | Ceiling breach → deny, owner notified | `[~]` extends `budget.rs` |
| T4.5 Egress control | External connections constrained by declared data class and jurisdiction | contract `terms` | contract | DP | Undeclared class/jurisdiction → deny | `[ ]` |
| T4.6 Protocol conformance & schema validation | Reject malformed or oversized JSON-RPC / A2A frames at the boundary | **JSON-RPC 2.0**, JSON Schema | automatic | DP | Malformed → dropped, logged | `[~]` `jsonrpc.rs` |
| T4.7 Latency budget | Contract verification is a signature check plus set membership — no network call on the hot path | — | — | DP | Cache miss → single control-plane fetch with timeout, then fail-closed | `[ ]` target **p99 < 5 ms** added |

## T5 · Continuous assurance & posture

| Capability | Mechanism | Standards | Interface | Point | Failure mode | Status |
|---|---|---|---|---|---|---|
| T5.1 Drift detection | Re-fetch and hash cards/manifests on a schedule and at every connect; diff against the pin | content addressing | `connect posture` | CP/DP | Drift → connection suspended pending re-approval | `[ ]` |
| T5.2 Declared-surface injection screening | Static analysis of tool descriptions, parameter docs and skill text for instruction-injection patterns | — (heuristics + allowlisted schema) | admission + re-attestation | CP | Finding → admission blocked or tier escalated | `[ ]` |
| T5.3 Scheduled re-attestation | Re-verify identity, provenance and surface on `assurance.reattest_every` | SLSA/Sigstore, SPIFFE | scheduler | CP | Overdue → posture `degraded` → contract not renewed | `[ ]` |
| T5.4 Posture scoring | Rolls identity, provenance, drift, age and tier into a single per-party state | — | `connect posture`, `/metrics` | CP | — | `[ ]` |
| T5.5 Credential-expiry watch | Track certificate/key/token expiry across the estate | — | `connect posture --expiring` | CP | Expiring credential → pre-emptive alert; expired → refuse | `[ ]` |
| T5.6 Blast-radius analysis | Compute the transitive reachable set for any party from the contract graph | graph query | `connect blast-radius <id>` | CP | — | `[ ]` |

## T6 · Containment & revocation

| Capability | Mechanism | Standards | Interface | Point | Failure mode | Status |
|---|---|---|---|---|---|---|
| T6.1 Contract revocation | Revoke by `cid`, by party, or by tier; propagated to every mediator | Warden signed revocation events | `connect revoke --cid/--party` | CP → DP | Revocation feed unreadable → strict mode denies all (fail-closed) | `[~]` extends `revocation.rs` |
| T6.2 Estate-wide quarantine | One verb severs every connection a party holds, inbound and outbound | — | `connect quarantine <party>` | CP → DP | Partial propagation → parties not yet confirmed are treated as denied | `[ ]` target **< 60 s estate-wide** |
| T6.3 Shared-signal ingestion | IdP/risk events automatically cut connectivity | **CAEP / SSF**, **RFC 8417 SET**, RFC 8935 push | `--revocations` feed | CP | Unsigned/unverifiable event → ignored + alerted (never trusted) | `[x]` shipped in core |
| T6.4 Shared-signal emission | Publish connection-lifecycle and quarantine events to the wider ecosystem | CAEP transmitter, signed SET | `[[sink]] format="caep"` | CP | — | `[x]` shipped in core |
| T6.5 Drain semantics | In-flight calls drained or aborted on revocation, per deployment policy | — | `--on-revoke=drain\|abort` | DP | Ambiguous config → abort (safe default) | `[~]` core pause/drain model |
| T6.6 Break-glass | Time-boxed, dual-controlled emergency connection, maximally logged | — | `connect breakglass --ttl` | CP | Expiry is unconditional; no renewal of a break-glass contract | `[ ]` |

## T7 · Evidence & interoperability

| Capability | Mechanism | Standards | Interface | Point | Failure mode | Status |
|---|---|---|---|---|---|---|
| T7.1 Connection-lifecycle audit | Register / admit / approve / mint / drift / revoke appended to the tamper-evident chain | SHA-256 hash chain + ES256 signed anchors | `connect audit verify` | CP | Chain break detected on verify → alert | `[x]` reuses `audit.rs` + `anchor.rs` |
| T7.2 SIEM export | Every lifecycle event as an OCSF activity/finding | **OCSF** | `[[sink]] format="ocsf"` | CP | Blocking sink unavailable → connection not issued | `[x]` reuses `sink.rs` |
| T7.3 Telemetry & tracing | `cid` propagated as a trace attribute; counters per decision | **OpenTelemetry** | `--log-format json`, `/metrics` | CP/DP | — | `[~]` `obs.rs` |
| T7.4 Regulatory register export | Generate the interconnect register in DORA / CPS 230 / OSCAL shapes | **OSCAL**, CSV/JSON | `connect export --format dora\|cps230\|oscal` | CP | — | `[ ]` |
| T7.5 External PDP interop | Delegate the connection decision to an external policy engine | **AuthZEN** (`POST /access/v1/evaluation`), OPA/Cedar/OpenFGA behind it | `--pdp-url` | CP | PDP unreachable → deny (fail-closed) | `[~]` `authzen.rs` is the bridge |
| T7.6 Cross-org federation | Federate registries so partners resolve each other's agents without exposing catalogues | **OpenID Federation** trust chains; **SD-JWT / VC** for selective disclosure | `connect federate` | CP | Untrusted federation entity → no resolution | `[ ]` |
| T7.7 Correlation root for `warden-trace` | `cid` stamped on every action, evidence and delegation downstream | — | automatic | DP | Missing `cid` → action recorded as uncorrelated and flagged | `[ ]` |

## T8 · Platform & operations

| Capability | Mechanism | Standards | Interface | Point | Failure mode | Status |
|---|---|---|---|---|---|---|
| T8.1 Control-plane API | REST + CLI over the registry, contracts, posture and exports | OpenAPI 3.1 | `/v1/*`, `connect` CLI | CP | — | `[ ]` |
| T8.2 Policy-as-code | Connection policy versioned, linted, dry-runnable, hot-reloadable | TOML (Warden style) + OPA/Cedar via AuthZEN | `connect-policy.toml`, `connect policy lint\|dry-run` | CP | Invalid policy → keep last-known-good, alert | `[~]` mirrors `policy.rs` |
| T8.3 Twelve-factor config | All configuration via `WARDEN_CONNECT_*` env | — | `.env` | CP/DP | — | `[~]` core convention |
| T8.4 Multi-tenancy | Tenant-scoped registries, policies, keys and audit chains | — | `--tenant` | CP | Cross-tenant resolution is structurally impossible | `[ ]` |
| T8.5 High availability | Stateless verification in DP; replicated CP with a signed, cacheable contract set | — | — | CP | CP outage: existing contracts keep working to `exp`; new issuance stops | `[ ]` |
| T8.6 Offline / air-gapped mode | Contracts pre-issued and shipped as signed bundles; no CP call at connect time | — | `--contract-bundle` | DP | Bundle expiry is hard | `[ ]` |

---

## 4.9 Threat coverage map

Indicative mapping to the OWASP Agentic AI threat set (T1–T15). "Owner" is which
family member is the *primary* control.

| Threat | Connection-layer manifestation | Primary control | Owner |
|---|---|---|---|
| **T9 Identity spoofing & impersonation** | Agent connects to (or is connected to by) a party impersonating a legitimate one | T1.1, T1.2, T1.5, T3.2 | **connect** |
| **T13 Rogue agents** | An unregistered or compromised agent inserts itself into a multi-agent topology | T2.1, T2.5, T3.1, T6.2 | **connect** |
| **T12 Agent communication poisoning** | Poisoned tool descriptions, cards and skill text injected via the declared surface | T2.2, T5.1, T5.2 | **connect** |
| **T2 Tool misuse** | Agent is introduced to tools it never needed; the surface itself is the exposure | T3.3, T3.4 (surface filtering) | connect + **core** |
| **T3 Privilege compromise** | Over-broad reachability becomes lateral movement | T2.3, T4.2, T5.6 | connect + **delegate** |
| **T4 Resource overload** | Recursive agent fan-out, call storms, denial-of-wallet | T4.3, T4.4 | **connect** |
| **T8 Repudiation & untraceability** | Multi-agent action cannot be reconstructed across hops | T7.1, T7.7 (`cid` root) | connect + **trace** |
| **T6 Intent breaking / goal manipulation** | Injected instructions arriving through a counterparty's response | T5.2 screening; runtime is **trace** taint | trace |
| **T1 Memory poisoning** | Poisoned content arriving from an untrusted connected party | T4.2 zone rules limit exposure | trace |
| **T10 Overwhelming HITL** | Approval fatigue from per-call prompts | T3.8 standing policy — approve the *relationship*, not every call | **connect** |
| **T11 Unexpected code execution** | Malicious tool server executing on the agent host | T1.4 provenance, T2.2 pinning | connect |
| **T5 Cascading hallucination** | Error propagation across an unbounded agent graph | T4.3 depth/fan-out limits | connect |
| **T7 Misaligned/deceptive behaviour**, **T14/T15 human-directed attacks** | Largely runtime/behavioural | out of scope; `trace` + core holds | trace / core |

Supply-chain threats (tool poisoning, rug-pull, cross-server shadowing) are not
in the T1–T15 list as separate entries but are the dominant real-world case and
are covered by **T1.4 + T2.2 + T5.1 + T5.2** — the four controls that only exist
at the connection layer.

---

## 4.10 Build leverage from Warden core

warden-connect is built to be **adopted on its own**. A team may run Warden core
plus `warden-trace` and substitute something else for the connection layer, or take
`warden-connect` alone for the register and the kill switch. So the family couples
through **two signed artifacts and one identifier** — the session token, the
connection contract, and `cid` — and not through a shared library.

Concretely: only the inline mediator links Warden core, because it compiles *into*
the shipped proxy so the data plane adds no second hop. Everything else stands
alone. In particular the contract verifier must: `connect verify` is the
conformance ground truth for a candidate standard, and a reference verifier that
requires the vendor's product is not a reference verifier.

The leverage is therefore in **design**, not in linked code — which is the more
durable kind, and the harder kind to acquire:

| Proven in Warden core, reimplemented here to the same design | Genuinely new |
|---|---|
| Tamper-evident hash chain + externally verifiable signed anchors | Registry & content-addressed per-item pinning (`wcs1`) |
| Signed revocation feed, tailed and applied as a deny-only set | Admission pipeline (provenance, card signature, surface screening) |
| OCSF/CAEP sinks with blocking vs fail-safe delivery semantics | Contract mint / verify / renew (`warden-connection+jws`) |
| Asymmetric-only JWS verification, JWKS by `kid`, DPoP binding | Discovery broker with mediated visibility |
| Policy engine shape: first-match rules, `when` condition trees, lint and dry-run | Zone model & zone-crossing assurance bars |
| Fail-closed dispatch with a named reason for every denial | Assurance: drift classification, re-attestation, posture scoring |
| Durable counters surviving restart; hot reload; twelve-factor config | Regulatory register export; cross-org federation |

Two things make that reimplementation cheap rather than wasteful. The patterns are
already validated in production code, so the design risk is gone. And wire
compatibility — chain format, revocation events, OCSF shapes — is held by **shared
golden vectors** rather than shared code, so it is *checked* on every build instead
of assumed. Where a primitive is genuinely trivial and must stay byte-identical
(canonical JSON, SHA-256 hex), it is vendored with vectors pinning its output; when
a third family member needs it, it gets extracted into a neutral crate.

The mediator is the deliberate exception, and it is an extension of a shipped
product rather than a new one — which is still the reason this is the right next
component to build.
