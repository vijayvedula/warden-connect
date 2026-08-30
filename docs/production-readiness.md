# Production readiness

Every item was verified against the code. **v0.2.0 is released**; what remains
is the backlog for the next one. Two caveats: 4.3 (cluster scale) is unverified
rather than known-good, and 1.2c is two terms that ship declared and unchecked.

## Closed

| # | Item | Result |
|---|---|---|
| P0 | the gate runs | CI green on a hosted runner, same gates as `ci-local.sh` |
| 0.4 | the gate is deterministic | concurrent spawns inherited each other's pipes. All spawns now serialise: 4 hangs in 60 runs became 0 in 180 |
| 1.2 | `Terms` audit | every field traced to what binds it — table below |
| 1.2b | documented-but-absent sweep | 11 of 82 error codes were never emitted. Each is now emitted or marked `RESERVED:`, enforced by `scripts/code-emission.sh` |
| 1.3 | ceilings | removed as a capability rather than fixed. See the CHANGELOG |
| 1.4 | several contracts per pair | resolution picks by tool; the catalogue is the union and must satisfy every pin; two contracts claiming one tool is a conflict |
| 2.3 | the trail is checkable | `connect evidence verify` and `evidence since`. `since` verifies the whole trail before returning a row |
| 3.1 | revocation (Envoy) | quarantine → feed → fetch → verify → deny-list → refusal, at a real Envoy |
| 3.1b | revocation (Kong) | each worker refreshes on its own background thread, not a Lua timer. Drilled inside a real nginx worker |
| 3.1c | connection-level revocation | `POST /v1/connections/{cid}/revoke`: register, evidence and deny-list |
| 3.1d | revocation custody | the feed takes its own key. `serve` warns at startup when it has none |
| 3.2 | both bindings ship | `wc-extproc`, `libwc_kong.so` and the Lua half are built, digested and attested |
| 3.3 | install without a checkout | [install.md](install.md). Every flag checked against `--help` and `schema.lua` |
| 3.4 | a config fails at deploy | `connect gateway check --plugin-config FILE` runs the binding's own `Handle::open` |
| 4.1 | independent security review | conducted outside this repository |
| 4.2 | the gates are covered | `scripts/gate-mutation-check.sh` breaks five gates and requires a test to notice. All five caught; in CI |
| 4.4 | Path A is walked | `attest-drill.sh` phase 4 executes a contracted call and refuses an uncontracted one, in enforce mode, over stdio |
| — | **v0.2.0 released** | five artifacts, each SLSA-attested and verified after publication |

## What binds each term

The gateway builds `Terms::default()` and reads no term at enforcement. A
contract is decided at issuance and is a ceiling, not a runtime budget.
"Policy fact" means a policy rule can read the value and refuse at issuance.

| Term | Folded | Policy fact | Refuses a mint | Enforced at a call | Verdict |
|---|---|---|---|---|---|
| `data_classes` | yes | yes | yes, via `is_closed` | — | binds |
| `jurisdictions` | yes | yes | yes, via `is_closed` | — | binds |
| `delegation.max_depth` | yes | yes | — | — | binds at issuance only |
| `evidence.delivery` | yes | — | — | yes — `WC-7001` on a blocking sink | binds |
| `evidence.sink` | yes | — | — | — | a pointer to a shipper, not a mechanism |
| `max_calls_per_hour` | yes | yes | — | withdrawn | announced at load |
| `max_spend_usd_per_day` | yes | yes | — | withdrawn | announced at load |
| `max_concurrent` | yes | — | — | withdrawn | announced at load (was bound by nothing) |
| `human_oversight` | yes | — | — | — | declared, never checked |
| `delegation.attenuation` | written as a constant | — | — | — | never compared |

Two of these were fixed during the audit. `max_concurrent` had no binding of
any kind, and the announcement meant to report that class of term tested rate
and spend only while its message said "rate, concurrency or spend". That
announcement also fired from `connect-mediate` alone, so the same artifact
loaded into Kong or Envoy was neither enforced nor mentioned. Both are fixed.

## Remaining

| # | Item | Effort |
|---|---|---|
| 1.2c | `human_oversight` and `delegation.attenuation` are declared and unchecked. Enforce, or refuse to mint | S |
| 2.4 | anchor the chain head on the ack, so the trail is tamper-evident and not only tamper-detecting | M |
| 4.2b | `wc-kong`'s own layer — FFI boundary, config parsing, per-worker trail — is not mutation-checked | S |
| 4.3 | cluster scale unverified | L |
| 4.4b | `connect-mediate` has no `--evidence`, so `terms.evidence.delivery` cannot bind there. Announced at startup; pending D1 | S |

## Open decisions

| # | Decision |
|---|---|
| D1 | Path A — keep, demote to developer feedback, or cut. Identity is self-asserted from `argv`, so it is not an assurance boundary for the callee's owner |
| D3 | External flows — permanently out of scope, or revisit |

## Coverage

Four enforcement paths exist. All four are drilled; two of those drills run
against a real proxy.

| Path | Binding | Drill | Real proxy |
|---|---|---|---|
| stdio mediator | `connect-mediate --upstream` | `attest-drill.sh` | no |
| HTTP mediator | `connect-mediate --upstream-url` | `http-mode-drill.sh` | no |
| Envoy | `wc-extproc` | `envoy-drill.sh` | yes |
| Kong | `libwc_kong.so` | `kong-drill.sh` | yes |

## Two recurring defects

Both appear repeatedly in the items above and are worth naming.

| Pattern | Where it appeared |
|---|---|
| A component is complete, tested and documented while nothing calls it | all three revocation breaks; the withdrawn-ceiling announcement; 11 unemitted error codes |
| A harness is more credulous about its own setup than about the system it tests | six of the nine P0 fixes; the Kong drill reporting a file it loaded as a contract it had pulled |
