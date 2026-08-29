# Production readiness

What stands between `main` and a release. Every gap here was verified against the
code, not recalled.

## Closed

| | | |
|---|---|---|
| **P0** | the gate runs | CI green on a hosted runner, same gates as `ci-local.sh`. Nine runs, nine fixes — one product bug, seven of them the harness believing its own setup had worked |
| **P2.1/2.2** | evidence | both enforcement points write a hash-chained decision trail, asserted in both drills. `terms.evidence.delivery = "blocking"` binds for the first time |
| **3.1 (Envoy)** | revocation | quarantine → feed → fetch → verify → deny-list → refusal at a real Envoy. Three separate breaks, each invisible alone: the plane set its feed from nowhere, no mediator fetched one, and the serving plane never appended to the feed it published |
| **1.3** | ceilings | removed as a capability rather than fixed — see the CHANGELOG |
| **3.1b** | revocation reaches Kong | each worker refreshes on its own background thread — not a Lua timer, which would stall the event loop. Drilled: a revocation applied inside a real nginx worker |
| **1.4** | several contracts per pair | resolution picks by tool; the catalogue is the union and must satisfy every pin; two contracts claiming one tool is a conflict, reported at load and refused at the call |
| **0.4** | the gate is deterministic | not a second scm race: concurrent spawns inherited each other's pipes, so a shim that exited 0 having printed its verdict was recorded as never answering. Every spawn is gated; 4 hangs in 60 runs became 0 in 180 |
| **3.1c** | connection-level revocation | `POST /v1/connections/{cid}/revoke` — the narrow cut, symmetric with quarantine: register, evidence, and the deny-list. The API harness had no revocation feed at all, which is why the serving plane's failure to append to one survived a full suite |
| **3.1d** | revocation custody | the feed takes a key of its own. `revoke` and `quarantine` have had `--revocation-key` since custody existed; `serve` took no such flag, so the separation was present where an operator acts by hand and absent from the path an estate runs. Without one, `serve` now says so at startup |
| **1.2b** | documented-but-absent sweep | 11 of 82 error codes were never emitted, 6 named in the LLD and 3 traced from a use case. Each now carries a `RESERVED:` reason or is emitted, `scripts/code-emission.sh` fails the build on a new one, and the doc claims that were wrong are corrected |
| **2.3** | the trail is checkable | `connect evidence verify PATH` and `evidence since PATH --seq N`. The chain was tamper-evident to the drills and to nobody operating it. `since` verifies the whole trail before returning a row, so an edited file yields nothing |
| **1.2** | `Terms` audit | every field traced to what binds it — table below. One term was bound by nothing anywhere, and the check meant to announce that class of term was itself an instance of it |

## What binds each term

The `Terms` audit (1.2), traced against the code. "Policy fact" means a policy rule can read the
value and refuse at issuance; the gateway builds `Terms::default()` and reads no term at
enforcement, which is by design — a contract is decided at issuance and is a ceiling, not a
runtime budget.

| Term | Folded | Policy fact | Refuses a mint | Enforced at a call | |
|---|---|---|---|---|---|
| `data_classes` | yes | yes | yes, via `is_closed` | — | binds |
| `jurisdictions` | yes | yes | yes, via `is_closed` | — | binds |
| `delegation.max_depth` | yes | yes | — | — | binds at issuance only |
| `evidence.delivery` | yes | — | — | **yes** — a blocking sink refuses on `WC-7001` | binds |
| `evidence.sink` | yes | — | — | — | a pointer, not a mechanism, and documented as one |
| `max_calls_per_hour` | yes | yes | — | withdrawn | announced |
| `max_spend_usd_per_day` | yes | yes | — | withdrawn | announced |
| `max_concurrent` | yes | — | — | withdrawn | **was bound by nothing at all** |
| `human_oversight` | yes | — | — | — | **declared, never checked** |
| `delegation.attenuation` | written as a constant | — | — | — | **never compared against anything** |

Three findings, of which one is fixed:

* `max_concurrent` was the single term with no binding of any kind — and the announcement that
  exists to say so tested rate and spend while its message read "rate, concurrency or spend".
  The check written to break a silence was keeping one. Fixed, with a test that fails against
  the old predicate.
* That announcement also fired from `connect-mediate` only, so the same legacy artifact loaded
  into Kong or Envoy was enforced by neither and mentioned by neither. The message and its
  predicate now live together and all three bindings call them.
* `human_oversight` and `delegation.attenuation` remain declared and unchecked — carried below
  as 1.2c rather than fixed here, because each is a product decision (enforce it, or refuse to
  mint it) and not a defect to patch.

## Remaining

| # | Item | Effort |
|---|---|---|
| 1.2c | `human_oversight` and `delegation.attenuation` are declared and unchecked — enforce, or refuse to mint | S |
| 2.4 | anchor the chain head on the ack, so the trail is tamper-*evident* and not merely tamper-detecting | M |
| 3.2 | neither binding ships; `release.yml` has no reference to `wc-extproc` or `wc-kong` | M |
| 3.3 | install path per binding without a repo checkout | S |
| 3.4 | `connect gateway check --config`, so a bad config fails at deploy | S |
| 4.1 | **independent security review** — submitted for external review | L |
| 4.2 | mutation testing has never covered `wc-gateway` or `wc-kong` | M |
| 4.3 | cluster scale unverified | L |
| 4.4 | Path A (the stdio mediator) has never been walked end to end | S |

## Open decisions

| # | Decision |
|---|---|
| D1 | Path A — keep, demote to developer feedback, or cut. Identity is self-asserted from `argv`, so it is not an assurance boundary for the callee's owner |
| D3 | External flows — permanently out of scope, or revisit |

## What this is not

Four enforcement paths exist and three are drilled against real proxies. The gap is
not coverage. Two things repeat across everything above and are worth reading as one
finding: **a component can be complete, tested and documented while nothing calls it**,
and **a harness is far more credulous about its own preconditions than about the
system it tests**. Six of the nine P0 fixes and all three revocation breaks were one
or the other.
