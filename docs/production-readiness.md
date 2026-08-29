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

## Remaining

| # | Item | Effort |
|---|---|---|
| 0.4 | second scm race under contention; the gate is non-deterministic until fixed | M |
| 1.2 | audit every remaining `Terms` field for a claim that binds nothing (`delegation.max_depth` is known) | S |
| 1.2b | sweep for documented-but-absent mechanisms — six found in one session | S–M |
| 2.3 | `connect evidence verify\|since` — needs a `wc-cli → wc-mediator` edge | S |
| 2.4 | anchor the chain head on the ack, so the trail is tamper-*evident* and not merely tamper-detecting | M |
| 3.1c | no HTTP route for connection-level revocation; `connect revoke --cid` fails `WC-8003` against a serving plane | S |
| 3.1d | revocations are signed with the issuer key, so anyone who can mint can revoke | S |
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
