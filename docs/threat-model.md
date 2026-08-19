# Threat model

§7.8 of [07-hld.md](07-hld.md) is the design's threat table: eleven threats, their controls,
and the residual each leaves. This document is the operator's and reviewer's side of it —
what to check, in what order, and **the failure mode this codebase actually produces**.

Written for production-readiness P2 #18, which said the threat model is *"the one with
teeth — the defects found in the last test pass were all silent control failures, and a
written threat model is what turns that pattern into a checklist instead of a habit."*

---

## Part 1 · The bug class this system produces

Every list below is secondary to this one.

Across the whole build, **the defects that mattered were almost never a missing control.
They were a control that read as configured and did nothing.** Not one was found by reading
the code, and several survived a test suite that asserted the configuration rather than the
effect.

Two adversarial passes and two drills have now been run against the paths in
[production-readiness.md](production-readiness.md), by executing the binaries, and together
they found **thirteen more of exactly this shape** — rows 12 to 24. Several had
passing unit tests sitting beside them: `SurfaceMatch::matches` was covered only for
`write = false`; the chain had tests for edited, deleted and reordered rows but none for a
**truncated** one; and `drain` had nine tests and no caller. A one-sided test is how a
one-sided control survives review, and a well-tested module is not a reachable one.

The last four are the most instructive, because in each case the control **was** reachable and
**was** correct — and the thing that needed it called something else. `Cache::resolve` applies
revocation properly and has many callers; the mediator's per-call path was simply not one of
them, so quarantine reached the cache and never the session. Three alert rules were loaded and
syntax-checked by a CI step that passes them to `promtool`, which never asks which rules it was
*not* given. Coverage of a control is not the same as coverage **by** the thing that depends on
it, and neither is visible from the control's own file.

The second pass was built around three questions, each of which found something:

1. **What can this control not see?** One injection string in six callee-controlled
   positions. Five scored a block; the property *name* scored zero, because the field walk
   used object keys to build a path and never as content.
2. **Which flag turns this on?** `grep` for callers of every module. `drain` had none.
3. **What does this counter reset with?** Ceilings are in-process, so a per-task mediator
   starts every allowance from zero.

A fourth question found the last two rows: **what actually makes this boundary a boundary?**
Two control planes with separate issuer keys are separate because an unknown `kid` is refused —
that is real, and it is the whole of it. `iss` was carried, printed, and never compared, so the
separation had exactly one mechanism and no defence in depth. The question is worth asking
because the answer is often "one thing", and the field that looks like a second one is
decoration until something checks it. `scripts/custody-drill.sh` phase 5 is that estate:
signature good, `aud` matching, planes different.

The full list is in [CHANGELOG.md](../CHANGELOG.md); here is the shape:

| What it read as | What it did |
|---|---|
| `--observe` set | denied anyway, regardless of mode |
| a revocation feed configured | an unreadable feed was treated as an *empty* feed — granting |
| `Terms::intersect` narrowing | could **widen**, and was not associative |
| posture gating issuance | standing policy auto-issued to unproven parties |
| a JWKS served and bundled | nothing could read one back; coordinates checked only for length |
| `--jwks-url` configured | the refresh loop held boot-time trust and never rotated |
| TLS termination mandated | a pod on `0.0.0.0` shipped bearer tokens in plaintext |
| `--require-external-signing` | reached **one of six** signing roles |
| approver keys "kept separate" | `cp issuer.pem approver.pem` satisfied every check |
| break-glass raised to `Critical` | `Quarantine` was already `Critical`; the override was a no-op |
| a break-glass alert | the new event kind fell outside the sink filter it was for |
| a latency gate | pointed at a benchmark that did not exist |
| a fuzz target's invariant | was stale, and the target had never been run |
| an SDK's `Outcome` | reported all three states false on a retried request |
| a pinned surface | ignored MCP's `title` and A2A's `examples`, so an injection there moved **no** digest and scored **zero** |
| `surface = { write = true }` | matched every surface; only `write = false` ever filtered |
| the money-movement rule | sat below the generic tier rule, so its spend cap and blocking evidence never applied to a payments contract |
| dual control at tier 1 | was enforced for `quarantine` and inexpressible for issuance |
| `audit verify` | said **"chain is intact"** on a chain whose most recent rows had been deleted |
| `wc_revocation_trusted 1` | on a mediator with no feed at all, so the containment alert could never fire for the topology with no containment |
| injection screening | never read a JSON object **key**, so a poisoned parameter name scored zero where the same string in `required` scored a block |
| `drain`/`abort` on revocation | has no caller and no flag: the stated `Abort` default is not in force |
| `max_calls_per_hour` | counts per **process**, so a 3-per-hour contract served 9 calls in one hour across three short-lived mediators |
| a quarantine | could never be lifted — no command, no route — so a false positive bricked a party permanently |
| `connect quarantine` | returned 202, revoked the contract, and **did not stop a running session** — the mediator logged "1 rejected" and kept serving |
| retiring an issuer key | did not stop sessions already admitted under it — the per-call path never re-consulted the cache that already knew |
| `drain.rs`'s own doc | asserted "new calls are refused — **this half is real**", which was true of `Cache::resolve` and false of the mediator, because the hot path never called it |
| ten unit-tested alert rules | three were asserted **nowhere**, and one of those could not fire at all — `promtool` checks the tests it is given and never asks what was left out |
| `iss` carried in every contract and printed by `connect verify` | **never checked**, and not listed among what the report said it had not checked, so once two planes' keys shared one keyring a non-production contract verified in production |
| an issuer key in a KMS | the mint path hard-coded `ES256` while `IssuerKeys`, `connect verify` and the mediator all accepted three algorithms — an estate mandated onto P-384 could verify contracts it had no way to mint |
| `Term.deprecates`, a published withdrawal date | had **no reader anywhere**; `Offer::deprecated_after` existed to serve it and had no caller either, so a consumer could contract an item for thirty days past the date the provider said it was gone |
| `Matched.offer_version`, commented "so a later upgrade can find what it affects" | was dropped on the floor at mint time — `ContractRecord` had no field for it, so *who breaks if I remove this?* was unanswerable and a comment in the source said otherwise |
| `Registry::revoke_contract` and `contain::Revoked::Connection`, both tested | had **no caller outside their own tests**, so the only way to end one contract early was `quarantine` — containing the whole counterparty |
| contract-set acknowledgements, served at `/v1/mediators/{id}/ack` and rendered at `/metrics` | lived in a `HashMap::new()` that was **never loaded or saved**, so a restart zeroed them and any gate built on them would block every deploy |
| every read-only CLI verb | took the **single-writer lock**, so `posture`, `discover`, `blast-radius`, `contracts`, `requests` and `show` all failed with `WC-8003` against a control plane that was serving — which in production is a control plane that is always serving |
| `--policy`, on three verbs that load the policy | `proposals apply`, `need apply` and **`breakglass`** never accepted it, so the file had to sit in the current directory — and `proposals apply` is designed to run from inside a contracts repo, where it does not. Break-glass is the one that matters: an incident is the worst moment to meet `WC-8001 cannot read connect-policy.toml` |
| `is_reviewed_merge`'s "an approver who is not the author" | the GitHub shim parsed PR JSON with `sed`, a real object has **three** `"user":{` occurrences, greedy matching took the last, and `author` came back **empty** — so every approver differed from it and a self-approved merge would have read as reviewed. The probe passed because that merge had genuinely been reviewed |
| `Registry::repin`, built and tested since admission existed | had **no caller outside its own tests**, so a catalogue row registered without a surface could never be given one — `register` refuses a live party as drift and nothing else re-pinned |
| `inventory promote --raise-pr`'s idempotency, derived-branch-named and drill-asserted | covered only the half of the lifecycle a stub can reach. The branch name is content-derived and was byte-identical on a live re-run — and GitHub **still opened a second, empty pull request**, because it permits a new PR from a branch whose previous PR was merged. The drill passed because its stub answers `open_pr` idempotently by branch and so cannot express the merged case; only the real host does. Proposing now reads `base` first, and matching content there means propose nothing |
| `TermApproval::NamedConsumer`, a documented approval mode with a parser, a strictness rank and tests | routed **nowhere**. `match_need` pushed it onto the *refusal* list reading "not wired yet", so the mode a provider can actually write on the day they publish — before any consumer exists — was the one mode that could not be used, and `pre_granted` was the only one that worked. The module's own doc says an offer "only ever permits the asking"; the only wired mode granted without being asked. Inverted severity: the most guarded terms were the least usable, so a provider's rational move was to publish the permissive one |
| the estate's `default = "allow"` versus a provider's gated term | nothing connected them. `Issuer::request` minted `ConnDecision::Allow` with `ApprovalRef::standing()` — no human at all — and never consulted whether the provider had asked to decide each consumer. A broad enough estate rule would have answered the provider's consent on their behalf. Found by writing the test, not by reading: the drill that was supposed to prove the fix passed with the fix deleted, because `cpolicy` refuses standing work to an `Unattested` party and every party in that fixture was unattested |
| the single-writer lock, after the sweep that moved seven read-only verbs off it | missed two. `connect entities` and `need check` still called `open_store`, so both failed with `WC-8003` against a serving control plane — and `need check` is the one designed to run in a consumer's own pipeline, which has no reason to hold the writer lock. Found by grep, twice; there is now a source-scanning guard (`no_read_only_verb_takes_the_writer_lock`) with an explicit writer allowlist, because a sweep is a one-off and a test is not |
| the SCM shim's error reporting | every failure was `WC-1001 workload identity unverifiable`, including the shim never running at all. A `~` inside a quoted shell variable made the path literal, bash exited 127, and the tool reported an identity problem — sending an operator to look at attestation instead of at the flag they mistyped. Now split: a shim that could not start is `WC-8004` and says the host was never asked; a shim that ran and refused stays `WC-1001`. Both halves tested, and the 127 case needed its own test — the missing-file test fails at *spawn* and never reaches the exit check, which mutation testing showed by leaving that branch untouched |
| `approver_role` and `dual_control` in connect-policy, on every merge-based path | **silently unenforced**. `Issuer::approve` is the only place they are checked, and both merge paths — `proposals apply` and `need apply` — reach a contract through `mint_with_identity` instead. Measured, not inferred: a rule reading `approver_role = "security.architect"` minted a contract with no role holder anywhere and **no approver registry loaded at all**. `mint_with_identity` exists for identity derivation, not approval, so the bypass was a side effect of routing around the check rather than a decision. Now refused unless the matched rule says `owner_merge_approves = true` — because refusing outright was too blunt: a policy naming the role `service.owner` means exactly what an owner-approved merge shows, and no system can read intent out of an opaque string |
| `need apply`'s gated half, on its first day | had **no idempotency at all**. The mint path checks the projection for an existing contract; a gated need has none yet, so a nightly pipeline opened a fresh request every run and buried the provider in duplicates of one question. `request_id` folds the clock and the log sequence, so it could not be the key — the request digest could, since it covers the parties, items, terms and lifetime. Introduced and found in the same session, by re-running the command twice |
| a two-branch `assert!` in `caep.rs` | the first branch looked for a literal newline escape and a run of spaces, which a Rust line continuation can never produce — so it could never match, and the `or` kept the test green. An assertion that cannot be true is not a weaker check, it is none |

### The review checklist

For any control, in this order:

1. **Is it reachable from the thing that deploys it?** A `Signer` trait with no `--signer`
   flag is custody nobody can adopt. Ask which flag, config key or API field turns it on.
2. **Does the enforcing path consult it, or a copy of it?** The mediator's refresh loop held
   its own `IssuerKeys` built at boot. A second copy of a decision diverges from the first
   time somebody forgets to update it.
3. **Does the test assert the decision, or the configuration?** `assert!(cfg.mode ==
   Observe)` proves nothing. Assert that the request was refused, the key stopped verifying,
   the digest changed.
4. **What happens when its input is unavailable, not just wrong?** An unreadable revocation
   feed is not an empty one. Compare against the fail-closed matrix below.
5. **Would you notice it failing?** A control whose failure is silent is a control you find
   out about from an incident. Is there a metric, an event kind, a non-zero exit?
6. **Run it.** Every defect above was found by running a binary, a script or a campaign —
   never by reading. If you have not executed the control, you have not reviewed it.

### For a reviewer of this repository

Two specific traps, both of which have bitten:

* **A doc comment is not a control.** `chain.rs` said the anchor key *"belongs offline or in
  an HSM"* for months while holding an in-process `EncodingKey`. Grep for prescriptive prose
  and ask what enforces it.
* **A skip must be loud.** `connect bench` counts a skipped gate as a failure unless the
  skip was *deliberate*, because a CI job that measured three of six gates and exited green
  is the failure the harness exists to prevent. Apply the same standard everywhere:
  attestation stages, conformance vectors, detectors.

---

## Part 2 · Trust boundaries

| Boundary | Trusted | **Untrusted** |
|---|---|---|
| agent ↔ mediator | the mediator | **the agent** — it may be prompt-injected; it is the thing being policed |
| mediator ↔ callee | the mediator | **the callee's declared surface and its responses** |
| control plane ↔ mediator | signed contracts and revocations | the transport |
| org ↔ partner org | our own trust anchor | **everything the partner asserts** |
| admission ↔ CI/CD | verified provenance | **self-asserted metadata** |

The one that surprises people: **the agent is on the untrusted side.** warden-connect does
not protect an agent from a bad tool; it protects the estate from the agent, on the
assumption that the agent will eventually be made to do something it should not.

---

## Part 3 · The eleven threats, as things to check

§7.8 has the full table with residuals. This is what an operator verifies.

### A1 · Forged contract
Asymmetric-only JWS, `kid`-directed key resolution, `aud` binding, revocation.

**Check:** run [`scripts/conformance.sh`](../scripts/conformance.sh) against the verifier you
actually deploy. Confirm `alg-none`, `hmac-hs256` and `alg-confusion-ed-for-es` are refused
with `WC-3101` — not merely refused.
**Residual:** issuer key compromise. Mitigated by rotation ([key-custody.md](key-custody.md))
and detectable through anchors.

### A2 · Replay against another mediator
`aud` per mediator, `nbf`/`exp`, `jti` tracking.

**Check:** `aud-other-mediator.jws` must produce `WC-3104`. Confirm each mediator's
`--mediator-id` is distinct — two mediators sharing an id makes `aud` meaningless.

### A3 · Peer impersonation
mTLS/SVID identity compared to contract claims — **authenticated, never claimed**.

**Check:** `connect-mediate --peer-mode configured` records that identity came from
configuration, not a handshake. Confirm the startup banner says so, and that a shared
gateway is not running in `configured` mode.
**Residual:** the workload-identity issuer. Stage 1 is verified against a real SPIRE 1.15.2
server (`fixtures/spire/`), so what is proven is that an SVID was signed by a key in the
bundle you configured. **Who is entitled to be in that bundle is SPIRE's problem** — a
trust domain that will attest any workload that asks makes a valid SVID worth nothing here.

### A4 · Rug-pull / tool poisoning
Pinned surface hash, connect-time comparison, re-attestation, injection screening.

**Check:** change a tool's description on a callee and confirm a drift event and suspension.
Confirm `screen-rules.toml` mode is what you think — `calibrated = false` ships by default
and blocking is earned per estate.
**Residual:** behaviour changing within an unchanged declared surface. That is
`warden-trace`'s problem, and it is not covered here.

**Interop is part of this threat.** Stage 4 rejected every real cosign attestation for two
reasons — a missing `keyid` and a DER signature — so an estate wiring up genuine SLSA
provenance would have been told its provenance was unverifiable and, reasonably, turned the
requirement off. A control that refuses valid evidence is a control that gets disabled.
`fixtures/cosign/` exists so that cannot recur.

The same check was then run one stage up, against a real SPIRE server, and stage 1 passed
unchanged — the only integration in this build that did. What it found instead was **four
wrong commands in this repository's own procedure for exercising it**, one of which would
have written an empty token file. Same lesson, one layer out: a control nobody can follow
the instructions for is a control nobody runs.

### A5 · Shadow endpoint bypassing the mediator
**Check:** this is a *deployment* property and the most commonly assumed-away threat. Confirm
from the network side that the callee is unreachable except through the mediator. A mediator
that was never started emits nothing, and so does an estate with no traffic — so alert on
**staleness** of the mediator's metrics file, not on a value.
**Residual:** stated, and not closable in code.

### A6 · Discovery as reconnaissance
Mediated results, no enumeration, throttling, indistinguishable empty results.
**Check:** `wc_discovery_throttled_total` is non-zero under a scripted sweep.

### A7 · Approval fatigue
Standing policy for the low-risk majority, risk-ranked queue, full context on each request.
**Check:** how many requests reach a human per week. If it is more than a person will read,
the standing policy is too tight and the approvals are rubber stamps.

### A8 · Control-plane compromise
Signed artifacts, tamper-evident chain, anchors, dual control for quarantine override.

**Check:** `connect audit verify --anchor-pub`, on a schedule, from a host that is not the
control plane. Confirm the anchor key is **not** on the control plane
([key-custody.md](key-custody.md) — move this key first).
**Residual:** full compromise is catastrophic; anchors are what make it detectable.

### A9 · Control-plane DoS
Mediators serve from cache to `exp`; issuance stops, the estate keeps running.
**Check:** stop the control plane and confirm existing connections continue and new ones do
not. This is asserted in `failure.rs`, and it is worth confirming in your topology.

### A10 · Insider widening a contract
Signed, versioned, every mint carries approver and `policy_version`.
**Check:** `connect policy dry-run` before any policy change. **Detection, not prevention** —
dual control at tier 1 is the preventive half.

### A11 · Delegation-depth evasion via a chain
`max_depth` enforced against the **originating** contract, not per hop.
**Residual:** requires `warden-delegate` on every hop. Not deployable today.

### The transport control's honest limit

`--behind-tls-proxy --trusted-proxy` believes `x-forwarded-proto: https` from a named address
or CIDR block. Verified end to end behind a real terminating proxy (Caddy): the forwarded
request is admitted, and a direct request with no header is refused.

**What it does not stop is a process at a trusted address forging the header.** If the proxy
runs on the same host as the listener — a localhost-terminating sidecar, which is a common
shape — then `--trusted-proxy 127.0.0.1` is satisfied by anything on that box, and a local
process can present a bearer token over plaintext and be believed.

Why this is a documented limit rather than a defect:

* **The threat the control exists for is *remote* plaintext** — "a pod bound to `0.0.0.0`
  shipped approval tokens in clear with nothing objecting". A remote client cannot source from
  a trusted address, so that threat is closed.
* **A local process has strictly better attacks available.** It can read `tokens.toml`, or the
  signing key if custody has not been delegated.

What it means operationally: **the address check is only as strong as the separation between
the proxy and everything else that can reach the port.** Put the proxy in its own network
namespace, or on its own host, and the check is real. Co-locate it with untrusted workloads
and the check is decorative — and no CIDR narrow enough fixes that, because the forger shares
the address.

The stronger property is now available: **`--proxy-secret-file`**. The proxy sets
`x-warden-proxy-secret`, the listener requires it, and forging then costs the secret rather
than the position — so a co-located process at `--trusted-proxy 127.0.0.1` is refused.
Verified over a socket from loopback, which is exactly the forger's own address: the request
that used to be admitted now returns 401. The secret is at least 32 characters, read from a
file so it stays out of the process list, compared in constant time, and it **narrows only**
— the address check and the `https` claim both still apply.

It is optional, because requiring it would break every existing deployment on upgrade. So
the weak configuration is still expressible, and the banner says so in those words: *"NO
proxy secret — any process at that address can forge the header"*. **Check the banner, not
the flags** — a `--trusted-proxy` line looks strict either way.

---

## Part 4 · The fail-closed matrix

The table an incident is judged against. From §7.8, restated because this is the operator's
copy.

| Condition | Strict (default) | Observe |
|---|---|---|
| no contract | **deny** | allow + finding |
| contract expired | **deny**, no grace | **deny** |
| surface hash mismatch | **deny** + drift event | allow + drift event |
| posture `unattested` | **deny** | allow + finding |
| posture `quarantined` | **deny** | **deny** — never overridable |
| control plane unreachable | serve from cache to `exp`; no new connections | same |
| revocation feed unreadable | **deny all** — feed integrity is load-bearing | allow + alarm |
| blocking evidence sink unavailable | **deny** — no connection without a recorded trail | allow + alarm |

Two rows are the ones people get wrong:

* **An unreadable revocation feed denies everything.** This looks from outside exactly like a
  broken estate, and it will arrive as *"all the agents are down"*. `wc_revocation_trusted ==
  0` on a mediator is the query that distinguishes them. It was a real defect — a corrupted
  feed was once treated as an empty one, and granted.
* **`quarantined` denies in observe mode too.** Observe mode softens posture and *not*
  containment. If that ever stops being true, the containment story is over.

---

## Part 5 · What is out of scope, and why

Being explicit, because a threat model that implies coverage it does not have is worse than a
short one.

* **Prompt injection inside the agent's reasoning.** warden-connect bounds *connections*. An
  injection that makes the agent call something its contract permits is the system working —
  that is what a narrow ceiling is for.
* **Semantic behaviour change within an unchanged declared surface.** A4's stated residual;
  `warden-trace`'s territory.
* **A host that already holds the signing keys.** Documented non-goal until custody is
  delegated. The seams exist; the tokens have not been bought.
* **Denial of service against the data plane.** A mediator is in-process with the proxy; its
  availability is the proxy's.
* **The correctness of Warden core's per-action policy.** A contract is a ceiling; core
  decides within it. Two layers, two threat models.

## Part 6 · Reporting

[SECURITY.md](../SECURITY.md) has the scope and the disclosure process. Two things it says
that belong here too:

* **"A control that is configured and does nothing" is in scope** even when no single request
  can be shown to bypass anything. That is this codebase's characteristic defect, and
  requiring a working exploit before taking it seriously would filter out exactly the class
  that matters.
* **A conformance disagreement is a finding**, whoever turns out to be wrong. In a format
  meant to be interoperable, disagreeing about what is valid *is* the bug.
