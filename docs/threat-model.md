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
**Residual:** the workload-identity issuer.

### A4 · Rug-pull / tool poisoning
Pinned surface hash, connect-time comparison, re-attestation, injection screening.

**Check:** change a tool's description on a callee and confirm a drift event and suspension.
Confirm `screen-rules.toml` mode is what you think — `calibrated = false` ships by default
and blocking is earned per estate.
**Residual:** behaviour changing within an unchanged declared surface. That is
`warden-trace`'s problem, and it is not covered here.

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
