# Changelog

All notable changes to warden-connect. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`WC-*` error codes and the `warden-connection+jws` artifact schema are part of the public
interface. A change to either is a breaking change even when no Rust signature moves,
because a third-party verifier depends on both.

---

## [Unreleased]

Pre-1.0. Nothing has been tagged yet; `main` is the only thing to run and
[docs/production-readiness.md](docs/production-readiness.md) is the list of what stands
between here and a release.

### The artifact and the core

- **Connection contracts** as signed JWS (`warden-connection+jws`), asymmetric-only, with
  `aud` bound per mediator, `nbf`/`exp`, `jti`, and a pinned `surface_digest`.
  A contract is a **ceiling, never a grant**: `effective = contract.surface ∩ token.scope
  ∩ policy_decision`.
- **`wcs1` canonicalisation** — field allowlist, NFC, per-item hashes and a
  `surface_digest`. Zero-width and bidirectional characters are preserved deliberately;
  normalisation must never launder an attack.
- **Nineteen conformance vectors** in `fixtures/contracts/` with an `expected.json` naming
  the `WC-*` code a conforming verifier must return for each.
- **Thirty-one `wcs1` canonicalisation vectors** in `fixtures/canon/` — *input surface →
  canonical bytes → digest*, each carrying the normative rule it pins, driven by
  `scripts/canon-conformance.sh` against any canonicaliser. Two implementations that disagree
  about these bytes cannot share a drift verdict, so this is the second half of the
  independence argument; the first was `fixtures/contracts/`. The harness compares the
  *document*, not only the digest, and reports the first differing byte — and it was checked
  against a deliberately wrong canonicaliser (stripped zero-width characters, `1.0`
  normalised to `1`, over-eager array sorting) so that it is known to fail when it should.
- **The `WC-*` taxonomy** with categories, so a code's class is machine-readable.

### The control plane

- Registry and admission with a five-stage attestation ladder, each stage skipped rather
  than assumed when its material is absent.
- **Real attestation verifiers** — SPIFFE JWT-SVID, signed A2A agent cards, DSSE/in-toto
  SLSA provenance. Fixtures are minted by an independent implementation
  (`scripts/gen-attest-fixtures.py`, using `cryptography`), so agreement is two readings
  of a spec rather than one implementation talking to itself. Two stages go further and
  run against other *implementations*: stage 1 against a real **SPIRE 1.15.2** server and
  agent (`fixtures/spire/`, minted by `scripts/spire-fixtures.sh`) and stage 4 against real
  **cosign v3.1.3** output (`fixtures/cosign/`).
- **Declared-surface injection screening** (A4) with observe/flag/enforce modes, a
  calibrated rule set, and precision and recall both gated in CI.
- **Connection policy** — zone bars, standing caps, `policy lint`, `policy show`,
  `policy dry-run` against live contracts.
- The **issuance loop** — request, approve, deny, mint, distribute — with dual control,
  and **break-glass** bounded by TTL, budget and window so it stays exceptional.
- **Evidence** — a hash-chained log with signed anchors, `audit verify`, and exports to
  CSV, JSON, DORA, CPS 230, OSCAL and CycloneDX.
- **Containment** — a signed revocation feed, quarantine with fan-out and per-mediator
  ACK deadlines, and a `quarantined` posture that is never overridable.
- The **assurance loop** — re-attestation schedule, drift detection, posture scoring,
  blast-radius queries.
- **Zone lattice**, **cross-org federation** over trust anchors, **multi-tenancy** isolated
  by construction, **mediated discovery** that answers without enumerating, and **CAEP
  ingest** so other people's signals can act here bounded by their authority.
- `EventSink` as the extension point. **No SQL adapter and no ORM** — persistence beyond
  the evidence chain is an integration, not a feature (§8.16b).
- HTTP API over `/v1`, with roles, idempotency, `healthz` and `readyz`.

### The mediator

- `connect-mediate` composes **unmodified** Warden core's gateway with the connect
  decorator in one process — no second hop, no fork of core.
- Contract cache, `tools/list` filtering, ceilings, drain, and peer identity
  (`configured`, mTLS, mesh, JWT-SVID) where an identity is **authenticated, never
  claimed**.
- Refuses to start if the first contract refresh fails. A mediator that silently degrades
  to pass-through is worse than none, because the estate believes it is protected.
- **Air-gapped bundles** — signed contract sets for estates with no control-plane call.

### Keys and custody

- Issuer keyring with a rotation lifecycle and the guard that makes it safe: **a key
  cannot be retired while a contract it signed is still live.**
- A `Signer` seam so every signing operation has a **delegated** form beside its PEM form
  — the private key can live in an HSM, a smartcard or a KMS and never enter this process.
  `--require-external-signing` makes a regression to a local key a startup failure.
- Every mint records which `kid` signed and where that key lives, so a local signature is
  answerable from the evidence chain rather than from configuration.
- **Custody is enforced per role, in one place** (`wc_control::custody`). Six signing roles
  with their own rules: `--require-external-signing` applies to all of them (`connect
  bench` is the one stated exemption); an approver key may never be the service's key
  material, and two approvers may not share one; the break-glass revocation key is
  declared, selected by a single `--break-glass` flag, refused when reached without
  consent, and recorded as its own event kind so a sink can alert on exactly it.
- **JWKS ingest** (`IssuerKeys::add_jwks`) and a TTL-cached `JwksSource`, so issuer trust
  rotates by publishing rather than by redeploying every mediator. A refresh **replaces**
  the trust set, so a withdrawn key stops verifying; a failed refresh keeps serving the
  cache, bounded by a staleness limit past which it refuses.

### Safety

- `serve` **refuses to start** on a non-loopback address unless TLS termination is
  declared. With `--behind-tls-proxy`, every authenticated request must carry
  `x-forwarded-proto: https` from a named address, so a request that bypasses the ingress
  is refused rather than trusted. `--insecure-plaintext` exists, is named, and is loud.

### Tests and CI

- **993 tests** across unit, e2e, failure-injection, property, fuzz and attestation-interop
  tiers, plus the conformance vectors.
- CI: fmt, clippy with `-D warnings`, the full suite, MSRV 1.89, the §8.10.3 latency gates
  via `connect bench`, screening calibration, `cargo deny`, and per-crate dependency
  ceilings.
- Clocks are injected everywhere, so no test depends on the wall clock.

### Notable defects found and fixed during the build

Recorded because each was a control that read as configured and did nothing — the failure
mode this component exists to prevent, occurring inside it:

- **Observe mode was not observed.** `MediatedUpstream` denied regardless of mode. Fixed,
  then narrowed again when the first fix also softened revocation distrust.
- **A corrupted revocation feed granted.** An unreadable feed was treated as an empty
  feed. Feed integrity is load-bearing; it now distrusts.
- **`Terms::intersect` could widen**, and was not associative. Per-list closure flags, and
  every branch sorts — signed bytes were order-dependent.
- **Standing policy auto-issued to unproven parties**, bypassing posture.
- **`JwtSvidIdentity` read the system clock**, so its expiry check could not be tested.
- **JWKS handling was write-only** — the document was emitted, served and bundled, and
  nothing could read one back. The coordinate extraction was covered only by length
  checks, which a swapped `x` and `y` would also satisfy.
- **The mediator's refresh thread held boot-time trust.** Contracts refreshed every tick
  and the keys checking them never did.
- **A non-loopback listener accepted bearer tokens in clear.** The deployment contract was
  documented and unenforced.
- **Stage 4 rejected every real cosign attestation.** `keyid` was required though DSSE calls
  it an optional hint and cosign omits it; and the verifier expected raw `R‖S` while cosign,
  like all of Sigstore, signs ECDSA as DER. It accepted exactly one dialect of a two-dialect
  format — its own.
- **Three mediator metric families were declared, documented, and never populated**, so the
  `wc_revocation_trusted == 0` alert could never fire.
- **A mediator living under the flush interval wrote no metrics file at all**, and there was
  no flush on exit beside the audit checkpoint that was already there.
- **`--trusted-proxy` took exact addresses only**, which made the strong configuration
  unusable behind an ALB or an Ingress whose address moves — so the practical choice was to
  omit it and believe the header from anywhere.
- **`--require-external-signing` reached one signing role in six.** It was checked in the
  issuer path and the anchor path and nowhere else, so both revocation keys, the approver
  keys and the bundle envelope could only ever use a key on local disk — while the estate
  believed the posture covered them.
- **Nothing kept approver keys away from the service's keys.** `cp issuer.pem
  approver.pem` satisfied every check and produced a valid approval proof that nothing
  afterwards could distinguish from real dual control.
- **A severity escalation that escalated nothing.** Break-glass revocation recorded a
  `Quarantine` at `Critical`; `Quarantine` is already `Critical`, so the override was a
  no-op and the event was indistinguishable from any other containment.
- **The break-glass alert would have missed the sink it was for.** The new event kind was
  outside `is_containment()`, so a sink filtered to `Filter::Revocation` — where operators
  point containment alerting — was the one destination that never heard.
- **The break-glass path opened a second writer on a single-writer log**, failing with
  `WC-8003` only when used, on the one path that must not have a bug in it.
- **A misdeclared revocation key half-applied a containment** — the registry recorded the
  quarantine, then the run failed, leaving mediators never told and the register reading
  as done.
- **Screening refused every localised tool server** — the S1 rule read localisation
  controls in complex scripts as concealment.
- **A latency gate pointed at a benchmark that did not exist**, so it silently never ran.
- **Admission stage 1 no longer requires SPIRE.** `--oidc-token` admits a Kubernetes
  projected service-account token, IRSA, Azure workload identity, a GCP service account or a
  Vault identity token — all JWTs with a published JWKS and a subject that is not a
  `spiffe://` URI, which `--svid` could never accept. Before this, an estate without SPIFFE
  could not pass stage 1, stayed `Unattested`, and had every mediated call refused
  `WC-3109`; `--observe` was the only workable configuration. **Enforce mode was effectively
  SPIRE-only, and that was never a design decision** — it was an unnoticed consequence of one
  verifier. Verified end to end with a Kubernetes SA token: `Attested`, a contract minted, and
  a mediated call that executes the contracted tool and blocks the uncontracted one, with no
  SPIFFE identity anywhere.

  The entity id is **derived, not asserted** — `urn:wc:oidc:<label>:<subject>` — so a token
  for one subject can only ever authenticate as the one id derived from it, and there is no
  mapping table whose editor could re-point an identity. `--oidc-label` folds the issuer in,
  because every cluster mints `system:serviceaccount:default:default` and two clusters are not
  one party; a label containing `:` is refused, since it would make the derivation ambiguous.
  `--oidc-issuer` is required rather than defaulted: without it, any key in the trust set
  authenticates a token from whichever issuer holds that key.

  What still requires SPIFFE is the mediator's *authenticated* peer modes (`mtls`, `mesh`,
  `jwt-svid`), which resolve through a SPIFFE URI. `configured` — the default and the honest
  mode for a sidecar — accepts a derived id, so the sidecar topology loses nothing.
  [`docs/identity-without-spire.md`](docs/identity-without-spire.md) has the per-issuer
  settings and the two things it does not change.

Closing the remaining **Unbuilt** items that a commit can close — and one of them turned out
to be a control that could not be reached:

- **A quarantine could never be lifted.** `Registry::clear_quarantine` existed,
  dual-controlled and tested, with **no CLI command and no API route**. So quarantine was a
  one-way door in the shipped product: a false-positive containment bricked a party for good,
  and the only recovery was hand-editing a hash-linked state log, which breaks every row after
  the edit. Found while wiring `wc_quarantine_duration_seconds`, whose only input is a
  clearing that could not happen — a metric nobody can populate is usually a path nobody can
  take. Now `connect unquarantine <id> --approver a --approver b` and
  `POST /v1/quarantine/clear`, dual-controlled like the order they lift, because clearing is
  the more dangerous direction: it restores a party the estate decided to cut. Contracts stay
  revoked, and the command, the response and the evidence record all say so, since "cleared"
  reads like "restored".
- **`wc_quarantine_duration_seconds` is emitted.** Observed at the clearing, from a new
  explicit `Entity::quarantined_at` — not from `updated_at`, which any unrelated write moves,
  and not derived at scrape time by pairing chain events, because the chain grows monotonically
  and every scrape would get slower than the last. A quarantine predating the field reports
  *no* duration rather than one measured from the epoch.
- **`--proxy-secret-file` closes the trusted-proxy forgery gap.** The address check's honest
  limit was that a process *sharing* a trusted address can forge `x-forwarded-proto`, and no
  CIDR fixes it because the forger shares the address — the ordinary shape when the proxy is a
  localhost sidecar. The proxy now sets `x-warden-proxy-secret` and the listener requires it,
  so forging costs the secret rather than the position. Verified over a socket from loopback,
  which is the forger's own address: the request that was admitted before returns 401. At least
  32 characters, read from a file so it stays out of the process list, compared in constant
  time, never rendered by `Debug` or the banner, and **narrowing only** — the address check and
  the `https` claim both still apply. Optional, because requiring it would break every existing
  deployment, so the banner names the weak configuration outright.
- **The SDK has tests that need no control plane.** Its only verification was "the examples run
  against a live control plane", which needs an estate, keys and an approver registry, and
  therefore never ran in CI. Twenty tests over what a status means, whether a retry is safe,
  and whether a refusal keeps its `WC-*` code — including the replay trap that was a real
  defect, and mutation-checked by reintroducing it. In CI now.

Found by the **second adversarial hardening pass**, over the five areas the first left
untouched — `screen`, the ceilings, the drain path, federation, residency:

- **Injection screening never read a JSON object key.** One string in six callee-controlled
  positions: `description`, a property `description`, an `enum` value, an entry in `required`
  and a schema `title` all scored a **block**; the property **name** scored **zero**.
  `walk_text` used keys to build the path label and never as content — so the one position a
  parameter name actually occupies was the one nobody screened, while the same name listed in
  `required` was screened. Parameter names are what a model reads to decide how to call a
  tool. Keys are now screened; precision and recall stay at 1.000 on the labelled corpus.
- **The drain path has no caller and no flag.** `OnRevoke` — `drain` vs `abort` for work in
  flight when a revocation lands — is referenced by nothing outside its own module. There is
  no `--on-revoke`, and `connect-mediate` never mentions it. So the module's own rule that
  **`Abort` is the default because `drain` is the permissive reading** is not in force: the
  in-flight call finishes, bounded by `--upstream-timeout` rather than `drain_timeout`. The
  containment half — new calls refused at lookup time — is real and unaffected. Not wired up,
  deliberately: a flag that cannot interrupt a blocking upstream read would be the same defect
  in a new place. Stated at the top of the module, in `limitations.md`, and pinned by a test
  that fails if somebody wires it without deleting the disclaimer.
- **Ceilings count per process, not per hour.** A contract with `max_calls_per_hour = 3`
  executed exactly 3 calls in one mediator and **9 across three**, in the same hour, because
  the sliding window is in memory. Correct for a long-lived sidecar; wrong for the per-task
  invocation shape this codebase names elsewhere. `max_spend_usd_per_day` behaves the same.
  The mediator now says so at startup when a contract carries either ceiling.

**Clean under the same probing:** federation refused all eleven hostile chains with the right
codes — `alg=none` → `WC-3101`, unknown anchor → `WC-2030`, 51 statements, null and numeric
elements, 200-deep nesting — and its documented exit codes hold exactly (0 valid, 3 stale
anchor, 4 unverifiable). Residency fails closed: a request declaring no jurisdiction, or the
wrong one, does not match a jurisdiction-scoped rule and lands on the default.

Found by the **first adversarial hardening pass** over the six paths in
`docs/production-readiness.md`, by running the binaries:

- **The pinned surface ignored two model-visible fields, so screening and drift detection
  were blind together.** MCP's tool-level `title` — added in revision **2025-06-18**, which
  is the revision `admission` negotiates — and A2A's `skills[].examples`, which the spec
  defines as example *prompts*. The `wcs1` allowlist covered `annotations.title` and `tags`
  but not these, and `screen::text_fields` walks that same projection, so the identical
  injection string scored a **block** in `description` and **zero** in `title` while the
  report still read "ran S1 S2 S3 S4 S5 S6 S7 S8". Neither field moved the pin, so no drift
  event fired either. One omission, both halves of A4.
- **`surface = { write = true }` matched every surface.** The only branch was
  `if !write_allowed && has_write`, so `write = true` was a no-op — and the shipped
  `connect-policy.toml` used it on its money-movement rule meaning the opposite.
- **The shipped policy's money-movement rule was shadowed.** It sat below
  `callee_tier < 3`, which matches every tier 1 and 2 payments callee — all of them — so the
  spend cap, the oversight threshold and `evidence_delivery = "blocking"` were never applied
  to a write-capable payments contract. `policy lint` did not flag it, correctly: the rule is
  reachable, just not for the callees it exists for.
- **Dual control at tier 1 was inexpressible for issuance.** It was enforced properly for
  `quarantine` (`WC-6001`) and could only be *asked for* by a zone bar, while `callee_tier`
  and `surface.write` are matchable only in a rule. A tier-1 write-capable money-movement
  contract minted on **one** signature. `[[rules]]` now takes `approval`, raise-only.
- **`audit verify` reported "chain is intact" on a truncated chain.** Dropping the tail of a
  hash chain leaves rows that link perfectly, and it is the one edit worth making: it removes
  the newest evidence. Checkpoint sequences are now compared on every run — without needing
  the anchor key, since an unverified checkpoint may raise an alarm even though it may not
  clear one — and the verdict never says "intact" without saying what bounds completeness.
  `backup` inherits this and now refuses to snapshot a truncated chain.
- **A mediator that nothing can contain reported `wc_revocation_trusted 1`.** With
  `--contract FILE` and no control plane, no pull ever happens, so nothing ever distrusts the
  empty set — and the `wc_revocation_trusted == 0` alert could never fire for the one
  topology where quarantine fan-out cannot arrive at all. There is now a separate
  `wc_revocation_source_configured` gauge, a startup warning, and two alerts instead of one.
- **`--tools ""` reached the approval queue.** An empty surface cannot mint (`WC-3012`), and
  it failed only when a human tried to approve it. Refused at request time now: approval
  fatigue is a listed threat and the queue is what it wears down.
- **`connect contracts <cid>` named neither approver**, so a two-controller contract printed
  identically to a one-controller one on the durable view an auditor reads.

- **The documented SPIRE procedure was wrong in four ways**, and running one turned all four
  up at once: `brew install spire` (SPIRE publishes no darwin build at all), `spire-agent api
  fetch jwtbundles` and `spire-server bundle show -format jwks` (neither exists), and a `sed`
  that matched nothing — the real output is `token(spiffe://…):` with the token on the *next*
  line, so it would have written an **empty** token file. `scripts/preflight.sh` compounded it
  by gating stage 1 on `command -v spire-server`, a check that can never pass on a Mac. No
  code was wrong; the instructions for exercising it were, which is how a control ends up
  never exercised.

### Known gaps

See [docs/production-readiness.md](docs/production-readiness.md). P0 and P1 are done or
code-complete; what remains needs something a commit cannot supply:

* **A hardware token and a KMS key** (P0 #5) — the custody seams and their enforcement are
  built; the procurement and the runbook are not.
* **A signing builder, and a reference A2A card signer** (P0 #3) — stages 1 and 4 now run
  against real output from SPIRE 1.15.2 and cosign v3.1.3. Stages 2 and 3 have no other
  implementation to disagree with, and stage 4's builder key is still local, which makes
  `builder.id` a string the fixture asserts about itself.
* **crates.io publishing** (P1 #13) — structurally blocked while Warden core is a path
  dependency. Changing that changes the family's coupling model.
* **Evidence segment retirement** (P1 #14) — retention reports the window and deletes
  nothing, because deleting a row from a hash-linked chain breaks every row after it.
* **The rotation and restore drills** — the mechanisms are tested; the procedures have not
  been rehearsed, and an unrehearsed procedure is an assumption.
* **P2 #15–#19** — a coverage-guided fuzz campaign, the conformance kit as a kit, an SDK
  and examples, operator documentation, and multi-tenancy at scale.

`RUSTSEC-2023-0071` (Marvin, in `rsa`) is ignored with an argued reason and a review date
in [`deny.toml`](deny.toml): `jsonwebtoken`'s `rust_crypto` feature is a bundle that pulls
`rsa` with no way to select curves without it, and **this tree performs no RSA
private-key operation** — a test enforces that every contract algorithm has a key loader
and that none of them is RSA.
