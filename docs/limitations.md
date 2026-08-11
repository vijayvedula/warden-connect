# Limitations

Everything this component does not do, in one place.

The other documents each carry their own honest-limits section, which is right — a limitation
belongs next to the thing it limits. This page exists because a reader deciding whether to
*rely* on warden-connect should not have to assemble that picture from nine files.

Four kinds of entry, labelled, because they have different answers:

| | |
|---|---|
| **By design** | It will not change. The reason is architectural, and building it would break something more important. |
| **Unbuilt** | It should exist and does not. Someone has to write it. |
| **Unproven** | The mechanism is built and tested; the *procedure* or the *scale* has not been exercised. |
| **Environmental** | Blocked on hardware, a cloud account, or a second environment — not on code. |

Status: pre-1.0, no independent audit, two internal hardening passes run.
[production-readiness.md](production-readiness.md) tracks the work; this tracks the gaps.

---

## 0 · The v1 posture, in one line

**Every connection is approved by a human.** Standing issuance — auto-approval — is built,
capped, tested and **switched off** (`[standing] enabled = false`). It is the widest policy
surface in the system, and the history here is that it once auto-issued to a party whose
attestation had just failed. It earns its place after an estate is stable and somebody has read
the evidence chain in anger. Turning it on later is a configuration change, not a new
subsystem.

## 1 · What warden-connect does not protect against at all

**By design**, and stated first because everything else is secondary to getting this right.

* **Prompt injection inside the agent's reasoning.** This bounds *connections*. An injection
  that makes an agent call something its contract already permits is the system working as
  intended — a narrow ceiling is the whole defence. If you need the agent's *reasoning*
  constrained, that is not this component.
* **Semantic behaviour change behind an unchanged declared surface.** A tool whose name,
  description and schema are identical but which now does something else passes every check
  here. Pinning covers the declaration, not the behaviour. This is `warden-trace`'s territory
  and it is not built.
* **A mediator that is not on the path.** Enforcement requires the mediator to be inline.
  That is a *deployment* property and nothing in this codebase can verify it. A mediator that
  was never started emits nothing — and so does a quiet one, so alert on **staleness** of its
  metrics file rather than on a value.
* **Denial of service against the data plane.** The mediator is in-process with the proxy; its
  availability is the proxy's.
* **The correctness of Warden core's per-action policy.** A contract is a ceiling; core
  decides within it. Two layers, two threat models.
* **A host that already holds the signing keys.** With a KMS the key cannot be *stolen*, but
  an attacker holding the host can ask it to sign for as long as they hold it. KMS moves the
  exposure from permanent to bounded-by-detection; the bounding is operational work (rate
  limits, per-key authorisation, alerting on mint volume) and none of it is built.

## 2 · Attestation and provenance

* **Stages 2 and 3 have no real-implementation counterpart.** Stage 1 now runs against a real
  SPIRE 1.15.2 server ([`fixtures/spire/`](../fixtures/spire/README.md)) and stage 4 against
  real cosign output ([`fixtures/cosign/`](../fixtures/cosign/README.md)). The card stages are
  verified only against material `scripts/gen-attest-fixtures.py` mints from the spec text,
  because there is no reference implementation of a signed A2A card to disagree with. That is
  the same position stage 4 was in before cosign, and stage 4 turned out to be **rejecting
  every real attestation**. *(Environmental)*
* **Stage 1 no longer requires SPIRE, but the mediator's authenticated peer modes still do.**
  `--oidc-token` admits a Kubernetes projected service-account token, IRSA, Azure workload
  identity, a GCP service account or a Vault identity token, deriving the party's id as
  `urn:wc:oidc:<label>:<subject>` — see
  [identity-without-spire.md](identity-without-spire.md). Verified end to end, including a
  mediated call. What still resolves through a `spiffe://` URI and refuses anything else is
  `--peer-mode mtls|mesh|jwt-svid`; only `configured` accepts a derived id. That costs nothing
  for the stdio sidecar, where `configured` is the honest mode anyway, and it means the
  shared-gateway topology remains SPIFFE-only. *(Unbuilt, for the gateway topology)*
* **An OIDC identity is worth what the issuer's own authorisation is worth.** Stage 1 proves a
  token was signed by a key in the JWKS you configured. A cluster where any pod can mint a
  token for any service account yields an identity worth exactly that cluster's RBAC — the
  same limit as a SPIRE trust domain, one layer out. *(By design)*
* **A SPIRE trust bundle is only as good as its trust domain.** `fixtures/spire/` uses a
  throwaway CA and `insecure_bootstrap = true`, which is right for a fixture and wrong for
  anything else. What stage 1 verifies is that an SVID was signed by a key in the bundle you
  configured; who is entitled to be in that bundle is SPIRE's problem, not ours. *(By design)*
* **Attesting an MCP server takes two steps nothing tells you about.** `Posture::Attested`
  requires the card-signature stage, and an MCP server has no agent card — so the obvious
  reading is that an MCP server can never be attested, and since the mediator's check 9
  refuses any counterparty short of `Attested`, that enforce mode is unusable for the primary
  topology. It is usable; the two steps are **`register server --id spiffe://…`** (the flag
  works and is missing from `--help`, so an endpoint-registered server otherwise gets a
  `urn:wc:` id that no SVID can ever name) and **signing the tools document** — the verifier
  falls back to the fetched surface, so a `signatures` array on the `--surface` file verifies
  under `--card-key`. Neither is documented, the stage is called "agent-card signature", and
  its finding reads *"card signature verification not configured"*. An operator who follows
  the messages concludes enforce mode is broken and reaches for `--observe`, which is the
  A4 failure mode — a control that gets disabled — arriving through documentation.
  *(By design, badly signposted; verified reachable by running it)*
* **Provenance proves a signature, not a builder.** `fixtures/cosign/` is a real cosign
  envelope with a real DER signature, so stage 4's *verification* path is genuine — but the
  key is local, which makes `builder.id` a string the fixture asserts about itself.
  Provenance that means anything comes from a builder whose own identity is attested.
  *(Environmental)*
* **Transparency-log inclusion is verified; the checkpoint's signature is not.**
  `connect attest verify --rekor-proof` performs the RFC 6962 §2.1.1 computation offline — no
  HTTP, no Sigstore client — and is tested against a **real entry from the public Rekor log**
  (`fixtures/rekor/`), including a substituted leaf, a tampered path, a reordered path, a
  truncated and a padded path, an out-of-range index, and a checkpoint that disagrees.

  What it establishes is that a leaf is in a tree **with a given root**, and that a checkpoint
  commits to the same root. What it does **not** do is verify that checkpoint's signature,
  which needs the log's public key as a configured trust root. So a response carrying both a
  proof and its root is still only self-consistent, and `Inclusion::root_trust` says so in
  words on every result rather than leaving the distinction to the reader. *(Unbuilt: the
  checkpoint signature)*
* **Stages are skipped, never assumed.** Not a limitation so much as the thing to understand:
  supply no material for a stage and the party simply does not attest for it. Read
  `connect posture` rather than assuming a green registration means five green stages.

## 3 · Key custody

* **The custody seams take existing corporate infrastructure; nobody has pointed them at
  any.** `--signer`, `--anchor-signer`, `--revocation-signer`, `--approver-signer` and
  `--envelope-signer` each run a command you supply, so Vault's transit engine, AWS/GCP/Azure
  KMS, or a PKCS#11 token all work through a wrapper — `examples/signers/` has a PKCS#11 one
  and a KMS one, and the KMS example exists because **every KMS returns DER while JWS ECDSA
  needs raw `R‖S`**, which is the trap that would otherwise be found in production. What has
  not happened is anyone running one against a real KMS key or a real token. That is
  configuration for an adopter with existing infrastructure, and unproven here.
  *(Environmental)*
* **Every seam is built; no custody arrangement is.** `--signer`, `--anchor-signer`,
  `--revocation-signer`, `--approver-signer`, `--envelope-signer`, two revocation `kid`s, and
  structural approver separation all exist and are verified against **SoftHSM**. That is a
  verified *wrapper*, not a verified *custody arrangement*: no KMS key has been created, no
  hardware token procured, no M-of-N PIN split, no holders rehearsed. *(Environmental)*
* **Approver separation catches a copied key, not a re-encoded one.** `custody::Separation`
  fingerprints the PEM's base64 payload, so `cp issuer.pem approver.pem` is refused and a
  whitespace or armour change still matches. It cannot equate PKCS#8 and SEC1 encodings of the
  same key — that needs an ASN.1 parse this deliberately does not do. It raises the cost of
  the mistake; it does not make sharing a key impossible. *(By design)*
* **A token in a safe protects against theft, not against a person with access.** A coerced or
  malicious holder can sign. M-of-N activation is the mitigation and it is procurement.
* **Nothing prevents a valid-but-wrong revocation.** Someone with legitimate access can revoke
  the estate. That is a recoverable outage, which is exactly why the revocation key can afford
  less ceremonial custody than the issuer key. *(By design)*
* **The rotation drill has never been run.** Publishing a new `kid` and confirming a running
  mediator picks it up without a restart. The mechanism is tested; the procedure is not.
  *(Unproven)*

## 4 · Ceilings

* **`max_calls_per_hour` and `max_spend_usd_per_day` count per mediator process, not per hour
  or per day.** The sliding window and the spend total live in memory, so a restart starts them
  again. Measured: a contract with a 3-per-hour ceiling executed exactly 3 calls in one mediator
  and **9 across three**, inside the same hour. A long-lived sidecar in front of a long-running
  agent enforces the figure as written; a per-task invocation — a fresh mediator per task, which
  is a shape this codebase names elsewhere — enforces it per task. The mediator cannot know its
  own lifetime, so it says this at startup whenever a contract carries either ceiling. The
  remedy if you need the real thing is persistence with a cross-process lock, and it is not
  built. *(By design, and now announced)*
* **`max_concurrent` is per process for the same reason**, and in the stdio sidecar there is
  one synchronous call at a time, so it does not bind there at all. *(By design)*

## 5 · The transport control

* **Without `--proxy-secret-file`, a process at a trusted address can forge
  `x-forwarded-proto`.** With a same-host proxy, `--trusted-proxy 127.0.0.1` is satisfied by
  anything on the box, so a local process could present a bearer token over plaintext and be
  believed. Confirmed by doing it — and closed by `--proxy-secret-file`, a secret the proxy
  sets in `x-warden-proxy-secret` and the listener requires, so forging costs the secret
  rather than the position. Verified over a socket from loopback, which *is* the co-located
  forger: the same request that was admitted before is now refused.

  What remains: the secret is **optional**, because requiring it would break every existing
  deployment on upgrade. So the weak configuration is still expressible, and the startup
  banner names it — *"NO proxy secret — any process at that address can forge the header"* —
  rather than leaving an operator to infer it from a configuration that looks strict. A local
  process also still has better attacks available, starting with reading `tokens.toml`.
  *(By design that it is optional; the mechanism is built)*
* **TLS is not terminated in-process, ever.** Deliberate: every supported topology terminates
  in front, so an in-process listener would be a security-critical path almost nobody runs.
  *(By design)*

## 6 · Containment

* **Unconfirmed is not contained.** A quarantine transitions the registry immediately; the
  party keeps working until every mediator holding its contracts stops honouring it. If a
  mediator is unreachable, the contract expires on its own `exp` and not before — **TTLs are
  the real containment bound.** *(By design)*
* **A revocation feed that cannot be verified denies everything.** Fail-closed, and
  indistinguishable from an outage from outside. Expect it to arrive as "all the agents are
  down". *(By design)*
* **The containment drill uses a file where the hardware token belongs.** `containment-drill.sh`
  runs in CI and rehearses the *wrapper*. What fails on the day — a flat battery, a forgotten
  PIN, a share-holder who left in March — is precisely what a laptop cannot rehearse.
  *(Unproven)*
* **Propagation has never been timed.** §7.10 promises under 60 s estate-wide;
  `wc_mediator_ack_lag_seconds` has a bucket at 60 so the claim is measurable, and nobody has
  measured it on a real estate. *(Unproven)*
* **Lifting a quarantine is dual-controlled and deliberately incomplete.** `connect
  unquarantine` and `POST /v1/quarantine/clear` return a party to `Pending` for full
  re-admission — a path that did not exist at all until the metric work went looking for it,
  which made quarantine a one-way door whose only recovery was hand-editing a hash-linked log.
  What clearing does **not** do is restore contracts: they stay revoked, and the party has to
  be issued new ones. That is intended, and it is stated in the command's output and in the
  evidence record because "cleared" reads like "back to normal". *(By design)*
* **The drain/abort choice does not exist yet.** `wc_mediator::drain` defines `drain` and
  `abort` for work in flight when a revocation lands, and **nothing calls it** — there is no
  `--on-revoke` flag. New calls are refused the moment a revocation is installed, which is the
  containment half and works; the in-flight call finishes, bounded by `--upstream-timeout`
  (30 s) rather than by a drain window. So the module's stated default — `abort`, because
  `drain` is the permissive reading — is not in force. For the stdio sidecar that is one
  already-authorised call; the distinction belongs to the shared-gateway topology, which is not
  deployable either. *(Unbuilt, and stated in the module)*
* **A `--contract FILE` mediator cannot be contained at all.** Revocation reaches a mediator
  only through the control-plane pull, so a mediator handed contract artifacts on disk serves
  them until they expire and no quarantine can arrive. It reported
  `wc_revocation_trusted 1` while in that state, which is now 0 alongside a
  `wc_revocation_source_configured 0` gauge, a startup warning and its own alert. The
  behaviour is unchanged and correct for a genuinely air-gapped deployment — **containment
  there is contract TTL, so the TTL is the containment decision.** *(By design, and now
  visible)*

## 7 · Evidence and retention

* **Segment retirement exists; it moves evidence and never deletes it.**
  `connect retention --retire SEQ --anchor-pub PEM` retires sequences `1..SEQ` out of the live
  chain into `retired/segment-*.jsonl`, leaving a tombstone that keeps `audit verify` passing
  and reports where the chain now starts. Four refusals: a chain that does not verify, a row
  still inside its retention window, a range **no signed checkpoint covers** — without one,
  retiring and truncating are the same operation — and retiring the head.

  Two things remain yours. **The archive is moved, not deleted**: shipping it to WORM storage
  and removing it is your hand, deliberately, because a control plane that can erase its own
  evidence is a control plane whose evidence is worth less. And **nothing schedules it** —
  there is no rotation daemon, so retirement is a cron job you write against the window
  `connect retention` reports. *(By design that it does not delete; scheduling is Unbuilt)*
* **`connect serve` requires durable storage.** An evidence chain that restarts on reschedule
  has no history, which for the regulatory purpose it serves is the same as none. No
  `emptyDir`. *(By design)*
* **Truncation is bounded by the anchor interval, not prevented.** A hash chain cannot detect
  its own truncation — drop the last rows and what remains links perfectly. `audit verify`
  used to report *"chain is intact"* on exactly that, and now compares the chain head against
  the highest checkpoint sequence (no anchor key needed) and refuses to print an unqualified
  verdict. What remains open is **everything appended since the newest checkpoint**: with the
  default `--anchor-interval 100`, up to 99 rows can be removed undetectably, and before the
  first checkpoint is written the whole chain can. Shorten the interval to shorten the window;
  an off-host copy of the anchor file is what closes it, because an attacker holding the
  control plane can truncate both files together. *(By design, and now stated in the output)*
* **`wc_anchor_age_seconds` is liveness, not integrity.** Read without verifying signatures,
  because a scrape has no public key. It is exactly the number an attacker who could rewrite
  the chain would want looking healthy. Integrity is `connect audit verify --anchor-pub`, on a
  schedule, from a host that is not the control plane. *(By design)*
* **No offsite shipping.** `connect backup` writes a directory; getting it to WORM storage is
  your scheduler's job. Deliberate — a WORM credential inside the control plane is a new blast
  radius. *(By design)*
* **No measured RTO.** The restore drill is a procedure; nobody has run it against a
  production-sized root and recorded the time. "We can restore" and "we can restore inside our
  RTO" are different claims. *(Unproven)*

## 8 · Availability

* **`flock` does not fence a partitioned active.** It is advisory and node-local, so the
  storage layer must guarantee single attachment — `ReadWriteOnce`, one EBS volume, one
  Managed Disk, one LUN. **The lock is the election; the volume is the fence.** A deployment
  that moves the state root to a shared filesystem to make failover easier has removed the
  thing that made failover safe. *(By design)*
* **Failover under load is untested.** The handover is exercised — including a crash, a torn
  final record, and a standby refusing to start when it cannot elect — but not with a mediator
  mid-pull. The design's answer is that an agent sees nothing (§7.8 A9), and that has not been
  demonstrated across a handover. *(Unproven)*
* **`connect serve` is single-writer and must not be replicated.** Active/standby only.
  *(By design)*
* **A `SIGTERM` loses up to one metrics flush interval.** Bounded and acceptable for
  cumulative counters. *(By design)*

## 9 · Interoperability

* **The `wcs1` vectors exist; nobody outside this repository has run them.**
  [`fixtures/canon/`](../fixtures/canon/README.md) publishes 31 *input surface → canonical
  bytes → digest* vectors with a harness (`scripts/canon-conformance.sh`), which is what was
  missing. What is still open is the part only a second implementation supplies: the set was
  checked against a deliberately wrong canonicaliser — it catches stripped zero-width
  characters, `1.0` normalised to `1`, and over-eager array sorting — and never against a real
  one. Three rules are the likely disagreements and are called out in that README: preserved
  invisibles, numbers kept in the form they were written, and the allowlist. *(Unproven)*
* **The conformance kit covers all nineteen vectors, plus six mediator scenarios.** The four
  context-stage vectors used to be reported as **deferred**, because a command-line verifier
  cannot answer them and covering them meant being a mediator with no fixtures for it.
  `fixtures/contracts/scenarios/` is those fixtures: each carries the authenticated peer pair,
  the presented surface, the revocation feed and the zone policy checks 6–11 need, and
  `connect verify --scenario` runs them. One is a **positive control** — without it an
  implementation that refuses everything would pass every refusal vector.

  What is still missing is the same thing as everywhere else: **no second implementation has
  run them.** The harness is mutation-checked against an artifact-only verifier and a
  refuse-everything stub, not against a real second mediator. *(Unproven)*
* **The vector set is not signed.** Nothing attests that the vectors you downloaded are the
  ones published. *(Unbuilt)*
* **Interop is only as good as the implementations tried.** Two defects in stage 4 survived
  every test because all our fixtures were minted from an independent *reading* of the specs
  rather than an independent *implementation* — cosign omits `keyid` and signs DER, and the
  verifier accepted only its own dialect. Assume the same is true of anything not yet tried
  against real output.

## 10 · Observability

* **`wc_standing_share` is not emitted, and in v1 there is nothing for it to measure.**
  Standing issuance — auto-approval — is **off** (`[standing] enabled = false`), so the share
  is definitionally zero and the panel would teach an operator to ignore it. Even once the
  feature is enabled the metric stays unbuilt on purpose: the caps apply per zone pair, tier
  and surface shape, so one ratio across an estate averages incomparable populations, and a
  number on a dashboard invites somebody to manage the ratio rather than the risk. The cap is
  *enforced* and a breach escalates to a human by itself, so the metric would inform no
  decision anybody is not already being asked to make. *(By design)*
* **A mediator has no `/metrics` endpoint.** By design — it speaks stdio to one agent, and a
  listener would add a port, a bind address and an auth decision to a sidecar whose argument
  is that it adds no surface. Metrics go to a file for a textfile collector. *(By design)*
* **The alerts are unit-tested, not battle-tested.** Nine rules with `promtool test rules`
  proving each fires and stays quiet, plus a live scrape. None has fired in anger.
  *(Unproven)*
* **Cardinality is capped at 256 series per family.** Past that, series fold into
  `overflow="true"` and the fold is counted. `wc_contracts_active{zone_pair,tier}` is quadratic
  in zones and is the family most likely to reach it. *(By design)*

## 11 · Multi-tenancy and residency

* **Residency escalates; it does not prevent.** §8.7.3's rule is that jurisdictions spanning
  more than one residency group escalate the tier one step, pulling the connection into human
  approval and then dual control. warden-connect does not route traffic and cannot see where
  bytes go: a crossing is **declared, tiered and approved**, not blocked. Anything stronger is
  a network and storage property. Asserted as a test so the claim cannot quietly grow.
  *(By design)*
* **Residency groups are a default, not a legal opinion.** Configurable because an estate's
  real boundaries are counsel's answer. *(By design)*
* **Two regions are two tenants under one root.** The tests exercise isolation, key separation
  and escalation — not two volumes, two failure domains, and a partner federation across them.
  *(Environmental)*

## 12 · Packaging and supply chain

* **Nothing is published to crates.io yet, but it can be.** `warden` is a **version**
  requirement now rather than a path, patched to the sibling checkout for local development
  only, so `cargo add wc-mediator` becomes possible and a consumer no longer needs two
  repositories at commits nothing recorded. `cargo package -p wc-core` succeeds and
  `cargo deny check bans` passes.

  What is left is sequencing and a decision: **Warden core must go to crates.io first**, since
  `wc-mediator` depends on a published `warden`; then wc-core, wc-control, wc-mediator, wc-cli
  in dependency order. And **the `[patch.crates-io]` must be deleted and the build repeated**
  before believing any of it — while the patch is present the build never touches the registry,
  so it is a development convenience and also a blindfold. Nothing is tagged. *(Environmental:
  a registry account and a decision to tag)*
* **Release provenance is built and the workflow has never run.** `release.yml` attests each
  binary with a DSSE/in-toto SLSA v1 envelope, signed keyless, and verifies what it just
  attested with our own verifier in the same run. A downloader runs
  `scripts/verify-release.sh`, which needs no Sigstore client, no network and no cosign.
  `connect attest verify` — the standalone command that makes it possible — is verified against
  **real cosign v3.1.3 output**, including a substituted artifact, an unlisted builder, an
  untrusted key and a missing allowlist. The workflow itself is written from documentation, so
  run it with `workflow_dispatch` before tagging.

  Still not done: **no signed git tags** (a key-custody decision like the rest), **no
  reproducible-build claim** (unmeasured), **the image is not attested** (only the binaries),
  and `connect attest verify` does **not** walk the Fulcio certificate chain — it is offline by
  design, so `cosign verify-blob-attestation` is the other required half and neither
  substitutes for the other. *(Unproven workflow; the rest Unbuilt)*
* **The SDK is not released.** `sdk/python` is installable from a checkout and has no packaged
  release **yet**. It has a test suite that needs no control plane — 20 tests over what a
  status means, whether a retry is safe, and whether a refusal keeps its `WC-*` code, run in
  CI and mutation-checked against a reintroduced replay bug. The wheel and sdist build, the
  wheel installs into a clean Python 3.9 venv and works when imported from outside the
  checkout, and the sdist's tests pass from the unpacked sdist. `sdk-release.yml` publishes it
  by OIDC with no stored token.

  What remains needs you: claiming the PyPI name, adding the trusted publisher, and creating
  a `pypi` environment with reviewers. **And the workflow has never run** — it is written from
  documentation, so the first run should target TestPyPI via `workflow_dispatch`. The examples
  still need a live control plane and so still run by hand. *(Environmental, plus one
  unproven workflow)*
* **The image is verified in CI only** for the arm64/amd64 pair CI builds; no multi-arch
  manifest is published.

## 13 · Configuration

* **Ten §8.13 keys are refused rather than honoured**, because the behaviour does not exist:
  `[server].tls`, `[policy].hot_reload` and `pdp_url`, `[admission].rekor` and
  `require_provenance`, and others. Refused *with a reason*, so an operator who sets
  `hot_reload = true` is told SIGHUP reloads nothing rather than finding out during a policy
  change. *(Unbuilt, and named at the point of refusal)*
* **No policy hot reload, by decision for v1.** A policy change takes effect on restart of the
  enforcement point — restart `connect serve`, and restart each `connect-mediate` whose
  `--policy` changed. On active/standby that restart *is* a failover: the standby is already
  waiting on the writer lock, takes it when the active releases, and binds its listener then,
  so the sequence is "restart the active, the standby takes over" rather than a coordinated
  swap. Contracts already minted are unaffected — a policy governs *issuance*, and a live
  contract carries its own terms and `policy_version`.

  Deliberately not built for v1: a hot reload is a second code path that changes the decision
  engine underneath in-flight requests, and it would want its own answer to "which
  `policy_version` did this mint use". A restart has one answer. *(By design for v1)*
* **No AuthZEN PDP passthrough, and it is out of scope here.** AuthZEN is the OpenID
  Foundation's Authorization API — a standard shape for asking a PDP *"may subject S do action A
  on resource R"*. **Warden core already implements it** (`warden/src/authzen.rs`, serving
  `POST /access/v1/evaluation`), which is the right layer: AuthZEN answers *per-request*
  questions and core is the per-action plane.

  warden-connect answers a different question — may these two parties have a standing
  relationship, and on what terms — decided by a human against a versioned policy and recorded
  in a signed artifact. Deferring that to an external PDP would mean the contract's terms came
  from somewhere the evidence chain cannot reconstruct, which breaks the property that every
  mint is answerable years later. It is not a `warden-delegate` candidate either: delegate is
  about authority *attenuating* across hops, and AuthZEN has no notion of a delegation chain.
  *(By design)*

## 14 · Testing depth

* **Two hardening passes have been run; neither was independent.** The first covered the six
  paths in [production-readiness.md](production-readiness.md); the second covered the five areas
  it left — `screen`, the ceilings, the drain path, federation, residency. Together **nine
  defects of the usual shape plus two reporting gaps**, all fixed or documented, all tabulated
  in [threat-model.md](threat-model.md) Part 1. Federation and residency came out clean under
  the same probing, which is the first time any area has.
  The reason this stays on the list is that both passes were run by the same author as the
  code, and the hit rate has not fallen off: pass two still found three in five areas. An
  independent reviewer is a different instrument, and there has not been one. *(Unproven)*
* **Fuzzing is smoke depth.** One minute per target. The nightly workflow turns that into hours
  per week and has not run yet. *(Unproven)*
* **No 10⁵-contract estate has been operated**, only benchmarked. The scale gates measure
  `rebuild`, `blast_radius` and a DORA export at that size; nobody has run a control plane
  holding it. *(Unproven)*
* **§8.10.3's published latency figures are reference-hardware figures.** The table names the
  machine now. Two capacity gates enforce a ceiling ~2× the slowest hardware we run on, which
  means a 2× regression in `blast_radius` or `rebuild` would slip through; it is not tighter
  because a shared runner swings more than 50% between runs and a flaky gate gets disabled.
  *(By design, and stated on the constants)*
* **Our own commands in these documents are checked; third-party commands are not.**
  `every_documented_command_exists_with_the_flags_it_claims` parses every `connect …` line in
  every Markdown file — 72 of them — and validates the subcommand and every flag against
  `COMMANDS` and `accepted_flags`, with the tables in scope rather than copied. On its first
  run it found **thirteen** claims that did not hold, all in the HLD and LLD: seven flags never
  built, one command renamed, and a mediator block describing a different binary. Those are
  fixed or marked.

  What is still unchecked is every command belonging to somebody else — `kubectl`, `openssl`,
  `spire-agent`, `brew`. The SPIRE procedure's four wrong commands were all of that kind, and
  nothing here can validate them short of running them. Assume any *third-party* invocation in
  these docs has not been run. *(Unproven, for third-party commands)*

---

## The pattern worth knowing before you rely on any of this

Across the build, **the defects that mattered were almost never a missing control — they were
a control that read as configured and did nothing.** Fourteen of them are tabulated in
[threat-model.md](threat-model.md) Part 1. Not one was found by reading code; every one was
found by executing a flow, and three were found inside tooling written to check other things.

Two consequences for a reader:

1. **Anything on this page marked *Unproven* should be read as "may not work".** The mechanism
   passing tests is weaker evidence than this repository's own history suggests it should be.
2. **Anything added recently is the least exercised.** If you are auditing, start with what
   changed last rather than with what looks most important.
