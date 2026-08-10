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

Status: pre-1.0, no independent audit, no hardening pass yet.
[production-readiness.md](production-readiness.md) tracks the work; this tracks the gaps.

---

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
* **No transparency log is consulted.** The verifier's own verdict says
  `rekor inclusion not checked`. An unchecked inclusion proof reported as verified provenance
  would be worse than none, so it is reported as unchecked. *(Unbuilt)*
* **Stages are skipped, never assumed.** Not a limitation so much as the thing to understand:
  supply no material for a stage and the party simply does not attest for it. Read
  `connect posture` rather than assuming a green registration means five green stages.

## 3 · Key custody

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

## 4 · The transport control

* **A process at a trusted address can forge `x-forwarded-proto`.** With a same-host proxy,
  `--trusted-proxy 127.0.0.1` is satisfied by anything on the box, so a local process can
  present a bearer token over plaintext and be believed. Confirmed by doing it.

  The threat the control exists for — *remote* plaintext — stays closed, since a remote client
  cannot source from a trusted address, and a local process has better attacks available
  starting with reading `tokens.toml`. But **the check is only as strong as the separation
  between the proxy and everything else that can reach the port**, and no CIDR narrow enough
  fixes it because the forger shares the address. The real mechanism is a shared secret
  between proxy and listener. *(Unbuilt)*
* **TLS is not terminated in-process, ever.** Deliberate: every supported topology terminates
  in front, so an in-process listener would be a security-critical path almost nobody runs.
  *(By design)*

## 5 · Containment

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
* **A `--contract FILE` mediator cannot be contained at all.** Revocation reaches a mediator
  only through the control-plane pull, so a mediator handed contract artifacts on disk serves
  them until they expire and no quarantine can arrive. It reported
  `wc_revocation_trusted 1` while in that state, which is now 0 alongside a
  `wc_revocation_source_configured 0` gauge, a startup warning and its own alert. The
  behaviour is unchanged and correct for a genuinely air-gapped deployment — **containment
  there is contract TTL, so the TTL is the containment decision.** *(By design, and now
  visible)*

## 6 · Evidence and retention

* **Retention deletes nothing.** Removing a row from a hash-linked chain breaks every row
  after it, so retention here is *segment retirement* — retire whole segments once every row
  is past its clock, keep the anchor that covered them. That design does not exist, so the
  chain grows monotonically. `connect retention` reports the window and says so. *(Unbuilt)*
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

## 7 · Availability

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

## 8 · Interoperability

* **The `wcs1` vectors exist; nobody outside this repository has run them.**
  [`fixtures/canon/`](../fixtures/canon/README.md) publishes 31 *input surface → canonical
  bytes → digest* vectors with a harness (`scripts/canon-conformance.sh`), which is what was
  missing. What is still open is the part only a second implementation supplies: the set was
  checked against a deliberately wrong canonicaliser — it catches stripped zero-width
  characters, `1.0` normalised to `1`, and over-eager array sorting — and never against a real
  one. Three rules are the likely disagreements and are called out in that README: preserved
  invisibles, numbers kept in the form they were written, and the allowlist. *(Unproven)*
* **The conformance kit covers 15 of 19 vectors.** The four context-stage vectors need an
  authenticated peer, a presented surface and a revocation feed; a CLI verifier must admit
  them and the harness reports them as **deferred**, never as passes. Covering them means
  being a mediator, and there are no fixtures for that. *(Unbuilt)*
* **The vector set is not signed.** Nothing attests that the vectors you downloaded are the
  ones published. *(Unbuilt)*
* **Interop is only as good as the implementations tried.** Two defects in stage 4 survived
  every test because all our fixtures were minted from an independent *reading* of the specs
  rather than an independent *implementation* — cosign omits `keyid` and signs DER, and the
  verifier accepted only its own dialect. Assume the same is true of anything not yet tried
  against real output.

## 9 · Observability

* **`wc_quarantine_duration_seconds` is not emitted.** Needs the interval between a quarantine
  and its clearing; both events are in the chain and nothing computes the pairing. *(Unbuilt)*
* **`wc_standing_share` is not emitted.** §8.17-Q4 cap utilisation. The cap is enforced;
  expressing utilisation as one ratio across zone pairs needs a definition nobody has written
  down, and inventing one would put a number on a dashboard that means whatever the
  implementation decided. *(Unbuilt)*
* **A mediator has no `/metrics` endpoint.** By design — it speaks stdio to one agent, and a
  listener would add a port, a bind address and an auth decision to a sidecar whose argument
  is that it adds no surface. Metrics go to a file for a textfile collector. *(By design)*
* **The alerts are unit-tested, not battle-tested.** Nine rules with `promtool test rules`
  proving each fires and stays quiet, plus a live scrape. None has fired in anger.
  *(Unproven)*
* **Cardinality is capped at 256 series per family.** Past that, series fold into
  `overflow="true"` and the fold is counted. `wc_contracts_active{zone_pair,tier}` is quadratic
  in zones and is the family most likely to reach it. *(By design)*

## 10 · Multi-tenancy and residency

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

## 11 · Packaging and supply chain

* **Nothing is published to crates.io, and cannot be.** Every crate is `publish = false`
  because `warden` is a path dependency that cannot resolve from a registry. `cargo publish`
  of `wc-mediator` would fail; of `wc-core` would succeed and publish half a product. Making
  this publishable means giving core a registry version — a change to the family's coupling
  model, not a packaging chore. *(By design, until that decision changes)*
* **No release provenance.** This component *verifies* DSSE/in-toto SLSA envelopes and produces
  none of its own: no signed tags, no SLSA provenance for the binaries or image, no cosign
  signature, no reproducible-build claim. Trust in a downloaded binary rests on the transport.
  *(Unbuilt)*
* **The SDK is not released.** `sdk/python` is installable from a checkout, has no packaged
  release, and has no test suite beyond an import check — its verification is the examples run
  against a live control plane. *(Unbuilt)*
* **The image is verified in CI only** for the arm64/amd64 pair CI builds; no multi-arch
  manifest is published.

## 12 · Configuration

* **Ten §8.13 keys are refused rather than honoured**, because the behaviour does not exist:
  `[server].tls`, `[policy].hot_reload` and `pdp_url`, `[admission].rekor` and
  `require_provenance`, and others. Refused *with a reason*, so an operator who sets
  `hot_reload = true` is told SIGHUP reloads nothing rather than finding out during a policy
  change. *(Unbuilt, and named at the point of refusal)*
* **No policy hot reload.** A policy change needs a restart. *(Unbuilt)*
* **No AuthZEN PDP passthrough.** *(Unbuilt)*

## 13 · Testing depth

* **One hardening pass has been run; it is not enough.** The first adversarial pass covered
  the six paths in [production-readiness.md](production-readiness.md) and found **six defects
  of the usual shape plus two reporting gaps** — all fixed, all tabulated in
  [threat-model.md](threat-model.md) Part 1. The reason this stays on the list is the hit
  rate: a single pass over six paths still found six, so the next pass should be expected to
  find more rather than to confirm the code is clean. Not yet exercised adversarially:
  `screen` beyond the field allowlist, the ceilings, the drain path, federation, residency.
  *(Unproven)*
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
* **Nothing checks the commands in these documents.** Standing up a real SPIRE server turned up
  **four wrong commands in this repository's own SPIRE procedure** — a `brew` formula that does
  not exist, two subcommands SPIRE does not have, and a `sed` that would have written an *empty*
  token file. Every one had been written, reviewed and left alone. The scripts under `scripts/`
  are executable and therefore checkable; a fenced block in a `.md` is neither. Assume any
  procedure here that is not backed by a script has not been run. *(Unproven)*

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
