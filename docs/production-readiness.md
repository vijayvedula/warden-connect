# Production-readiness plan

> **Status (2026-08-07): feature-complete against [08-lld.md](08-lld.md), not
> production-ready.** Every module in the P0–P4 build order (§8.16) exists and is
> tested. What is missing is almost entirely the operational layer around it —
> starting with the fact that **there is no CI**, so nothing below is verified
> anywhere except one laptop.
>
> Same shape as Warden core's
> [production-readiness checklist](../../warden/docs/production-readiness.md), and
> the same rule: an item is only checked off when something *runs* that proves it.

## Where the build actually is

| | Evidence |
|---|---|
| Modules delivered | All of P0–P4 (§8.16). `wc-core` 7 modules, `wc-control` 23, `wc-mediator` 8, `wc-cli` |
| Tests | 791 green — 685 unit, 44 integration, 15 e2e (§8.15.4), 12 failure-injection (§8.15.5), 15 property (§8.15.1), 6 fuzz-mirror (§8.15.2) |
| Conformance | 19 vectors in `fixtures/contracts/`, driven off `expected.json`; `connect verify` is the ground truth (§8.15.3) |
| Lint | `cargo clippy --workspace --all-targets` clean, `unwrap_used`/`expected_used` warned workspace-wide |
| Fuzz | 5 libfuzzer targets compile on nightly; **no campaign has been run** — `cargo-fuzz` is not installed |

Four §8.16 acceptance criteria **are** met and demonstrated: conformance vectors
100%, `tools/list` filtering end-to-end against unmodified Warden core, the
200-mediator quarantine under 60 s with unconfirmed reported, and drift suspension
exercised in e2e. The rest of the criteria are listed under P1 #9 below, unmet.

---

## P0 — blockers to production

Nothing ships to a real estate until every one of these is done. They are ordered
by what unblocks the others.

- [x] **1. CI.** `.github/` does not exist. Every claim in this
  repository — the 791 tests, clippy clean, the conformance vectors, the bench
  gates — is true on one machine, today, and nothing keeps it true. This is the
  largest gap in the project and it blocks everything below it, because the value
  of the rest is that it *stays* proven.

  [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — five jobs: `fmt` +
  `clippy -D warnings` + test on stable; the same tests on the pinned MSRV; the
  release-mode latency gates; `cargo-deny` plus a dependency-count ceiling; and the
  fuzz targets compiling on nightly. Every step was run locally before it was
  committed, including `cargo +1.89 test --workspace` against a real 1.89 toolchain —
  a CI job nobody has executed is the same species of claim as the gate that pointed
  at a test that did not exist.

  Three things it does that a default workflow would not:

  * **The release-mode gates are named.** `cargo test` defaults to debug, where a
    latency ceiling measures the debug build; `gate_filter` asserts a 12× tripwire
    there and says loudly that it is not the real gate, so `--release` is invoked
    explicitly.
  * **It lays the tree out the way `warden` expects.** Core is a path dependency at
    `../warden` by design (§8.3), so CI checks out both repositories side by side.
    Needs a `WARDEN_CORE_TOKEN` secret while core is private.
  * **No global `RUSTFLAGS: -D warnings`.** It applies to dependencies too, so a
    warning from a new compiler version in somebody else's crate would fail the build
    for a reason nobody here can fix. `-D warnings` goes on the clippy invocation.

- [x] **2. Every §8.10.3 gate now runs.** Both missing gates are implemented, and
  running them for the first time found a defect and moved a threshold.

  * **`store::rebuild` at 10⁵ contracts** — implemented in `connect bench`, which
    writes the fixture once and replays it. Passes at **p99 293 ms against 600 ms**.
    The fixture is asserted to have replayed what was written, because a gate timing
    a rebuild that produced an empty projection would report an excellent number for
    doing nothing.
  * **`filter_tools_list` at 256 tools** — implemented as `gate_filter_tools_list_
    256_tools` in `wc-mediator`'s suite, because measuring it needs a crate the CLI
    does not link (§8.3). The skip message `connect bench` prints is now built from
    `thresholds::FILTER_GATE_COMMAND`, and a test asserts that command selects this
    test — the previous pointer named `gate_filter` and no such test existed.

  **The defect.** `filter_catalog` deep-cloned every *permitted* entry into a new
  vector, so filtering a 256-tool catalogue cost a nested-object clone per surviving
  tool: p99 189 µs. Retaining in place instead is ~40 µs. Found by the gate, on its
  first run.

  **The threshold.** 50 µs was written down without ever being measured. Post-fix
  the p99 is 35–45 µs, which passes — but with margins between 9% and 31% across
  runs, because the residual is dominated by *deallocating* removed entries and is
  allocator-noise bound. `bench.rs` says a gate passing at thin margin is worse than
  one that fails outright, and that has to hold when it is inconvenient, so
  `FILTER_256` is now 100 µs (~2.2× the measured p99: stable, and still tight enough
  to catch the 4.7× regression class this gate just caught). Recorded on the
  constant, in §8.10.3, and pinned by a test.

  Not a recalibration to the machine — the same measurement pass moved
  `MINT_OVERHEAD` the *other* way, from a 500 µs rubber stamp to 50 µs. A threshold
  nobody has run is a guess, and which direction it moves is not predictable.

  Remaining, for CI (#1): the latency gates only mean anything in a release build.
  `cargo test` defaults to debug, so `gate_filter` asserts a 12× tripwire there and
  says loudly that it is **not** the §8.10.3 gate. **CI must run
  `cargo test -p wc-mediator --release gate_filter` and `connect bench` explicitly**,
  or those two gates read as covered by a debug test run.

- [ ] **3. Real attestation material, end to end.**
  [`attest.rs`](../crates/wc-control/src/attest.rs) has the verifiers —
  `JwtSvidIdentity`, `JwksCardVerifier`, `DsseProvenanceVerifier` — and
  `admission` runs on **P0 stand-ins** unless an operator supplies material for
  each stage. Nothing proves the real path against a real SPIRE SVID, a real
  signed agent card, or real SLSA provenance from an actual builder. Until it
  does, every party in a real estate is `Unattested`, and P2's whole posture model
  is untested against reality rather than against fixtures.

  Needs: an integration environment with SPIRE and a signing builder, and the
  four-stage happy path asserted against material this repo did not mint.

- [ ] **4. Screening ships uncalibrated, and its own exit gate is unmeasured.**
  `ScreenRules::calibrated = false` is deliberate — blocking is earned on
  `fixtures/screening/`, never asserted in a default — and that is correct. But
  §8.16's P2 exit criterion is *precision ≥ 0.98 on the labelled corpus*, and the
  test that measures precision prints it and says **"measured, not gated"**. So the
  number that decides whether a detector may block is a number CI does not check.

  Needs: the corpus expanded (it is small enough that one bad case moves precision
  by more than the threshold's own margin), the number gated in CI, then a shipped
  ruleset with `calibrated = true` and a documented basis for it.

- [~] **5. Signing keys are PEM files on a filesystem.** The seam and the first
  key are done; the remaining sub-items are custody *deployments*, not code. See
  [key-custody.md](key-custody.md) for the decision and its reasoning. Six
  operations sign, `IssuerKey` is the seam for five of them, and they do **not**
  all want the same custody — so this is five sub-items, not one:

  | | Key | Custody | Why |
  |---|---|---|---|
  | 5a | **Anchor** (chain checkpoints) | HSM or offline | **Done in code** — `Anchor` holds an `IssuerKey`, `connect --anchor-signer CMD` delegates it, and an existing `anchor.jsonl` written before the change still verifies. What remains is procuring the token and writing the procedure |
  | 5b | **Issuer** (contract mint) | KMS, no local copy | **Done in code** — `--signer`, `--require-external-signing` enforcing it, and `key_custody` recorded in every mint event so the posture is auditable backwards. The `contract::mint` gate did **not** need raising: measured p99 is 677 µs against 20 ms, so ~19 ms of signing already fits. A new `contract::mint overhead` gate (1.9 µs / 50 µs) separates our cost from the signer's, so a slow delegated mint is attributable. What remains is procuring the KMS key and the mint-volume alerting that bounds a held host |
  | 5c | **Revocation** | two `kid`s: online in KMS, offline on a hardware token | Deny-only, so its failure mode is availability, not forged authority. Must work when the KMS does not. Detail below |
  | 5d | **Approver** | never the service's KMS | If the control plane can sign its own approvals, dual control is theatre. Wants a hardware token or the approver's IdP-backed key. Separate PEMs today, kept apart by the operator rather than by anything structural |
  | 5e | **Bundle envelope, CAEP sink** | follow the issuer key | Low volume, latency irrelevant |

  **The `Signer` trait is in place.** [`wc_core::contract::Signer`],
  `IssuerKey::external`, and [`wc_control::signer::CommandSigner`] — which
  delegates to an operator-supplied command, so an HSM or KMS needs no new
  dependency. `--signer` and `--anchor-signer` on every command that signs;
  supplying both a PEM and a delegated form is an error rather than a silent
  preference. It replaced "hand me an `EncodingKey`" with
  `sign(signing_input) -> signature`, so `mint` and `sign_detached` stop calling
  `jsonwebtoken::encode` and construct the JWS compact form themselves. The
  pattern already exists here — `pae()` and `card_signing_input()` in
  [`attest.rs`](../crates/wc-control/src/attest.rs) do exactly this. The risk is
  byte-exactness: a hand-rolled header must match `jsonwebtoken`'s serialisation or
  every existing artifact stops verifying, which is what the 19 conformance vectors
  are for.

  **Two revocation keys, not a copy of one (5c).** The verification side already
  supports this and needs no change: `SignedRevocation` carries a per-entry `kid`
  and `verify` resolves it against an `IssuerKeys` map, so mediators can trust two
  revocation keys at once and the feed records which one signed each order.

  - `revoke-online` — in the KMS, used by `connect quarantine` in normal
    operation. Fast, scriptable, no ceremony.
  - `revoke-offline` — private key **non-exportable on a hardware token** (PIV /
    YubiKey / Nitrokey), token in a tamper-evident bag in a safe, activation PIN
    split M-of-N across named holders in separate locations. Used only when the
    KMS or the control plane is unavailable.

  Not named `breakglass`: [`connect breakglass`](../crates/wc-cli/src/main.rs)
  already means time-boxed emergency *issuance*, and colliding the vocabulary of
  emergency-grant and emergency-revoke is how a runbook gets followed wrongly at
  03:00.

  Three properties this buys that a second copy of one key does not: compromise of
  either does not imply the other; `revoke-offline` can be rotated without touching
  normal operation; and **use of the offline `kid` is itself a high-severity
  event** — it happens approximately never, so one use is a page. The evidence
  chain, `Severity` and blocking sinks already carry that.

  **And it must be rehearsed.** A break-glass key nobody has used is a key that
  probably does not work: flat token, forgotten PIN, share-holder who left in
  March. This is what the quarterly containment drill in §8.16's P3 is for — see
  P1 #9, where it is listed as missing. The drill must exercise the offline path,
  not only the online one.

- [ ] **6. JWKS is file-only.** `keys.rs` has the keyring, rotation lifecycle and
  retirement guard, and `connect keys jwks` writes the document. A mediator is
  pointed at a *file*, so a rotated issuer key needs an out-of-band deploy before
  anything verifies against it. Same residual Warden core carries; here it is
  worse, because contracts outlive a rotation by design.

  Needs: HTTP fetch with a TTL cache, and a rotation drill that proves a mediator
  picks up a new `kid` without a restart.

- [ ] **7. No TLS on `connect serve`, and bearer tokens do not require it.** The
  default listener is `127.0.0.1:8787`, which is fine; nothing stops an operator
  binding `0.0.0.0` and shipping approval tokens in plaintext. Warden's answer is
  TLS at a front proxy — that needs to be the documented answer here *and* the
  binary should refuse bearer-token auth on a non-loopback listener unless the
  operator asserts a terminating proxy.

- [~] **8. Nothing that a shipped repository needs exists.** No `README.md`, no
  `LICENSE`, no `SECURITY.md`, no `CONTRIBUTING.md`, no `CHANGELOG.md`.
  `docs/twelve-factor.md` is referenced by the LLD and is not there.

  `deny.toml` **is** now there, and it found a real advisory on its first run —
  see below. It also settled the dependency-count question: the LLD claimed 30
  crates for `wc-core` and 61 for `wc-control`; the tree resolves to **80 and 110**,
  of which `jsonwebtoken`'s `rust_crypto` feature is 75 on its own. Ceilings are now
  asserted by [`scripts/dep-count.sh`](../scripts/dep-count.sh) at the measured truth
  plus headroom, so the next addition is visible rather than silent.

---

## P1 — scale and operability

- [ ] **9. Four §8.16 acceptance criteria were never measured.** They are stated
  as exit gates and no run exists:

  | Phase | Criterion | Status |
  |---|---|---|
  | P0 | 10⁴ entities registered from CI | never run |
  | P3 | quarterly containment drill script in the repo | no script |
  | P4 | DORA register generated in < 1 h at 10⁵ contracts | never run |
  | P4 | partner federation e2e against a **second** control plane | never run |

  The last one matters most: federation is the claim that two organisations
  interoperate on two signed artifacts, and it has only ever been tested against
  itself.

- [ ] **10. HA is one sentence, not a tested mode.**
  [`store.rs`](../crates/wc-control/src/store.rs) says *"High availability is
  active/standby with that lock as the election primitive."* The failure-injection
  tier proves a second writer is refused (`WC-8003`) and that the lock is released
  when the holder goes away. It does not exercise a **handover**: what a standby
  does with a projection that is behind, how long election takes, what a mediator
  sees during it, or what happens to an in-flight approval.

- [ ] **11. Observability is a counter set, not an operable signal.**
  `api.rs` has six `AtomicU64` counters (`requests`, `denied`, `minted`,
  `escalated`, `replays`, `pulls`) behind `/metrics`. §8.14 specifies roughly
  fifteen metric families with labels — `wc_denials_total{code}` for *every* WC-\*
  code, `wc_verify_duration_seconds_bucket{path}`,
  `wc_filter_tools{state}`, `wc_drift_total{class}`. Almost none are emitted, and
  there is **no structured decision log on the mediator path at all**, which is
  the thing an operator would actually alert on.

  Needs: the §8.14 families emitted; per-decision JSON logs carrying `cid`, code
  and mode; and a documented alert set. The four alerts this design implies and
  nobody has written down: ACK lag, mediators reported unconfirmed, a **distrusted
  revocation set**, and blocking-sink failures.

- [ ] **12. Config is flags plus two TOML sections.** `connect.toml` covers
  `[[sink]]` and `[assurance]`; everything else is command-line flags. The LLD
  claims twelve-factor config with a stated precedence (flag over file over env)
  and the binaries do not implement it — which is also why `docs/twelve-factor.md`
  is missing rather than merely unwritten.

- [ ] **13. Packaging.** No Dockerfile, no published image, no release process, no
  SBOM. Worth naming plainly: `export::cyclonedx_bom` produces a CycloneDX BOM of
  a *tool surface*, and the product that generates BOMs ships without one of
  itself.

- [ ] **14. Backup, restore and retention are undocumented and untested.** The
  evidence chain and the state log **are** the system of record — that is the
  whole argument for shipping no database (§8.16b). There is no tested restore
  procedure, no retention policy against the regulatory clock the export module
  assumes, and no WORM/offsite shipping for signed anchors. A tamper-evident chain
  on a disk nobody backs up is a compliance story with one point of failure.

---

## P2 — completeness and developer experience

- [ ] **15. Coverage-guided fuzzing has never run.** Five targets and seed corpora
  exist; the stable mirror runs on `cargo test` and exists precisely so the targets
  cannot rot into not compiling. That is not the same as a campaign. Needs
  `cargo-fuzz` in CI on a schedule, corpus committed as it grows, and any crash
  turned into a unit test.

- [ ] **16. The conformance kit is fixtures, not a kit.** The independence
  argument — *implement the checks in your own egress layer and still
  interoperate* — rests on `connect verify` being ground truth. Today that is 19
  files and an `expected.json` in `fixtures/contracts/`. There is no packaged kit,
  no documented harness for a third party, and no version policy for the vectors.
  Until there is, "no lock-in to our data plane" is an assertion.

- [ ] **17. No SDK, no examples.** Warden core has `sdk/` and `examples/`. For the
  mediator this matters least (it compiles into the proxy by design); for the
  control-plane API it matters most, and that is the surface a platform team
  integrates against.

- [ ] **18. Operator documentation.** The design docs are thorough and are not
  operator documentation. Missing, all of which Warden core has: a deployment
  guide, a runbook, and a **threat model**. The threat model is the one with teeth
  — the five defects found in the last test pass were all *silent control
  failures*, and a written threat model is what turns that pattern into a checklist
  instead of a habit.

- [ ] **19. Multi-tenancy and residency at scale.** `tenant.rs` and `federate.rs`
  are unit-tested, including the path-traversal fix and cross-tenant `WC-8002`.
  No two-region deployment has been stood up, and residency is the constraint the
  one-pager leads with.

---

## Hardening review — planned, not started

Warden core ran an adversarial pass over its security-critical paths before going
open source and it found a dozen real defects, each of which now has a regression
test. warden-connect has not had one, and the case for it is already made: the
test work of the last two days found **five** defects without looking for them,
and every one was the same species — a control that reads as configured and does
nothing, or does the opposite:

1. observe mode enforced, making the P0 rung undeployable;
2. an enforce-mode refusal that left no incident behind;
3. standing policy auto-issuing to a party whose attestation had just failed;
4. a corrupted revocation feed that reported itself and granted anyway;
5. `Terms::intersect` — the narrowing algebra — able to widen under a fold.

Paths to review, in the order their compromise costs most:

| Path | Why it is first |
|---|---|
| Issuance and key handling | The issuer key is the root of every contract |
| The 11-check mediation pipeline | The only place enforcement actually happens |
| `canon` / `wcs1` | A pin that can be laundered defeats all of drift detection |
| Chain and store integrity | The evidence is the regulatory artifact |
| Revocation and containment | The kill switch, and the one thing that must never fail open |
| `screen` | Attacker-controlled text by definition |

One rule for the pass, taken from what actually worked this week: **run the
binaries.** Every one of the five defects was found by executing a flow, not by
reading code — and 46 passing unit tests sat next to the traversal-direction bug
because they asserted struct fields while the bug was in the label above them.

---

## Working order

The sequencing is not arbitrary; each block makes the next one meaningful.

**First — make the claims durable (P0 #1, #2, #8).** CI before anything else,
because every subsequent item is a claim that needs to keep being true, and the
two dead bench gates plus `cargo-deny` are the cheapest possible proof that CI is
doing real work rather than running `cargo test`.

**Second — close the trust gaps (P0 #3, #4, #5, #6, #7).** These are the items
where the product currently *cannot* do what it says: nothing is attested,
screening cannot block, a rotated key needs a deploy, and the issuer key is a file.
Any one of them is a reasonable question from a security architect on day one, and
#5 needs a decision from you before there is anything to build.

**Third — make it operable (P1 #9–#14).** The unmeasured acceptance criteria first,
because two of them (federation against a second control plane; DORA at 10⁵) could
still surface design problems, and finding those after packaging is expensive.
Observability and the runbook next. Backup and retention before any pilot holds
data somebody would be asked about later.

**Fourth — the hardening pass.** After #3–#7, so the review covers the real
verifiers rather than the stand-ins, and before any external exposure.

**Fifth — reach and DX (P2 #15–#19).** The conformance kit is the highest-leverage
item in this block, because it is what makes the independence argument checkable
by somebody who does not trust us.

### One thing to decide before starting

**P0 #5 — KMS or a documented boundary.** Everything else on this list is work;
this one is a choice, it changes the shape of `issuance` and `keys`, and it is
cheaper to make now than after the hardening pass has been written against the
file-based assumption.
