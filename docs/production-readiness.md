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

- [ ] **1. CI. There is none.** `.github/` does not exist. Every claim in this
  repository — the 791 tests, clippy clean, the conformance vectors, the bench
  gates — is true on one machine, today, and nothing keeps it true. This is the
  largest gap in the project and it blocks everything below it, because the value
  of the rest is that it *stays* proven.

  Needs: `fmt` + `clippy -D warnings` + build + test on the pinned MSRV (1.89) and
  stable; `connect bench` on a reference runner (§8.10.3 thresholds are the
  design's, not the machine's, so a slow runner must report honest failures rather
  than recalibrate); the conformance vectors; the fuzz mirror; `cargo-deny`.

- [ ] **2. Two named performance gates do not run.** §8.10.3 names six.
  `connect bench` implements `contract::mint`, `gate::verify warm`,
  `gate::verify cold`, `assurance::blast_radius`, `canon::wcs1` and `screen` —
  which means **`filter_tools_list` at 256 tools and `Projection::rebuild` at 10⁵
  contracts are named in [`bench.rs`](../crates/wc-control/src/bench.rs)'s own doc
  comments and never measured.** A named gate that does not run is exactly the
  species this codebase keeps hunting, and `bench` is the module that argues
  loudest that a skipped gate must fail the run.

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

- [ ] **5. Signing keys are PEM files on a filesystem.** Issuer keys, approver
  keys, revocation keys, anchor keys. The issuer key is the root of authority for
  every contract in the estate: a host compromise is an estate compromise, and
  nothing in the design limits the blast radius of that one file.

  Needs a decision, then either half of it: a `Signer` trait with a KMS/HSM
  implementation behind it, **or** an explicit `SECURITY.md` boundary that puts
  host compromise out of scope, as Warden core does. Shipping without picking one
  is the gap, not the choice.

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

- [ ] **8. Nothing that a shipped repository needs exists.** No `README.md`, no
  `LICENSE`, no `SECURITY.md`, no `CONTRIBUTING.md`, no `CHANGELOG.md`.
  `docs/twelve-factor.md` is referenced by the LLD and is not there. No
  `deny.toml` — for a component whose central operational argument is a thin
  dependency tree (30 crates for `wc-core`, 61 for `wc-control`), not asserting
  that in CI with advisory and licence policy is a strange omission.

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
