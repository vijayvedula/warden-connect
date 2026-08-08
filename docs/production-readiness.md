# Production-readiness plan

> **Status (2026-08-08): feature-complete against [08-lld.md](08-lld.md), not
> production-ready.** Every module in the P0–P4 build order (§8.16) exists and is
> tested. What is missing is almost entirely the operational layer around it.
>
> Same shape as Warden core's
> [production-readiness checklist](../../warden/docs/production-readiness.md), and
> the same rule: an item is only checked off when something *runs* that proves it.
> `[~]` means partly landed with the remainder named in the entry.
>
> **P0: six of eight done, and the two partials are code-complete.** #5 (key custody)
> and #3 (real attestation material) now need procurement and an integration
> environment, not commits.
>
> Working through P0 in order turned up **ten** defects the tests as written could not
> see: a gate pointing at a benchmark that did not exist; a blocking detector that
> refused every localised tool server; a verifier reading the system clock; a listener
> accepting bearer tokens in clear; a JWKS path that could emit and never ingest; a
> refresh loop holding boot-time trust; `--require-external-signing` reaching one
> signing role in six; a severity escalation that was a no-op because the kind was
> already Critical; an alert that would have missed the sink it was for; and an
> emergency path that opened a second writer on a single-writer log, failing only when
> used. Every one is the same species: **a control that reads as configured and does
> nothing.** The full list across the whole build is in
> [CHANGELOG.md](../CHANGELOG.md).

## Where the build actually is

| | Evidence |
|---|---|
| Modules delivered | All of P0–P4 (§8.16). `wc-core` 7 modules, `wc-control` 23, `wc-mediator` 8, `wc-cli` |
| Tests | **958 green** — unit, integration, 17 e2e (§8.15.4), 12 failure-injection (§8.15.5), 15 property (§8.15.1), 6 fuzz-mirror (§8.15.2), 9 attestation-interop, 8 transport |
| Conformance | 19 vectors in `fixtures/contracts/`, driven off `expected.json`; `connect verify` is the ground truth (§8.15.3) |
| Lint | `cargo clippy --workspace --all-targets` clean, `unwrap_used`/`expect_used` warned workspace-wide |
| CI | [`ci.yml`](../.github/workflows/ci.yml) — 5 jobs: stable, MSRV 1.89, release-mode latency gates, supply chain + dependency ceilings, nightly fuzz build |
| Supply chain | `cargo deny check` green; one argued advisory exception with a review date |
| Fuzz | 5 libfuzzer targets compile on nightly; **no campaign has been run** — `cargo-fuzz` is not installed |

Four §8.16 acceptance criteria **are** met and demonstrated: conformance vectors
100%, `tools/list` filtering end-to-end against unmodified Warden core, the
200-mediator quarantine under 60 s with unconfirmed reported, and drift suspension
exercised in e2e. The rest of the criteria are listed under P1 #9 below, unmet.

---

## P0 — blockers to production

Nothing ships to a real estate until every one of these is done. They are ordered
by what unblocks the others.

- [x] **1. CI.** As written, this said: *`.github/` does not exist. Every claim in
  this repository — the tests, clippy clean, the conformance vectors, the bench gates —
  is true on one machine, today, and nothing keeps it true.* It was the largest gap in
  the project and it blocked everything below it, because the value of the rest is that
  it *stays* proven.

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

- [~] **3. Real attestation material, end to end.**

  **What landed:** `admission` is now driven through the real verifiers —
  `JwtSvidIdentity`, `JwksCardVerifier`, `DsseProvenanceVerifier` — rather than
  through P0 stand-ins, so a party can actually reach `Attested`
  (`crates/wc-e2e/tests/attest.rs`). The material is minted by
  [`scripts/gen-attest-fixtures.py`](../scripts/gen-attest-fixtures.py) using
  `cryptography` and assembling ES256 `R‖S` from scratch — **a different
  implementation of the same specifications**, with three distinct keypairs because a
  SPIFFE bundle key, a card key and a builder key are three roles. Agreement between
  it and our verifiers is two readings of a spec rather than one implementation
  talking to itself. It also surfaced a defect: `JwtSvidIdentity` read the system
  clock, so its expiry check could not be tested at all.

  Since P0 #6, a SPIRE JWT bundle is readable as it comes — `spire-agent api fetch
  jwtbundles` returns a JWKS and `IssuerKeys::add_jwks` ingests it, so the
  convert-to-PEM step between here and a real SPIRE is gone.

  **What is still missing:** the material did not come out of a SPIRE server or a
  build pipeline. Replacing the three files with real output and re-running
  `cargo test -p wc-e2e --test attest` is the remaining step, and it is why they are
  files on disk rather than constants in the test. Needs an integration environment
  with SPIRE and a signing builder.

- [x] **4. Screening precision and recall are gated, and the corpus could not see
  its worst false-positive class.** This entry was wrong when written: precision
  *was* asserted at `>= 0.98` with `fp.is_empty()`. What was wrong was the label —
  the test printed **"(measured, not gated)"** directly above the assertions that
  gate it — and recall, which was measured at 1.000 and gated at nothing.

  Chasing the corpus found the real defect. **S1, a blocking detector, refused any
  tool server whose descriptions were localised.** It blocked `U+200B..U+200F` and
  `U+2066..U+2069` wholesale, which covers `U+200E`/`U+200F` (LRM/RLM, standard in
  mixed-direction text), the bidi isolates (the *recommended* modern embedding
  mechanism), `U+200C` ZWNJ (**required** in Persian and Urdu) and `U+200D` ZWJ
  (required in Indic scripts, and in every multi-person emoji). Measured, not
  theorised: Arabic, Hebrew, Persian, Hindi and an emoji team name were all refused.
  On a product whose own documents lead with multi-market residency.

  The corpus had CJK and accented Latin and **nothing that exercises bidi at all**,
  so it could not have caught this at any precision threshold.

  Three changes, and the third is what makes the first two safe:

  1. **`is_concealing` narrowed to what can hide or reorder** — zero-width with no
     shaping role, the deprecated embedding/override family (the Trojan Source
     primitive), and the Unicode **tag block `U+E0000..U+E007F`**, which was not
     detected at all before and is the carrier for ASCII smuggling. A recall gain,
     not a trade.
  2. **Legitimacy is contextual, not a blanket exemption.** A ZWJ between two
     Devanagari letters is doing a job; the same ZWJ between `Amount.` and
     ` Ignore limits.` is not. `has_complex_script` decides per field, so
     `benign-arabic-with-rlm` passes and `attack-rlm-in-latin-text` still blocks.
  3. **`matchable()` strips every invisible character before phrase matching.** The
     matchers were plain `to_lowercase().contains()`, so S1's broad block list was
     the only thing preventing evasion — one ZWJ inside
     `ignore all previous instructions` breaks a substring match. Now the phrase
     detectors see what a human sees, and `attack-zwj-split-override-phrase` fires
     **S1 and S5** where it used to fire only S1.

  Corpus: 49 → **63 cases** (28 block, 35 pass), ten of them benign near-misses
  including six localisation cases, and four new attack families. Precision **1.000**,
  recall **1.000**, both gated, and named as its own step in CI so the §8.16 P2 exit
  criterion is checked rather than buried in a summary line.

  `known_miss` is the escape hatch that lets recall be gated at all: a newly-understood
  attack the detectors miss is a reviewable line in a fixture, not a threshold quietly
  drifting down. A stale marker fails too — if the detectors start catching a case
  marked `known_miss`, the test says so.

  Still deliberately **not** done: `ScreenRules::calibrated` stays `false` by default
  and `screen-rules.toml` still ships `calibrated = false`. Blocking is earned per
  estate against that estate's own surfaces (§8.9), and our corpus is evidence for our
  detectors, not for somebody else's tool servers.

- [~] **5. Signing keys are PEM files on a filesystem.** All five sub-items are now
  done **in code**; what remains is procurement and procedure — a token to buy, a KMS
  key to create, a runbook to write, a drill to run. That was the original claim about
  5c–5e ("custody *deployments*, not code") and it was wrong: building them found three
  defects, two of them in the enforcement of what 5a and 5b had already shipped. See
  [key-custody.md](key-custody.md) for the decision and its reasoning. Six
  operations sign, `IssuerKey` is the seam for five of them, and they do **not**
  all want the same custody — so this is five sub-items, not one:

  | | Key | Custody | Why |
  |---|---|---|---|
  | 5a | **Anchor** (chain checkpoints) | HSM or offline | **Done in code** — `Anchor` holds an `IssuerKey`, `connect --anchor-signer CMD` delegates it, and an existing `anchor.jsonl` written before the change still verifies. What remains is procuring the token and writing the procedure |
  | 5b | **Issuer** (contract mint) | KMS, no local copy | **Done in code** — `--signer`, `--require-external-signing` enforcing it, and `key_custody` recorded in every mint event so the posture is auditable backwards. The `contract::mint` gate did **not** need raising: measured p99 is 677 µs against 20 ms, so ~19 ms of signing already fits. A new `contract::mint overhead` gate (1.9 µs / 50 µs) separates our cost from the signer's, so a slow delegated mint is attributable. What remains is procuring the KMS key and the mint-volume alerting that bounds a held host |
  | 5c | **Revocation** | two `kid`s: online in KMS, offline on a hardware token | **Done in code** — `--revocation-signer`, `--break-glass-kid` declaring which `kid` is offline, `--break-glass` selecting it, and `EventKind::BreakGlassKeyUsed` so its use is alertable. Detail below |
  | 5d | **Approver** | never the service's KMS | **Done in code**, structurally — `custody::Separation` refuses an approver key that is the service's key material, and two approvers holding one key. `--approver-signer` / `--second-signer` for hardware tokens |
  | 5e | **Bundle envelope, CAEP sink** | follow the issuer key | **Done in code** — `--envelope-signer`, and the envelope now honours `--require-external-signing`, which it did not |

  **The largest thing wrong was invisible: `--require-external-signing` reached one
  role in six.** It was checked inside the CLI's `issuer_key()` and inside the anchor
  path and nowhere else, so both revocation keys, the approvers and the bundle envelope
  could only ever use a key on local disk — and an estate that set the posture and
  believed no signing key was read from disk had no way to find out except by reading
  the source. A posture that covers a third of what it claims is worse than none,
  because it is believed. Every signing site now resolves through
  [`wc_control::custody`](../crates/wc-control/src/custody.rs), which applies the rule
  per `Role`; `connect bench` is the one exemption and the role says so, because the
  other five were exempt by accident.

  **Two more defects, both found by running it rather than by testing it:**

  * The first break-glass implementation recorded a `Quarantine` event with
    `.with_severity(Critical)` — **a no-op**, because `EventKind::Quarantine` is already
    `Critical`. Severity cannot distinguish "the emergency key signed this" from "a
    party was contained". It needed its own kind, `containment.breakglass_key`, and that
    kind needed adding to `is_containment()` — otherwise a sink filtered to
    `Filter::Revocation`, which is exactly where containment alerting is pointed, would
    have been the one destination that never heard the emergency path was used.
  * The escalation opened a *second* evidence handle while the first was still held. The
    chain is single-writer by design (§8.5.2), so it failed with `WC-8003` — **only on
    the break-glass path**, the one path that must not have a bug in it.

  Also fixed while in there: a misdeclared revocation key used to quarantine the party
  in the registry, *then* fail, leaving a half-applied containment that reads in the
  register as done. Custody is now resolved before any state is written, the way
  `open_evidence` already refuses on posture before it locks the chain.

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
  supported this and needed no change: `SignedRevocation` carries a per-entry `kid`
  and `verify` resolves it against an `IssuerKeys` map, so mediators can trust two
  revocation keys at once and the feed records which one signed each order. What was
  missing was on the signing side — **nothing knew which `kid` was the offline one**, so
  nothing could switch to it deliberately, refuse it casually, or record that it
  happened. `--break-glass` now selects the offline key rather than merely permitting it,
  because an operator at 03:00 should type one flag, not get a pairing right; naming the
  offline `kid` without `--break-glass` is refused, which is the reach-for-it-out-of-habit
  case; and one `kid` declared for both roles is refused outright, because two names for
  one key reads in a runbook as two keys and buys none of the three properties below.

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

- [x] **6. Issuer trust can rotate without a deploy.**

  What was wrong was narrower and worse than "no HTTP fetch": **JWKS handling was
  write-only.** `keys jwks` rendered the document, `/v1/jwks.json` served it, `bundle`
  carried it — and nothing in the repository could read one back. The coordinate
  extraction in `jwk_from_pem` was covered only by length assertions, which a swapped
  `x` and `y` would also satisfy. So a mediator was pointed at a PEM, one `kid` fixed
  at startup, and rotation meant a file on every host plus a restart. That cost is why
  keys in practice do not get rotated at all.

  - `IssuerKeys::add_jwks` — the ingest. EC P-256/P-384 and Ed25519; **skips** RSA, a
    key with no `kid`, `use: enc` and an unknown curve, each with a reason in the
    returned `JwksReport`; **refuses** a symmetric key outright, because anyone who can
    verify with it can mint with it. All-or-nothing on the error path, so a caller that
    logs and carries on keeps its previous trust rather than an arbitrary prefix of a
    document it rejected. A document where *nothing* is usable is an error, not an
    empty success.
  - `wc_mediator::jwks::JwksSource` — TTL cache over a URL or a file. Every refresh
    **replaces** the set rather than merging into it: a key the issuer has withdrawn
    has to stop verifying, and a merging cache would keep honouring a compromised key
    while reporting healthy refreshes. A failed refresh keeps serving the cached set —
    the keys are still valid and the issuer being briefly unreachable is not a reason
    to deny every connection — but only to `max_stale`, past which it refuses, because
    a set that can no longer be refreshed is a set nobody can withdraw a key from.
    `status()` exposes age, staleness and the last error, so "running on cache" is
    alertable rather than inferred afterwards.
  - `Trust::{Pinned, Rotating}` refreshes **at the call site**. `connect-mediate`'s
    refresh thread used to rebuild `IssuerKeys` from the startup PEM, so it held a copy
    of boot-time trust: contracts refreshed every tick and the keys checking them never
    did. `--jwks-url` would have looked configured and rotation would never have
    arrived. Keys and contracts now refresh together, and a `kid` change is logged.
  - Flags: `--jwks-url`, `--jwks-file`, `--jwks-ttl`, `--jwks-max-stale` on
    `connect-mediate`; `--jwks FILE` on `connect verify`. Exactly one trust source —
    passing two is refused rather than resolved by precedence, and `--kid`/`--alg`
    alongside a key set is refused rather than silently ignored.
  - The round trip is now proven: `the_emitted_jwks_can_be_read_back_and_verifies_a_
    real_signature` emits from a `Keyring` and verifies a live signature through the
    ingest. That is the test that could not be written while the path was write-only.

  It also removes the "convert the JWKS to PEM" step from
  `fixtures/attest/README.md` — `spire-agent api fetch jwtbundles` returns a JWKS, so
  a SPIRE trust bundle is now readable as it comes.

  **Still outstanding:** the rotation *drill* — a rehearsal that publishes a new `kid`
  and proves a running mediator picks it up. The mechanism is tested; the procedure is
  not, and per P1 #9 an unrehearsed procedure is an assumption.

- [x] **7. A non-loopback listener no longer accepts credentials in clear.**

  In-process TLS is deliberately **not** implemented, and that is the decision rather
  than the omission: every topology in
  [physical-architecture.md](physical-architecture.md) terminates TLS at an ALB, an
  Ingress, HAProxy or Front Door, so a rustls listener in this binary would be a
  security-critical code path almost nobody runs. `rustls` is already in the tree
  transitively via `ureq`, so the cost would have been code and risk, not a dependency.

  What *was* the defect: the plan said "a terminating proxy is mandatory" and the
  binary had no opinion. A pod bound to `0.0.0.0` came up, served, and shipped approval
  tokens in plaintext with nothing objecting — a control that existed in a document.

  **The contract is now enforced, and enforced per request.** A startup flag says only
  what an operator intended, so `--behind-tls-proxy` is an assertion that has to be
  *paid for* on every authenticated request: `x-forwarded-proto: https`, believed only
  from an address named by `--trusted-proxy`. A request that reaches the listener
  directly — bypassing the ingress, which is the actual attack — carries no such header
  and is refused. Same reasoning as `wc_mediator::peer::MeshTrust`: a forwarding header
  is worth exactly as much as the hop that set it.

  | | |
  |---|---|
  | Loopback bind | Admitted with no assertion. The default |
  | Non-loopback, no assertion | **Refuses to start**, naming the two flags that would fix it |
  | `--behind-tls-proxy [--trusted-proxy ADDR]` | Per-request `x-forwarded-proto` check |
  | `--insecure-plaintext` | Accepts anything, and says `INSECURE` in the banner and on every start |

  The check hangs off token resolution rather than the router, because a check a route
  can forget to call is one that a route eventually will — and `/healthz` still answers,
  since a liveness probe failing on a credential policy would take a pod down for the
  wrong reason. Refusals are counted (`transport_refused`), so "nothing can
  authenticate" is a number rather than a discovery. The posture prints at startup.

  Loopback is decided by parsing the host and asking `is_loopback`, never
  `starts_with("127.")` — `127.0.0.1.evil.example` passes the string test, which is a
  bug this codebase already fixed once in `peer`. There is a test for the hostname.

  Thirteen new tests: eight over a real socket, because the peer address comes from the
  accepted socket and a handler-level test would have to invent the thing being checked.

- [x] **8. A repository anyone outside this conversation can read.**

  `README.md`, `LICENSE` + `LICENSE-APACHE` (FSL-1.1-ALv2, converting to Apache 2.0),
  `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md` and
  [twelve-factor.md](twelve-factor.md) all now exist. Every local link in them is
  checked to resolve.

  Three of them are worth more than their genre usually is:

  - **`SECURITY.md`** is scoped against the real threat model — the eleven threats in
    §7.8, not a generic list. It puts **"a control that is configured and does
    nothing"** in scope explicitly, even where no single request can be shown to bypass
    anything, because that is the defect class this repository actually produces. And it
    names what is *out* of scope with the reason: prompt injection inside the agent's
    reasoning, semantic drift within an unchanged declared surface (A4's stated
    residual), `--insecure-plaintext` doing what it says.
  - **`twelve-factor.md` opens by contradicting the LLD.** §1 claims config resolves
    *"flag over file over env"*; there is no general config file, so the chain is two
    layers, not three. Recorded rather than quietly satisfied — a component whose own
    design document overstates its configurability is the same species of defect as a
    control that reads as enforced and is not consulted. It also states the deviation
    from factor VI plainly: `connect serve` **requires** durable storage, because an
    evidence chain that restarts on reschedule has no history.
  - **`CHANGELOG.md`** carries a *"notable defects found and fixed during the build"*
    section listing ten silent-control failures, each with what it read as versus what
    it did. That list is the most useful thing in the file for anyone deciding whether
    to trust this.

  `docs/README.md` said *"Status: design / definition"* and omitted the four documents
  written after the build; both fixed.

  `deny.toml` was already there, and it found a real advisory on its first run — see
  below. It also settled the dependency-count question: the LLD claimed 30 crates for
  `wc-core` and 61 for `wc-control`; the tree resolves to **80 and 110**, of which
  `jsonwebtoken`'s `rust_crypto` feature is 75 on its own. Ceilings are asserted by
  [`scripts/dep-count.sh`](../scripts/dep-count.sh) at the measured truth plus
  headroom, so the next addition is visible rather than silent.

  **Not done here:** issue and PR templates, and a release process — packaging is P1
  #13, and every crate is `publish = false` until it exists.

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

- [x] **10. HA is a tested mode, and the standby it needed did not exist.**

  The sentence was *"high availability is active/standby with that lock as the election
  primitive"* (§8.5.2) — and there was **no standby**. `lock::acquire` uses
  `LOCK_EX | LOCK_NB`, so a second process failed at startup and exited. Failover meant
  an external supervisor restarting a process that would then race the dying one. The
  primitive existed; nothing stood by on it.

  * **`lock::acquire_waiting`** is the election: poll until the lock is free, announce the
    wait once per elapsed second, and return an `Election` saying whether this process
    succeeded somebody. A crash releases the lock as surely as a clean exit, because it
    belongs to the file descriptor — no lease to expire, no heartbeat to tune, which is
    the main reason this stayed `flock`.
  * **`Store::open_waiting`** elects **then** rebuilds. The old `Store::open` rebuilt the
    projection *before* taking the lock; on that path it was only wasted work, because the
    subsequent lock attempt failed and took the whole open with it. For a standby it is
    exactly wrong — the log has been growing the entire time it waited — so the order is
    now lock-first for both, and `Store::open`'s doc says why.
  * **`connect serve --standby [--standby-timeout N]`**. No listener is bound while
    waiting: a load balancer sees nothing rather than something answering "not ready",
    which is the same signal with no room for a health check to be misconfigured. A
    timeout exits non-zero, because a standby that started anyway would be a second
    writer *and would present as a successful failover*.
  * **Four handover tests** (`failure.rs` §13): a successor sees writes the active writer
    made while the standby was waiting; a standby waits through a real handover rather
    than exiting; a standby that cannot elect refuses to serve; and a torn final record —
    the in-flight-approval question — is rejected and **reported** rather than
    half-applied, because a successor that started clean on a damaged log would be
    asserting the estate is intact when it is not.
  * Verified between two real processes with `kill -9`: the successor logged *"took over
    the writer lock after 1271 ms; the previous active writer is gone"* and served.

  **A defect found while building it.** `Election::uncontended` was first inferred from
  `waited == 0` in whole seconds — so any handover completing inside a second reported as
  uncontended, and the successor's own startup line would have claimed it was the first
  writer. That is the single line an operator reads after a failover. Now tracked
  explicitly, and `waited_ms` is milliseconds because a healthy handover is fast and a
  whole-second figure can only measure the bad ones.

  **What `flock` does not do: fence a partitioned active.** It is advisory and
  node-local, so the storage layer has to guarantee single attachment — RWO, one EBS
  volume, one Managed Disk, one LUN. The lock is the *election*; the volume is the
  *fence*. [physical-architecture.md](physical-architecture.md) now carries that per
  variant, because a deployment that moves the state root to a shared filesystem to make
  failover easier has removed the thing that made failover safe.

  **Still not covered:** failover *under load*, with a mediator mid-pull. The design's
  answer is that an agent should see nothing — a mediator serves from cache to `exp` and
  only new issuance stops (§7.8 A9) — and that is asserted elsewhere, but not across a
  handover.

- [x] **11. Observability is now an operable signal.**

  What was there: seven unlabelled `AtomicU64`s behind `/metrics`, all of them about the
  **HTTP surface** — requests, denials, replays — and none about the estate. A control
  plane can serve two hundred clean requests a second while every contract in the
  register is expiring and no mediator has acknowledged anything. And there was **no
  structured decision log on the mediator path at all**, which was the sharpest part of
  this item: issuance stays healthy while every call in the estate is refused, and the
  only process that knows a call was denied is the mediator.

  * **`wc_core::obs`** — a labelled registry (counters, gauges, histograms), Prometheus
    text and JSON, in `wc-core` because both planes need it and they can share nothing
    else: `wc-control` may not depend on Warden core (§8.3), and `warden::obs` is a
    fixed-shape counter set with no `cid`, no `WC-*` code and no mode — the three fields
    this item asks for. No new dependency; `BTreeMap` and atomics.
  * **Cardinality is capped at 256 per family, and overflow folds rather than drops.** The
    fold is the decision worth defending: a silently missing series reads as *zero* on a
    dashboard, so an alert stops firing and nothing says why. `wc_obs_series_dropped_total`
    counts what folded, and `wc_obs_unknown_family_total` catches a misspelled metric name
    — which would otherwise be a flat line everyone reads as a quiet estate.
  * **Counters are incremented; gauges are derived at scrape time.** An
    incrementally-maintained gauge is a second copy of an answer the projection already
    holds, and it diverges the first time a code path forgets — producing a number that is
    believed and wrong. So `/metrics` and `connect posture` cannot disagree.
  * **The mediator's decision log** — one JSON object per line on stderr, carrying `cid`,
    the `WC-*` code and the mode. Hooked at **all four** refusal exits, which is where the
    real work was: a refused `tools/call` leaves through `tool_denial` as a JSON-RPC result
    rather than through `blocked`, so hooking the obvious one would have logged
    connection-level refusals and silently dropped every expired contract, uncontracted
    tool and ceiling breach — most of what there is to see.
  * **An allow carries `WC-0000`, not a synthesised success code.** There is no `Code::OK`
    and inventing one would put success and failure in one namespace, making the estate's
    most common "error" everything working.
  * **`--decision-log off|notable|all`, default `notable`.** Allows are counted at every
    level including `off`, so turning logging down costs detail rather than visibility —
    otherwise the cheapest way to reduce log spend is to go blind, which is what happens.
  * **`--metrics-file` for the mediator**, written atomically via rename. It has no
    listener by design, so there is no `/metrics` to scrape; this is the node-exporter
    textfile-collector convention.
  * **[observability.md](observability.md)** — every family, and the four alerts as PromQL
    with severities and runbooks: mediators reported unconfirmed, ACK lag breaching
    §7.10's own 60-second claim, a distrusted revocation set, and blocking-sink failure.
    Plus what this telemetry **cannot** answer, named so a permanently-zero panel does not
    teach an operator to ignore the panel.

  Two things the design forced that are worth recording. `wc_revocation_trusted` lives on
  the **mediator** and not the control plane: distrust is local, and a mediator refusing
  everything is indistinguishable from the control plane's side from a healthy estate with
  no traffic. And `wc_anchor_age_seconds` is read **without verifying the signature** —
  it is a liveness signal, and it is exactly the number an attacker who could rewrite the
  chain would want to look healthy, so it says so in its own documentation and points at
  `connect audit verify` as the integrity path.

  The seven original unlabelled series are still served under `_total` names. A renamed
  metric does not make a dashboard panel error; it makes it go blank.

- [x] **12. Config resolves flag over file over env, as §8.13 says it does.**

  It said so and it did not. There was no configuration file at all — `connect.toml`
  held `[[sink]]` and `[assurance]` for their own loaders and nothing else — and env was
  four hand-wired lookups. `connect serve --config connect.toml`, which §8.13 shows in
  an example, was not something the binary could do.

  * **File layer** — `--config FILE`, or `connect.toml` beside the process if it exists.
    Resolved after the command is known, because which keys apply depends on it: one
    deployment-wide file holds `listen` for `serve` beside `revocation_key` for
    `quarantine`, and injecting all of it everywhere would make `connect entities` fail
    the unknown-flag check because the file mentions a listener.
  * **Env layer generalised** — `WARDEN_CONNECT_<FLAG>` for every flag, derived from the
    flag name rather than hand-wired, so a new flag gets its variable by existing. The
    four original names are unchanged, so an existing deployment keeps working. An empty
    value does not override: `WARDEN_CONNECT_ROOT=` is how a variable gets unset in a
    profile, and reading it as the empty path would put the estate in the working
    directory.
  * **An unknown key is refused, not ignored** — with the known keys listed. This is the
    decision that makes the item worth doing rather than cosmetic: a config file is
    version-controlled and reviewed by somebody who believes it took effect, so a
    silently-dropped key is a false belief *with an audit trail behind it*. Same for a
    key in the wrong section, which would otherwise be a near-miss that does nothing.
  * **Ten §8.13 keys describe behaviour this build does not have** — `[server].tls`,
    `[policy].hot_reload`, `pdp_url`, `[admission].rekor`, `require_provenance` and
    others. Each is refused **with the reason**, so an operator who writes
    `hot_reload = true` is told SIGHUP does not reload anything rather than discovering
    it during a policy change. Accepting them would have been the failure above.

  Two guard tests: every mapping points at a flag some command actually accepts, and the
  precedence holds through `tenant_id` rather than only inside the parser — the rule was
  never in doubt, the wiring was.

- [~] **13. Packaging: a Dockerfile, an SBOM of ourselves, and a written release process.**

  * **[`Dockerfile`](../Dockerfile)** — multi-stage, pinned to the **MSRV** rather than
    `rust:1`, because an image built on a newer toolchain than the one gating the tests is
    an image nobody verified. Both binaries in one image on purpose: a mediator's version
    has to be answerable during an incident, and two images means two answers. Non-root,
    one volume, `ca-certificates` (without it every `--jwks-url` fetch fails with a
    certificate error that reads as a server problem).

    The build context is the **parent** of both repositories, because Warden core is a path
    dependency (§8.3). Building from inside this repo fails at `cargo build`, which is the
    correct failure — an image without core is an image whose mediator cannot exist.

    `debian:bookworm-slim` and not `scratch`, stated as a trade rather than a default:
    §8.3's crypto choice would allow a static image, but `connect audit verify`,
    `connect backup` and the restore drill are run by a human in or beside this container,
    and `scratch` makes each of them need a second image holding the same binary.

  * **[`scripts/sbom.py`](../scripts/sbom.py)** — a CycloneDX 1.5 BOM of the two shipped
    binaries: 145 components, every one with a licence. Built from `cargo metadata` rather
    than `cargo-cyclonedx`, so it needs no tool nobody has. **Reproducible by
    construction** — no timestamp, and `bom-ref` is `name@version` rather than cargo's
    package id, which for a path dependency is `path+file:///Users/…` and would put the
    build machine's filesystem into a published artifact. A BOM that differs between two
    checkouts of one commit cannot be diffed, and a diff is how anyone notices a dependency
    appeared. Dev-dependencies are excluded: they are not in the artifact, and inflating
    the surface a consumer believes they run is the direction of error that gets BOMs
    filtered.

  * **[releasing.md](releasing.md)** — the preconditions (all already in CI, listed because
    a release is when somebody is tempted to skip one), the fact that a release is pinned
    by **two revisions** rather than one, and why removing a metric family is breaking even
    though no Rust signature moves.

  * **CI gained two jobs:** `image` builds the Dockerfile and runs both binaries including
    a write to the state root as the unprivileged user; `supply-chain` generates the SBOM,
    asserts it is byte-identical on a second run, and uploads it.

  **Honest limits.** The image **has not been built locally** — there is no container
  runtime on this machine, so CI is the only place it is verified, and `releasing.md` says
  so in a table rather than implying otherwise.

  **Still outstanding, and structural:** publishing to crates.io is impossible while
  `warden` is a path dependency. `cargo publish` of `wc-mediator` would fail and one of
  `wc-core` would succeed, publishing half a product. Making this publishable means giving
  core a registry version and depending on it by version — a change to the family's
  coupling model, not a packaging chore. Also missing: release provenance. This repository
  **verifies** DSSE/in-toto SLSA envelopes and produces none of its own, so the shortest
  path is to attest releases in the format it already accepts and then verify our own
  artifacts with our own code.

- [~] **14. Backup and restore are code, tested, and documented.**

  * **`connect backup --out DIR`** — a verified snapshot. It **verifies the chain first and
    refuses if it is broken**, which is the reason this is code rather than `cp -r`: a
    snapshot of an already-corrupt root looks like insurance, launders the corruption into
    every copy, and is discovered at the exact moment somebody needed it to be real. No
    manifest is written for a chain that did not verify. The manifest records head
    sequences, because after a restore the first question is *how much did we lose*.
  * **`connect restore --from DIR --into ROOT`** — four refusals in the order that matters:
    no manifest, a digest mismatch (checked **before** anything is placed, since a restore
    that copies first has overwritten what it would compare against), a non-empty target
    (never merged — two append-only logs joined are a third history that never happened,
    *and it would verify*), and a live writer.
  * **Hot backups are safe and say when they were hot.** Both logs are append-only, so a
    mid-append copy is a prefix plus possibly a torn final line, never a scrambled middle.
    The manifest names a sequence rather than claiming an instant, and `torn_tail` reports
    a caught partial write.
  * **`connect retention`** reports the window and **deletes nothing** — see below.
  * **[operations.md](operations.md)** — the paths, what losing each one costs, the restore
    drill including `connect export --format dora` against the restored root (the line that
    proves the recovery is worth having), and what is still missing.

  Verified end to end: backup → restore into a new root → `audit verify` → the estate is
  present, and a second restore into the same root is refused.

  **Retention deletes nothing, deliberately.** Removing a row from a hash-linked chain
  breaks every row after it, so retention here is *segment retirement* — retire whole
  segments once every row in one is past its clock, keep the anchor that covered them —
  and that rotation design does not exist. Implementing a row-level delete would silently
  destroy the property the chain exists for while reporting success, so the command reports
  the window instead and says why.

  **Still outstanding:** segment retirement itself; a measured RTO (the drill is a
  procedure, not a measurement); automated offsite shipping, left out on purpose because a
  WORM credential inside the control plane is a new blast radius; and cross-tenant backup
  in one invocation.

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
