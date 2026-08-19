# Contributing to warden-connect

Thanks for your interest. warden-connect is the connection control plane for AI agents —
the layer that decides whether two parties may be connected at all, and bounds what that
connection can ever carry.

## You don't need to "join" — just contribute

Standard open-source flow: **no access is required.** Fork, push a branch to your fork,
open a pull request. A maintainer reviews and merges.

The most valuable contributions here, roughly in order:

1. **A conformance test vector we fail.** The contract format is meant to be a candidate
   standard: any implementation may mint a contract, and a contract is valid iff a
   conforming verifier accepts it. If you build an independent minter or verifier and we
   disagree, that disagreement is worth more than a feature. See
   [Conformance](#conformance) below.
2. **A control that is configured and does nothing.** Nearly every real defect found in
   this codebase has been one species: a check that reads as enforced and is not
   consulted, a bound that never trips, a trust set that never refreshes. If you find
   one, the report alone is a contribution.
3. **A mediator for an enforcement point we don't cover** — an Envoy filter, an API
   gateway plugin, another agent framework. The eleven checks are specified in
   [docs/08-lld.md](docs/08-lld.md) and `fixtures/contracts/` is the suite you must pass.
4. **Docs, deployment recipes, policy examples.**

## Ground rules

- **Be respectful.** See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **Security issues are private.** Do not open a public issue for a vulnerability —
  follow [SECURITY.md](SECURITY.md).
- **Licence.** warden-connect is source-available under the **Functional Source License
  1.1 (FSL-1.1-ALv2)**, which converts each version to Apache-2.0 two years after
  release. By contributing you agree your contribution is licensed under the same terms,
  and you grant the Licensor the right to license it under the FSL and the Apache-2.0
  Future License, so the project keeps a single consistent licence.

## Development setup

Warden core is **optional**. A default build needs nothing beside this repository; only
`--features warden-proxy` does, and then it must be checked out at `../warden`. Under that
feature the coupling is
the deployment model rather than a dependency choice.

```sh
git clone https://github.com/vijayvedula/warden.git
git clone https://github.com/vijayvedula/warden-connect.git
cd warden-connect

cargo build --workspace
cargo test --workspace
```

MSRV is **1.89** and CI tests on it, so do not reach for newer language features.

## The checks CI runs — run them before you push

```sh
cargo fmt --all                             # note: not idempotent in one pass; run twice
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check                            # advisories, licences, bans, sources
./scripts/dep-count.sh                      # per-crate dependency ceilings
```

CI additionally runs the MSRV job, the §8.10.3 latency gates (`connect bench`), the
conformance vectors, the screening calibration, six drills, and regenerates the attestation
fixtures with `scripts/gen-attest-fixtures.py` (Python 3.9-compatible; it needs `cryptography`).

### The drills — run one when you touch what it covers

Each executes the shipped binaries end to end. Every one of them exists because something that
read as working was not, and reading the code had not found it.

```sh
./scripts/attest-drill.sh          # a party reaches Attested; enforce mode admits it
./scripts/rotation-drill.sh        # issuer-key rotation, and containment reaching a live session
./scripts/containment-drill.sh     # the quarterly break-glass rehearsal
./scripts/custody-drill.sh         # an external issuer key, and two planes that stay separate
./scripts/upgrade-drill.sh         # a provider changes terms; everyone finds out in time
./scripts/distribution-drill.sh    # the deploy gate, durable acks, last-use  (binds a port)
./scripts/inventory-drill.sh       # MCP servers found from repo config, with nothing provisioned
```

Two are **not** in CI, because they measure rather than assert:

```sh
./scripts/scale-drill.sh           # operate a 10⁵ estate; ~10 min, prints timings, gates nothing
./scripts/fuzz.sh 600              # a real campaign; needs nightly + cargo-fuzz
```

`scale-drill.sh` deliberately sets no thresholds: a number from one laptop fails on a smaller CI
runner and passes on a bigger one, which this project got wrong twice with latency assertions.

`cargo fmt --all` does not reach `fuzz/`, which is deliberately outside the workspace.

## House rules for the code

From [DRILL.md](DRILL.md) §2, and they are not negotiable in review:

1. **No `unwrap()` or `expect()` outside `#[cfg(test)]`.** Enforced by clippy lints in
   the workspace `Cargo.toml`. In tests they are fine and idiomatic.
2. **`Result<T>` wherever something can fail**, carrying a `WcError` with a `WC-*` code.
   No `Option` to mean failure, no sentinel values, no panics on bad input — panics are
   for broken *invariants*, never for bad *data*.
3. **Every `pub` item gets a doc comment** saying what it does and what it promises.
   `#![warn(missing_docs)]` will nag; the nag is the point.
4. **Borrow before you clone.** When you reach for `.clone()`, be able to say why the
   borrow would not work.
5. **Match the surrounding code** — its idiom, its comment density, its naming. This
   extends Warden core's style rather than importing a new one.
6. **Inject the clock.** Nothing calls `SystemTime::now()` below the binary layer.
   `AdmissionCtx::now`, `GateCfg::now`, `VerifyOpts::now`, `Issuer::now` exist so no test
   depends on the wall clock and no behaviour depends on the date.
7. **No new dependency without a reason in the PR.** §8.3's "no async runtime, no ORM, no
   database, no ML runtime" is enforced by `deny.toml`, and the per-crate counts are
   ceilinged. If you need to raise a ceiling, say why in the commit.

## What review will push on

- **Does the control actually run?** A test that asserts a config field was set proves
  nothing. Assert on the *decision*: the request was refused, the key stopped verifying,
  the digest changed. Several tests in this repository exist specifically because an
  earlier version asserted the configuration instead of the effect.
- **Does the comment say why, not what?** The code says what it does. Comments here carry
  the reasoning — what was rejected, what breaks if this changes, which attack it is for.
- **Can a contract widen anything?** A contract is a **ceiling, never a grant**. Any code
  path where `effective` could end up wider than
  `contract.surface ∩ token.scope ∩ policy_decision` is a blocking objection.
- **Does a failure fail closed?** Compare against the fail-closed matrix in
  [docs/07-hld.md §7.8](docs/07-hld.md). A dependency failure that yields "allow" where
  that table says deny is a bug even if the happy path is fine.
- **Is the error actionable?** `WC-8004 configuration invalid` with no detail makes an
  operator read source. Say which value, from where, and what it should have been.

## Conformance

`fixtures/contracts/` is nineteen signed artifacts plus an `expected.json` naming the
`WC-*` code a conforming verifier must produce for each — algorithm confusion,
`alg: none`, HMAC substitution, a tampered payload, a superset surface, a wrong
audience, an unknown `kid`, an expired contract.

```sh
connect verify fixtures/contracts/valid-es256.jws \
    --jwks your-keys.json --mediator-id warden:mediator:apac-ops
```

Adding a vector is a welcome PR on its own. Include the artifact, the entry in
`expected.json`, and a one-line description of what it attacks.

## Commit and PR style

- Commit subject: what changed, in the imperative, under ~70 characters.
- Commit body: **why**, and what you rejected. The commit log here is a design record —
  the reasoning is the part that will be re-read.
- One logical change per PR. A refactor and a behaviour change in the same diff makes the
  behaviour change unreviewable.
- If you fixed a control that was silently not running, say so plainly in the body and
  name the test that now keeps it running. That is the most important sentence in the
  commit.
