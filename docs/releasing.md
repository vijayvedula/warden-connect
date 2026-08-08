# Releasing

Nothing has been tagged yet. This is the process a release follows when one is, written for
production-readiness P1 #13 — which observed, correctly, that there was no Dockerfile, no
image, no release process and no SBOM, and that *"the product that generates BOMs ships
without one of itself"*.

---

## What ships

| Artifact | What it is |
|---|---|
| `connect` | the control plane and the operator CLI |
| `connect-mediate` | the inline mediator, one process composing unmodified Warden core |
| `warden-connect.cdx.json` | a CycloneDX SBOM of the two binaries above |
| the container image | both binaries, `debian:bookworm-slim`, non-root, one volume |

Both binaries in one image on purpose. A mediator's version has to be answerable during an
incident, and two images means two answers.

## The version is two revisions, not one

Warden core is a **path dependency** at `../warden` (§8.3) — `wc-mediator` compiles *into*
the proxy, so the coupling is the deployment model. A release is therefore pinned by a pair:
this repository's tag and the core commit it was built against. The SBOM records the core
commit as a property rather than a `pkg:cargo/...` purl, because a path dependency has no
registry coordinates and claiming otherwise would assert a provenance that does not exist.

Say both in the release notes. "warden-connect v0.2.0" alone is not a reproducible
statement.

## Preconditions

Every one of these already runs in CI, so a release is *checking that CI was green*, not
running them by hand. They are listed because a release is the moment somebody is tempted to
skip one.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                       # 978 tests
cargo +1.89 test --workspace                 # the MSRV, which CI pins
cargo test -p wc-mediator --release gate_filter
connect bench --iterations 400 \
  --signing-key fixtures/keys/test_issuer_es256_priv.pem \
  --verify-pub  fixtures/keys/test_issuer_es256_pub.pem --kid wc-test-es256
cargo deny check
./scripts/dep-count.sh
python3 scripts/sbom.py --check
```

CI also runs `./scripts/containment-drill.sh` and the cross-organisation federation tests,
which are the §8.16 P3 and P4 acceptance criteria.

Two things remain release-specific and are **not** automated, both because they need
something a runner does not have:

* **The restore drill at production size.** [operations.md](operations.md) — back up a real
  root, restore it into a fresh one, `audit verify`, and produce a DORA export from the
  restored copy. The mechanism is tested and the drill script exercises it on a scratch
  estate; what nobody has done is run it against a root with 10⁵ contracts in it and record
  the elapsed time. "We can restore" and "we can restore inside our RTO" are different
  claims.
* **The rotation drill.** Publish a new issuer `kid` and confirm a running mediator picks it
  up without a restart. The mechanism is tested (`wc_mediator::jwks`); the procedure is not.
  An unrehearsed procedure is an assumption.

## Versioning

`0.x` while pre-1.0: a minor bump may break things, and the changelog says which.

Two parts of the interface are **public regardless of Rust signatures**, and a change to
either is breaking even when nothing in the API moves:

* **The `WC-*` error codes.** A third-party verifier switches on them, and
  `fixtures/contracts/expected.json` asserts specific codes for specific artifacts.
* **The `warden-connection+jws` schema.** Anyone may mint a contract; a schema change makes
  someone else's minter wrong.

Removing a metric family is also breaking in practice, because a dashboard panel does not
error when its metric disappears — it goes blank. Rename by adding the new name and keeping
the old one, the way the seven original unlabelled counters are still served under `_total`.

## Cutting it

```sh
# 1 · the changelog moves from Unreleased to a version, with the core commit named
$EDITOR CHANGELOG.md

# 2 · versions in lockstep across the workspace
$EDITOR Cargo.toml            # [workspace.package] version
cargo update --workspace      # so Cargo.lock matches
cargo test --workspace

# 3 · the SBOM for this exact tree
python3 scripts/sbom.py > warden-connect.cdx.json

# 4 · tag, with the core commit in the message
git commit -am "release: v0.2.0"
git tag -a v0.2.0 -m "warden-connect v0.2.0 (warden core <commit>)"

# 5 · the image, from the PARENT directory — see the Dockerfile's header
cd ..
docker build -f warden-connect/Dockerfile -t warden-connect:0.2.0 .
docker run --rm warden-connect:0.2.0 version
```

Push the tag last. A tag is the thing people pin, so it should be the last thing that
becomes true.

## Publishing to crates.io

**Not possible, and the reason is structural.** Every crate is `publish = false`, because
`warden` is a path dependency that cannot resolve from a registry (§8.3). A `cargo publish`
of `wc-mediator` would fail; one of `wc-core`, which has no core dependency, would succeed
and publish half a product.

Making this publishable means giving Warden core a registry version and depending on it by
version — which changes the family's coupling model, not just its packaging. That is a
design decision, not a release chore, and it is why P1 #13 stays partial.

## Provenance

This repository verifies **other people's** provenance —
`wc_control::attest::DsseProvenanceVerifier` checks DSSE/in-toto SLSA envelopes — and
produces none of its own. A release should be signed and attested, and the honest statement
today is that it is not:

* no signed tag requirement,
* no SLSA provenance for the binaries or the image,
* no cosign signature on the image,
* no reproducible-build claim.

The verifier already exists, so the shortest path is to attest releases with the format this
component already accepts, and then verify our own artifacts with our own code. Until that
happens, an operator's trust in a downloaded binary rests on the transport, which is exactly
the residual §7.8 A8 describes for a control plane.

## What is verified where

| Claim | Verified by | Verified now? |
|---|---|---|
| the tests pass, on the MSRV | CI `check` + `msrv` | yes |
| the §8.10.3 latency gates hold | CI `gates`, release mode | yes |
| no banned dependency, no advisory | CI `supply-chain` | yes |
| the SBOM is complete and reproducible | CI `supply-chain` | yes |
| the containment drill still works | CI `gates` | yes — but on a scratch estate with a *file* standing in for the hardware token |
| federation against a second control plane | CI `gates` | yes |
| **the image builds and runs** | CI `image` | **only in CI** — it cannot be built on a machine with no container runtime, and it has not been built on one yet |
| the containment drill against the real offline token | a human, quarterly | no |
| the restore drill at production size, timed | nobody | no |
| the rotation drill | nobody | no |
| release provenance | nobody | no |
