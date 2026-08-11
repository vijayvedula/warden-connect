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
cargo test --workspace                       # 993 tests
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

**Structurally possible now.** `warden` was a path dependency, which meant `wc-mediator`
could not resolve from a registry at all: `cargo add wc-mediator` was impossible, and a
consumer had to check out two repositories at commits nothing recorded — no version
constraint, no semver contract, and a binary whose core revision was unanswerable from its own
manifest.

It is a **version** requirement now, `warden = "0.1"`, with a `[patch.crates-io]` at the
workspace root pointing at the sibling checkout. That patch applies when building *this*
workspace and is not part of published crate metadata, so a registry consumer resolves
`warden` from crates.io and never sees a path.

The coupling model is unchanged — one dependency, still only from `wc-mediator`, still the
deployment model rather than a dependency choice. What changed is that it is now expressible.

### The order matters

1. **Publish Warden core first.** `wc-mediator` depends on a published `warden`, so its own
   publish fails until that exists. Core is already publish-ready: full metadata, keywords,
   categories, an `exclude` list, and no `publish = false`.
2. Then, dependency order: `wc-core`, `wc-control`, `wc-mediator`, `wc-cli`.
3. `wc-e2e` stays `publish = false`. It exists so the top of the test pyramid can reach both
   planes at once and ships nothing.
4. **Delete the `[patch.crates-io]` stanza and rebuild** before believing any of it. While the
   patch is present the build never touches the registry, so a broken version requirement
   would not show up here — the patch is a development convenience and also a blindfold.

`cargo package -p wc-core` succeeds today (13 files, 92 KiB compressed), which is as far as
verification can go before core is on the registry.

### What making this publishable already found

`cargo deny check bans` failed the moment the crates stopped being `publish = false`: the
**intra-workspace** dependencies were bare path deps, and crates.io does not accept those.
They now carry `path` *and* `version`, which is the standard pattern — Cargo prefers the path
in-workspace and rewrites it to the version on publish. Nothing would have surfaced that while
everything was unpublishable.

## Publishing the Python SDK

The SDK versions and ships **independently of the Rust crates**, and it can ship, because it
has no path dependency to resolve. `sdk-release.yml` is the workflow, triggered by a
`sdk-v*` tag — prefixed so a Rust release tag cannot publish a Python package by accident.

It uses **PyPI trusted publishing (OIDC), not an API token.** There is no secret to store,
rotate or leak: PyPI verifies a short-lived credential GitHub mints for this repository, this
workflow file and a named environment. A long-lived `PYPI_API_TOKEN` in repository secrets
would put a credential that can publish under this name where a compromised workflow can read
it, which would sit badly beside the rest of this document.

One-time setup nobody can do from a checkout, because it needs the project owner:

1. create or claim `warden-connect-sdk` on PyPI;
2. **Manage → Publishing → add a GitHub publisher**: owner `vijayvedula`, repository
   `warden-connect`, workflow `sdk-release.yml`, environment `pypi`;
3. **Settings → Environments → `pypi`**, with required reviewers.

Step 3 is the one that matters: it makes publishing a decision somebody approves rather than
a side effect of pushing a tag. A published version cannot be replaced on PyPI, only yanked.

The workflow gates in order — tests on **Python 3.9**, the floor `requires-python` claims,
then a build, then `twine check`, then installing the built wheel into a fresh venv and
importing it **from outside the checkout**, because a package that only works from its own
source tree passes every test here and fails for every user. Only then does it publish.

> **This workflow has never run.** It is written from PyPI's and the action's documentation,
> which is the position `limitations.md` describes for anything not backed by an executed
> script. Run it once with `workflow_dispatch` against **TestPyPI** before tagging.

What *has* been verified locally: the wheel and sdist build, the wheel installs into a clean
3.9 venv and behaves when imported from `/tmp`, and the sdist's own tests pass when run from
the unpacked sdist (19 passed, 1 skipped — the skip is the check that cross-references role
names against the Rust source, correctly standing down outside a checkout).

## Provenance

This repository verifies **other people's** provenance and used to produce none of its own,
so trust in a downloaded binary rested on the transport — the residual §7.8 A8 describes for a
control plane. `release.yml` closes that **in the format this component already accepts**,
which is the whole reason it is worth doing this way rather than adopting a second toolchain:

* each binary carries a DSSE / in-toto **SLSA v1** envelope, signed keyless through Fulcio so
  there is no signing key in repository secrets;
* the workflow **verifies what it just attested, with our own verifier**, in the same run. If
  that step fails the release does not ship, which is what keeps this section true rather than
  turning it into prose;
* a downloader runs `scripts/verify-release.sh`, which needs **no Sigstore client, no network
  and no cosign** — a `connect` binary they already trust and the public key.

```sh
scripts/verify-release.sh connect connect.dsse.json builder-pub.pem \
  https://github.com/vijayvedula/warden-connect/.github/workflows/release.yml
```

Three bindings, all required, because a valid signature vouches for nothing in particular:
signed by the key you expected, `subject[].digest.sha256` equal to **the file in front of
you**, and `builder.id` in an allowlist you wrote. The script computes the digest from the
bytes rather than reading `SHA256SUMS`, because a digest retyped from a release page is a
digest whoever controls the page chose. `SHA256SUMS` ships for humans.

### What is still not done

* **Keyless signing means the verifying key is in a certificate.** `connect attest verify` is
  offline and Sigstore-free by design, so it checks the envelope and the bindings and does
  **not** walk the Fulcio chain. Both halves are needed: run `cosign verify-blob-attestation`
  as well, with `--certificate-identity` and `--certificate-oidc-issuer`. Neither substitutes
  for the other, and a release note that mentioned only one would be worse than mentioning
  neither.
* **Rekor inclusion is not verified.** `connect attest verify` prints *"inclusion NOT
  checked"* rather than implying otherwise.
* **No signed git tags, and no reproducible-build claim.** Tag signing is a key-custody
  decision like every other; reproducibility has not been measured.
* **The image is not signed.** `release.yml` covers the binaries; the container image is
  built in CI and not attested.

> **`release.yml` has never run.** It is written from the actions' and cosign's documentation
> — the position `limitations.md` describes for anything not backed by an executed script, and
> the class the four wrong SPIRE commands came from. What *is* verified is the half that can be:
> `connect attest verify` and `scripts/verify-release.sh` against **real cosign v3.1.3 output**
> in `fixtures/cosign/`, including every refusal — a substituted artifact, an unlisted builder,
> an untrusted key, a missing allowlist, and a missing subject. Run the workflow with
> `workflow_dispatch` and verify the artefacts by hand before tagging.

## What is verified where

| Claim | Verified by | Verified now? |
|---|---|---|
| the tests pass, on the MSRV | CI `check` + `msrv` | yes |
| the §8.10.3 latency gates hold | CI `gates`, release mode | yes |
| no banned dependency, no advisory | CI `supply-chain` | yes |
| the SBOM is complete and reproducible | CI `supply-chain` | yes |
| the containment drill still works | CI `gates` | yes — but on a scratch estate with a *file* standing in for the hardware token |
| federation against a second control plane | CI `gates` | yes |
| **the image builds and runs** | CI `image` | yes — built and all four steps run locally on Docker 29.5 (linux/arm64), which is also how the `register server` bug in that job was found |
| the containment drill against the real offline token | a human, quarterly | no |
| the restore drill at production size, timed | nobody | no |
| the rotation drill | nobody | no |
| release provenance | nobody | no |
