# Prerequisites for executing every flow

The hardening pass has one rule: **run the binaries.** Every defect this build turned up was
found by executing a flow, not by reading code — including three inside the tooling written
to check things. So the first question is which flows are reachable, and that is a question a
script should answer rather than a document:

```sh
scripts/preflight.sh
```

It prints what is present, what is missing, the install line for each miss, and **what each
one unlocks**. This page is the reasoning behind that list.

---

## Nothing extra needed

These flows run today on a stock toolchain plus `../warden`:

| Flow | Command |
|---|---|
| The whole suite | `cargo test --workspace` |
| The conformance kit against any verifier | `scripts/conformance.sh ./my-verifier` |
| Containment, including break-glass | `scripts/containment-drill.sh` |
| A mediator over a real MCP upstream | `connect-mediate --upstream "python3 ../warden/examples/echo_mcp_server.py" …` |
| Backup, restore, `audit verify` | `connect backup` / `restore` |
| The standby handover | `connect serve --standby` |
| Federation across two control planes | two `connect serve`, two roots, two ports |
| The container image | `cd .. && docker build -f warden-connect/Dockerfile .` |

Warden core ships `examples/echo_mcp_server.py`, so **no external MCP server is needed** to
drive `tools/list` and `tools/call` through a mediator.

## 1 · Core toolchain

```sh
# Rust, and the MSRV CI pins — a newer-only toolchain hides MSRV breaks
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install 1.89

# Warden core, beside this repo. A path dependency by design (§8.3): wc-mediator
# compiles *into* the proxy, so cargo cannot fetch it.
git clone https://github.com/vijayvedula/warden.git   # as a sibling directory

# python3 and openssl are used by the SBOM, the conformance plan and the drills.
```

## 2 · Verification tooling

```sh
cargo install cargo-deny        # advisories, licences, the §8.3 bans
cargo install cargo-fuzz       # coverage-guided campaigns
rustup toolchain install nightly   # libfuzzer needs it
pip install cryptography       # mints attestation fixtures independently of our Rust
brew install jq                # optional, convenience in the drills
```

Docker from <https://docs.docker.com/get-docker/>. **The build context is the parent
directory** — building from inside this repo fails at `cargo build`, which is the correct
failure, because an image without core is an image whose mediator cannot exist.

## 3 · A delegated signer — the highest-value gap to close

P0 #5's remaining gap. `--signer` and `--anchor-signer` exist and had never been driven
against a real PKCS#11 device. SoftHSM closes that for the cost of one `brew install`, and it
exercises the trap that actually costs estates.

```sh
brew install softhsm opensc          # apt: softhsm2 opensc

export SOFTHSM2_CONF=~/.softhsm2.conf
mkdir -p ~/.softhsm2/tokens
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $HOME/.softhsm2/tokens
objectstore.backend = file
log.level = ERROR
EOF

softhsm2-util --init-token --slot 0 --label wc-issuer --so-pin 1234 --pin 1234
MOD=/opt/homebrew/lib/softhsm/libsofthsm2.so     # apt: /usr/lib/softhsm/libsofthsm2.so
pkcs11-tool --module "$MOD" --login --pin 1234 \
    --keypairgen --key-type EC:prime256v1 --label wc-issuer-2026 --id 01
```

Then sign with it:

```sh
export WC_PKCS11_MODULE="$MOD" WC_PKCS11_PIN=1234 WC_PKCS11_LABEL=wc-issuer-2026

connect quarantine <id> --reason "hsm-signed" \
    --revocation-signer "python3 examples/signers/pkcs11.py" \
    --kid wc-issuer-2026 --require-external-signing --by human:you
```

Two ready wrappers, both verified end to end:

| | For |
|---|---|
| [`examples/signers/pkcs11.py`](../examples/signers/pkcs11.py) | PKCS#11 — SoftHSM, YubiKey PIV, a real HSM |
| [`examples/signers/kms-der.py`](../examples/signers/kms-der.py) | anything returning **DER** — AWS/GCP/Azure KMS, `openssl dgst` |

### The trap, and why there are two files

`CKM_ECDSA` returns raw `R‖S`, which is already JWS form. **Almost everything else returns
DER**: every cloud KMS, and `openssl dgst -sign`. A wrapper forwarding DER produces contracts
that are well-formed, look signed, and verify nowhere — reported as `WC-3102 signature or
issuer chain invalid`, which reads like a *tampered artifact* rather than a wrapper bug. That
misdirection is the cost.

Both wrappers therefore **assert the length** (64 bytes for P-256, 96 for P-384) and fail
loudly. `kms-der.py`'s `der_to_raw` handles the two subtleties naive versions get wrong: DER
integers are signed, so a coordinate with its top bit set carries a leading `0x00` to strip;
and a short coordinate must be **left**-padded, or the signature is quietly the wrong length.

**A real token for `revoke-offline`.** SoftHSM rehearses the wrapper, not the ceremony. What
fails on the day is a flat battery, a forgotten PIN, or a departed share-holder — so
`scripts/containment-drill.sh`'s closing note stands: run it quarterly against the real token
(`brew install ykman`), in the safe, with the named holders present.

## 4 · SPIRE — attestation stage 1

**Done, and re-runnable.** Stage 1 has been verified against a real SPIRE 1.15.2 server and
agent; the material is checked in at [`fixtures/spire/`](../fixtures/spire/README.md). The
only dependency is **Docker**, already covered in §2:

```sh
scripts/spire-fixtures.sh          # downloads SPIRE, verifies the digest, mints
cargo test -p wc-e2e --test attest
```

Nothing to install by hand, and nothing to install on a Mac at all: **SPIRE publishes linux
and windows binaries only**, so `brew install spire` does not exist and `command -v
spire-server` will never succeed there. The script mounts the linux musl release binaries
into Alpine instead — the official images are distroless and have no shell.

The bundle needs no conversion: `spire-server bundle show -format spiffe` is already a JWKS
and `IssuerKeys::add_jwks` reads it directly, which is what P0 #6 removed.

> An earlier version of this section gave three commands that do not exist — `brew install
> spire`, `spire-agent api fetch jwtbundles`, and a `sed` that never matched SPIRE's real
> output. [`fixtures/spire/README.md`](../fixtures/spire/README.md) records what they should
> have been. Worth knowing about any procedure in these docs that has not been run.

## 5 · cosign — attestation stage 4

Real DSSE/in-toto SLSA provenance instead of a locally minted envelope.

```sh
brew install cosign
cosign attest-blob --predicate provenance.json --type slsaprovenance1 \
    --key cosign.key --output-signature provenance.dsse.json <artifact>
```

## 6 · Prometheus — the four alerts have never been evaluated

`docs/observability.md` states four alerts as PromQL and **not one has been run against a
live series.** An alert nobody has evaluated is a query, not an alert.

```sh
brew install prometheus       # brings promtool
promtool check rules alerts.yml
```

Point it at `connect serve`'s `/metrics` and at the mediator's `--metrics-file` through
node-exporter's textfile collector. The one worth confirming first is
`wc_mediator_unconfirmed > 0` — *unconfirmed is not contained* is the most dangerous state
this system has, and it is the alert most worth knowing fires.

## 7 · A TLS proxy — `--behind-tls-proxy` above the socket level

Asserted today only at socket level in `crates/wc-control/tests/transport.rs`. Never behind a
real terminating proxy.

```sh
brew install caddy
caddy reverse-proxy --from https://localhost:8443 --to 127.0.0.1:8787
```

The thing to verify is that a real proxy sets `x-forwarded-proto: https` from an address you
named in `--trusted-proxy`, and that reaching `:8787` **directly** is refused.

---

## Cost, honestly

| | Time | Unlocks |
|---|---|---|
| SoftHSM | ~5 min | the delegated-signer path, verified — **do this one** |
| Prometheus | ~15 min | four alerts that are currently unevaluated PromQL |
| A TLS proxy | ~10 min | the transport control end to end |
| cosign | ~10 min | attestation stage 4 |
| SPIRE | hours | attestation stage 1 against a real issuer |

SPIRE is the only genuinely expensive one, and it is last for that reason rather than because
it matters least.

## What no installation fixes

* **Two real regions** (#19) — two volumes, two failure domains. The tests run two tenants
  under one root, which exercises isolation and escalation but not operational reality.
* **crates.io publishing** (#13) — blocked by the path dependency on core. A coupling
  decision, not a tooling one.
* **A measured RTO** — restore at production size, timed. Needs a production-sized root.
* **WORM storage for anchors** — S3 Object Lock in compliance mode, or MinIO locally.
