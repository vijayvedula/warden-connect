# SPIRE fixtures — real output, not minted here

Produced by [`scripts/spire-fixtures.sh`](../../scripts/spire-fixtures.sh) from a **real
SPIRE 1.15.2 server and agent**, and read by the interop tests at the end of
`crates/wc-e2e/tests/attest.rs`.

| File | What it is |
|---|---|
| `jwt-svid.token` | A JWT-SVID SPIRE issued for `warden-connect://control-plane/apac` |
| `jwt-svid-other-audience.token` | The same workload, an SVID for the EMEA control plane |
| `bundle.spiffe.json` | `spire-server bundle show -format spiffe`, **unedited** |
| `manifest.json` | The `kid`, `sub`, `aud`, `iat` and `exp` the tests read rather than hard-code |

## Why this exists beside `fixtures/attest/`

[`fixtures/attest/`](../attest/README.md) is minted by `scripts/gen-attest-fixtures.py`
from the SPIFFE and JOSE spec text. That is a genuinely independent second reading, and it
catches a disagreement about **what the specs say**. It cannot catch a disagreement about
**what an issuer actually emits** — and that is precisely where stage 4 was broken, where
`DsseProvenanceVerifier` rejected every real cosign attestation over a missing `keyid` and
a DER signature. `fixtures/cosign/` closed that gap one stage down. This closes it here.

**Unlike cosign, stage 1 needed no code change.** `JwtSvidIdentity` accepted a real SPIRE
SVID first time. That is worth recording as a result rather than assumed — it is the only
integration in this build that did.

## What the real shape turned out to be

Three properties the verifier is allowed to depend on, each asserted by
`a_real_spire_svid_omits_iss_and_nbf` so a future change that breaks them fails with the
reason attached:

* **No `iss` claim.** SPIRE does not emit one; the trust domain lives in `sub`. A verifier
  calling `set_issuer(...)` would reject every real SVID while every fixture in
  `fixtures/attest/` kept passing.
* **No `nbf` claim.** Only `iat` and `exp`.
* **`aud` is an array**, even for a single audience.

And one about the bundle: `bundle show -format spiffe` returns the **x509-svid signing key
beside the jwt-svid one, and the x509 key has no `kid`**. It is checked in whole because
that whole document is what an operator will paste. `IssuerKeys::add_jwks` skips it, adds
the JWT key, and reports `is_complete() == false` with the reason — which is the behaviour
`the_whole_spiffe_bundle_loads_and_says_what_it_could_not_use` pins down.

## The token is expired, and that is correct

SPIRE's default JWT-SVID lifetime is an hour, so the checked-in token was expired against
the wall clock within an hour of being minted and always will be. Nothing here needs
refreshing. `JwtSvidIdentity::now` is injected — like `AdmissionCtx::now`, `GateCfg::now`
and `VerifyOpts::now` — so the tests judge the token at instants they choose, and
`a_real_spire_svid_is_refused_once_its_own_exp_passes` asserts both sides of its own `exp`.

A fixture that never expired would be a fixture no real issuer would ever mint.

## Regenerating

```sh
scripts/spire-fixtures.sh          # downloads SPIRE, verifies the digest, mints
cargo test -p wc-e2e --test attest
```

Every run produces a new CA and a new `kid`, so the tests read `manifest.json` rather than
hard-coding one. There is no keypair checked in here: the private key never leaves the
throwaway server this script creates and destroys.

## Two commands that do not exist

Both were in this repository's own documented procedure, and neither works. Recorded here
because a broken procedure is how a control ends up never exercised:

* **`spire-agent api fetch jwtbundles`** — there is no such subcommand. `api fetch` takes
  `x509` and `jwt`; the JWT bundle comes back inside `api fetch jwt` output, or from
  `spire-server bundle show -format spiffe`.
* **`spire-server bundle show -format jwks`** — `-format` takes only `pem` or `spiffe`.
  The SPIFFE bundle format already *is* a JWKS with extra members, so no conversion step
  is needed; that is what `add_jwks` reads.

A third was subtler: the documented extraction

```sh
spire-agent api fetch jwt -audience … | sed -n 's/^ *token: *//p'
```

matches nothing, because the real output is `token(spiffe://…):` — with the SPIFFE ID in
parentheses — and the token itself on the *next* line. It would have written an empty
file. Use `-output json` and `jq -r '.[0].svids[0].svid'`, which is what the script does.

## Docker, because there is no darwin build

SPIRE publishes linux and windows binaries only, so `command -v spire-server` will never
succeed on a Mac however much you install — which also made
[`scripts/preflight.sh`](../../scripts/preflight.sh)'s original SPIRE check unsatisfiable
there. The official container images are distroless and have no shell, so the script mounts
the release binaries into Alpine and verifies the tarball digest against the published sum
first.
