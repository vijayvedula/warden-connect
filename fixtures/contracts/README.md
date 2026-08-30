# Connection-contract conformance vectors

`connect verify` is the ground truth for `application/warden-connection+jws`
(LLD §7.4). These files are what that means concretely: **any** implementation may
mint a contract, and a contract is valid iff a conforming verifier accepts it.

That is what makes the artifact a candidate standard rather than a product format
— so this directory is the interoperability contract, and it is deliberately
checkable without linking any warden-connect code.

## What is here

| File | Contents |
|---|---|
| `*.jws` | One artifact per case, one line each |
| `expected.json` | For every vector: a description, the `WC-*` code a conforming verifier must produce (`null` means it must be admitted), its `stage` (`artifact` or `context`), and the `trust_kid`/`trust_alg` a verifier must be **configured** with |

`stage`, `trust_kid` and `trust_alg` are machine-readable so a third party's harness does
not have to hard-code the two tables below out of this document. `trust_*` is deliberately
**not** the artifact's own header `kid`: `unknown-kid.jws` is a vector precisely because the
artifact names a key nobody published, and a harness that configured itself from the
artifact's claim would register the trusted key under the attacker's name and admit it.

**Use the harness rather than driving these by hand:**

```sh
scripts/conformance.sh ./my-verifier
```

See [docs/07-hld.md § Conformance](../../docs/07-hld.md) for the calling convention, the
version policy for this vector set, and what the kit does not yet cover.

The signing keys are in [`../keys/`](../keys) and are **published test keys,
worthless by construction**. `expected.json` names which `kid` maps to which
public key.

## Running them

```sh
connect verify valid-es256.jws \
  --issuer-pub ../keys/test_issuer_es256_pub.pem \
  --kid wc-test-es256 \
  --mediator-id warden:mediator:apac-ops \
  --now 1785312500
```

`--now` is required for reproducibility: several vectors are about the validity
window, so a fixed clock is part of the vector. Exit code `0` means valid, `4`
means the artifact failed verification.

## The two kinds of vector

Verification splits in two, and the vectors do too (§8.6.3):

**Artifact checks (1–5, plus schema and size)** need only the artifact and a
trusted key, so `connect verify` reaches them:

| Vector | Code | Why it must fail |
|---|---|---|
| `hmac-hs256.jws` | `WC-3101` | A shared-secret algorithm would let anyone who can *verify* also *mint* |
| `alg-none.jws` | `WC-3101` | Unsigned, claiming `alg: none` |
| `alg-confusion-ed-for-es.jws` | `WC-3101` | Real EdDSA signature under a `kid` registered for ES256 |
| `unknown-kid.jws` | `WC-3102` | Signed by a key the verifier does not trust |
| `no-kid.jws` | `WC-3102` | No `kid`, so no key can be resolved |
| `tampered-payload.jws` | `WC-3102` | Surface widened after signing |
| `expired.jws` | `WC-3103` | `exp` in the past — there is no grace period |
| `nbf-future.jws` | `WC-3103` | Not valid yet |
| `aud-other-mediator.jws` | `WC-3104` | Addressed elsewhere; replay across mediators must fail |
| `schema-99.jws` | `WC-3120` | A newer payload schema: reject rather than guess |
| `unknown-claim.jws` | `WC-3120` | An unrecognised claim a verifier must not silently ignore |
| `wrong-typ.jws` | `WC-3120` | A JWT that is not a connection contract |
| `oversize.jws` | `WC-3121` | Past the 64 KiB artifact ceiling |

**Context checks (6–11)** need an authenticated peer, the callee's presented
surface, a revocation feed and local zone policy. A command-line tool has none of
those, so these vectors are **valid artifacts that must fail at admission** — they
are for a mediator, not for `connect verify`:

| Vector | Code | Why it must fail |
|---|---|---|
| `revoked-jti.jws` | `WC-3105` | The artifact id is on the revocation feed |
| `surface-superset.jws` | `WC-3108` | Surface widened and re-signed; the digest no longer matches the surface it claims |
| `posture-unattested.jws` | `WC-3109` | Counterparty is not attested (a finding, not a denial, in observe mode) |
| `zone-crossing.jws` | `WC-3110` | `internal` → `partner` with no explicit rule |

`connect verify` names both sets in its output, listing what it checked *and* what
it did not. A verdict that overstates its scope is worse than no verdict.

## Two properties worth testing against

Both concern the per-item surface digest, and both are asserted in
`crates/wc-core/src/contract.rs`:

1. **An additive tool outside the contracted surface must still admit.** The
   callee may grow new tools; a contract over the untouched ones keeps verifying.
2. **Any change to a contracted tool must deny** with `WC-3108`, including a
   description edit that adds an exfiltration instruction.

If your implementation gets (1) wrong you will suspend every contract each time a
tool server ships a release. If you get (2) wrong you have no rug-pull defence at
all.

## Regenerating

Only after an **intentional** format change:

```sh
cargo test -p warden-connect-core conformance::generate_vectors -- --ignored
```

`the_fixtures_on_disk_match_the_generator` fails the build if the code and these
files disagree, so a format change cannot land while leaving the published vectors
stale.
