# Twelve-factor: what holds, and what does not

Referenced by [08-lld.md](08-lld.md) §1 as *"Everything via `WARDEN_CONNECT_*` env, TOML
file, or flag — flags override file overrides env (core's precedence)."*

**That sentence is not what the code does, and the difference is the first thing on this
page.** There is no general configuration file. Config is flags plus four environment
variables, and the TOML files this component reads are *domain* documents — a policy, a
keyring, a token table — not a config layer with precedence over flags. The three-layer
chain the LLD describes is two layers.

That is recorded here rather than quietly satisfied, because a component whose own
design document overstates its configurability is the same defect class this repository
keeps finding: a control that reads as configured and is not there.

---

## I · Codebase

One repository, one revision, many deploys. A control plane, any number of mediators,
and the same binaries in CI.

Warden core is a **path dependency** at `../warden`, not a registry crate. That is
deliberate (§8.3) — `wc-mediator` compiles *into* the proxy — but it means a deploy is
pinned by two revisions, not one. `.github/workflows/ci.yml` checks out both side by
side, so the pairing is explicit rather than whatever happened to be on the builder.

## II · Dependencies

Declared in `Cargo.toml`, locked in `Cargo.lock`, and **bounded**:

- [`deny.toml`](../deny.toml) refuses async runtimes, ORMs, database drivers and
  `openssl` by name. §8.3's "no async runtime, no ORM, no graph database" is enforced,
  not remembered.
- [`scripts/dep-count.sh`](../scripts/dep-count.sh) asserts a ceiling per crate, so the
  next transitive addition is visible.

No system packages. `jsonwebtoken`'s `rust_crypto` backend is chosen over `aws_lc_rs`
precisely so the binary builds and runs in a `scratch` container with no linked C
library. The cost is `rsa` in the tree — see the RUSTSEC-2023-0071 note in `deny.toml`,
which is an argued exception with a review date, not a blanket ignore.

## III · Config

**What exists:**

| Env | Flag | Meaning |
|---|---|---|
| `WARDEN_CONNECT_ROOT` | `--root` | state and evidence root (default `.connect`) |
| `WARDEN_CONNECT_TENANT` | `--tenant` | tenant on this root (default `default`) |
| `WARDEN_CONNECT_ACTOR` | `--by`, `--as` | who is acting, for evidence rows |
| `WARDEN_CONNECT_REQUIRE_EXTERNAL_SIGNING` | `--require-external-signing` | refuse to start if any signing key would be read from local disk |

Precedence is **flag, then env**. Nothing else.

**Domain documents, passed by path:** `connect-policy.toml`, `keys.toml`,
`tokens.toml`, `approvers.toml`, `screen-rules.toml`, `tenants.toml`, `streams.toml`,
`anchors.toml`, `mediators.toml`. These are versioned artifacts an operator reviews and
an auditor reads — a zone matrix is not an environment variable, and flattening one into
`WARDEN_CONNECT_ZONE_BARS` would make it unreviewable to make it twelve-factor.

**Secrets are not config.** No private key is ever read from an environment variable. A
signing key is a file path or a delegated signer command
([key-custody.md](key-custody.md)); bearer tokens live in `tokens.toml`, which is
expected to be a mounted secret. An env var is readable from `/proc`, inherited by every
child process, and printed by any crash reporter that dumps the environment.

**The gap:** no `--config FILE` for the flags themselves, so a deployment with many
flags carries them in its unit file or its pod spec. That is workable and it is not what
the LLD claims.

## IV · Backing services

There are almost none, which is the point of §8.16b shipping **no SQL adapter**.

| Service | How it is treated |
|---|---|
| State store | The filesystem under `--root`. A directory, a lock file, append-only logs. |
| Evidence chain | A hash-chained log under the same root, with a signed anchor. |
| Contract source (mediator) | `--contracts URL` over HTTP, or `--contract FILE` for an air-gapped estate. Attached by config, swappable. |
| Issuer keys | `--jwks-url`, `--jwks-file`, or a pinned PEM. Attached by config; a URL and a mounted file are the same code path. |
| Event sink | `EventSink` over HTTP, for a SIEM. Optional, and its failure is logged rather than fatal. |

Every one of these is named by a flag and can move between environments without a code
change. What is *not* a swappable backing service is the state root itself — see below.

## V · Build, release, run

`cargo build --release` produces `connect` and `connect-mediate`. Nothing is generated
at boot; nothing is fetched at boot except the issuer key set and the contract set, and
both failures are startup failures rather than degradations:

- `connect-mediate` **refuses to start** if the first contract refresh fails. A mediator
  that silently degrades to pass-through is worse than no mediator, because the estate
  believes it is protected.
- It refuses to start if the issuer key set is unusable, for the same reason.

## VI · Processes

Stateless where it can be, and honest where it cannot.

`connect-mediate` is stateless: contracts are pulled, verified and cached in memory, and
losing the cache costs one refresh interval. Scale it horizontally, one per agent or one
per gateway.

`connect serve` is **not** stateless and must not be scaled by adding replicas.
Registration, approval and evidence-append are writes to a hash-chained log, and two
writers would fork the chain. `store.rs` takes an exclusive lock and a second writer is
refused with `WC-8003`; HA is **active/standby with that lock as the election
primitive**. See P1 #10 in [production-readiness.md](production-readiness.md) — the
refusal is tested, the failover is not.

No async runtime. Concurrency is OS threads: an accept loop, a refresh loop. The reason
is §8.3 — `wc-core` has to stay embeddable in a caller's own event loop, and an async
runtime in it would make that impossible.

## VII · Port binding

`connect serve --listen 127.0.0.1:8787`. Self-contained HTTP; no application server, no
web server in front of it as a *runtime* requirement.

TLS is a different matter and is **not** terminated in-process. Every topology in
[physical-architecture.md](physical-architecture.md) terminates at an ALB, an Ingress,
HAProxy or Front Door, so a rustls listener here would be a security-critical path
almost nobody runs. What the binary does instead is refuse to be deployed wrong: a
non-loopback listener will not start unless you declare how TLS is handled, and
`--behind-tls-proxy` then requires per-request evidence (`x-forwarded-proto: https` from
a named address) rather than trusting a startup flag.

## VIII · Concurrency

Threads, bounded and named at their call sites. A refresh thread per mediator, an accept
loop per listener. No thread pool tuning knobs, because there is nothing here whose
throughput is thread-bound — see the §8.10.3 latency gates asserted by `connect bench`.

## IX · Disposability

Mediators start in well under a second and can be killed at any point: the contract
cache is derived state.

`connect serve` is disposable **on a persistent root**. `Shutdown` stops the accept loop
so in-flight requests finish; the state log is append-only with the lock released on
exit, and an unclean kill leaves a recoverable log rather than a corrupt one.

## X · Dev/prod parity

The same binaries, the same fixtures, injected clocks everywhere (`AdmissionCtx::now`,
`GateCfg::now`, `VerifyOpts::now`, `Issuer::now`) so no test depends on the wall clock
and no environment behaves differently because of the date.

The deliberate parity break is `--insecure-plaintext`, which accepts bearer tokens over
plaintext from anywhere. It exists because a local demo is real and an operator who
cannot say "yes I mean it" reaches for something worse. It is named so it appears in the
process list and shouts in the startup banner.

## XI · Logs

Event streams on **stderr**, never a file this process manages, never rotated by it.
Anything an operator must act on says what to do: which `kid` changed, which contract
was rejected and with what `WC-*` code, whether a key set is being served from cache.

The **evidence chain is not logs.** It is a hash-chained, signed record with a
verification command (`connect audit verify`) and export formats for DORA, CPS 230 and
OSCAL. Logs may be lost; the chain may not, and it must land on WORM storage.

## XII · Admin processes

The same binary, one-off: `connect audit verify`, `connect export`, `connect policy
dry-run`, `connect keys rotate`, `connect bench`, `connect federate`. No separate admin
image, no shell into a running container to reach a maintenance script.

---

## The factor that does not fit: persistent storage

An operator asked the right question — *what happens on ephemeral storage, in a
Kubernetes pod?*

**Mediators are fine.** Everything under `--root` is derived; a pod can have `emptyDir`
or nothing at all.

**`connect serve` requires durable storage and there is no way around it.** Not for
convenience: the evidence chain's value *is* that it cannot be rewritten. A control
plane on `emptyDir` loses its chain on reschedule, and a chain that restarts has no
history — the audit trail becomes "since the last time the pod moved", which is the same
as nothing for the regulatory purposes it exists to serve. So `serve` needs a
`ReadWriteOnce` volume, and because it is single-writer that constraint and the HA model
are the same constraint.

This is a real deviation from factor VI, stated rather than finessed. A control plane
that could be reconstructed from anywhere would be a control plane whose records could
be reconstructed by anyone.
