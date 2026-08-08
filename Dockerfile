# warden-connect — the connection control plane and the inline mediator.
#
# Two binaries, two very different jobs, one image. `connect` is the control plane and the
# operator CLI; `connect-mediate` is the data-plane sidecar. They ship together because a
# mediator's version has to be answerable during an incident, and two images means two
# answers.
#
# ── The build context is the PARENT directory ──────────────────────────────────
#
# Warden core is a path dependency at `../warden` by design (§8.3): `wc-mediator` compiles
# *into* the proxy, so the coupling is the deployment model rather than a dependency
# choice. Cargo cannot fetch it, so the build context must contain both repositories:
#
#     cd ..                      # the directory holding warden/ and warden-connect/
#     docker build -f warden-connect/Dockerfile -t warden-connect:dev .
#
# Building from inside `warden-connect/` fails at `cargo build` with an unresolved path
# dependency, which is the correct failure — it is the same constraint CI carries, and an
# image built without core would be an image whose mediator cannot exist.

# ── Build ─────────────────────────────────────────────────────────────────────
#
# Pinned to the MSRV rather than `rust:1`. The MSRV job in CI tests 1.89, and an image built
# on a newer toolchain than the one that gates the tests is an image nobody verified.
FROM rust:1.89-bookworm AS build

WORKDIR /src

# Manifests first, so the dependency tree caches independently of source edits. Both
# repositories' manifests are needed before either can resolve.
COPY warden/Cargo.toml warden/Cargo.lock warden/
COPY warden-connect/Cargo.toml warden-connect/Cargo.lock warden-connect/
COPY warden-connect/crates/wc-core/Cargo.toml warden-connect/crates/wc-core/
COPY warden-connect/crates/wc-control/Cargo.toml warden-connect/crates/wc-control/
COPY warden-connect/crates/wc-cli/Cargo.toml warden-connect/crates/wc-cli/
COPY warden-connect/crates/wc-mediator/Cargo.toml warden-connect/crates/wc-mediator/
COPY warden-connect/crates/wc-e2e/Cargo.toml warden-connect/crates/wc-e2e/

# Stub sources so `cargo build` resolves and downloads the tree. `|| true` because the
# stubs do not compile — the point is the download, not the artifact.
RUN set -eu; \
    mkdir -p warden/src; echo 'fn main() {}' > warden/src/main.rs; \
    echo '' > warden/src/lib.rs; \
    for c in wc-core wc-control wc-mediator wc-e2e; do \
      mkdir -p "warden-connect/crates/$c/src"; \
      echo '' > "warden-connect/crates/$c/src/lib.rs"; \
    done; \
    mkdir -p warden-connect/crates/wc-cli/src; \
    echo 'fn main() {}' > warden-connect/crates/wc-cli/src/main.rs; \
    cd warden-connect && cargo build --release --locked || true

# The real sources. `fixtures/` comes along because the conformance vectors and the
# attestation material are compiled in by `include_bytes!`, so the build needs them —
# without this the image fails to compile rather than shipping something untested.
COPY warden/ warden/
COPY warden-connect/ warden-connect/

# Touch the roots so the stub-cached crates are genuinely rebuilt. Cargo keys on mtime,
# and a stub .rlib silently reused would produce an image with an empty library in it.
RUN set -eu; cd warden-connect; \
    find . ../warden -name '*.rs' -newermt '1970-01-01' -exec touch {} +; \
    cargo build --release --locked --bin connect --bin connect-mediate

# ── Runtime ───────────────────────────────────────────────────────────────────
#
# `debian:bookworm-slim`, not `scratch`. §8.3 chose `jsonwebtoken`'s `rust_crypto` backend
# specifically so this *could* be a static scratch image — but the operator story needs a
# shell: `connect audit verify`, `connect backup` and the restore drill in
# docs/operations.md are all run by a human inside or beside this container, and a scratch
# image makes every one of them require a second image with the same binary in it.
#
# The trade is stated rather than defaulted: if your threat model wants no shell, build
# with `--target x86_64-unknown-linux-musl` and copy into `scratch`. Nothing here links a
# system library, so that works.
FROM debian:bookworm-slim

# `ca-certificates` because the mediator fetches contracts and key sets over HTTPS
# (`--contracts`, `--jwks-url`) and `ureq`'s rustls needs a trust store. Without it every
# fetch fails with a certificate error that looks like a server problem.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --system --no-create-home --uid 10001 connect; \
    mkdir -p /var/lib/warden-connect; \
    chown connect:connect /var/lib/warden-connect

COPY --from=build /src/warden-connect/target/release/connect /usr/local/bin/connect
COPY --from=build /src/warden-connect/target/release/connect-mediate /usr/local/bin/connect-mediate

# Non-root, and the state root is a volume. `connect serve` needs durable storage — an
# evidence chain that restarts on reschedule has no history, which for the regulatory
# purpose it exists to serve is the same as nothing (docs/twelve-factor.md).
USER connect
VOLUME ["/var/lib/warden-connect"]
ENV WARDEN_CONNECT_ROOT=/var/lib/warden-connect

# `serve` binds 8787 by default. Deliberately plain HTTP: TLS is terminated in front of
# this process in every topology docs/physical-architecture.md describes, and a non-loopback
# listener refuses to start unless the operator says how that is handled.
EXPOSE 8787

# `/readyz` is about being able to decide, not about being up — which is the distinction a
# readiness probe should use. `/healthz` is the liveness one.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/connect", "version"]

ENTRYPOINT ["connect"]
CMD ["--help"]
