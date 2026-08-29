# Installing an enforcement point

Both bindings are release artifacts. Nothing here needs a clone of this
repository — which was the gap this document closes: the bindings were built,
tested and drilled, and the only way to obtain one was `cargo build`.

Every artifact is attested. **Verify before you run it**, in this order — the
certificate first, because a signature checked against a key of unknown
provenance vouches for nothing:

```sh
cosign verify-blob-attestation \
  --bundle wc-extproc.provenance.bundle --new-bundle-format \
  --type slsaprovenance1 \
  --certificate-identity 'https://github.com/<owner>/warden-connect/.github/workflows/release.yml@refs/tags/<tag>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  wc-extproc
sha256sum -c SHA256SUMS --ignore-missing
```

| Artifact | What it is |
|---|---|
| `connect` | the control plane CLI |
| `connect-mediate` | the mediator |
| `wc-extproc` | the Envoy binding: an `ext_proc` gRPC daemon |
| `libwc_kong.so` | the Kong binding: a cdylib loaded by LuaJIT FFI |
| `wc-kong-lua.tar.gz` | the Kong plugin's Lua half, and the C header the FFI is declared against |
| `SHA256SUMS` | digests. `verify-release.sh` computes its own from the bytes rather than reading this |

## Envoy — one hop

`wc-extproc` is a standalone daemon. Envoy calls it per request over
`ext_proc`; it answers with a verdict.

```sh
install -m 0755 wc-extproc /usr/local/bin/

wc-extproc \
  --listen      127.0.0.1:9002 \
  --routes      /etc/warden-connect/routes.toml \
  --issuer-pub  /etc/warden-connect/issuer.pub.pem \
  --kid         issuer-1 \
  --mediator-id warden:mediator:edge-1 \
  --issuer-id   https://connect.example/t/prod \
  --contracts   https://connect.example \
  --token       "<a token with the connect.mediator role>" \
  --refresh     5 \
  --max-stale   300 \
  --evidence    /var/log/warden-connect/decisions.jsonl
```

`wc-extproc --help` lists the rest. Four points repay reading twice:

- **Exactly one of `--callee` or `--routes`.** The callee comes from
  configuration and the route Envoy chose, never from the request: a caller who
  could name its own callee could name one it holds a contract for while the
  traffic went somewhere else.
- **`--contracts URL` needs `--token`.** Without a pull the daemon serves the
  artifacts it started with and **no revocation can reach it**; contract expiry
  becomes the only containment. The air-gapped alternative is `--contract FILE`,
  repeatable — a different flag, singular, and it accepts no URL.
- **`--max-stale`** bounds how long the set may go without a *successful*
  refresh before every call is refused. Only a clean refresh counts as fresh.
- **`--evidence-delivery blocking`** for calls that have no contract and so no
  terms to read. A contract's own `terms.evidence.delivery` overrides it.

## Kong — zero hops

Two halves, and both are required: the cdylib does the deciding, the Lua loads
it and hands it the request.

```sh
tar -xzf wc-kong-lua.tar.gz -C /usr/local/share/lua/5.1/   # gives kong/plugins/warden-connect/
install -m 0755 libwc_kong.so /usr/local/lib/
```

Then in Kong's configuration:

```yaml
plugins:
  - name: warden-connect
    config:
      library_path: /usr/local/lib/libwc_kong.so
      contracts:    ["/etc/warden-connect/c.jws"]
      routes:       /etc/warden-connect/routes.toml
      identity:     tls            # or xfcc, behind a mesh you trust
      issuer_pub:   /etc/warden-connect/issuer.pub.pem
      kid:          issuer-1
      mediator_id:  "warden:mediator:edge-1"
      issuer_id:    "https://connect.example/t/prod"
      mode:         enforce
      evidence_path: /var/log/kong/wc-%w.jsonl
      contracts_url: https://connect.example
      token:        "<a token with the connect.mediator role>"
      refresh_secs: 5
      max_stale:    300
```

with `KONG_PLUGINS=bundled,warden-connect`.

Four of those repay reading twice:

- **`%w` in `evidence_path` is required when `worker_processes > 1`.** Each
  worker keeps its own hash chain; two appending to one file interleave into a
  trail that never verifies, while every row still looks well-formed.
- **`contracts_url` needs `token`.** Configured without one, every pull is
  refused and the worker keeps a set no revocation can reach. The binding
  refuses to start rather than run in that state.
- **`max_stale`** bounds how long a worker may run on a set nobody has
  refreshed. Past it, every call is refused: a set that cannot be refreshed is
  a set a revocation cannot reach, and refusing is the only honest answer.
- **`identity: xfcc`** trusts a header. Only use it where the mesh terminates
  mTLS and the hop to Kong is one you control — the binding requires the
  connection to be local and refuses `WC-4020` otherwise.

## Before you deploy either

```sh
connect gateway check --plugin-config plugin.json
```

Runs the binding's own startup path against your configuration. What it
refuses, a worker would have refused too — at request rate, in an nginx error
log, after the traffic arrived.

## Checking the trail

```sh
connect evidence verify /var/log/kong/wc-0.jsonl
connect evidence since  /var/log/kong/wc-0.jsonl --seq 1042 --json
```

`since` verifies the whole trail before returning a row, so an edited file
yields nothing rather than the rows after the break.
