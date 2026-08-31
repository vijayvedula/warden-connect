# Installing an enforcement point

All artifacts come from a release. No checkout is needed.

## Artifacts

| Artifact | What it is |
|---|---|
| `connect` | control plane CLI |
| `connect-mediate` | inline mediator |
| `wc-extproc` | Envoy binding: an `ext_proc` gRPC daemon |
| `libwc_kong.so` | Kong binding: a cdylib loaded by LuaJIT FFI |
| `wc-kong-lua.tar.gz` | the Kong plugin's Lua half and the C header |
| `SHA256SUMS` | digests |

## Verify first

Check the certificate before the signature. A signature checked against a key
of unknown provenance proves nothing.

```sh
cosign verify-blob-attestation \
  --bundle wc-extproc.provenance.bundle --new-bundle-format \
  --type slsaprovenance1 \
  --certificate-identity 'https://github.com/<owner>/warden-connect/.github/workflows/release.yml@refs/tags/<tag>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  wc-extproc
sha256sum -c SHA256SUMS --ignore-missing
```

`scripts/verify-release.sh` computes its own digests from the bytes rather than
reading `SHA256SUMS`.

## Envoy

Envoy calls `wc-extproc` per request over `ext_proc`. One network hop.

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
  --token       "<token with the connect.mediator role>" \
  --refresh     5 \
  --max-stale   300 \
  --evidence    /var/log/warden-connect/decisions.jsonl
```

`wc-extproc --help` lists the rest. Four flags matter most:

| Flag | Rule |
|---|---|
| `--callee` / `--routes` | Exactly one. The callee comes from configuration and the route Envoy chose, never from the request |
| `--contracts URL` | Requires `--token`. Without a pull, no revocation reaches the daemon and expiry is the only containment. `--contract FILE` (singular, repeatable) is the air-gapped alternative |
| `--max-stale` | Seconds the set may go without a *successful* refresh before every call is refused. Only a clean refresh counts |
| `--evidence-delivery` | What a call with no contract gets. `terms.evidence.delivery` overrides it per contract |

## Kong

Two halves, both required: the cdylib decides, the Lua loads it and passes the
request. No network hop.

```sh
tar -xzf wc-kong-lua.tar.gz -C /usr/local/share/lua/5.1/   # gives kong/plugins/warden-connect/
install -m 0755 libwc_kong.so /usr/local/lib/
```

```yaml
plugins:
  - name: warden-connect
    config:
      library_path:  /usr/local/lib/libwc_kong.so
      contracts:     ["/etc/warden-connect/c.jws"]
      routes:        /etc/warden-connect/routes.toml
      identity:      tls            # or xfcc
      issuer_pub:    /etc/warden-connect/issuer.pub.pem
      kid:           issuer-1
      mediator_id:   "warden:mediator:edge-1"
      issuer_id:     "https://connect.example/t/prod"
      mode:          enforce
      evidence_path: /var/log/kong/wc-%w.jsonl
      contracts_url: https://connect.example
      token:         "<token with the connect.mediator role>"
      refresh_secs:  5
      max_stale:     300
```

Set `KONG_PLUGINS=bundled,warden-connect`. Four keys matter most:

| Key | Rule |
|---|---|
| `evidence_path` | Must contain `%w` when `worker_processes > 1`. Each worker keeps its own hash chain; two workers appending to one file produce a trail that never verifies |
| `contracts_url` | Requires `token`. Without one the plugin refuses to start rather than hold a set no revocation can reach |
| `max_stale` | Seconds a worker may run on an unrefreshed set. Past it, every call is refused |
| `identity` | `tls` uses the client certificate. `xfcc` trusts a header and requires the connection to be local, refusing `WC-4020` otherwise |

## Inline mediator

`connect-mediate` sits in the path as a stdio sidecar and spawns the upstream
server itself. Identity is configured by the operator, not authenticated, which
suits a sidecar owning one agent and not a shared gateway.

```sh
install -m 0755 connect-mediate /usr/local/bin/

connect-mediate \
  --upstream    "python3 /opt/payments/server.py" \
  --caller      spiffe://bank.example/ns/agents/sa/recon-bot \
  --callee      spiffe://bank.example/ns/mesh/sa/payments-mcp \
  --mediator-id warden:mediator:edge-1 \
  --issuer-id   https://connect.example/t/prod \
  --issuer-pub  /etc/warden-connect/issuer.pub.pem \
  --kid         issuer-1 \
  --contract    /etc/warden-connect/c.jws
```

Use `--upstream-url` instead of `--upstream` for a remote server over Streamable
HTTP. This binding writes no decision trail.

## Running the control plane

```sh
connect serve --listen 0.0.0.0:8787 --issuer-key .keys/k-2026-01.pem --kid k-2026-01 \
    --behind-tls-proxy --trusted-proxy 10.0.1.5 \
    --tokens tokens.toml --approvers approvers.toml
```

`serve` speaks **plain HTTP on purpose** — every supported topology terminates TLS
at an ALB, an Ingress, HAProxy or Front Door. A non-loopback listener therefore
**refuses to start** unless you say how TLS is handled.

| Flag | Rule |
|---|---|
| `--behind-tls-proxy` | Every authenticated request must carry `x-forwarded-proto: https` |
| `--trusted-proxy ADDR` | …and must arrive from an address you named. A request that reaches the port directly, bypassing the ingress, is refused rather than trusted |
| `--require-external-signing` | Refuses to start if any key would be read from local disk |

Signing keys have a delegated form everywhere they have a PEM form
([LLD §8.12.1](../08-lld.md#8121-keys--keys-custody-signer)): `--signer COMMAND`
reads a base64url signing input on stdin and writes a base64url signature on
stdout, so the private key can live in an HSM, a smartcard or a KMS and never
reach this process.

## Before deploying

```sh
connect gateway check --plugin-config plugin.json
```

Runs the binding's own startup path against the configuration. Whatever it
refuses, a worker would also have refused at request time.

## Checking the trail

```sh
connect evidence verify /var/log/kong/wc-0.jsonl
connect evidence since  /var/log/kong/wc-0.jsonl --seq 1042 --json
```

`since` verifies the whole trail before returning any row, so an edited file
yields nothing rather than the rows after the break.
