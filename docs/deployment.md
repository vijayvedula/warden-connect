# Deployment guide

How to get from nothing to enforcing, without a step that requires trusting this document
over the binary. [physical-architecture.md](physical-architecture.md) has the four
topologies; this is the order of operations.

Written for production-readiness P2 #18.

---

## The adoption ladder

Four stages. **Each one is useful on its own**, and the reason to say so is that most of the
value arrives before any enforcement does — an estate that stops at stage 1 has a register
and an audit trail it did not have, at zero risk to production.

| Stage | What runs | What you get | What can break |
|---|---|---|---|
| 1 · Register | `connect serve` only | the inventory, pinned surfaces, the evidence chain | nothing — no data-plane component exists |
| 2 · Observe | `connect-mediate --observe` | what is actually talking to what, as findings | nothing is denied; §8.16's exit criterion is *zero behaviour change measured on the proxy path* |
| 3 · Enforce, per zone pair | `connect-mediate` in enforce, narrow scope | real ceilings on the relationships you understand best | uncontracted calls in scope now fail |
| 4 · Enforce, estate-wide | the same, everywhere | the whole model | anything you missed in stage 2 |

**Do not skip stage 2.** It is the only cheap way to discover the connections nobody
documented, and its findings are the input to stage 3's policy.

---

## Stage 1 · The control plane

### Keys, before anything else

```sh
connect keys new --kid k-2026-q3 --out .keys     # prints the openssl command
```

Six operations sign, and they do not want the same custody — read
[key-custody.md](key-custody.md) before generating anything you intend to keep. The order
that matters:

1. **The anchor key leaves the host first.** A checkpoint signed by a key the control plane
   holds proves only that the control plane agrees with itself, which is precisely what an
   anchor exists to rule out. `--anchor-signer COMMAND`.
2. **The issuer key goes to a KMS.** `--signer COMMAND`.
3. **Approver keys never touch the service's KMS.** Refused structurally now — a key that is
   also a service's is rejected — but the runbook has to put them on the approvers' own
   tokens.
4. **Two revocation keys**, `revoke-online` in the KMS and `revoke-offline` on a hardware
   token. Rehearse the offline one:
   [`scripts/containment-drill.sh`](../scripts/containment-drill.sh).

Once every signer is delegated, set `--require-external-signing` so a regression to a local
key is a **startup failure** rather than a silent downgrade. It covers all six roles;
`connect bench` is the one exemption and says so.

### Storage

`connect serve` **requires durable storage.** Not for convenience: the evidence chain's value
is that it cannot be rewritten, and a control plane on ephemeral storage loses its chain on
reschedule — an audit trail that restarts is, for the regulatory purpose it exists to serve,
the same as none. One `ReadWriteOnce` volume, one EBS volume, one Managed Disk, one LUN.

That constraint and the HA model are the same constraint: the writer lock is the *election*,
the volume is the *fence*.

### TLS, which is not terminated here

```sh
connect serve --listen 0.0.0.0:8787 \
  --issuer-key .keys/k-2026-q3.pem --kid k-2026-q3 \
  --behind-tls-proxy --trusted-proxy 10.0.1.5 \
  --tokens tokens.toml --approvers approvers.toml
```

A non-loopback listener **refuses to start** unless you say how TLS is handled. With
`--behind-tls-proxy`, every authenticated request must carry `x-forwarded-proto: https` from
an address you named — so a request reaching the port directly, bypassing the ingress, is
refused rather than trusted. Omitting `--trusted-proxy` means *any* source may assert its own
security, which is correct only if nothing else can reach the port.

`--insecure-plaintext` exists for demos. It is named so it appears in the process list and
shouts in the banner.

### Register the estate

```sh
connect register server --endpoint https://payments.internal/mcp \
    --owner human:vijay --zone internal.payments --surface payments-surface.json
connect register agent --card recon-agent.json --owner human:vijay --zone internal.apac-ops
connect activate <id>
```

Every party needs an accountable **human** owner. A party with no owner is what invariant 1
exists to prevent, and it is refused.

Attestation is a five-stage ladder and **each stage stays skipped without its material** —
it is never assumed passed. Supply what you have; `connect posture` shows what that left
unproven.

### Before moving on

```sh
connect audit verify --anchor-pub .keys/anchor.pub.pem
connect posture
connect backup --out /backup/wc-$(date -u +%Y%m%dT%H%M%SZ)
```

Then **restore that backup into a scratch root and produce a DORA export from it**
([operations.md](operations.md)). An untested restore is a directory, and this is the cheapest
moment to find that out.

---

## Stage 2 · Observe

One mediator per agent runtime, in the sidecar topology:

```sh
connect-mediate --upstream "python payments_mcp.py" \
    --mediator-id warden:mediator:apac-ops \
    --caller spiffe://org/ns/agents/sa/recon \
    --callee spiffe://org/ns/tools/sa/payments \
    --jwks-url https://connect.internal/v1/jwks.json \
    --contracts https://connect.internal --token "$MEDIATOR_TOKEN" \
    --observe --decision-log all --metrics-file /var/lib/node_exporter/wc.prom
```

Four things worth setting deliberately:

* **`--jwks-url`, not a pinned PEM.** Then a compromised issuer key is withdrawn by
  publishing rather than by redeploying every mediator. Keep `--jwks-max-stale` tight enough
  that a key set nobody can refresh stops being served.
* **`--decision-log all` during stage 2**, and `notable` afterwards. Stage 2's whole output is
  the findings; in production a line per allow makes the log a cost centre, and the
  observable outcome of a cost centre is that somebody switches it off — losing the denials
  too.
* **`--metrics-file`.** The mediator has no listener by design, so this is the
  node-exporter textfile-collector convention.
* **`--mediator-id` must be unique per mediator.** Two sharing an id makes `aud` binding
  meaningless — see A2 in [threat-model.md](threat-model.md).

### The exit criterion

§8.16's is **zero behaviour change measured on the proxy path.** Confirm it, do not assume
it: `wc_decisions_total{decision="deny"}` must be zero, and the agent's own error rate must
be unchanged. A mediator that refused uncontracted traffic while calling itself an observer
would be the worst version of this — it reads as configured and it breaks production.

Read the findings. Every `decision="record"` line is a connection nobody had written down.

---

## Stage 3 · Enforce, narrowly

Turn enforcement on for **one zone pair you understand**, not for the estate.

```sh
connect policy dry-run --policy connect-policy.toml      # against live contracts
connect policy show                                      # resolved bars and standing caps
```

`dry-run` before every policy change, always. It is the only thing that says what a change
does to contracts that already exist.

Then remove `--observe` from the mediators in scope. Expect the calls stage 2 recorded as
findings to start failing — that is the point, and it is why stage 2 comes first.

### Alerts before enforcement

Set up the four in [observability.md](observability.md) **before** you enforce, not after:
mediators reported unconfirmed, ACK lag, a distrusted revocation set, and blocking-sink
failure. The third one will arrive as *"the agents are all down"*, and knowing that in
advance is the difference between a five-minute diagnosis and an hour.

---

## Stage 4 · Estate-wide

Nothing new mechanically. What changes is that the residuals start to matter:

* **A5** — a mediator that is not on the path enforces nothing. Verify from the network side,
  and alert on *staleness* of each mediator's metrics file, because a mediator that was never
  started emits nothing and so does a quiet one.
* **A7** — count how many requests reach a human per week. More than somebody will read means
  the standing policy is too tight and the approvals have become rubber stamps.
* **HA** — run a standby (`connect serve --standby`) and rehearse a failover.

---

## The checklist

Before calling a deployment production:

- [ ] anchor key off the host; issuer key in a KMS; `--require-external-signing` set
- [ ] two revocation keys, and the offline one **rehearsed** with the real token
- [ ] approver keys on approvers' own hardware, not the service's KMS
- [ ] durable `ReadWriteOnce` storage; a standby configured
- [ ] `--behind-tls-proxy` **and** `--trusted-proxy` on any non-loopback listener
- [ ] backup running, **and a restore drill completed and timed**
- [ ] evidence shipped to WORM/SIEM; `connect audit verify --anchor-pub` on a schedule
- [ ] the four alerts firing into somewhere a human sees
- [ ] `connect-mediate --metrics-file` collected, with a staleness alert
- [ ] stage 2 findings read, and stage 3 policy derived from them
- [ ] [threat-model.md](threat-model.md) Part 3 walked through against your topology
