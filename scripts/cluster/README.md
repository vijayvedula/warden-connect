# The cluster items, as commands

The proving-ground register — retired in the 2026-08-21 docs rewrite, in git history at `3f30697` — named six items that need a Kubernetes cluster
and said what each one must prove. This directory is the same six as **commands you can run**, so the work between
"provisioned" and "measured" is not a fresh act of interpretation at the end of a long day.

> **Everything here is UNVERIFIED.** No warden-connect deployment has run on a cluster from this
> repository. The manifests are written from the binaries' own flags — which *are* verified, by the
> six local drills — but nothing here has been applied to a real API server. Treat it as a
> starting point that will need edits, not a recipe. Where a command is a guess, it says so.
>
> The honest reason this is not verified: a cluster costs money and somebody has to own the
> account. That is exactly the boundary that register drew.

## What is already closed locally, so do not re-litigate it

Provisioning is for the things a laptop genuinely cannot do. These are done:

| Question | Where |
|---|---|
| Does enforce mode admit an attested party? | `scripts/attest-drill.sh` |
| Does rotation overlap safely, and does containment reach a live session? | `scripts/rotation-drill.sh` |
| Does the break-glass path work end to end? | `scripts/containment-drill.sh` |
| Can the issuer key live outside the process, and do two planes stay separate? | `scripts/custody-drill.sh` |
| Does a provider's change of terms reach consumers? | `scripts/upgrade-drill.sh` |
| Does the deploy gate work, and survive a restart? | `scripts/distribution-drill.sh` |
| What does operating a 10⁵ estate cost? | `scripts/scale-drill.sh` |

What the cluster adds is **many mediators, real time, and hardware you did not choose** — which is
the whole of items 2.1–2.4 and none of the above.

## Before you provision: the pre-flight that saves the money

Run these first. Each has cost a wasted run somewhere in this project's history.

```sh
# 1 · the binaries you are about to ship are the ones you tested
cargo build --release --workspace
./scripts/preflight.sh

# 2 · every drill green on this commit, or the cluster measures a broken build
for d in attest rotation containment custody upgrade distribution; do
    ./scripts/$d-drill.sh >/dev/null 2>&1 || echo "FAILING: $d"
done

# 3 · the alert rules are asserted, not merely syntactically valid (§2.2 depends on this)
./scripts/alert-coverage.sh

# 4 · the fuzz targets can actually fail — see `mutation-check` below. Item 2.6's own note says
#     it: hours against an assertion that cannot fail is the most expensive way to learn nothing.
```

## Deploying

`control-plane.yaml` and `mediator.yaml` are the two workloads. Read both before applying; each
carries comments where a value is a decision rather than a default.

```sh
kubectl create namespace warden-connect

# Trust material. The issuer PRIVATE key belongs in the KMS (item 1) — this secret is the public
# half plus the mediator's bearer token, and nothing that can mint.
kubectl -n warden-connect create secret generic wc-trust \
    --from-file=issuer.pub.pem=./issuer.pub.pem \
    --from-literal=mediator-token="$MEDIATOR_TOKEN"

kubectl -n warden-connect apply -f control-plane.yaml
kubectl -n warden-connect apply -f mediator.yaml
kubectl -n warden-connect scale deploy/wc-mediator --replicas=50
```

**The control plane is a single replica and must stay one.** The state log is single-writer by
construction — two writers fork a hash chain — so HA here is active/standby with the writer lock as
the election primitive, which is itself the subject of item 2.4. `replicas: 2` would not be high
availability, it would be the failure mode.

If your estate's writers are pipelines rather than the API, run the control plane with
`--read-only` and let `offer publish` / `need apply` hold the lock. `control-plane.yaml` has both
forms; pick one deliberately, because the two are mutually exclusive.

## 2.1 · Propagation timing — under 60 s estate-wide?

```sh
# Baseline: every mediator confirmed the current set before you start timing anything.
connect distribution --mediators mediators.toml --wait --timeout 300

# Cut one connection and start the clock.
START=$(date +%s)
connect revoke "$CID" --reason "propagation measurement" \
    --revocation-key rev.pem --kid rev-1 --mediators mediators.toml --ack-deadline 120

# The claim to measure is when the last call was REFUSED, not when the last mediator answered.
# Both, because only one of them is what an incident review asks for.
kubectl -n warden-connect logs -l app=wc-mediator --since=5m --prefix \
    | grep -E "WC-3105|WC-4001" | tail -1
```

**Pass:** p99 `wc_mediator_ack_lag_seconds` < 60 at the default refresh interval.
**Also record:** the gap between last-ack and last-refusal. The containment seam makes an ack
precede enforcement now, so the gap should be small — but "should" is why this is being measured.

## 2.2 · Alerts battle-tested

`promtool test rules` tests expressions against synthetic series; it cannot tell you whether a rule
fires on real ones. Run for seven days with traffic, then judge.

```sh
# Every alert that fired, with its duration — a rule that fired 400 times is a rule nobody reads.
curl -sG "$PROM/api/v1/query" --data-urlencode \
    'query=count_over_time(ALERTS{alertstate="firing"}[7d]) > 0' | python3 -m json.tool
```

**Pass:** no rule fired that an operator would have ignored, and no incident happened that no rule
covered. The second half needs you to *cause* incidents — kill a mediator, withdraw a key, fill a
disk — not to wait for them.
**Watch for:** a rule that cannot fire at all. Three were asserted nowhere and one of those could
never fire, and `promtool` never asks what it was not given. `scripts/alert-coverage.sh` is the
guard that closed it; run it here too, because a rule added for the cluster can reopen it.

## 2.3 · Measured RTO

```sh
# Snapshot the state volume, then destroy the control plane entirely.
kubectl -n warden-connect delete deploy/wc-control-plane
# ...restore the volume, then:
START=$(date +%s)
kubectl -n warden-connect apply -f control-plane.yaml
until curl -sf "http://$CP/readyz" >/dev/null; do sleep 1; done
echo "control plane back in $(( $(date +%s) - START ))s"

# But readiness is not recovery. Recovery is when a mediator is serving the current set again.
connect distribution --mediators mediators.toml --wait --timeout 600
```

**Pass:** an RTO you would write in a DR document, with the chain verifying afterwards
(`connect audit verify --anchor-pub anchor.pub.pem` — the anchor key is what makes truncation
during the outage detectable).
**Watch for:** measuring process start instead of service restoration. `scale-drill.sh` measures
`store::rebuild` at 10⁵ — around 300 ms on a laptop — so replay is unlikely to dominate; the
volume restore is.

## 2.4 · Failover under load

```sh
# Standby waits for the lock and binds no listener until it holds it, which is what makes this
# safe to run under traffic.
connect serve --standby --standby-timeout 600 --listen 0.0.0.0:8787 ...

# Kill the active writer mid-flight and watch the lock move.
kubectl -n warden-connect delete pod "$ACTIVE_POD" --grace-period=0 --force
```

**Pass:** exactly one writer at all times, the successor's log continues the predecessor's without
a gap, and `connect audit verify` is clean afterwards. Two writers would fork the chain, and a
forked chain is the one failure this design cannot recover from — so this item is a *safety* test
before it is an availability one.
**Watch for:** the successor reporting itself as the first writer rather than a successor.
`Election::describe` distinguishes them, and after a failover the first question is whether a
takeover happened or a fresh process started.

## 2.5 · A 10⁵-contract estate, operated

**Largely closed locally** — `scripts/scale-drill.sh`, with numbers in the limitations register, retired in the 2026-08-21 docs rewrite, in git history at `3f30697`. Run
it on a cluster node to get the same table on hardware you did not choose:

```sh
kubectl -n warden-connect exec deploy/wc-control-plane -- \
    sh -c 'SCALE=100000 /usr/local/bin/scale-drill.sh'
```

**What the cluster adds:** a real SSD's latency, a memory limit that can actually be hit, and a
container the measurement cannot escape. The laptop run says the shape is fine; it says nothing
about a 512 MiB pod.

## 2.6 · Fuzzing at depth

Do the mutation-check **before** buying CPU. Item 2.6's own note explains why, and this project has
already shipped a fuzz target whose invariant was stale and had never been run.

```sh
./scripts/fuzz-mutation-check.sh    # every target must fail against deliberately broken code
./scripts/fuzz.sh 3600              # then an hour per target, or a weekend on a spot VM
```

**Pass:** 24 CPU-hours per target with no new crashes, and the corpus committed.

## 13 · Real SPIRE attestation

```sh
# Node attestation is the point: a workload identity the workload itself cannot assert.
helm install spire spiffe/spire -n spire --create-namespace
kubectl -n warden-connect apply -f spire-registration.yaml   # not in this directory: write it
                                                             # against your own node attestor
```

**Pass:** a party reaches `Attested` with stage 1 satisfied by a JWT-SVID SPIRE issued to a pod,
not by a fixture. `scripts/spire-fixtures.sh` generates the fixtures the tests use, and the whole
point of this item is to stop depending on them.
**Watch for:** the SPIFFE id. `register --id` must be the workload's real `spiffe://` id, because a
derived `urn:wc:` id can never appear as a JWT-SVID `sub` and stage 1 then cannot pass — which the
`register` help text now says, having cost a day.
