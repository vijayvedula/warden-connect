# Physical architecture

> Four deployment variants for the shipped binaries. Grounded in what the code does
> today, including where that constrains the topology — see
> [Gaps that shape the design](#gaps-that-shape-the-design) before choosing.
>
> Companion to [08-lld.md](08-lld.md) (logical), [key-custody.md](key-custody.md)
> (which key goes where) and [production-readiness.md](production-readiness.md)
> (what is not built yet).

## What is identical in all four

Five properties fix the physical shape before any platform is chosen. Everything
below is a rendering of these.

**1. The control plane is one writer.** `Store` and `Chain` each take an advisory
`flock`, and `store.rs` calls that lock the HA election primitive. It is a backstop
against a second writer *on the same filesystem*, not a distributed lock — so the
supported shape is **one active instance with a durable volume**, and any standby
needs an election the platform provides.

**2. The mediator is stateless.** Its contract set is an in-memory
`Arc<Snapshot>` rebuilt by pulling from the control plane; it holds no
authoritative state. Restart is free, horizontal scale is free, ephemeral storage is
correct.

**3. Nothing on the request path signs.** The hot path is `gate::verify` — a
public-key check, p99 198 µs measured. Every signing operation is off-path, which is
what makes remote key custody (HSM, KMS, smartcard) viable rather than a latency
problem.

**4. Distribution is pull with acknowledgement.** Mediators fetch and ACK; the
control plane never initiates. So mediators need egress to the control plane and the
control plane needs no inbound path to the data plane. A missed update shows up as
ACK lag rather than as silence.

**5. The evidence anchor must leave the box.** The chain proves no row was *altered*.
It cannot prove rows once *existed* — an empty chain verifies clean from `seq 1`,
indistinguishable from a fresh install. Only a signed checkpoint compared against an
external record detects deletion, and by default `anchor.jsonl` is written beside the
chain it protects. **In every variant below, anchors go somewhere the control plane
cannot rewrite.**

## The two deployables

| | `connect` (control plane) | `connect-mediate` (data plane) |
|---|---|---|
| State | Authoritative: state log, evidence chain, artifacts, revocation feed | None |
| Instances | **1 active** + optional standby | As many as there are paths |
| Storage | Durable volume, read-write-once | Ephemeral |
| Network | Inbound HTTPS (behind a terminator); egress to sinks, IdP, KMS | Egress to the control plane; in-path to its upstream |
| Restart cost | **293 ms** to rebuild 10⁵ contracts (measured) | Re-pull, seconds |
| Scales by | Not scaling — federating per residency zone | Adding instances |

### Sizing from measured gates

All from `connect bench` and the wc-mediator gate, on a developer machine — treat as
a floor, not a capacity model.

| Operation | Measured p99 | Implication |
|---|---|---|
| `gate::verify` (steady) | 198 µs | Connection establishment is not a bottleneck |
| `filter_tools_list` (256 tools) | 40 µs | Per `tools/list`, not per call |
| `contract::mint` | 328 µs, of which **1.7 µs is ours** | The rest is the signature — so a KMS round trip dominates and up to ~19 ms fits the gate |
| `blast_radius` (10⁵ edges) | 27 ms | "What can this agent reach?" is interactive |
| `store::rebuild` (10⁵ contracts) | 293 ms | **Restart is cheap**, which is what makes one active instance a defensible availability story |

The last row carries the most architectural weight: a control plane that becomes
answerable 300 ms after its process starts does not need active/active. Its RTO is
whatever the platform takes to reschedule it.

---

## Variant 1 · On-premise, virtual machines

```
                        ┌──────────────────────────────────────┐
   operators ── HTTPS ─▶│  HAProxy / nginx  (TLS termination)  │
   (approvals, CLI)     │  VIP, mTLS to clients                │
                        └──────────────────┬───────────────────┘
                                           │ loopback / private VLAN
                     ┌─────────────────────▼─────────────────────┐
                     │  connect serve       VM-A  (ACTIVE)       │
                     │  ─────────────────────────────────────    │
                     │  state/  evidence/  artifacts/            │──▶ PKCS#11 ──▶ ┌──────────────┐
                     │  flock: single writer                     │                │ Network HSM  │
                     └─────────────────────┬─────────────────────┘                │ issuer key   │
                                           │ replicated block device              │ revoke-online│
                     ┌─────────────────────▼─────────────────────┐                └──────────────┘
                     │  connect serve       VM-B  (STANDBY)      │
                     │  cold; started only by the cluster mgr    │   anchor key: PIV token in a safe,
                     └───────────────────────────────────────────┘   or a separate HSM slot VM-A cannot use
                                           │
              fail-safe EventSink ─────────┼─────────▶ Splunk / Kafka
              anchors (rsync, append-only) ┴─────────▶ WORM appliance (SnapLock / PowerProtect)

   ── data plane ─────────────────────────────────────────────────────────────────
        app VM                                    or: shared egress gateway pair
     ┌──────────────────────────┐                ┌────────────────────────────────┐
     │ agent ──stdio──▶ connect-│                │ warden proxy + wc-mediator     │
     │                 mediate  │── HTTPS ──▶ CP │ --peer-mode mtls               │
     │  --peer-mode configured  │                │ many agents, one hop           │
     └──────────────────────────┘                └────────────────────────────────┘
```

**Control plane.** Active/passive, shared or replicated block storage. **Do not use
`flock` on an NFS mount as the election** — advisory locking over NFS is not a
fencing primitive, and two writers is the one failure the design cannot absorb. Use
Pacemaker/Corosync with real fencing (STONITH), or accept single-VM with hypervisor
HA (vSphere HA restarts it elsewhere) and lean on the 293 ms rebuild.

For most estates, **single VM + hypervisor HA is the honest choice**: RTO of a minute
or two, one writer by construction, and no distributed-consensus surface to get wrong.

**Storage layout.** Separate mounts for `state/` and `evidence/`, because their
policies differ — state is compacted and snapshotted, evidence is never compacted and
carries the regulatory retention clock. Local NVMe for latency, block-level
replication for the standby.

**Keys.** Network HSM (Thales Luna, Entrust nShield) via a `CommandSigner` wrapper
around `pkcs11-tool` — which returns `R‖S` directly and so needs no DER conversion,
the reason to prefer it. Anchor key on a PIV token in a safe, or an HSM slot whose
credentials VM-A does not hold.

**Identity.** SPIRE server on-prem, agents on every host; workloads get JWT-SVIDs for
admission stage 1. Without SPIRE, stage 1 stays skipped and every party is
`Unattested` — see production-readiness P0 #3.

**Air-gapped segments.** `connect bundle export` produces a signed `.wcb`; a mediator
in a segment with no route to the control plane imports it. Hard expiry, so a stale
bundle fails closed rather than serving indefinitely.

---

## Variant 2 · On-premise, Kubernetes

```
   ┌──────────────────────────────────────────────────────────────────────────┐
   │  Ingress (nginx / Istio gateway)   TLS terminated here                   │
   └────────────────────────────────────┬─────────────────────────────────────┘
                                        │
   ┌────────────────────────────────────▼─────────────────────────────────────┐
   │  StatefulSet  connect-cp   replicas: 1        ← NOT a Deployment         │
   │  ┌────────────────────────────────────────────────────────────────────┐  │
   │  │ connect serve --listen 0.0.0.0:8787                                │  │
   │  │   /v1/entities /v1/connections /v1/requests /v1/mediators          │  │
   │  │   /healthz  /readyz  /metrics                                      │  │
   │  └────────────────────────────────────────────────────────────────────┘  │
   │   PVC state-pvc     (RWO, Ceph RBD / vSphere CSI)                        │
   │   PVC evidence-pvc  (RWO, separate retention + backup policy)            │
   │   Secret: bearer tokens · ConfigMap: connect-policy.toml, jwks.json      │
   └───┬──────────────────────────────────────────────────────────────────┬───┘
       │ PKCS#11 over the network                                         │
       ▼                                                                  ▼
   Network HSM (issuer, revoke-online)                    external signer for the
                                                          ANCHOR — outside this
   fail-safe EventSink ──▶ Loki / Kafka                    cluster, by design
   anchors ──▶ object store with object-lock

   ── data plane: sidecar per agent pod ──────────────────────────────────────
   ┌──────────────────────────────────────────┐
   │ Pod: recon-agent                         │
   │  ┌────────────┐   stdio   ┌────────────┐ │
   │  │ agent      │──────────▶│ connect-   │ │── HTTPS ──▶ connect-cp
   │  │ container  │           │ mediate    │ │
   │  └────────────┘           │ (sidecar)  │ │
   │                           └─────┬──────┘ │
   │  SA token / SPIFFE SVID         │        │
   └─────────────────────────────────┼────────┘
                                     ▼  upstream MCP server
   ── or: mesh egress gateway, --peer-mode mesh (XFCC from Envoy) ─────────────
```

**`replicas: 1`, and say why in the manifest.** Scaling this StatefulSet to 2 does
not fail loudly: each pod has its own PVC, each takes its own `flock`, both write,
and `WC-8003` never fires. Two divergent state logs with no error is the worst
outcome available. A `PodDisruptionBudget` with `maxUnavailable: 1` and a
`readinessProbe` on `/readyz` is the availability story; the kubelet reschedule plus
a 293 ms rebuild is the RTO.

If you want a standby, the election has to be a `Lease` in
`coordination.k8s.io` — **which the code does not implement today**. Until it does,
one replica is not a limitation to work around; it is the contract.

**Two PVCs, not one.** State and evidence have different retention, different backup
cadence, and different blast radius on corruption. One volume conflates them.

**Peer identity.** `--peer-mode mesh` honours `x-forwarded-client-cert` from a
trusted origin, so Istio/Linkerd already supplies authenticated peer identity —
`peer.rs` has the XFCC path. `--peer-mode configured` is correct for a sidecar that
fronts exactly one agent, and wrong for a shared gateway.

**The anchor key does not belong in the cluster.** The whole property is *"an attacker
who controls the control plane must not be able to re-sign a forged chain"*, and a
key in a Secret in the same cluster is a key the control plane's service account can
reach. Use an external signing endpoint, or a token on a node the CP does not
schedule to.

---

## Variant 3 · Workloads on AWS

```
   Route 53 ─▶ ALB (ACM cert, OIDC auth optional) ─▶ target: connect-cp
                                                        │
   ┌────────────────────────────────────────────────────▼──────────────────────┐
   │  EKS StatefulSet (replicas: 1)  ·  or ECS service, desiredCount: 1        │
   │    connect serve                                                          │
   │    EBS gp3 volume via EBS CSI  ← RWO, snapshotted                        │
   │    IRSA role: kms:Sign on the issuer key ONLY                             │
   └───┬──────────────────────────────────┬───────────────────────────────┬────┘
       │                                  │                               │
       ▼ kms:Sign                          ▼ fail-safe EventSink           ▼ anchors
   ┌─────────────────────────┐      Kinesis / OpenSearch          ┌────────────────────┐
   │ KMS  ECC_NIST_P256      │                                    │ S3 + Object Lock   │
   │  alias/wc-issuer        │      state + evidence backup ─────▶│ COMPLIANCE mode    │
   │  alias/wc-revoke-online │      EBS snapshots ─▶ AWS Backup   │ separate account   │
   └─────────────────────────┘                                    └────────────────────┘
   ANCHOR key: KMS in a SEPARATE ACCOUNT. The CP's role gets kms:Sign and nothing
   else; the CP cannot delete the anchors it writes, which is the property.
   revoke-offline: YubiKey in a safe. Not in AWS at all.

   ── data plane ─────────────────────────────────────────────────────────────
   Pod: agent + connect-mediate sidecar        SPIRE agent (DaemonSet) ─▶ JWT-SVID
        └── HTTPS via VPC endpoint / NLB ──▶ connect-cp
   Provenance: CodeBuild or GitHub Actions SLSA attestation ─▶ DsseProvenanceVerifier
```

**Custody maps cleanly.** KMS asymmetric `ECC_NIST_P256` with `SIGN_VERIFY` is exactly
what `ES256` needs. Two cautions, both already documented in
[`signer.rs`](../crates/wc-control/src/signer.rs):

* **`aws kms sign` returns DER.** JWS needs raw `R‖S`. The wrapper must convert;
  `IssuerKey` catches a forwarded DER signature and names it, but catching it in CI
  beats catching it in production.
* KMS signing latency (10–50 ms) dominates mint. The `contract::mint` gate at 20 ms
  will fail on a cross-region key. Keep the key in-region, and watch
  `contract::mint overhead` (1.7 µs) to prove a slow mint is the KMS and not us.

**The anchor key in a second account is the strongest cheap control here.** It gives
the same property as offline hardware — the control plane can sign checkpoints and
cannot forge or remove them — through an IAM boundary rather than a safe. Pair with
**S3 Object Lock in compliance mode**, which not even the root of that account can
delete before the retention expires. That is the WORM substitute for immutable
storage, and it is what makes the ephemeral-storage question answerable.

**Storage.** EBS, not EFS. `flock` semantics over NFS are not a foundation for the
single-writer invariant, and RWO is what the design wants anyway.

**Identity.** SPIRE on EKS for JWT-SVIDs. A pragmatic interim: projected service
account tokens are JWTs and `JwtSvidIdentity` verifies against a JWKS — it gives you
stage 1 against the cluster's OIDC issuer without standing up SPIRE. Weaker (it
attests the pod's identity, not the workload's build), and honest about being
weaker.

---

## Variant 4 · Workloads on Azure

```
   Front Door / Application Gateway (TLS, WAF) ─▶ connect-cp
                                                    │
   ┌────────────────────────────────────────────────▼──────────────────────────┐
   │  AKS StatefulSet (replicas: 1)                                            │
   │    connect serve                                                          │
   │    Azure Disk (Premium SSD v2) via disk CSI  ← RWO                        │
   │    Workload Identity: Key Vault Crypto User on the issuer key ONLY        │
   └───┬──────────────────────────────────┬───────────────────────────────┬────┘
       │                                  │                               │
       ▼ sign                              ▼ fail-safe EventSink           ▼ anchors
   ┌──────────────────────────────┐   Event Hubs / Log Analytics   ┌──────────────────┐
   │ Key Vault Managed HSM        │                                │ Blob Storage     │
   │  wc-issuer      (EC P-256)   │   disk snapshots ─▶ Azure      │ immutability     │
   │  wc-revoke-online            │   Backup                       │ policy + legal   │
   └──────────────────────────────┘                                │ hold, separate   │
   ANCHOR key: Managed HSM in a SEPARATE SUBSCRIPTION. The CP identity gets Sign     │
   and no delete on the anchor container.                          └──────────────────┘
   revoke-offline: hardware token in a safe.

   ── data plane ─────────────────────────────────────────────────────────────
   Pod: agent + connect-mediate sidecar
        Entra Workload ID (federated SA token) or SPIRE ─▶ JWT-SVID
        └── HTTPS via Private Endpoint ──▶ connect-cp
```

**Managed HSM over Key Vault Premium** if FIPS 140-3 Level 3 matters; Key Vault
Premium is adequate otherwise and cheaper. Either way the wrapper is
`CommandSigner` around `az keyvault key sign`.

**Verify the signature encoding before trusting the wrapper.** Azure's ES256 signing
takes a digest and the output encoding must be confirmed to be raw `R‖S` rather than
DER for your API version. Do not assume it from either direction — mint one contract
and run `connect verify`. The length check in `IssuerKey` will catch DER, and a
test in CI is where you want that to happen.

**Immutable Blob Storage** with a time-based retention policy plus legal hold is the
Object-Lock equivalent, and the same reasoning applies: it substitutes for immutable
volumes by making the *evidence* undeletable rather than the filesystem.

**Identity.** Entra Workload ID federates a projected SA token, which
`JwtSvidIdentity` can verify — same trade-off as the AWS interim path: it attests the
workload's identity, not its provenance. Stage 4 still needs a build attestation
(`DsseProvenanceVerifier`) from the pipeline.

---

## Cross-variant mapping

| | On-prem VM | On-prem K8s | AWS | Azure |
|---|---|---|---|---|
| **CP placement** | VM, active/passive | StatefulSet, `replicas: 1` | EKS StatefulSet or ECS `desiredCount: 1` | AKS StatefulSet |
| **Election** | Pacemaker + fencing, or hypervisor HA | kubelet reschedule (Lease not implemented) | kubelet / ECS scheduler | kubelet |
| **State volume** | Local NVMe + block replication | PVC RWO (Ceph/vSphere) | **EBS gp3, not EFS** | Azure Disk Premium |
| **Evidence volume** | Separate mount | Separate PVC | Separate EBS volume | Separate disk |
| **Issuer key** | Network HSM (PKCS#11) | Network HSM | KMS `ECC_NIST_P256` | Key Vault Managed HSM |
| **Anchor key** | PIV token in a safe | External signer, outside the cluster | **KMS in a second account** | **Managed HSM, second subscription** |
| **`revoke-online`** | HSM slot | HSM slot | KMS | Key Vault |
| **`revoke-offline`** | Hardware token, safe, M-of-N PIN | same | same — **not in the cloud** | same |
| **Approver keys** | Smartcard per approver | same | same — **never the service's KMS** | same |
| **WORM for evidence** | SnapLock / PowerProtect | Object store with object-lock | **S3 Object Lock, compliance mode** | **Blob immutability + legal hold** |
| **TLS termination** | HAProxy / nginx | Ingress / mesh gateway | ALB + ACM | App Gateway / Front Door |
| **Peer identity** | `configured` (sidecar) or `mtls` (gateway) | `mesh` (XFCC from Envoy) | `mesh` or `configured` | `mesh` or `configured` |
| **Workload identity** | SPIRE on-prem | SPIRE on K8s | SPIRE on EKS, or projected SA token | Entra Workload ID, or SPIRE |
| **Mediator** | Sidecar process, or gateway VM pair | Sidecar container, or mesh egress gateway | Sidecar container | Sidecar container |

### Multi-market residency

Federation is per residency zone, not one global control plane: anchors of trust
cross borders, stored records do not. Physically that means **one control plane per
zone**, each with its own volumes, its own keys and its own evidence chain, joined by
signed entity statements (`connect federate`). In AWS that is one deployment per
region with no cross-region replication of `state/` or `evidence/`; in Azure the same
per geography. `tenant.rs` gives per-tenant roots *within* a zone; it is not a
substitute for separation *across* them.

---

## Gaps that shape the design

These are code facts, not platform choices, and they constrain every variant.
Tracked in [production-readiness.md](production-readiness.md).

**`connect serve` has no TLS.** Bearer tokens over plaintext HTTP. A terminating
proxy is mandatory for any non-loopback listener, in all four variants. P0 #7.

**JWKS is read from a file.** Rotating the issuer key means delivering a new
`jwks.json` to every mediator — a ConfigMap update, a file sync, a redeploy. There is
no HTTP fetch or TTL cache, so rotation is a deployment event rather than a
background one. P0 #6.

**`flock` is not a cross-node election.** It is a same-filesystem backstop. Any
topology with two potentially-active instances needs the platform to guarantee one,
and on separate volumes there is no mutual exclusion at all. P1 #10.

**A control plane with an empty register empties the mediators.** `refresh()` installs
whatever contract set the control plane returns, and `ContractSet.removed` is
documented as explicit *"so a partial fetch cannot look like a revocation"* — but an
empty `active` with an empty `removed` does exactly that. So control-plane data loss
becomes an estate-wide deny rather than a degraded read. Fail-closed, and still an
outage. It raises the cost of getting the storage wrong, and it is worth fixing
before it is worth engineering around.

**Attestation stand-ins.** Until SPIRE and a provenance-emitting pipeline are wired
in, admission runs on P0 stand-ins and every party is `Unattested`. The physical
design should include the IdP and the build attestation path from the start, because
retrofitting them changes what every party's posture means. P0 #3.
