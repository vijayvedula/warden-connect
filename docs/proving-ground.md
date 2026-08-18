# The proving ground

What must be **provisioned** to close each item [limitations.md](limitations.md) marks
*Unproven*, on Azure and GCP.

*Unproven* means the mechanism is built and unit-tested and the **procedure or the scale** has
never been exercised. Every defect this build produced was found by running something (see
[threat-model.md](threat-model.md) Part 1), so an Unproven item should be read as *may not
work* — the rotation drill was Unproven for a week and turned out to hide the most serious
finding in the repository.

The headline: **thirteen items, but only two environments and one KMS key.** Five items need
no cloud at all, and of the eight that do, six share a single Kubernetes cluster.

---

## 0 · What this cannot buy

Provisioning settles *scale* and *procedure*. It does not settle **independence**, and three
Unproven items are independence claims:

| Item | Why no amount of infrastructure closes it |
|---|---|
| A second `wcs1` implementation | The point is that it was written by someone who read [conformance.md](conformance.md) and not `canon.rs`. Our own second implementation would inherit our own misreading. |
| An independent hardening pass | Two passes have been run; both by the author. A third by the author is a third pass by the author. |
| Third-party commands in these docs | `every_documented_command_exists_with_the_flags_it_claims` guards our own commands. The Vault/SPIRE/cosign invocations are unguarded prose, and we have already shipped four wrong SPIRE commands. Needs a reader who is not us. |

A **fourth** is nearly free and worth doing before spending anything: `release.yml` and
`sdk-release.yml` have never run. Both are GitHub Actions with public OIDC (Fulcio, PyPI
trusted publishing) — **no cloud account, no cost**. Fire them with `workflow_dispatch` against
a throwaway tag. A release workflow that has never run is a release workflow that does not
work; that is not a pessimistic reading, it is the base rate.

Do those first. They cost nothing and they will fail.

---

## 1 · One KMS key — the hardware custody item

> *"The containment drill uses a file where the hardware token belongs."*

**This needs no new Rust code.** `crates/wc-control/src/signer.rs` already implements the seam:
`--signer COMMAND` spawns a helper, writes the JWS signing input to its stdin as base64url, and
reads a base64url signature from its stdout. A cloud KMS is a fifteen-line shell script. This
was a deliberate choice over vendoring three cloud SDKs (§8.3 dependency ceilings), and it
means the cheapest possible resource closes the item.

### Provision

| | Azure | GCP |
|---|---|---|
| Resource | **Key Vault Premium**, one EC-HSM key, curve P-256 | **Cloud KMS** keyring, one key, `EC_SIGN_P256_SHA256`, protection level **HSM** |
| Why the cheap tier | Managed HSM is a dedicated single-tenant pool billed **per hour**; you need a non-exportable key, not your own security domain | Software protection level would prove the wrapper but not the custody — pay the small delta for HSM |
| Rough cost | ~$1/key/month + per-operation | ~$1–2.50/key/month + per-operation |
| Identity | a service principal with *Key Vault Crypto User* | a service account with `cloudkms.signerVerifier` |

### The trap, which is why this section exists

**JWS ECDSA is the raw `R‖S` concatenation, 64 bytes for P-256. Most KMS interfaces return
DER.** A wrapper that forwards DER produces contracts that are well-formed, signed, distributed
and rejected by every mediator. `IssuerKey` length-checks and names DER specifically, so this is
one error message rather than an outage — but the conversion belongs in the wrapper, and the two
clouds differ:

* **Azure Key Vault `sign` with `ES256`** takes a **digest** and returns **`R‖S`**. No
  conversion. The wrapper hashes and forwards.
* **GCP `asymmetric-sign` with `EC_SIGN_P256_SHA256`** takes a digest and returns **DER**. The
  wrapper must unwrap the `SEQUENCE { INTEGER r, INTEGER s }`, strip leading zero padding, and
  left-pad each to 32 bytes. `a_real_helper_produces_a_signature_that_verifies` in
  `signer.rs`'s tests is a working example of exactly that conversion, kept executable.

Both wrappers must hash the input themselves: the helper receives the **signing input**, not a
digest, and both KMS APIs want a digest.

### What is already closed locally

`scripts/custody-drill.sh` runs both halves of that pass condition against openssl-as-KMS: a
contract minted through `--signer` verifies, a wrapper that forwards DER is refused with a
message naming DER, and `--require-external-signing` refuses a PEM. So the *protocol* half is
no longer an open item — the base64url round trip and the DER→`R‖S` conversion are proven by a
script that runs in CI.

What the KMS key buys is the half that script explicitly disclaims: a real authorisation policy,
a real rate limit, a real availability characteristic, and a wrapper written against a vendor's
CLI rather than against openssl. The drill's own closing note says so.

### Pass condition

A contract signed through the wrapper passes `connect verify` — the whole acceptance test, and
`custody-drill.sh` phase 1 is the shape of it — and
`connect request --require-external-signing` **refuses** a `--issuer-key` PEM. Then run
`containment-drill.sh` with the break-glass shares held as KMS keys under distinct
principals — which is the part a laptop cannot rehearse, because it is the only version where
"a share-holder who left in March" is representable as a revoked role assignment.

Note what this still does not prove: a flat battery, a forgotten PIN, an unreachable token. A
KMS is high-availability infrastructure; a YubiKey in a safe is not. It closes the *custody*
claim and leaves the *human* claim open.

---

## 2 · One Kubernetes cluster — six items share it

Six Unproven items are all "does this hold across many mediators over real time", and one
cluster carries all of them. Provision this **once** and run the six drills against it.

### Provision

| | Azure | GCP |
|---|---|---|
| Cluster | **AKS**, 1 system node (`Standard_D2s_v5`) + a **Spot** user pool | **GKE Standard** with a **Spot** node pool (not Autopilot — see below) |
| Size | enough for **50 mediator pods** + 1 control plane + Prometheus: ~3 × 8-vCPU spot nodes | same |
| Metrics | **Azure Monitor managed Prometheus** + Managed Grafana | **Managed Service for Prometheus** + Cloud Monitoring |
| Storage | one **Premium SSD** managed disk for the state log | one **balanced PD** for the state log |
| Rough cost | ~$3–6/day with spot, destroyed between runs | ~$3–6/day |

**Not Autopilot, and not because of cost.** Autopilot restricts host access and pod scheduling
in ways that interfere with two of these tests: the fuzzing item wants sustained CPU on a node
you control, and the failover item wants to kill a process and watch a lock move. Use Standard.

Mediators are `connect-mediate` sidecars; 50 pods each holding one contract is a small
deployment. The control plane is a single `connect serve` — the state log is **single-writer**,
so do not scale it, and note that this is itself the subject of item 2.4.

### 2.1 · Propagation timing — is it under 60 s estate-wide?

§7.10 promises estate-wide propagation under 60 s and `wc_mediator_ack_lag_seconds` has a
bucket at 60, so the claim is *measurable* and has never been measured.

**Minimum:** 50 mediator pods across 3 nodes, one revocation, and the histogram.
**Pass:** p99 `wc_mediator_ack_lag_seconds` < 60 with the refresh interval at its default.
**Watch for:** the metric measuring ACK receipt rather than enforcement. These were briefly
different things — a mediator ACKed a revocation and kept serving — and the containment seam
that closed that gap is now enforced per call, so an ACK genuinely does precede enforcement.
Time both anyway: the claim to measure is *when the last call was refused*, not when the last
mediator answered, and only one of those is what an incident review asks for.

### 2.2 · Alerts battle-tested

Ten rules pass `promtool test rules`, which tests the expression against synthetic series. It
does not tell you whether the rule fires on real cardinality, or whether it is so noisy that
somebody silences it in week two.

Writing this section found that **three of the ten were asserted nowhere**, and that one of
those could not fire at all. Both are fixed, and `scripts/alert-coverage.sh` guards the gap.
Mentioned here because it is the argument for the whole page: the item was on the Unproven
list as *needs a week of real traffic*, and a ten-minute coverage diff found a dead rule
first. Cheap checks before provisioned ones.

**Minimum:** the managed Prometheus above scraping all 50 mediators for **7 days**, with the
rules loaded and a real notification channel.
**Pass:** every rule has fired at least once deliberately (induce each condition), and no rule
fired spuriously over the week. A rule that never fires and a rule that always fires are the
same defect.

### 2.3 · Measured RTO

The restore drill is a written procedure. "A procedure exists" and "the RTO is *n* minutes" are
different claims.

**Minimum:** the state log on the managed disk, a snapshot, then destroy the control plane VM
and restore from the snapshot with a stopwatch running.
Azure: managed-disk snapshot. GCP: PD snapshot. Both are trivially cheap at this size.
**Pass:** a number, written into limitations.md, replacing the absence of one. Include the
**detection** time, not just the restore — an RTO that starts when a human notices is the RTO.

### 2.4 · Failover under load

The handover is exercised locally including a crash and a torn write. Under concurrent load
across two hosts, it is not.

**Minimum:** two control plane instances, one shared volume, and a load generator holding
sustained request volume through the handover.
Azure: **Azure Files** (NFS 4.1) or a shared Premium SSD. GCP: **Filestore Basic**.
**Expect to discover something here.** The state log is single-writer and the lock is what
enforces it — and `flock` semantics over NFS and SMB are notoriously partial. There is a real
chance this test finds that the lock does not hold across hosts, which would mean the
single-writer guarantee is a *single-host* guarantee. That is worth knowing before an estate
depends on it, and it is precisely the shape of every other defect this project has produced: a
control that reads as configured and does nothing.
**Pass:** zero lost or duplicated log entries across the handover, verified by `audit verify`.

### 2.5 · A 10⁵-contract estate, operated

Benchmarked, never operated. `--scale` accepts up to 1,000,000 and the gates *measure*; nobody
has lived with a log that size.

**Minimum:** one control plane with a 10⁵-contract state log on the SSD above, then run the
**operator** commands — `audit verify`, `retention --retire`, `chain` verification, `lint` — and
time each.
**Pass:** every command completes in a time an operator would tolerate, and `audit verify` over
10⁵ entries is not an overnight job. Also measure the **disk footprint** and the memory high
water mark; a control plane that needs 8 GB to verify its own chain is a constraint that belongs
in the docs.

### 2.6 · Fuzzing at depth

One minute per target is smoke. The nightly workflow turns that into hours per week and **has
not run yet**.

**Minimum:** honestly, GitHub Actions already covers this — just enable the nightly and let it
accumulate. If you want depth sooner, one **Spot** 8-vCPU VM (`Standard_D8as_v5` / `n2-standard-8`)
for a weekend beats a month of nightlies and costs a few dollars.
**Pass:** 24 CPU-hours per target with no new crashes, and the corpus committed.
**Watch for:** this target's invariant was once **stale** and the target had never been run. Before
buying CPU, mutation-check each target — break the code deliberately and confirm the fuzzer
catches it. Hours against an assertion that cannot fail is the most expensive way to learn nothing.

---

## 3 · The item that is not on the list but belongs here

**Real SPIRE node attestation.** `scripts/spire-fixtures.sh` stands up the smallest server that
can issue a JWT-SVID: sqlite and **join-token** attestation. Join tokens are a bootstrap
mechanism, not an attestation story — the whole point of SPIFFE is that a workload's identity
derives from something the platform can vouch for, and a join token is a shared secret.

This can **only** be tested on a cloud, because the attestors attest cloud metadata:

| | Azure | GCP |
|---|---|---|
| Node attestor | `azure_msi` — the node's Managed Service Identity token | `gcp_iit` — the Instance Identity Token |
| Workload attestor | `k8s` / `k8s_psat` on the cluster above | same |
| Extra cost | none beyond the cluster | none beyond the cluster |

**Pass:** a mediator obtains a JWT-SVID whose `sub` derives from platform-attested node
identity, with no join token anywhere, and `connect` verifies it. This is the difference between
"we support SPIFFE" and "we have run SPIFFE".

---

## 4 · The whole list, as a shopping list

| # | Item | Needs | Where |
|---|---|---|---|
| 1 | `release.yml` first run | nothing | GitHub Actions |
| 2 | `sdk-release.yml` first run | nothing | GitHub Actions + PyPI |
| 3 | Second `wcs1` implementation | a person who has not read `canon.rs` | — |
| 4 | Independent hardening pass | a reviewer who is not the author | — |
| 5 | Third-party commands in docs | a reader on a clean machine | — |
| 6 | Hardware custody | **1 KMS key** + a 15-line wrapper | Key Vault Premium / Cloud KMS |
| 7 | Propagation timing | 50 mediators + Prometheus | the cluster |
| 8 | Alerts battle-tested | the same, for 7 days | the cluster |
| 9 | Measured RTO | 1 disk snapshot + a stopwatch | the cluster |
| 10 | Failover under load | 2 hosts + a shared volume | the cluster |
| 11 | 10⁵-contract estate | 1 SSD + patience | the cluster |
| 12 | Fuzzing at depth | 1 spot VM for a weekend, or nothing | either |
| 13 | Real SPIRE attestation | the cluster's own node identity | the cluster |
| — | Rotation drill | **closed** — `scripts/rotation-drill.sh` | local |
| — | Signing protocol, DER trap, ES384 | **closed** — `scripts/custody-drill.sh` (item 6 keeps the *custody* half) | local |
| — | Two planes, separate issuer keys | **closed** — `scripts/custody-drill.sh` phases 4–5 | local |

So: **one KMS key, one Kubernetes cluster, one weekend spot VM.** Held for a week and destroyed,
on either cloud, this is small money — well under a hundred dollars. The expensive items on the
list are the three that money cannot buy.

### Order of operations

1. **The two workflows.** Free, and they will fail.
2. **The KMS key.** Cheapest resource, closes a *custody* claim, and the wrapper is reusable
   forever after.
3. **The cluster**, then 2.1 → 2.4 in that order. Do **failover** early rather than last: it is
   the one most likely to find something structural, and finding it after a week of other
   measurements means re-running them.
4. **Fuzzing**, whenever, after mutation-checking the targets.

### Before provisioning anything

The containment gap that made item 2.1 unmeasurable is **closed** — a revocation now stops a
live session on the next call, proven by the drill and by seven tests, both mutation-checked.
That was the prerequisite: measuring propagation while the mediator logged `1 rejected` and
kept serving would have produced a green dashboard for a control that did not work.

The remaining pre-flight is the cheap-checks-first principle that produced this page. Before
provisioning anything, re-run the coverage-style questions against the areas the cluster is
meant to test — which rules have no test, which module has no caller, which counter resets
with the process. Two of the last four defects here were found that way in minutes, and a
provisioned week measuring the wrong thing costs more than the cluster does.
