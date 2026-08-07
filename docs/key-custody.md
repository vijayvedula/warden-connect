# Key custody

> Decision note for [production-readiness.md](production-readiness.md) P0 #5.
> Six operations in warden-connect sign with a private key. They do not all want
> the same custody, and treating them uniformly gets one of them wrong.

## The six

| # | Operation | Key | Where | Request path? |
|---|---|---|---|---|
| 1 | Contract mint | issuer | [`contract.rs`](../crates/wc-core/src/contract.rs) `mint`, from `issuance` | No — once per connection, at approval |
| 2 | Revocation feed entries | revocation | [`contain.rs`](../crates/wc-control/src/contain.rs) → `sign_detached` | No — but during an incident |
| 3 | Chain checkpoints | anchor | [`chain.rs`](../crates/wc-control/src/chain.rs) — its own `EncodingKey` | No — periodic |
| 4 | Air-gapped bundle envelope | envelope | [`bundle.rs`](../crates/wc-control/src/bundle.rs) `export` | No — operator action |
| 5 | Approval assertions | **a human's** | [`issuance.rs`](../crates/wc-control/src/issuance.rs) `sign_approval` | No |
| 6 | Signed CAEP events | sink | [`sink.rs`](../crates/wc-control/src/sink.rs) | Per event |

All but #3 funnel through `IssuerKey`, which wraps `jsonwebtoken::EncodingKey` — an
in-process private key. `IssuerKey` is therefore the seam, and a `Signer` trait
behind it covers five of the six in one change.

**Nothing on the hot path signs.** `gate::verify` (p99 ≤ 1.5 ms) is a public-key
verification in the mediator and never touches a private key. That is what makes
remote custody tractable at all here.

## The asymmetry that decides the split

The two most important keys have **opposite** failure modes, and the intuition that
"the kill switch needs the strongest protection" is backwards.

| | Stolen issuer key | Stolen revocation key |
|---|---|---|
| What the attacker gains | **Mints authority.** Forges contracts the whole estate honours | **Revokes things.** The feed is deny-only, so nothing can be granted with it |
| Recovery | Rotate, then wait for every mediator to refresh. Contracts already minted stay valid until `exp` | Rotate, re-mint. An outage, not a breach |
| Therefore | Confidentiality-critical | **Availability**-critical |

So: protect the issuer key hardest and accept a slower signing path for it. Make
the revocation key *most available* and accept a weaker confidentiality posture,
because its worst case is a recoverable outage.

This also settles the tension in putting revocation behind a KMS. `WC-6002` is
*revocation feed unwritable → closed, alarm* — a KMS dependency on the containment
path makes the kill switch depend on a network service during exactly the incident
where the network may be part of the problem. That is a dependency inversion on the
one path that must work when everything else does not.

## How this is done elsewhere

Every mature answer to "a signing key that must survive compromise, and a second
one that must work when the first is unreachable" converges on the same five
mechanisms. Named examples, for the shape rather than the specifics:

**Two-tier keys — offline root, online worker.** Public CAs keep root keys offline
in HSMs and let online intermediates do daily signing; the root only comes out for
a scripted ceremony. This is the direct model for #1 and #2: one key for the
routine, a different key of last resort. Not a second copy of the same key.

**Non-exportable hardware.** The key never exists as bytes on a disk. A PIV
smartcard, YubiKey or Nitrokey generates the key on-device and will not release it;
signing is a device operation gated by a PIN, often plus a physical touch. Sigstore
and the TUF root roles are run this way, with holders geographically distributed.
This is the single largest improvement over a PEM file: host compromise means
malware can *ask* the token to sign, and touch-to-sign means it cannot do so
silently or in bulk.

**M-of-N activation.** HashiCorp Vault is the closest analogue to our problem: the
master key is Shamir-split into shares with a threshold, and when auto-unseal
delegates to a cloud KMS, Vault deliberately keeps *recovery keys* as the fallback
for when the KMS is unavailable. ICANN's DNSSEC root ceremony is the ceremonial
extreme — HSMs in two facilities, crypto officers holding smartcards and safe
deposit box keys, separate recovery share holders for disaster recovery, the whole
thing filmed and audited. The principle both share: no single person can activate
the key, and no single person's absence can prevent it.

**Use is the alarm.** Cloud break-glass practice — root credentials and their MFA
device in a safe, two-person retrieval, alerting on any use. The credential is used
approximately never, so a single use is high-signal. This is cheap and it is the
control most often skipped.

**Rehearsal.** DNSSEC and CT ceremonies are periodic partly so the procedure is
known to work. A break-glass key nobody has exercised is a key that probably does
not work: flat token, forgotten PIN, share-holder who left in March.

## What warden-connect should do

### Already supported, needs no code

The verification side already handles two revocation keys. `SignedRevocation`
carries a per-entry `kid`, and `RevocationFeed::verify` /
`client::apply_revocations` resolve it against an `IssuerKeys` map — so mediators
can trust two revocation keys at once, and **the feed records which one signed each
order.**

### The two revocation keys

| `kid` | Custody | Used by | When |
|---|---|---|---|
| `revoke-online` | KMS | `connect quarantine` | Normal operation. Fast, scriptable, no ceremony |
| `revoke-offline` | Non-exportable on a hardware token; token in a tamper-evident bag in a safe; activation PIN split M-of-N across named holders in separate locations | A documented manual procedure | Only when the KMS or the control plane is unavailable |

Deliberately **not** called `breakglass`: `connect breakglass` already means
time-boxed emergency *issuance*, and colliding the vocabulary of emergency-grant
and emergency-revoke is how a runbook gets followed wrongly at 03:00.

Three properties this has that a second copy of one key does not:

1. compromise of either does not imply the other;
2. `revoke-offline` can be rotated without touching normal operation;
3. use of the offline `kid` is a high-severity event in its own right — the
   evidence chain, `Severity` and blocking sinks already carry it, and because that
   `kid` is used approximately never, one use is a page rather than a log line.

### The rest

| Key | Custody | Note |
|---|---|---|
| **Anchor** | HSM or offline | Do this first. `chain.rs` already states the requirement — *"the key belongs offline or in an HSM: an attacker who controls the control plane must not be able to re-sign a forged chain"* — and does not implement it. Periodic and off-path, so there is no latency argument against it |
| **Issuer** | KMS, no local copy | Raise the `contract::mint` gate and record why: minting is once per connection at human-approval time, so a 10–50 ms KMS round trip is invisible. The gate exists to protect the *verify* path, which is untouched |
| **Approver** | Never the service's KMS | See below |
| **Bundle envelope, CAEP sink** | Follow the issuer key | Low volume, latency irrelevant |

### Approver keys are a finding, not a trade-off

If the control plane's KMS can sign approvals, the control plane can approve its
own connections, and dual control becomes theatre. The approval signature is the
entire mechanism behind *the approval is the enforcement* — it is what makes an
approval an artifact rather than a row in a ticket system.

Today `--issuer-key` and `--approver-key` are separate files and `ApproverRegistry`
verifies against separate public keys, so the separation holds. It holds because
the operator keeps them apart, **not because anything structural prevents
collapsing them** — which is the same species of gap this codebase keeps finding
elsewhere. A KMS design that lumps them would be a regression that no test would
currently catch.

Human keys want a different mechanism anyway: a hardware token the approver
carries, or a key the approver's IdP holds.

## Honest limits

- **A token in a safe protects against theft, not against a person with access.**
  A coerced or malicious holder can sign. That is what M-of-N activation is for,
  and it is the reason to split the PIN rather than only lock the door.
- **Nothing here prevents a valid-but-wrong revocation.** Someone with legitimate
  access can revoke the estate. In this system that is a recoverable outage — which
  is precisely why the revocation key can afford a more available, less ceremonial
  custody than the issuer key.
- **Host compromise still forges nothing but still hurts.** With the issuer key in
  a KMS, an attacker on the control-plane host cannot steal the key — but they can
  ask it to sign, for as long as they hold the host. KMS moves the problem from
  *permanent* to *bounded by detection*. Rate limits, per-key authorisation policy
  and alerting on mint volume are what bound it; they are operational work, not a
  property the KMS provides for free.
- **This note is a decision, not an implementation.** Nothing in it is built.
