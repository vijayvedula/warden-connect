# Runbook

What to do when something has gone wrong. Symptom first, because that is what you have at
03:00 — not a diagnosis.

The alert definitions are in [observability.md](observability.md); the recovery procedures in
[operations.md](operations.md). This is the index that gets you to the right one.

Written for production-readiness P2 #18.

---

## First: which plane is broken?

**A healthy control plane tells you nothing about whether calls are succeeding.** Issuance
can be perfectly clean while every call in the estate is refused. So:

```sh
curl -s $CP/readyz                    # can the control plane decide?
grep '"decision":"deny"' <mediator stderr> | tail -20
```

`/readyz` green and denials climbing means the **data plane**. `/readyz` red means the
control plane, and existing connections are almost certainly still working — mediators serve
from cache to `exp` (A9, by design).

---

## "All the agents are down"

The most likely cause is a control operating correctly, which is why it needs to be first.

```promql
wc_revocation_trusted == 0            # on any mediator
```

**If 0:** the mediator cannot verify the revocation feed and is therefore **refusing every
connection**. Fail-closed, working as designed, and indistinguishable from the outside from a
broken estate.

1. The decision log says which code: a distrusted feed denies with `WC-4001` on connections
   that previously worked.
2. Fix the feed's **signature or transport** — never by disabling the check. A feed you
   cannot verify is a feed an attacker may have written.
3. Check `wc_revocation_feed_serving` on the control plane. `0` means it serves no feed at
   all, so nothing it revokes can ever reach a mediator.

**If 1:** look at `wc_decisions_total{decision="deny",code=...}`. A spike in one code is a
diagnosis:

| Code | Meaning | Usual cause |
|---|---|---|
| `WC-4001` | no contract | a contract expired and nothing renewed it |
| `WC-3103` | contract expired | same, seen from the artifact side |
| `WC-4002` | tool not contracted | the callee added a tool, or policy tightened |
| `WC-3108` | pin mismatch | the callee's surface changed — **drift**, see below |
| `WC-3109` | posture not attested | re-attestation lapsed |
| `WC-3102` | signature invalid | an issuer key was retired too early, or a real attack |

`WC-3102` appearing across many parties at once is almost always **a key retired while
contracts it signed were still live**. `connect keys list` shows what may safely be retired;
the guard refuses an early retirement, so this means it was forced or the key set changed
out of band.

---

## "A party was quarantined but is still working"

```promql
wc_mediator_unconfirmed > 0
```

**Unconfirmed is not contained.** The registry transition is the control plane's own state;
the party keeps working until every mediator holding one of its contracts stops honouring it.

```sh
connect mediators                     # names the ones that have not confirmed
```

An unconfirmed mediator is down, unreachable, or holding a stale contract set that is still
inside its `exp`. If it cannot be reached, the contract expires on its own `exp` and not
before — there is no way to shorten that from here, which is why TTLs are the real
containment bound.

**If no mediator is configured at all**, the quarantine reached nothing. That is the
control-plane-only topology: a supported deployment, and not containment.

---

## "The KMS is down and I need to contain something now"

The break-glass path. It is expected to be used approximately never, so its use pages
somebody by design.

```sh
connect quarantine <id> --reason "KMS unreachable, containing now" \
    --revocation-signer <offline token command> \
    --break-glass --break-glass-kid revoke-offline --by human:you
```

* `--break-glass` **selects** the offline key; one flag, so a runbook can be followed under
  pressure without getting a pairing right.
* Naming the offline `kid` without `--break-glass` is refused — that is the
  reach-for-it-out-of-habit case.
* It records `containment.breakglass_key` at `Critical` in the chain. Expect the page.

Rehearse this quarterly with the real token:
[`scripts/containment-drill.sh`](../scripts/containment-drill.sh).

---

## "Drift was detected on a callee"

A callee's declared surface changed (A4). Material drift **suspends** the affected contracts.

```sh
connect posture --drift
connect show <callee-id>              # the pinned manifest vs what was presented
```

Then decide, and the decision is not technical:

* **An expected change** (a release added a tool) → `connect activate` re-pins after review.
* **An unexpected change** → this is the rug-pull threat. Do not re-pin. Quarantine the
  callee and find out why its surface moved.

`connect screen` on the new surface says whether the *new* descriptions carry injection
patterns, which is the question that distinguishes the two cases.

---

## "The evidence chain will not verify"

The most serious thing in this document.

```sh
connect audit verify --anchor-pub /keys/anchor.pub.pem
```

* **Hash links intact, anchors fail** → the chain was rewritten after signing. Treat as a
  control-plane compromise (A8). Preserve the volume, do not restart the service, and
  restore from a backup into a *separate* root for comparison.
* **Hash links broken at a sequence** → truncation or corruption. The rows before the break
  are intact by construction. `connect backup` refuses to snapshot a broken chain, so your
  most recent successful backup is the last known-good state.
* **No anchors configured** → the chain is readable and *not* independently verifiable. Those
  are different claims. Fix by configuring an anchor key, off the host.

**Do not "repair" a chain.** A hash-linked log cannot be edited without breaking every row
after the edit; anything that appears to fix it has replaced the record with a different one.

---

## "The control plane will not start"

Every one of these is deliberate refusal, not a crash:

| Message | Meaning |
|---|---|
| `WC-8003 store write lock held` | another writer has it. `--standby` waits; a one-shot command should not |
| `WC-8004 … is a key on this disk` | `--require-external-signing` is set. Use the delegated form |
| `WC-8004 … refusing to start` on a listener | a non-loopback bind with no TLS declaration |
| `policy has N error(s); refusing to start` | a broken policy. A control plane that booted with one would believe it was enforcing something it was not |
| `WC-8004 unknown key …` | a config key that resolves to nothing. It is refused rather than ignored |
| `first contract refresh failed, refusing to start` (mediator) | a mediator that degraded to pass-through would be worse than none |

---

## "Failover"

```sh
connect serve --standby --standby-timeout 3600 ...      # on the standby host
```

A standby binds **no port** while waiting, so a load balancer sees nothing rather than
something answering "not ready". On takeover it logs `took over the writer lock after N ms`.

The lock releases on a crash as well as a clean exit, because it belongs to the file
descriptor. What `flock` does **not** do is fence a partitioned active — the volume must
guarantee single attachment. See [physical-architecture.md](physical-architecture.md).

If the standby times out it exits non-zero rather than starting: a standby that started
anyway would be a second writer, and would present as a successful failover.

---

## "Restore"

Full procedure in [operations.md](operations.md). The two rules:

1. **Restore into a new root and switch to it.** Never over the root you are recovering — if
   the restore is wrong, the thing you needed is gone.
2. **Read the sequence numbers.** `Anything committed after state seq N is not in this
   restore` is the line the incident report turns on.

---

## Escalation

* A control that reads as configured and does nothing → a security finding, even with no
  demonstrated bypass. [SECURITY.md](../SECURITY.md).
* Two verifiers disagreeing about a conformance vector → a finding, whoever is wrong.
* Anything in [threat-model.md](threat-model.md) Part 1 that this runbook did not anticipate →
  the checklist there is the review, and it is the part worth adding to.
