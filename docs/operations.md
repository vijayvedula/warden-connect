# Operations: backup, restore, retention

The state log and the evidence chain **are** the system of record. That is the whole
argument for §8.16b shipping no database, and it has a corollary that had not been written
down: a tamper-evident chain on a disk nobody backs up is a compliance story with a single
point of failure, and an untested restore is not a backup — it is a directory.

Written for production-readiness P1 #14.

---

## What has to survive

| Path | What it is | If you lose it |
|---|---|---|
| `<root>/tenants/<t>/state/events-*.jsonl` | the state log — every registration, contract, approval | the register is gone. Contracts already issued keep working until `exp`, because a mediator verifies signatures rather than asking. But nothing new can be issued and nothing can be revoked by `cid` |
| `<root>/tenants/<t>/evidence/chain.jsonl` | the hash-linked evidence chain | **the audit trail is gone, unrecoverably.** No re-derivation exists: the chain is the record |
| `<root>/tenants/<t>/evidence/anchor.jsonl` | signed checkpoints | the chain can still be read but its integrity can no longer be proven to anyone outside the operating team |
| `keys.toml` + the private keys | issuer, anchor, revocation | see [key-custody.md](key-custody.md). Losing the issuer key is unrecoverable in a different way — every contract it signed stops verifying when it leaves the JWKS |

`*.lock` files are process state and are deliberately **not** part of a backup.

## Backup

```sh
connect backup --root /var/lib/warden-connect --out /backup/wc-$(date +%Y%m%dT%H%M%SZ)
```

```
backed up default to /backup/wc-20260808T041200Z
  state seq   4182
  chain seq   9931
  chain head  dc5cecb10593277c3c7d
  files       3 (2.4 MiB)
  verified    the chain was intact before this manifest was written
```

Three things this does that `cp -r` cannot:

* **It verifies the chain first, and refuses if it is broken.** A snapshot of an
  already-corrupt root is the worst artifact this system can produce: it looks like
  insurance, it launders the corruption forward into every copy, and it is discovered at
  the exact moment somebody needed it to be real. No manifest is written for a chain that
  did not verify.
* **It records the head sequences.** After a restore the first question is *how much did we
  lose*, and the only way to answer it is to know where the backup stopped.
* **It digests every file.** A snapshot altered afterwards is refused at restore time
  rather than installed.

Pass `--anchor-pub` to verify the signed checkpoints too, not just the hash links. Without
it the chain is checked for internal consistency, which catches damage but not a
deliberate rewrite by somebody who could recompute the hashes.

### Hot or cold

`backup` does **not** take the writer lock, so it can run against a live control plane.
Both logs are append-only, so a file copied mid-append yields a prefix plus possibly a
torn final line — never a scrambled middle. The manifest names a sequence rather than
claiming an instant: **the snapshot is consistent as of the sequence it names**, and
anything committed later is absent rather than half-present.

If a copy catches a partial append the report says so:

```
  NOTE        a log ended mid-record: this was a hot copy, so the last append may be
              absent from the restore
```

For a cold backup, stop the active writer first. The trade is yours: a lock-holding backup
would block issuance for its duration, which is why this does not do it for you.

### Where to put it

**Offsite, and on WORM storage if the retention clock matters.** The anchor file is the
part that most wants immutability — see the AWS variant in
[physical-architecture.md](physical-architecture.md) for S3 Object Lock in compliance mode,
which not even that account's root can delete before its retention expires.

A backup on the same volume as the thing it backs up is not a backup.

## Restore

```sh
connect restore --from /backup/wc-20260808T041200Z --into /var/lib/warden-connect-new
connect audit verify --root /var/lib/warden-connect-new --anchor-pub /keys/anchor.pub.pem
```

```
restored 3 file(s) into /var/lib/warden-connect-new/tenants/default
  taken at    1786177716
  state seq   4182
  chain seq   9931
  chain head  matches the manifest

Anything committed after state seq 4182 is not in this restore. Run `connect audit verify`
against the new root before serving from it.
```

Four refusals, in this order, because each protects the evidence the next would otherwise
destroy:

1. **No manifest** → not a snapshot this tool wrote. Its layout is not something to guess.
2. **A digest mismatch** → refused *before anything is placed*. A restore that copies first
   and compares afterwards has already overwritten what it was going to compare against.
3. **A non-empty target** → refused, never merged. Two append-only logs joined together are
   a third history that never happened — and it would verify, because every row would still
   chain to the one before it.
4. **A live writer** → the lock is held for the whole placement, so a control plane cannot
   start on a half-restored root.

**Restore into a new root and switch to it.** Do not restore over the root you are trying
to recover: if the restore is wrong, the thing you needed is gone.

### The drill

An untested restore is a directory. Once a quarter, on a host that is not production:

```sh
connect restore --from <newest backup> --into /tmp/drill-$(date +%s)
connect audit verify --root /tmp/drill-... --anchor-pub /keys/anchor.pub.pem
connect entities --root /tmp/drill-... --json | jq 'length'
connect export --root /tmp/drill-... --format dora --anchor-pub /keys/anchor.pub.pem
```

The last line is the one that matters: it proves the restored root can still produce the
regulatory artifact, which is the reason any of this is retained.

Record how long it took. "We can restore" and "we can restore inside our RTO" are
different claims, and only the second one is useful during an incident.

## Retention

```sh
connect retention --root /var/lib/warden-connect --contracts 7y --discovery 90d
```

```
retention  contracts 220752000s · discovery 7776000s
  rows retained  9931
  rows expired   0
  oldest row     1786176875 (914s of history)

Nothing was deleted — the chain is hash-linked, so retention is segment retirement rather
than row deletion: removing a row would break every row after it.
```

**This command deletes nothing, and that is not an omission.** Removing a row from a
hash-linked chain breaks every row after it, so retention on this structure is not a delete
— it is *segment retirement*: retire whole segments once every row in one is past its
clock, and keep the anchor that covered them. That rotation design does not exist in this
build, and implementing a row-level delete would silently destroy the property the chain
exists for while reporting success.

So what you get is the window, which is what an auditor asks for and what you need before
sizing a volume. Defaults are seven years for contracts and ninety days for discovery —
the clock the export module already assumes, because a contract nobody can produce is
indistinguishable from a contract that never existed.

**Plan capacity rather than deletion.** A chain row is a few hundred bytes; at 10⁵
contracts per tenant per §7.10, seven years of issuance and revocation is single-digit
gigabytes. That is a smaller problem than retiring segments correctly, which is why the
order of work is capacity first.

## What is still missing

Named plainly, since this page is the one an operator would rely on:

* **Segment retirement.** Described above; not implemented. Until it is, the chain grows
  monotonically.
* **A tested RTO.** The drill above is a procedure, not a measurement, and nobody has run
  it against a production-sized root.
* **Automated offsite shipping.** `backup` writes to a directory. Getting that directory to
  WORM storage is your scheduler's job, and there is no built-in uploader — deliberately,
  because a credential for offsite storage inside the control plane is a new blast radius.
* **Cross-tenant backup.** `backup` takes one tenant, chosen by `--tenant`. A root with
  many tenants needs one invocation each.
