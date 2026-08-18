# A real Rekor entry, for the inclusion-proof maths

`entry.json` is entry **1000000** from the public `rekor.sigstore.dev` log, captured whole:
the body, the inclusion proof, and the signed checkpoint.

It is **somebody else's entry**, and that is the point. What has to be right here is the
RFC 6962 §2.1.1 computation — leaf hash, audit path, root — and the only way to know it is
right is to run it against a proof a real log produced. It makes no claim about our own
provenance; `fixtures/cosign/` is that, and it was key-signed rather than keyless so it
carries no log entry.

| Field | Value |
|---|---|
| log index | 1000000 |
| tree size | 4163431 |
| audit path | 22 hashes |
| checkpoint | `rekor.sigstore.dev - 3904496407287907110` |

## Refresh it with

```sh
curl -sS "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=1000000" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); u,e=next(iter(d.items())); json.dump({"uuid":u,**e}, sys.stdout, indent=2)' \
  > fixtures/rekor/entry.json
```

The log is append-only, so this entry and its path are stable — but the tree grows, so a
*fresh* proof for the same entry has a different `treeSize`, a different root and a longer
path. That is why the fixture is captured rather than fetched at test time: a test that
reached the network would fail on a plane and pass differently every week.

## What the proof does and does not establish

An inclusion proof shows a leaf is in a tree **with a given root**. It says nothing about
whether that root is the log's. A response carrying both the proof and its root is
self-consistent by construction, and an attacker serving a forged entry can serve a matching
root just as easily.

The **checkpoint** is where trust comes from: a signed note committing to a size and a root.
`wc_control::rekor` compares the computed root against it and refuses when they disagree —
and **does not verify the checkpoint's signature**, which needs the log's public key as a
configured trust root. `Inclusion::root_trust` says which of the two you got, in words,
because an inclusion result with no statement about the root's provenance is the misleading
half of the feature.

## The log's public key

`log-public-key.pem` is `rekor.sigstore.dev`'s signing key, captured with

```sh
curl -sS "https://rekor.sigstore.dev/api/v1/log/publicKey" > fixtures/rekor/log-public-key.pem
```

It is here so the checkpoint's **signature** can be verified offline, which is what turns "a
checkpoint commits to this root" into "the log said so". Without it the entry and its proof are
only self-consistent: an attacker serving a forged entry can serve a matching checkpoint just as
easily, because nothing in the response is signed by anyone the verifier trusts.

Two details were determined by running candidates against this fixture rather than reasoned
about, and both would have produced a verifier that rejects every real checkpoint while passing
every note we signed ourselves:

* **the signature covers the note text ending in one newline** — not through the blank line that
  separates text from signatures. Of four plausible byte ranges, only that one verifies;
* **the four-byte key hash is `SHA256(SPKI DER)[..4]`**, Rekor's convention. It is *not* the Go
  sumdb convention (`SHA256(name ‖ 0x0A ‖ 0x01 ‖ key)`), which produces a different value here.

A key is a trust root, so treat this one as what it is: the public key of a log somebody else
runs, captured at a moment in time. If Sigstore rotates it, this fixture stops verifying and the
refresh command above is how to update it — and `a_different_key_for_the_same_log_name_is_named_as_such`
is the test that will tell you that is what happened, rather than leaving you to guess.
