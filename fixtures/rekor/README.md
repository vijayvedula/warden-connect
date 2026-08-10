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
