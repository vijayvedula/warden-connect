# A real cosign attestation

Produced by **cosign v3.1.3**, not by this repository. That is the entire point: everything
in [`../attest/`](../attest) is minted by `scripts/gen-attest-fixtures.py`, and a fixture
produced by an independent *implementation* of a spec catches things a fixture produced by an
independent *reading* of it cannot.

It caught two, and both meant `DsseProvenanceVerifier` **rejected every real cosign
attestation outright**:

| What cosign does | What the verifier did |
|---|---|
| omits `keyid` — DSSE calls it an optional, unauthenticated hint | refused: *"signature has no keyid"* |
| signs ECDSA as **DER** | expected raw `R‖S`, as JWS uses |

Neither is cosign being unusual. DSSE specifies no signature encoding, and Sigstore emits DER
throughout — so the verifier accepted exactly one dialect of a two-dialect format, and the one
it accepted was its own.

**Deliberately not in `../attest/`**: CI does `rm -rf fixtures/attest` before regenerating
that directory, so anything committed there that the generator does not produce is deleted.

## What is here

| File | |
|---|---|
| `provenance.dsse.json` | the DSSE envelope, extracted from the bundle — what a verifier is handed |
| `provenance.sigstore.json` | the whole Sigstore bundle cosign wrote, kept for shape reference |
| `cosign.pub.pem` | the public half. Worthless: a throwaway keypair with an empty password |
| `artifact.bin`, `artifact.digest` | the subject the statement is about |

## Reproducing it

cosign 3.x will not sign offline without a signing config that names no transparency log —
hence the extra step, which is also the honest one for a fixture that must not depend on the
network.

```sh
export COSIGN_PASSWORD=""
cosign generate-key-pair
cosign signing-config create --out signingconfig.json     # no Rekor, so nothing is uploaded
cosign attest-blob --predicate predicate.json --type slsaprovenance1 \
    --key cosign.key --bundle bundle.json --signing-config signingconfig.json artifact.bin
python3 -c "import json;json.dump(json.load(open('bundle.json'))['dsseEnvelope'],open('envelope.json','w'))"
```

## What this still does not prove

The statement was signed by a **local key**, not by a build system with an identity. It is a
real cosign envelope with a real DER signature and no `keyid` — which is what the two fixes
needed — but the `builder.id` inside it is a string this fixture asserts about itself.
Provenance that means anything comes from a builder whose identity is attested, and that is
the remaining half of P0 #3.

`rekor inclusion not checked` in the verifier's own verdict says the same thing: nothing here
consults a transparency log.
