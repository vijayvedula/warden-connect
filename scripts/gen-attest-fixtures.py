#!/usr/bin/env python3
"""Mint the attestation fixtures for §8.7.1 stages 1, 3 and 4.

Run from the repository root:

    python3 scripts/gen-attest-fixtures.py

# Why this is Python and not a Rust test helper

Everything it writes is verified by `wc-control::attest`, and a fixture produced by
the same code that reads it proves only that the code agrees with itself. Round-trip
tests are worth having and `wc-core::contract` already has them; what they cannot tell
you is whether a **real** SPIRE JWT-SVID or a **real** SLSA provenance envelope would
be accepted, because those are produced by other implementations.

So these are minted with `cryptography` and OpenSSL primitives — a different
implementation of the same specifications — and the ES256 signatures are assembled
here as raw `R‖S` from scratch. If our verifier and this script agree, two independent
readings of the spec agree, which is the closest thing to an interop test that fits in
a repository with no network.

# Three distinct keys, on purpose

A SPIFFE trust bundle key, a card-signing key and a builder key are three different
roles held by three different parties. One key doing all three would let a test pass
while the code confused them, so each gets its own.

# What this still does not prove

The material is minted locally. It is the right *shape* — SPIFFE's `sub`/`aud`/`exp`,
an in-toto Statement with a SLSA v1 predicate inside a DSSE envelope — but it did not
come out of a SPIRE server or a build pipeline. Replacing these three files with real
output and re-running `cargo test -p wc-e2e --test attest` is the remaining step, and
the reason the fixtures are files on disk rather than constants in the test.
"""
import base64
import hashlib
import json
import pathlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "fixtures" / "attest"
OUT.mkdir(parents=True, exist_ok=True)

# Fixed so the fixtures are reproducible and the tests are not time-dependent. The
# same instant the rest of the test suite uses.
NOW = 1_785_312_500
DAY = 86_400

SPIFFE_ID = "spiffe://org/ns/agents/sa/recon"
AUDIENCE = "warden-connect://control-plane/apac"
BUILDER = "https://github.com/vijayvedula/warden-connect/.github/workflows/release.yml"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def keypair(name: str):
    """A P-256 keypair, written as PEM. Reused if it already exists, so regenerating
    the fixtures does not invalidate a trust bundle somebody has configured."""
    priv_path, pub_path = OUT / f"{name}.priv.pem", OUT / f"{name}.pub.pem"
    if priv_path.exists():
        key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        priv_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        pub_path.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def es256(key, message: bytes) -> bytes:
    """An ES256 signature in **JWS form**: raw `R‖S`, 64 bytes.

    `cryptography` returns DER, which is the trap the whole key-custody work is
    littered with. Converted here rather than trusted, and the length is asserted —
    a 70-byte signature would be silently wrong everywhere it was used.
    """
    der = key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    out = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert len(out) == 64, f"expected 64 bytes of R||S, got {len(out)}"
    return out


def jws(key, kid, payload, typ=None):
    header = {"alg": "ES256", "kid": kid}
    if typ:
        header["typ"] = typ
    signing_input = f"{b64u(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{b64u(json.dumps(payload, separators=(',', ':')).encode())}"
    return f"{signing_input}.{b64u(es256(key, signing_input.encode()))}"


def canonical(value) -> str:
    """The canonical JSON `wc_core::util::canonical_json` produces: sorted keys, no
    insignificant whitespace. The card signature is over these exact bytes, so a
    disagreement here is a disagreement about what was signed."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# --- stage 1 · a SPIFFE JWT-SVID --------------------------------------------
# SPIFFE spec: `sub` carries the SPIFFE ID, `aud` the intended audiences, `exp` is
# required, and the header carries `kid` so the verifier can pick a bundle key.
bundle_key = keypair("spiffe-bundle")
svid = jws(bundle_key, "spiffe-bundle-1", {
    "sub": SPIFFE_ID,
    "aud": [AUDIENCE],
    "exp": NOW + 3600,
    "iat": NOW - 60,
    "iss": "https://spire-server.internal",
}, typ="JWT")
(OUT / "jwt-svid.token").write_text(svid + "\n")

# --- stage 3 · a signed A2A agent card --------------------------------------
# The signature covers the card with its own `signatures` field removed, canonicalised
# — otherwise the document would have to contain a hash of itself.
card_key = keypair("card-signer")
card = {
    "name": "recon-agent",
    "description": "Nightly ledger reconciliation.",
    "version": "2.4.1",
    "skills": [{"id": "reconcile", "description": "Reconcile the ledger."}],
}
protected = b64u(json.dumps({"alg": "ES256", "kid": "card-signer-1"},
                            separators=(",", ":")).encode())
card_sig_input = f"{protected}.{b64u(canonical(card).encode())}"
card["signatures"] = [{
    "protected": protected,
    "signature": b64u(es256(card_key, card_sig_input.encode())),
}]
(OUT / "agent-card.signed.json").write_text(json.dumps(card, indent=2) + "\n")

# --- stage 4 · SLSA provenance in a DSSE envelope ---------------------------
# An in-toto Statement carrying a SLSA v1 provenance predicate, wrapped in DSSE. The
# subject digest is what binds the statement to the artifact being admitted; without
# it the envelope vouches for nothing in particular.
builder_key = keypair("builder")
artifact = b"warden-connect recon-agent 2.4.1 (fixture artifact)"
digest = hashlib.sha256(artifact).hexdigest()
(OUT / "artifact.bin").write_bytes(artifact)
(OUT / "artifact.digest").write_text(f"sha256:{digest}\n")

statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": "recon-agent", "digest": {"sha256": digest}}],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": "https://slsa.dev/container-based-build/v0.1",
            "externalParameters": {"source": "git+https://github.com/vijayvedula/warden-connect"},
        },
        "runDetails": {
            "builder": {"id": BUILDER},
            "metadata": {"invocationId": "run/1", "startedOn": "2026-08-07T00:00:00Z"},
        },
    },
}
payload = json.dumps(statement, separators=(",", ":")).encode()
payload_type = "application/vnd.in-toto+json"


def pae(ptype: str, body: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding. Implemented from the spec text rather than
    copied from our Rust, which is the point of this file existing."""
    return b"DSSEv1 " + str(len(ptype)).encode() + b" " + ptype.encode() + b" " \
        + str(len(body)).encode() + b" " + body


envelope = {
    "payloadType": payload_type,
    "payload": base64.b64encode(payload).decode(),
    "signatures": [{
        "keyid": "builder-1",
        "sig": base64.b64encode(es256(builder_key, pae(payload_type, payload))).decode(),
    }],
}
(OUT / "provenance.dsse.json").write_text(json.dumps(envelope, indent=2) + "\n")

# --- a manifest, so the test does not hard-code what the script chose --------
(OUT / "manifest.json").write_text(json.dumps({
    "note": "Generated by scripts/gen-attest-fixtures.py. Minted by `cryptography` and "
            "not by this repository's Rust, so agreement is two readings of a spec "
            "rather than one implementation talking to itself.",
    "now": NOW,
    "spiffe_id": SPIFFE_ID,
    "audience": AUDIENCE,
    "builder": BUILDER,
    "artifact_digest": f"sha256:{digest}",
    "keys": {
        "spiffe_bundle": {"kid": "spiffe-bundle-1", "pub": "spiffe-bundle.pub.pem"},
        "card_signer": {"kid": "card-signer-1", "pub": "card-signer.pub.pem"},
        "builder": {"kid": "builder-1", "pub": "builder.pub.pem"},
    },
}, indent=2) + "\n")

print(f"  wrote {len(list(OUT.iterdir()))} files to fixtures/attest/")
for f in sorted(OUT.iterdir()):
    print(f"    {f.name}")
