#!/usr/bin/env python3
"""Mint the three pieces of attestation material a party needs to reach `Attested`.

Called by `scripts/attest-drill.sh`. Separate because it needs `cryptography`, and because
minting from the **specification text** rather than from our Rust is the point: if this and
`wc-control::attest` agree, that is two readings of SPIFFE/JOSE/DSSE agreeing rather than one
implementation talking to itself. `scripts/gen-attest-fixtures.py` exists for the same reason and
this follows its shapes deliberately.

    .attest-material.py <outdir> <spiffe-id> <audience> <builder-id> <surface-digest>

Writes: jwt-svid.token (stage 1), provenance.dsse.json (stage 4), and the three public keys the
registration trusts them against.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

NOW = int(time.time())


def b64u(raw: bytes) -> str:
    """base64url, no padding — for JWS only."""
    import base64

    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64std(raw: bytes) -> str:
    """Standard base64, padded — for DSSE only.

    The two are not interchangeable and the drill's first run proved it:
    `WC-1004 build provenance unverifiable: payload is not base64 — Invalid symbol 95`,
    which is `_`, the base64url alphabet leaking into a DSSE envelope. JOSE uses base64url
    (RFC 7515); DSSE uses standard base64 (RFC 4648 §4). One script minting both has to keep
    them apart, and naming the two functions differently is cheaper than remembering to."""
    import base64

    return base64.b64encode(raw).decode()


def keypair(out: pathlib.Path, name: str):
    """A P-256 key, written as PKCS#8 private and SPKI public PEM.

    Three *different* keys are minted by the caller — SPIFFE bundle, card signer, builder — and
    that separation is the point of the exercise. One key doing all three jobs would let a
    single compromise satisfy every stage, and `containment-drill.sh` already found that
    `cp issuer.pem approver.pem` satisfied every check it was supposed to separate.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    (out / f"{name}.priv.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (out / f"{name}.pub.pem").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key


def es256(key, message: bytes) -> bytes:
    """A JOSE ES256 signature: the raw r‖s concatenation, not DER.

    The trap `signer.rs` documents at length, reproduced here on purpose. `cryptography` returns
    DER; forwarding it would produce material that is well-formed, signed and rejected by every
    verifier for no reason visible from either end.
    """
    der = key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def jws(key, kid: str, payload: dict, typ: str | None = None) -> str:
    header = {"alg": "ES256", "kid": kid}
    if typ:
        header["typ"] = typ
    protected = b64u(json.dumps(header, separators=(",", ":")).encode())
    body = b64u(json.dumps(payload, separators=(",", ":")).encode())
    return f"{protected}.{body}.{b64u(es256(key, f'{protected}.{body}'.encode()))}"


def pae(ptype: str, body: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding, from the spec text."""
    return (
        b"DSSEv1 "
        + str(len(ptype)).encode()
        + b" "
        + ptype.encode()
        + b" "
        + str(len(body)).encode()
        + b" "
        + body
    )


def main() -> int:
    out = pathlib.Path(sys.argv[1])
    spiffe_id, audience, builder_id, surface_digest = sys.argv[2:6]
    out.mkdir(parents=True, exist_ok=True)

    # --- stage 1 · a SPIFFE JWT-SVID ---------------------------------------
    # `sub` carries the SPIFFE ID, `aud` the intended audiences, `exp` is required, and the
    # header carries `kid` so the verifier can pick a bundle key.
    bundle_key = keypair(out, "spiffe-bundle")
    (out / "jwt-svid.token").write_text(
        jws(
            bundle_key,
            "spiffe-bundle-1",
            {
                "sub": spiffe_id,
                "aud": [audience],
                "exp": NOW + 3600,
                "iat": NOW - 60,
                "iss": "https://spire-server.drill",
            },
            typ="JWT",
        )
        + "\n"
    )

    # --- stage 3 · the card key ---------------------------------------------
    # Only the key: the surface itself is signed by `connect attest surface`, so the drill
    # exercises the shipped command rather than a python re-implementation of it. That is the
    # difference between proving the product works and proving this script does.
    keypair(out, "card-signer")

    # --- stage 4 · SLSA provenance in a DSSE envelope -----------------------
    # The subject digest binds the statement to what is being admitted. `--bind-surface` binds
    # it to the surface manifest, which is the honest option for a party with no container
    # digest — and it is what the drill passes, so the digest here must be that manifest hash.
    builder_key = keypair(out, "builder")
    algo, hexdigest = surface_digest.split(":", 1)
    if algo != "sha256":
        sys.exit(f"expected a sha256 surface digest, got {surface_digest!r}")

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": spiffe_id, "digest": {"sha256": hexdigest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://slsa.dev/container-based-build/v0.1",
                "externalParameters": {"source": "git+https://drill.example/payments-mcp"},
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {"invocationId": "attest-drill/1"},
            },
        },
    }
    payload = json.dumps(statement, separators=(",", ":")).encode()
    payload_type = "application/vnd.in-toto+json"
    (out / "provenance.dsse.json").write_text(
        json.dumps(
            {
                "payloadType": payload_type,
                "payload": b64std(payload),
                "signatures": [
                    {
                        "keyid": "builder-1",
                        "sig": b64std(es256(builder_key, pae(payload_type, payload))),
                    }
                ],
            },
            indent=2,
        )
        + "\n"
    )

    # Printed so the drill can assert the digest it bound is the digest it computed, rather
    # than trusting that two commands agreed.
    print(f"sha256:{hexdigest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
