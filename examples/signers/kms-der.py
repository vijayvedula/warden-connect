#!/usr/bin/env python3
"""A delegated signer for a KMS that returns **DER** — the trap, handled.

    connect ... --signer "python3 examples/signers/kms-der.py"

Contract (see `wc_control::signer`):
    stdin  : the JWS signing input, base64url, unpadded
    stdout : the signature, base64url, unpadded — raw R||S for ECDSA

# Why this file exists separately from pkcs11.py

PKCS#11's `CKM_ECDSA` returns raw `R||S`, which is already JWS form. **Almost everything
else returns DER**: AWS KMS, GCP KMS, Azure Key Vault, and `openssl dgst -sign`. A wrapper
that forwards DER produces contracts that are well-formed, look signed, and verify nowhere —
and the mediator reports `WC-3102 signature or issuer chain invalid`, which reads like a
tampered artifact rather than a wrapper bug. An estate can lose a day to that.

So this converts, and asserts the result, which is the part worth copying.

Set WC_KMS_KEY_ID and adapt `sign_with_kms` to your provider. The AWS call is shown because
it is the one most people reach for first.
"""
import base64
import os
import subprocess
import sys


def b64u_decode(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def sign_with_kms(signing_input: bytes) -> bytes:
    """Return whatever the provider gives. For AWS that is DER."""
    key_id = os.environ["WC_KMS_KEY_ID"]
    # `--message-type RAW` lets KMS hash; ECDSA_SHA_256 matches JWS ES256.
    proc = subprocess.run(
        ["aws", "kms", "sign",
         "--key-id", key_id,
         "--message-type", "RAW",
         "--signing-algorithm", "ECDSA_SHA_256",
         "--message", "fileb://-",
         "--output", "text", "--query", "Signature"],
        input=signing_input, capture_output=True, check=True,
    )
    return base64.b64decode(proc.stdout.strip())


def der_to_raw(der: bytes, coord_len: int = 32) -> bytes:
    """Unwrap `SEQUENCE { INTEGER r, INTEGER s }` into fixed-width `r || s`.

    Hand-rolled rather than pulled from a library: this is the one conversion the whole
    delegated-signing story turns on, and a dependency here would be a dependency in every
    operator's signing path.

    The two subtleties that make naive versions wrong:

      * DER INTEGERs are signed, so a coordinate whose top bit is set carries a leading
        0x00 that must be stripped;
      * a coordinate shorter than the curve width must be **left**-padded to `coord_len`,
        or the signature is silently the wrong length and fails to verify.
    """
    if not der or der[0] != 0x30:
        raise ValueError(f"not a DER SEQUENCE (first byte {der[:1].hex()})")

    # Skip SEQUENCE tag and length (short or long form).
    i = 1
    if der[i] & 0x80:
        i += 1 + (der[i] & 0x7F)
    else:
        i += 1

    def read_int(pos: int):
        if der[pos] != 0x02:
            raise ValueError("expected an INTEGER in the ECDSA signature")
        length = der[pos + 1]
        start = pos + 2
        value = der[start:start + length].lstrip(b"\x00")
        if len(value) > coord_len:
            raise ValueError(f"coordinate is {len(value)} bytes, wider than the curve")
        return value.rjust(coord_len, b"\x00"), start + length

    r, pos = read_int(i)
    s, _ = read_int(pos)
    return r + s


def main() -> int:
    signing_input = b64u_decode(sys.stdin.read())
    signature = sign_with_kms(signing_input)

    if signature and signature[0] == 0x30:
        signature = der_to_raw(signature)

    # The assertion that turns a silent failure into a loud one. 64 bytes for P-256, 96 for
    # P-384. Without this the wrapper happily emits DER and every contract it signs is
    # unverifiable — reported as WC-3102, which sends you looking for an attacker.
    if len(signature) not in (64, 96):
        sys.stderr.write(
            f"signer: {len(signature)} bytes is neither P-256 (64) nor P-384 (96) raw R||S\n"
        )
        return 1

    sys.stdout.write(b64u_encode(signature))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
