#!/usr/bin/env python3
"""A delegated signer for warden-connect: `--signer` / `--anchor-signer`.

Contract, from `connect --help` > KEY CUSTODY:

    stdin  : the JWS signing input, base64url, unpadded
    stdout : the signature, base64url, unpadded
    ECDSA in JWS is raw R||S — **not** DER.

Environment:
    WC_PKCS11_MODULE   e.g. /opt/homebrew/lib/softhsm/libsofthsm2.so
    WC_PKCS11_PIN
    WC_PKCS11_LABEL    the private key's CKA_LABEL

PKCS#11's CKM_ECDSA returns raw R||S already, so there is nothing to convert. That is the
*opposite* of `openssl dgst -sign` and `aws kms sign`, which both return DER — the trap
docs/key-custody.md warns about, and the reason this script asserts the length.
"""
import base64
import os
import subprocess
import sys
import tempfile


def b64u_decode(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def main() -> int:
    module = os.environ["WC_PKCS11_MODULE"]
    pin = os.environ["WC_PKCS11_PIN"]
    label = os.environ["WC_PKCS11_LABEL"]

    signing_input = b64u_decode(sys.stdin.read())

    with tempfile.TemporaryDirectory() as work:
        src = os.path.join(work, "in")
        dst = os.path.join(work, "sig")
        with open(src, "wb") as f:
            f.write(signing_input)

        proc = subprocess.run(
            ["pkcs11-tool", "--module", module, "--login", "--pin", pin,
             "--sign", "--mechanism", "ECDSA-SHA256", "--label", label,
             "--input-file", src, "--output-file", dst],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            sys.stderr.write(f"signer: pkcs11-tool failed: {proc.stderr.strip()}\n")
            return 1

        with open(dst, "rb") as f:
            sig = f.read()

    # 64 bytes for P-256. Anything near 70 means DER came back and the mechanism was wrong.
    # Failing here beats emitting a signature that nothing can verify: a mediator would
    # report WC-3102 and an operator would go looking for a tampered artifact.
    if len(sig) != 64:
        sys.stderr.write(
            f"signer: expected 64 bytes of raw R||S for P-256, got {len(sig)}. "
            "If this is ~70 bytes it is DER — unwrap it, do not ship it.\n"
        )
        return 1

    sys.stdout.write(b64u_encode(sig))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
