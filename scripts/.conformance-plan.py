#!/usr/bin/env python3
"""Flatten expected.json into unit-separator records for scripts/conformance.sh.

A separate file rather than a heredoc so the shell script stays readable and so the record
separator is chosen in one place.
"""
import json
import sys

doc = json.load(open(sys.argv[1]))
keys = doc["keys"]

for name, v in sorted(doc["vectors"].items()):
    # `trust_kid` is the key the verifier must be CONFIGURED to trust, which is not the
    # artifact's own header kid — see the note in the generator. Using the artifact's claim
    # would register the trusted key under an attacker's name.
    kid = v["trust_kid"]
    print("\x1f".join([
        name,
        str(v.get("expect") or ""),
        v.get("stage", "artifact"),
        kid,
        v.get("trust_alg", "ES256"),
        keys[kid],
        v.get("description", ""),
    ]))
