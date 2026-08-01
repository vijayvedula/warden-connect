# Test keys

**These are test keys. They are published in this repository and are worthless.**

Generated with:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out sec1.pem
# jsonwebtoken's from_ec_pem expects PKCS#8, not the SEC1 form openssl emits.
openssl pkcs8 -topk8 -nocrypt -in sec1.pem -out test_anchor_priv.pem
openssl ec -in test_anchor_priv.pem -pubout -out test_anchor_pub.pem
```

Used only by unit tests that need a real ES256 keypair to sign and verify audit
anchors. Never use them for anything else; a production anchor key belongs in an
HSM or KMS and preferably offline (LLD §8.12.1).
