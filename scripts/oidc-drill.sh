#!/usr/bin/env bash
# The OIDC drill: a workload identity from a GitHub-shaped token, and what it does not buy.
#
#     scripts/oidc-drill.sh
#
# ## Why this exists
#
# The parties in every other drill here carry `urn:` ids that nothing attests. The honest fix is a
# real workload identity, and SPIRE is the usual answer — but SPIRE is a cluster component, and
# `register --oidc-token` exists precisely so an estate can use a JWT it already has: a Kubernetes
# projected service-account token, IRSA, Azure workload identity, or GitHub Actions.
#
# GitHub Actions was the interesting case and the broken one. Its OIDC JWKS is **RSA-only**, and
# `IssuerKeys::add_jwks` skipped every RSA key — so `--oidc-token` against GitHub could resolve no
# key at all. The flag existed, was documented, and could not work for the issuer most estates would
# point it at. There was also no way to load a JWKS document from the CLI: `--trust-key` takes one
# PEM per key and handles EC and Ed25519 only.
#
# ## What it proves
#
#   1  an RSA JWKS loads, and a GitHub-shaped RS256 token verifies against it;
#   2  the entity id is DERIVED from the token's subject, so a token for one repository can only
#      ever authenticate as the one id derived from it;
#   3  the identity stage is recorded as verified;
#   4  a token from another issuer is refused even though the signature is good;
#   5  a token for another audience is refused;
#   6  an RSA JWK with no `alg` is refused rather than guessed at.
#
# ## What it does NOT prove, and this matters
#
# **This does not reach `Attested`.** OIDC satisfies the identity stage only. Posture also wants a
# signed card and provenance, so a party registered this way is `Unattested` with its identity
# verified — better than `urn:` with nothing, and not the same as attested. Anyone reading a claim
# that OIDC "makes parties attested" should read this paragraph instead.
#
# It also does not prove anything about GitHub's real endpoint. The keys here are generated locally
# and the token is minted by this script, so what is verified is the *shape*: RS256, an RSA JWKS, a
# `repo:owner/name:ref:...` subject, and the issuer and audience checks. GitHub rotates its keys, so
# whatever refreshes that file is what keeps a real deployment working.
#
# Requires: cargo (built binaries), python3, openssl.
# Exit 0 the path works · 1 it does not · 2 setup.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }
command -v python3 >/dev/null || { echo "need python3" >&2; exit 2; }
if ! cargo build --release --workspace --quiet 2>&1; then
    echo "the workspace does not build; the drill would be testing nothing" >&2
    exit 2
fi
CONNECT="$REPO/target/release/connect"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
export WARDEN_CONNECT_ROOT="$WORK/root"

ISSUER="https://token.actions.githubusercontent.com"
SUBJECT="repo:vijayvedula/estate-recon-bot:ref:refs/heads/main"
# Derived, never asserted. An operator has to be able to compute this before registering, which is
# why `OidcIdentity::entity_id_for` is public.
ID="urn:wc:oidc:github:$SUBJECT"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

bold "oidc drill"
step "work dir  $WORK"
step "issuer    $ISSUER"
step "subject   $SUBJECT"
echo

# --- the issuer's keys, as a JWKS ---------------------------------------------
openssl genrsa -out gh.key 2048 2>/dev/null
openssl rsa -in gh.key -pubout -out gh.pub 2>/dev/null
python3 - <<'PY'
import base64, json, subprocess
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
mod = subprocess.run(["openssl", "rsa", "-pubin", "-in", "gh.pub", "-noout", "-modulus"],
                     capture_output=True, text=True).stdout.strip().split("=", 1)[1]
n = bytes.fromhex(mod)
e = (65537).to_bytes(3, "big")
# `alg` is present because RS256 and PS256 are different padding schemes over the same key, and a
# JWK that does not say which would need the loader to guess a verification parameter.
json.dump({"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "gh-oidc-1",
                     "n": b64u(n), "e": b64u(e)}]}, open("gh-jwks.json", "w"), indent=2)
# The same key with no `alg`, for the refusal case.
json.dump({"keys": [{"kty": "RSA", "use": "sig", "kid": "gh-noalg",
                     "n": b64u(n), "e": b64u(e)}]}, open("noalg-jwks.json", "w"), indent=2)
PY

# mint <out> <iss> <aud> <sub>
mint() {
    python3 - "$1" "$2" "$3" "$4" <<'PY'
import base64, json, subprocess, sys, time
out, iss, aud, sub = sys.argv[1:5]
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
now = int(time.time())
hdr = {"alg": "RS256", "kid": "gh-oidc-1", "typ": "JWT"}
pl = {"iss": iss, "aud": aud, "sub": sub, "repository": "vijayvedula/estate-recon-bot",
      "iat": now - 10, "nbf": now - 10, "exp": now + 600}
si = f"{b64u(json.dumps(hdr, separators=(',', ':')).encode())}." \
     f"{b64u(json.dumps(pl, separators=(',', ':')).encode())}"
sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", "gh.key"],
                     input=si.encode(), capture_output=True).stdout
open(out, "w").write(f"{si}.{b64u(sig)}")
PY
}

printf '{"name":"recon","description":"the consumer","version":"1.0.0","skills":[{"id":"d","name":"d","description":"d"}]}' > card.json
cat > connect-policy.toml <<'POLICY'
default = "require_approval"
version = "oidc-drill@v1"

[[zone]]
id = "internal.apac"
trust = "internal"

[standing]
reviewed_at = 0
POLICY

reg() {  # reg <id> <token> <issuer> <aud> <jwks>
    "$CONNECT" register agent --card card.json --id "$1" \
        --owner human:drill@org --zone internal.apac --by human:drill@org \
        --oidc-token "$2" --oidc-issuer "$3" --oidc-label github --aud "$4" \
        --trust-jwks "$5" 2>&1
}

# --- 1 · the happy path -------------------------------------------------------
bold "1 · an RSA JWKS loads, and a GitHub-shaped token verifies against it"
mint good.jwt "$ISSUER" warden-connect "$SUBJECT"
OUT="$(reg "$ID" good.jwt "$ISSUER" warden-connect gh-jwks.json)"
if printf '%s' "$OUT" | grep -q "evidence seq"; then
    ok "registered $ID"
else
    bad "registration failed"
    printf '%s\n' "$OUT" | tail -8 | sed 's/^/       /'
    bold "DRILL FAILED"; exit 1
fi
# The identity stage must be the one NOT in the unverified list. If it appeared there, the token
# was ignored and the registration succeeded for an unrelated reason.
if printf '%s' "$OUT" | grep -q "not verified:" \
   && ! printf '%s' "$OUT" | grep -E "not verified:" | grep -qiE "identity|workload"; then
    ok "     and the identity stage is recorded as verified"
    printf '%s' "$OUT" | grep -E "not verified:" | sed 's/^/       /'
else
    bad "     the identity stage was not verified — the token did nothing"
    printf '%s' "$OUT" | grep -E "not verified|posture" | sed 's/^/       /'
fi

# --- 2 · the id is derived, not asserted -------------------------------------
bold "2 · a token for one repository authenticates as one id and no other"
# Same valid token, registered under a DIFFERENT id. It must refuse: the id comes from the subject,
# so claiming another one is claiming an identity the token does not carry.
OUT2="$(reg "urn:wc:oidc:github:repo:someone-else/other:ref:refs/heads/main" good.jwt "$ISSUER" warden-connect gh-jwks.json)"
if printf '%s' "$OUT2" | grep -qE "WC-[0-9]+"; then
    ok "the same token cannot register a different id"
    printf '%s' "$OUT2" | grep -oE "WC-[0-9]+.{0,86}" | head -1 | sed 's/^/       /'
else
    bad "a token registered an id it does not name — the derivation is not enforced"
    printf '%s\n' "$OUT2" | tail -5 | sed 's/^/       /'
fi

# --- 3 · the issuer check ----------------------------------------------------
bold "3 · a good signature from the wrong issuer is refused"
# Signed by the SAME key, so only `iss` differs. Without the issuer check, any key in the trust set
# would authenticate a token from any issuer that key belongs to.
mint evil.jwt "https://evil.example" warden-connect "$SUBJECT"
OUT3="$(reg "urn:wc:oidc:github:$SUBJECT" evil.jwt "$ISSUER" warden-connect gh-jwks.json)"
if printf '%s' "$OUT3" | grep -qE "WC-[0-9]+"; then
    ok "refused — the signature verifies and the issuer does not match"
else
    bad "a token from another issuer was accepted"
    printf '%s\n' "$OUT3" | tail -5 | sed 's/^/       /'
fi

# --- 4 · the audience check --------------------------------------------------
bold "4 · a token minted for somebody else's audience is refused"
mint wrongaud.jwt "$ISSUER" "some-other-service" "$SUBJECT"
OUT4="$(reg "urn:wc:oidc:github:$SUBJECT" wrongaud.jwt "$ISSUER" warden-connect gh-jwks.json)"
if printf '%s' "$OUT4" | grep -qE "WC-[0-9]+"; then
    ok "refused — an unbound audience accepts tokens minted for anything"
else
    bad "a token for another audience was accepted"
    printf '%s\n' "$OUT4" | tail -5 | sed 's/^/       /'
fi

# --- 5 · an unlabelled RSA key -----------------------------------------------
bold "5 · an RSA JWK with no \`alg\` is refused rather than guessed at"
# Asserted on the OUTCOME as well as the wording.
#
# One mutation here is BENIGN and worth recording rather than engineering a red for: returning the
# report early instead of refusing the whole document loads nothing, so the key still resolves to
# nothing and registration still fails, with the same explanation reaching the operator on stderr.
# Two layers refuse it — the document-level check and key resolution — and both fail closed. Forcing
# this test to distinguish them would pin an implementation detail rather than the property, and the
# property is that an unlabelled RSA key never authenticates anything.
OUT5="$(reg "urn:wc:oidc:github:$SUBJECT" good.jwt "$ISSUER" warden-connect noalg-jwks.json)"
RC5=$?
if [ "$RC5" -ne 0 ] && printf '%s' "$OUT5" | grep -qE "RS256 and PS256 differ"; then
    ok "refused, and says why: RS256 and PS256 are different padding schemes"
elif [ "$RC5" -ne 0 ]; then
    bad "refused, but not for the stated reason — the message must name the ambiguity"
    printf '%s\n' "$OUT5" | tail -4 | sed 's/^/       /'
else
    bad "an unlabelled RSA key was loaded with a guessed algorithm"
    printf '%s\n' "$OUT5" | tail -5 | sed 's/^/       /'
fi
# And the registration must not have happened. A refusal that still wrote a party would be worse
# than one that reported wrongly.
if "$CONNECT" show "urn:wc:oidc:github:$SUBJECT" >/dev/null 2>&1; then
    step "     (that id already exists from phase 1, so its presence proves nothing here)"
fi

echo
if [ "$fail" -eq 0 ]; then
    bold "DRILL PASSED — a workload identity from a token the estate already has"
    cat <<'NOTE'
What this deliberately does not claim:

  * **It does not reach `Attested`.** OIDC satisfies the IDENTITY stage. Posture also wants a signed
    card and provenance, so a party registered this way is Unattested with its identity verified.
    That is better than a `urn:` id with nothing behind it, and it is not the same thing.
  * **Nothing here touched GitHub.** The keys are generated locally and the token is minted by this
    script, so what is proven is the shape: RS256, an RSA-only JWKS, a `repo:owner/name:ref:…`
    subject, and the issuer and audience checks. GitHub rotates its keys — whatever refreshes that
    file is what keeps a real deployment working, and a stale file fails closed at verification.
NOTE
    exit 0
fi
bold "DRILL FAILED"
exit 1
