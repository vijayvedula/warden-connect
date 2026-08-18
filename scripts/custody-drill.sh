#!/usr/bin/env bash
# The custody drill: an issuer key this process never holds, and two planes that stay separate.
#
#     scripts/custody-drill.sh
#
# ## Why this exists
#
# Two claims needed executing rather than reading.
#
# The first is `--signer`: `docs/key-custody.md` says the issuer key can live in a KMS or on a
# hardware token and that this process never sees it. The seam has been there for a while and
# `signer.rs` unit-tests the wrapper, but nothing had ever taken a contract from `connect`
# through an external signer and back out through `connect verify`. A wrapper that returns DER
# instead of raw `R‖S` produces a contract that is well-formed, signed, distributed — and
# rejected by every mediator, for no reason visible from either end. So phase 2 makes that
# mistake deliberately and asserts the error names it.
#
# The second is the plane boundary, and here reading was actively misleading. `iss` was carried
# in every contract, printed by `connect verify`, and **never checked**. With one issuer's keys
# in a keyring it makes no difference: an unknown `kid` is refused, so the keyring *is* the
# boundary. Phase 4 asserts that. But a keyring is a file, and files get copied between
# environments to unblock a deployment — and a federation feed imports a peer's keys by design.
# Once two planes' keys share a keyring, `aud` is the only check left, and `aud` is the mediator
# id, commonly templated to the same string in every plane. Phase 5 is that estate: everything
# matches, the signature is good, and before `WC-3112` the non-production contract verified.
#
# ## What it proves
#
#   1  a contract minted through an EXTERNAL signer verifies — the private key is on disk only
#      as far as a wrapper this process cannot read into, and `connect` never loads it;
#   2  a wrapper that forwards DER is refused, and the message says DER;
#   3  `--require-external-signing` refuses a PEM issuer key, so "KMS, no local copy" is a
#      control and not a wiki page;
#   4  two planes with separate keys: plane B refuses plane A's contract (WC-3102);
#   5  two planes whose keys have ended up in ONE keyring: still refused, on `iss` (WC-3112);
#   6  an ES384 issuer key mints and verifies — the mint path used to be locked to ES256 while
#      everything downstream accepted three algorithms.
#
# Phase 5 is the point. Everything else was either already working or already failing loudly.
#
# ## What it does not prove
#
# * **A verified wrapper is not a verified custody arrangement.** This drill's "KMS" is openssl
#   against a file. It proves the protocol, the base64url round trip and the DER→R‖S conversion.
#   It says nothing about a real KMS's authorisation policy, rate limits or availability.
# * Phase 5 uses `connect verify --issuer-id`, which is the same `verify_artifact` a mediator
#   calls, but it is not a running mediator. `attest-drill.sh` covers the mediator in enforce
#   mode; `--issuer-id` is required there and a wrong value is a startup refusal.
#
# Requires: cargo (built binaries), python3, openssl.
# Exit 0 custody and the plane boundary hold · 1 they do not · 2 setup.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CONNECT="$REPO/target/release/connect"
MEDIATE="$REPO/target/release/connect-mediate"
[ -x "$CONNECT" ] || CONNECT="$REPO/target/debug/connect"
[ -x "$MEDIATE" ] || MEDIATE="$REPO/target/debug/connect-mediate"
[ -x "$CONNECT" ] || { echo "no $CONNECT; run cargo build --release --workspace" >&2; exit 2; }
command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }
command -v python3 >/dev/null || { echo "need python3" >&2; exit 2; }

# Ask cargo rather than compare timestamps: a stale binary once made a drill report the OLD
# behaviour after the fix was written and tested.
if ! cargo build --release --workspace --quiet 2>&1; then
    echo "the workspace does not build; the drill would be testing nothing" >&2
    exit 2
fi
CONNECT="$REPO/target/release/connect"
MEDIATE="$REPO/target/release/connect-mediate"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
export WARDEN_CONNECT_ROOT="$WORK/root"

AGENT="spiffe://drill.example/ns/agents/sa/recon-bot"
SERVER="spiffe://drill.example/ns/svc/sa/payments-mcp"
MEDIATOR="warden:mediator:custody-drill"
# The same string in both planes, on purpose. It is what a templated deployment produces, and it
# is what makes `aud` useless as a plane boundary.
PLANE_A="https://connect.apac.internal"
PLANE_B="https://connect.emea.internal"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

bold "custody drill"
step "work dir  $WORK"
step "planes    A=$PLANE_A  B=$PLANE_B  (both aud=$MEDIATOR)"

# --- the estate ---------------------------------------------------------------
cat > connect-policy.toml <<'POLICY'
default = "require_approval"
version = "custody-drill@v1"

[[zone]]
id = "internal.drill"
trust = "internal"

[standing]
reviewed_at = 0

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
decision = "require_approval"
approver_role = "drill.operator"
ttl_max = "7d"
terms = { evidence_sink = "ocsf://siem", evidence_delivery = "fail-safe" }
reason = "the drill approves by hand"
POLICY

printf '{"tools":[{"name":"get_balance","description":"Read an account balance."}]}' > surface.json
printf '{"name":"caller","description":"The drill caller.","version":"1.0.0","skills":[{"id":"drive","name":"drive","description":"Drives the drill."}]}' > card.json

openssl ecparam -name prime256v1 -genkey -noout -out approver.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in approver.tmp -out approver.priv.pem 2>/dev/null
openssl ec -in approver.priv.pem -pubout -out approver.pub.pem 2>/dev/null
rm -f approver.tmp
cat > approvers.toml <<'APPROVERS'
[[approver]]
id = "human:drill@org"
key = "approver.pub.pem"
roles = ["drill.operator"]
APPROVERS

"$CONNECT" register agent --card card.json --owner human:drill@org --zone internal.drill \
    --id "$AGENT" --by human:drill@org >/dev/null 2>&1
"$CONNECT" register server --id "$SERVER" --surface surface.json --endpoint stdio://drill \
    --owner human:drill@org --zone internal.drill --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$AGENT" --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$SERVER" --by human:drill@org >/dev/null 2>&1

# --- the signing wrappers ----------------------------------------------------
#
# One script for both phases, because the difference between a wrapper that works and one that
# silently poisons every contract is a single conversion. Passing --der skips it.
cat > sign.py <<'SIGNER'
#!/usr/bin/env python3
"""A KMS-shaped signing wrapper: base64url in, base64url out, nothing else on stdout.

The two things that bite a real wrapper are both here, because both are easy to get silently
wrong: base64url arrives UNPADDED and has to be re-padded before it can be decoded, and ECDSA
signers return DER while JWS wants raw R‖S.
"""
import base64, os, subprocess, sys, tempfile

raw = sys.stdin.read().strip()
raw += "=" * (-len(raw) % 4)
message = base64.urlsafe_b64decode(raw)

digest = os.environ.get("WC_DIGEST", "sha256")
with tempfile.NamedTemporaryFile(delete=False) as f:
    f.write(message)
    path = f.name
try:
    der = subprocess.run(
        ["openssl", "dgst", f"-{digest}", "-sign", os.environ["WC_KEY"], path],
        check=True, capture_output=True,
    ).stdout
finally:
    os.unlink(path)

out = der
if "--der" not in sys.argv:
    width = int(os.environ.get("WC_WIDTH", "32"))
    assert der[0] == 0x30, "not a DER SEQUENCE"
    i = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)

    def integer(i):
        assert der[i] == 0x02, "not a DER INTEGER"
        n = der[i + 1]
        # A leading 0x00 is DER's sign padding; a short value needs left-padding.
        return der[i + 2 : i + 2 + n].rjust(width, b"\0")[-width:], i + 2 + n

    r, i = integer(i)
    s, _ = integer(i)
    out = r + s

sys.stdout.write(base64.urlsafe_b64encode(out).decode().rstrip("="))
SIGNER

# Plane A's issuer key, held only where the wrapper can reach it.
openssl ecparam -name prime256v1 -genkey -noout -out plane-a.key 2>/dev/null
openssl ec -in plane-a.key -pubout -out plane-a.pub.pem 2>/dev/null
# Plane B's. A DIFFERENT key under the SAME kid, which is the realistic shape: `kid` is a local
# label, so two planes independently calling their current key `issuer-1` is normal.
openssl ecparam -name prime256v1 -genkey -noout -out plane-b.key 2>/dev/null
openssl ec -in plane-b.key -pubout -out plane-b.pub.pem 2>/dev/null

# Each plane names its own key. That is not a detail: a merged key set holds both kids, so a
# contract's header resolves to the key that actually signed it — the signature verifies, and
# `iss` is the only thing left that could tell the two planes apart.
KID_A="apac-issuer-1"
KID_B="emea-issuer-1"

# Mint one contract in a plane, through the external signer. Echoes the artifact path.
mint_in_plane() {
    local key="$1" iss="$2" kid="$3" extra="${4-}"
    local req
    req=$(WC_KEY="$WORK/$key" "$CONNECT" request \
            --from "$AGENT" --to "$SERVER" --tools get_balance \
            --justify "the custody drill mints in $iss" --mediator "$MEDIATOR" \
            --ttl 1d --iss "$iss" --by human:drill@org \
            --signer "python3 $WORK/sign.py $extra" --kid "$kid" 2>&1 \
          | awk '/^awaiting approval/ {print $3}')
    [ -n "$req" ] || { echo "    (no request id; the request itself failed)" >&2; return 1; }
    WC_KEY="$WORK/$key" "$CONNECT" approve --id "$req" \
        --approvers approvers.toml --approver-key approver.priv.pem \
        --iss "$iss" --by human:drill@org \
        --signer "python3 $WORK/sign.py $extra" --kid "$kid" 2>&1
}

# --- 1 · a contract minted through an external signer, verified ---------------
bold "1 · the issuer key is somewhere else"
OUT=$(mint_in_plane plane-a.key "$PLANE_A" "$KID_A")
ART=$(printf '%s' "$OUT" | awk '/^  artifact/ {print $2}')
if [ -n "$ART" ] && [ -s "$ART" ]; then
    ok "minted through --signer: $(basename "$ART")"
else
    bad "the external signer did not produce a contract"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -6
fi

# The proof that the wrapper's R‖S is right, and over the right bytes. A signature that is
# merely 64 bytes long passes the length check and fails here.
if [ -n "$ART" ] && VERIFIED=$("$CONNECT" verify --file "$ART" --issuer-pub plane-a.pub.pem \
        --kid "$KID_A" --mediator-id "$MEDIATOR" --issuer-id "$PLANE_A" 2>&1) \
        && printf '%s' "$VERIFIED" | grep -q "^valid"; then
    ok "     and it verifies — the private key was never loaded by connect"
    printf '%s' "$VERIFIED" | grep -q "aud, iss, revocation" \
        && ok "     the report says iss was checked, because it was" \
        || bad "     the report does not name iss among the checks"
else
    bad "     the contract the external signer produced does not verify"
    printf '%s\n' "${VERIFIED-}" | sed 's/^/       /' | head -6
fi

# --- 2 · the DER trap --------------------------------------------------------
bold "2 · a wrapper that forwards DER"
DER_OUT=$(mint_in_plane plane-a.key "$PLANE_A" "$KID_A" --der 2>&1)
if printf '%s' "$DER_OUT" | grep -qi "DER"; then
    ok "refused, and the message names DER"
    printf '%s' "$DER_OUT" | grep -io "der.*" | head -1 | sed 's/^/       /'
else
    bad "a DER signature was not refused with a message naming DER"
    printf '%s\n' "$DER_OUT" | sed 's/^/       /' | head -6
fi

# --- 3 · no local copy, as a control -----------------------------------------
bold "3 · --require-external-signing"
openssl ecparam -name prime256v1 -genkey -noout -out on-disk.pem 2>/dev/null
PEM_OUT=$("$CONNECT" request --from "$AGENT" --to "$SERVER" --tools get_balance \
    --justify "a PEM under an external-signing posture" --mediator "$MEDIATOR" \
    --by human:drill@org --issuer-key on-disk.pem --kid "$KID_A" \
    --require-external-signing 2>&1)
if printf '%s' "$PEM_OUT" | grep -q "require-external-signing"; then
    ok "a PEM issuer key is refused while the posture is set"
    printf '%s' "$PEM_OUT" | tail -1 | cut -c1-110 | sed 's/^/       /'
else
    bad "a PEM issuer key was accepted under --require-external-signing"
    printf '%s\n' "$PEM_OUT" | sed 's/^/       /' | head -4
fi

# --- 4 · two planes, separate keyrings ---------------------------------------
bold "4 · plane B, trusting only its own key"
python3 - <<'JWKS'
import base64, json
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def jwk(path, kid):
    n = load_pem_public_key(open(path, "rb").read()).public_numbers()
    b = lambda v: base64.urlsafe_b64encode(v.to_bytes(32, "big")).decode().rstrip("=")
    return {"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid, "x": b(n.x), "y": b(n.y)}

a = jwk("plane-a.pub.pem", "apac-issuer-1")
b = jwk("plane-b.pub.pem", "emea-issuer-1")
# Plane B as it should be configured: its own key, nobody else's.
json.dump({"keys": [b]}, open("plane-b-only.jwks", "w"))
# And plane B after a merge — the misconfiguration this drill exists for. Both kids resolve, so
# plane A's contract verifies on its own key. Nothing is broken here; a key set holding two
# planes' keys is exactly what copying one between environments, or importing a federation
# peer's, produces.
json.dump({"keys": [b, a]}, open("both-planes.jwks", "w"))
JWKS
if [ ! -s both-planes.jwks ]; then
    echo "could not build the key sets (python3 needs the cryptography package)" >&2
    exit 2
fi

B_ONLY=$("$CONNECT" verify --file "$ART" --jwks plane-b-only.jwks \
    --mediator-id "$MEDIATOR" --issuer-id "$PLANE_B" 2>&1)
if printf '%s' "$B_ONLY" | grep -q "WC-3102"; then
    ok "plane A's contract is refused: WC-3102, no trusted key for that kid"
else
    bad "plane B admitted plane A's contract with only its own key trusted"
    printf '%s\n' "$B_ONLY" | sed 's/^/       /' | head -4
fi

# --- 5 · two planes, ONE keyring — the case iss exists for --------------------
bold "5 · plane B, after somebody copied the key set"
# `--kid` is not passed with `--jwks`: a key set carries its own. A's key is in there under
# `issuer-1-apac`, so the signature verifies. `aud` matches, because both planes were deployed
# from the same template. Nothing but `iss` distinguishes these two contracts.
SHARED=$("$CONNECT" verify --file "$ART" --jwks both-planes.jwks \
    --mediator-id "$MEDIATOR" --issuer-id "$PLANE_B" 2>&1)
if printf '%s' "$SHARED" | grep -q "WC-3112"; then
    ok "still refused, and on iss alone: WC-3112"
    printf '%s' "$SHARED" | grep -o "contract was issued by.*" | cut -c1-104 | sed 's/^/       /'
else
    bad "a contract from plane A verified against plane B — the boundary is gone"
    printf '%s\n' "$SHARED" | sed 's/^/       /' | head -6
fi

# And the same artifact, same shared keyring, against its OWN plane: admitted. Otherwise phase 5
# would pass for a verifier that refuses everything.
OWN=$("$CONNECT" verify --file "$ART" --jwks both-planes.jwks \
    --mediator-id "$MEDIATOR" --issuer-id "$PLANE_A" 2>&1)
if printf '%s' "$OWN" | grep -q "^valid"; then
    ok "     and the same keyring still admits it in plane A"
else
    bad "     plane A no longer admits its own contract"
    printf '%s\n' "$OWN" | sed 's/^/       /' | head -4
fi

# --- 6 · an algorithm other than ES256 --------------------------------------
bold "6 · an ES384 issuer key"
# The mint path hard-coded ES256 while `IssuerKeys`, `connect verify` and the mediator all
# accepted three algorithms — so an estate mandated onto P-384, which is not unusual where the
# issuer key sits in a bank's KMS, could verify contracts it had no way to mint.
openssl ecparam -name secp384r1 -genkey -noout -out plane-a-384.key 2>/dev/null
openssl ec -in plane-a-384.key -pubout -out plane-a-384.pub.pem 2>/dev/null
REQ384=$(WC_KEY="$WORK/plane-a-384.key" WC_DIGEST=sha384 WC_WIDTH=48 "$CONNECT" request \
    --from "$AGENT" --to "$SERVER" --tools get_balance --justify "an ES384 issuer key" \
    --mediator "$MEDIATOR" --ttl 1d --iss "$PLANE_A" --by human:drill@org \
    --signer "python3 $WORK/sign.py" --kid es384-1 --alg ES384 2>&1 \
    | awk '/^awaiting approval/ {print $3}')
OUT384=$(WC_KEY="$WORK/plane-a-384.key" WC_DIGEST=sha384 WC_WIDTH=48 "$CONNECT" approve \
    --id "${REQ384:-none}" --approvers approvers.toml --approver-key approver.priv.pem \
    --iss "$PLANE_A" --by human:drill@org \
    --signer "python3 $WORK/sign.py" --kid es384-1 --alg ES384 2>&1)
ART384=$(printf '%s' "$OUT384" | awk '/^  artifact/ {print $2}')
V384=$("$CONNECT" verify --file "${ART384:-none}" --issuer-pub plane-a-384.pub.pem \
    --kid es384-1 --alg ES384 --mediator-id "$MEDIATOR" --issuer-id "$PLANE_A" 2>&1)
if [ -n "$ART384" ] && printf '%s' "$V384" | grep -q "^valid"; then
    ok "minted and verified under ES384"
else
    bad "an ES384 issuer key cannot mint a verifiable contract"
    printf '%s\n' "$OUT384" | sed 's/^/       /' | head -3
    printf '%s\n' "$V384" | sed 's/^/       /' | head -4
fi

# --- 7 · the mediator will not start without a plane ------------------------
bold "7 · a mediator with no --issuer-id"
# Required rather than defaulted, and asserted here because a required flag that quietly
# acquires a default is how `iss` went unchecked in the first place. The refusal has to happen
# at startup: a mediator that starts and then refuses every call is an outage presenting as a
# policy problem, and one that starts and checks nothing is worse.
NO_PLANE=$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    | "$MEDIATE" --upstream "python3 -c pass" --mediator-id "$MEDIATOR" \
        --caller "$AGENT" --callee "$SERVER" \
        --issuer-pub plane-a.pub.pem --kid "$KID_A" --contract "$ART" 2>&1 >/dev/null)
if printf '%s' "$NO_PLANE" | grep -q -- "--issuer-id is required"; then
    ok "refuses to start, naming the flag"
else
    bad "a mediator started without knowing which control plane it obeys"
    printf '%s\n' "$NO_PLANE" | sed 's/^/       /' | head -4
fi

echo
if [ "$fail" -eq 0 ]; then
    bold "DRILL PASSED — the issuer key can live elsewhere, and two planes stay two planes"
    cat <<'NOTE'
This drill's "KMS" is openssl against a file. It proves the protocol, the base64url round
trip and the DER→R‖S conversion — a verified wrapper, not a verified custody arrangement.
A real KMS's authorisation policy, rate limits and availability are procurement and
ceremony, and `docs/limitations.md` says so.
NOTE
    exit 0
fi
bold "DRILL FAILED"
exit 1
