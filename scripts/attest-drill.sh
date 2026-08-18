#!/usr/bin/env bash
# The attestation drill: take a party to `Attested` and run a mediator in ENFORCE mode.
#
#     scripts/attest-drill.sh
#
# ## Why this exists
#
# `docs/limitations.md` recorded that enforce mode refused every call, and the reason took two
# wrong guesses to find. `Posture::Attested` is a conjunction:
#
#     identity.verified && card.verified && provenance.verified
#
# and `JwksCardVerifier` reports `verified: false` — not an error — for a document with no
# `signatures` field. So a server registered from a plain `surface.json` was permanently
# `Unattested`, `WC-3109` is `ClosedUnlessObserve`, and every mediated call was denied. MCP has
# no convention for signing a `tools/list` result, so nothing produced the input the verifier
# wanted, and `rotation-drill.sh` has run in `--observe` ever since.
#
# Two claims were made about that and both were wrong, which is why this drill asserts rather
# than explains. First: "the drill never gets through the attestation pipeline" — it was not the
# drill, it was the missing signature. Second: "`attest surface` unblocks enforce mode" — it
# unblocks **one of three legs**. This drill supplies all three, and the last phase is the only
# thing that can prove it: a call, executed, in enforce mode.
#
# ## What it proves
#
#   1  three DISTINCT keys — SPIFFE bundle, card signer, builder. One key doing all three jobs
#      would let a single compromise satisfy every stage;
#   2  the surface is signed by the shipped `connect attest surface`, not by this script, so a
#      passing drill says the product works rather than that the drill does;
#   3  the party reaches `Attested`, asserted from `connect show`;
#   4  a mediator in ENFORCE mode executes a contracted call, and refuses an uncontracted one.
#
# Phase 4 is the point. Everything before it has been unit-tested for a while; none of it had
# ever produced a party that enforce mode would admit.
#
# ## What it does not prove
#
# * **Only the callee is attested.** `issuance` copies `callee.posture` into the contract's
#   assurance, so the caller's posture never reaches the mediator. That asymmetry is worth
#   knowing before assuming both ends are checked at admission.
# * Stage 5 screening and stage 6 tier derivation are not exercised here.
#
# Requires: cargo (built binaries), python3 with `cryptography`, openssl.
# Exit 0 the attested path works · 1 it does not · 2 setup.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CONNECT="$REPO/target/release/connect"
MEDIATE="$REPO/target/release/connect-mediate"
[ -x "$CONNECT" ] || CONNECT="$REPO/target/debug/connect"
[ -x "$MEDIATE" ] || MEDIATE="$REPO/target/debug/connect-mediate"
for b in "$CONNECT" "$MEDIATE"; do
    [ -x "$b" ] || { echo "no $b; run cargo build --release --workspace" >&2; exit 2; }
done
command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }
python3 -c "import cryptography" 2>/dev/null || {
    echo "need python3 with cryptography (pip install 'cryptography>=42')" >&2; exit 2; }

# Build rather than compare timestamps.
#
# This started as an mtime check — refuse if any source is newer than the binary — because a
# stale binary once made a drill report the OLD behaviour after the fix was already written and
# tested. The check was right about the danger and wrong about the mechanism: `cargo fmt`
# rewrites files and bumps their mtime without changing content, so cargo correctly declines to
# rebuild and the guard can never clear. It went from catching a real problem to blocking every
# run.
#
# Asking cargo is both simpler and stricter: it knows what is actually stale, and a no-op build
# costs nothing. The drill can no longer run against a binary that does not match the tree.
if ! cargo build --release --workspace --quiet 2>&1; then
    echo "the workspace does not build; the drill would be testing nothing" >&2
    exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
export WARDEN_CONNECT_ROOT="$WORK/root"

CALLEE="spiffe://drill.example/ns/svc/sa/payments-mcp"
CALLER="spiffe://drill.example/ns/agents/sa/recon-bot"
AUDIENCE="warden:mediator:attest-drill"
BUILDER="https://drill.example/ci/builder@v1"
MEDIATOR_ID="$AUDIENCE"
# The plane. `connect request` defaults `iss` to this, and the mediator now requires it: a
# mediator that does not know which control plane it obeys has only its keyring as a boundary.
ISSUER_ID="https://connect.internal"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

bold "attestation drill"
step "work dir  $WORK"

# --- the declared surface ----------------------------------------------------
cat > surface.json <<'SURFACE'
{"tools":[
  {"name":"get_balance","description":"Read an account balance."},
  {"name":"transfer_funds","description":"Move money between accounts."}
]}
SURFACE

# --- 1 · three distinct keys, plus stage 1 and stage 4 material -------------
# The surface digest has to be known before the provenance is minted, because `--bind-surface`
# binds the statement's subject to the surface manifest. `connect canon` computes exactly what
# `surface_artifact_digest` does, so the digest is taken from the product rather than recomputed
# here — a second implementation of the canonicaliser is the last thing this drill should have.
SURFACE_DIGEST=$("$CONNECT" canon surface.json --kind mcp --entity "$CALLEE" 2>/dev/null \
    | awk '/^manifest/ {print $2}')
[ -n "$SURFACE_DIGEST" ] || { echo "could not compute the surface digest" >&2; exit 2; }

python3 "$REPO/scripts/.attest-material.py" "$WORK/material" \
    "$CALLEE" "$AUDIENCE" "$BUILDER" "$SURFACE_DIGEST" >/dev/null \
    || { echo "could not mint attestation material" >&2; exit 2; }
M="$WORK/material"

for k in spiffe-bundle card-signer builder; do
    [ -s "$M/$k.pub.pem" ] || { echo "missing $k key" >&2; exit 2; }
done
distinct=$(cat "$M"/spiffe-bundle.pub.pem "$M"/card-signer.pub.pem "$M"/builder.pub.pem \
    | grep -v -- "-----" | sort -u | wc -l | tr -d ' ')
if [ "$distinct" -lt 3 ]; then
    bad "the three keys are not distinct — one compromise would satisfy every stage"
else
    ok "1 · three distinct keys: spiffe-bundle, card-signer, builder"
fi
step "     surface digest $SURFACE_DIGEST"

# --- 2 · sign the surface with the SHIPPED command --------------------------
"$CONNECT" attest surface --surface surface.json \
    --card-key "card-signer-1=$M/card-signer.priv.pem" \
    --out surface.signed.json >/dev/null 2>&1 \
    || { bad "2 · connect attest surface failed"; }
if python3 -c "
import json,sys
d=json.load(open('surface.signed.json'))
sys.exit(0 if d.get('signatures') else 1)" 2>/dev/null; then
    ok "2 · the surface is signed by \`connect attest surface\`, not by this script"
else
    bad "2 · the signed surface carries no signatures field"
fi

# The signature must not disturb the pin, or every contract pinned to the unsigned surface
# would break the moment a provider attested it.
SIGNED_DIGEST=$("$CONNECT" canon surface.signed.json --kind mcp --entity "$CALLEE" 2>/dev/null \
    | awk '/^manifest/ {print $2}')
if [ "$SIGNED_DIGEST" = "$SURFACE_DIGEST" ]; then
    ok "     signing does not move the pin ($SIGNED_DIGEST)"
else
    bad "     signing MOVED the pin: $SURFACE_DIGEST -> $SIGNED_DIGEST"
fi

# --- 3 · register with all three legs, and check the posture ---------------
"$CONNECT" register server --id "$CALLEE" --surface surface.signed.json \
    --endpoint stdio://drill --owner human:drill@org --zone internal.payments \
    --by human:drill@org \
    --svid "$M/jwt-svid.token" \
    --trust-key "spiffe-bundle-1=$M/spiffe-bundle.pub.pem" \
    --aud "$AUDIENCE" \
    --card-key "card-signer-1=$M/card-signer.pub.pem" --require-card-signature \
    --attest "$M/provenance.dsse.json" \
    --prov-key "builder-1=$M/builder.pub.pem" \
    --builder "$BUILDER" \
    --bind-surface > register.log 2>&1
REG=$?

POSTURE=$("$CONNECT" show "$CALLEE" 2>/dev/null | awk '/^  posture/ {print $2}')
if [ "$POSTURE" = "Attested" ]; then
    ok "3 · the party reached Attested — all three legs verified"
else
    bad "3 · posture is ${POSTURE:-unknown}, not Attested (register exit $REG)"
    echo "       the register output, which names the stage that failed:"
    sed 's/^/         /' register.log | head -20
fi

# --- 4 · a caller, a contract, and a mediator in ENFORCE mode --------------
printf '{"name":"recon-bot","description":"Reconciles.","version":"1.0.0","skills":[{"id":"reconcile","name":"reconcile","description":"Reconcile."}]}' > card.json
cat > connect-policy.toml <<'POLICY'
default = "require_approval"
version = "attest-drill@v1"

[[zone]]
id = "internal.payments"
trust = "internal"

[[zone]]
id = "internal.recon"
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

openssl ecparam -name prime256v1 -genkey -noout -out issuer.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in issuer.tmp -out issuer.priv.pem 2>/dev/null
openssl ec -in issuer.priv.pem -pubout -out issuer.pub.pem 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out appr.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in appr.tmp -out approver.priv.pem 2>/dev/null
openssl ec -in approver.priv.pem -pubout -out approver.pub.pem 2>/dev/null
rm -f issuer.tmp appr.tmp

cat > approvers.toml <<'APPROVERS'
[[approver]]
id = "human:drill@org"
key = "approver.pub.pem"
roles = ["drill.operator"]
APPROVERS

"$CONNECT" register agent --card card.json --owner human:drill@org \
    --zone internal.recon --id "$CALLER" --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$CALLER" --by human:drill@org >/dev/null 2>&1
"$CONNECT" activate "$CALLEE" --by human:drill@org >/dev/null 2>&1

REQ=$("$CONNECT" request --from "$CALLER" --to "$CALLEE" --tools get_balance \
    --justify "attestation drill" --ttl 1d --mediator "$MEDIATOR_ID" \
    --issuer-key issuer.priv.pem --kid issuer-1 --by human:drill@org 2>&1 \
    | grep -oE 'req_[a-f0-9]+' | head -1)
if [ -z "$REQ" ]; then
    bad "4 · no contract request was raised"
else
    "$CONNECT" approve "$REQ" --by human:drill@org --approver-key approver.priv.pem \
        --issuer-key issuer.priv.pem --kid issuer-1 --out . >/dev/null 2>&1 \
        || bad "4 · the contract could not be approved"
fi

CONTRACT=$(ls ./*.jws 2>/dev/null | head -1)
if [ -z "$CONTRACT" ]; then
    bad "4 · no contract artifact was written"
else
    # ENFORCE mode. No --observe anywhere: that is the entire point of this drill.
    # The upstream must declare exactly the surface the contract pinned, descriptions included:
    # they are inside the digest. The first run of this drill got WC-3108 because the upstream
    # declared `alpha` — the pin was correct and the harness was wrong.
    export UPSTREAM_TOOLS="get_balance=Read an account balance.|transfer_funds=Move money between accounts."

    RESULT=$(printf '%s\n%s\n' \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"attest-drill","version":"1"}}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_balance","arguments":{}}}' \
        | "$MEDIATE" --upstream "python3 $REPO/scripts/.rotation-upstream.py" \
            --mediator-id "$MEDIATOR_ID" --issuer-id "$ISSUER_ID" \
            --caller "$CALLER" --callee "$CALLEE" \
            --issuer-pub issuer.pub.pem --kid issuer-1 \
            --contract "$CONTRACT" 2>mediate.log)

    if printf '%s' "$RESULT" | grep -q "executed"; then
        ok "4 · a contracted call EXECUTED in enforce mode"
    else
        bad "4 · the contracted call was refused in enforce mode"
        printf '%s\n' "$RESULT" | sed 's/^/       /' | head -4
        sed 's/^/       /' mediate.log | head -12
    fi

    # The negative, so a green drill is not just "enforce mode passes everything".
    UNCONTRACTED=$(printf '%s\n%s\n' \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"attest-drill","version":"1"}}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"transfer_funds","arguments":{}}}' \
        | "$MEDIATE" --upstream "python3 $REPO/scripts/.rotation-upstream.py" \
            --mediator-id "$MEDIATOR_ID" --issuer-id "$ISSUER_ID" \
            --caller "$CALLER" --callee "$CALLEE" \
            --issuer-pub issuer.pub.pem --kid issuer-1 \
            --contract "$CONTRACT" 2>/dev/null)
    if printf '%s' "$UNCONTRACTED" | grep -q "WC-4002\|not in the contracted surface"; then
        ok "     an uncontracted tool is still refused (the surface is a ceiling)"
    else
        # Deliberately reports what it got. When the whole session is refused — an unattested
        # party, say — this check sees WC-3109 rather than a surface refusal, and a message
        # that said "not enforcing" would send a reader in exactly the wrong direction.
        bad "     an uncontracted tool was not refused on the SURFACE (see the code below)"
        printf '%s\n' "$UNCONTRACTED" | sed 's/^/       /' | head -3
    fi
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "DRILL PASSED — a party reaches Attested and enforce mode admits it."
    echo "Only the CALLEE is attested here: issuance copies callee.posture into the"
    echo "contract's assurance, so the caller's posture never reaches the mediator."
    exit 0
fi
echo "DRILL FAILED"
exit 1
