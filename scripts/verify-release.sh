#!/usr/bin/env bash
# Verify a downloaded warden-connect release with warden-connect's own verifier.
#
#     scripts/verify-release.sh <binary> <provenance.dsse.json> <builder-pub.pem> <builder-id>
#
# `docs/releasing.md` said the honest thing: this repository verifies **other people's**
# provenance and produces none of its own, so trust in a downloaded binary rested on the
# transport — which is the residual §7.8 A8 describes for a control plane. The shortest way
# to close that is not to adopt another toolchain: it is to attest releases in the format
# this component already accepts, and then verify our own artifacts with our own code.
#
# That is this script. It needs no Sigstore client, no network, and no cosign — only a
# `connect` binary and the public key. Which matters, because the thing you are verifying may
# be the first `connect` binary you have ever downloaded: use one you already trust, or build
# from source and verify the download with that.
#
# Three bindings, all required, because a valid signature on its own vouches for nothing in
# particular:
#
#   1  signed by the builder key you were told to expect;
#   2  the statement's subject digest equals **the file in front of you**, computed here
#      rather than read off a release page — a digest you retype from a page an attacker
#      controls is a digest the attacker chose;
#   3  `builder.id` is the workflow you expect, so a valid attestation from somebody else's
#      pipeline is not accepted as ours.
#
# Exit 0 verified · 4 not bound or not verified · 2 usage.

set -uo pipefail

BINARY="${1:-}"
ENVELOPE="${2:-}"
PUBKEY="${3:-}"
BUILDER="${4:-}"

usage() {
    sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}
[ -n "$BINARY" ] && [ -n "$ENVELOPE" ] && [ -n "$PUBKEY" ] && [ -n "$BUILDER" ] || usage
for f in "$BINARY" "$ENVELOPE" "$PUBKEY"; do
    [ -f "$f" ] || { echo "not a file: $f" >&2; exit 2; }
done

# Ours if it is built, otherwise whatever is on PATH — and said out loud either way, because
# "which verifier checked this" is the first question to ask of any verification.
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CONNECT="${CONNECT:-}"
if [ -z "$CONNECT" ]; then
    for candidate in "$REPO/target/release/connect" "$REPO/target/debug/connect" "$(command -v connect || true)"; do
        [ -n "$candidate" ] && [ -x "$candidate" ] && CONNECT="$candidate" && break
    done
fi
[ -n "$CONNECT" ] && [ -x "$CONNECT" ] || {
    echo "no connect binary; build one or set CONNECT=/path/to/connect" >&2
    exit 2
}

printf 'verifier   %s\n' "$CONNECT"
printf 'artifact   %s\n' "$BINARY"
printf 'builder    %s\n\n' "$BUILDER"

# `--artifact` rather than `--artifact-digest`: the digest is computed from the bytes on this
# disk, so there is no step where a human copies a hash.
exec "$CONNECT" attest verify "$ENVELOPE" \
    --prov-key "release=$PUBKEY" \
    --artifact "$BINARY" \
    --builder "$BUILDER"
