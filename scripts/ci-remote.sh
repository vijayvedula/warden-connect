#!/usr/bin/env bash
# Watch a CI run on the Actions mirror.
#
#     scripts/ci-remote.sh push     push main to the mirror and follow the run
#     scripts/ci-remote.sh watch    follow whatever is running now
#
# `origin` is vijayvedula/warden-connect and stays that way. The mirror exists only because
# Actions minutes are available on the other account; it is a runner, not a home. Nothing should
# ever be merged there, and `main` here always tracks origin.
#
# The mirror is private, so its API needs that account's token explicitly — the active `gh`
# account cannot read it. That is deliberate: it keeps the mirror out of the way rather than
# making it a second place to look.
set -u
MIRROR=${WC_MIRROR:-vedulavijay/warden-connect}
REMOTE=${WC_MIRROR_REMOTE:-vedulavijay}

TOKEN=$(gh auth token -u "${MIRROR%%/*}" 2>/dev/null) || true
[ -n "$TOKEN" ] || { echo "no gh token for ${MIRROR%%/*}; run: gh auth login" >&2; exit 2; }
q() { GH_TOKEN="$TOKEN" gh "$@"; }

# The mirror is private, so git needs THAT account's token — the active `gh` account cannot
# even see the repository and the push fails with "Repository not found", which is a confusing
# way to say "wrong credentials". Passed through GIT_ASKPASS rather than embedded in the URL, so
# the token never appears in argv, `ps`, or shell history.
mirror_push() {
  ASK="$(mktemp)"
  cat > "$ASK" <<'ASKEOF'
#!/bin/sh
case "$1" in
  Username*) echo x-access-token ;;
  *)         printenv WC_MIRROR_TOKEN ;;
esac
ASKEOF
  chmod +x "$ASK"
  # `-c credential.helper=` clears the inherited helper for this invocation only. Without it
  # the macOS keychain answers first with the ACTIVE account's credential, and a private repo
  # that account cannot see reports "Repository not found" rather than a permission error.
  WC_MIRROR_TOKEN="$TOKEN" GIT_ASKPASS="$ASK" GIT_TERMINAL_PROMPT=0 \
    git -c credential.helper= push "$REMOTE" HEAD:main
  rc=$?
  rm -f "$ASK"
  return $rc
}

case "${1:-watch}" in
  push)
    mirror_push || exit 1
    echo "pushed $(git rev-parse --short HEAD) to $MIRROR"
    sleep 8
    ;;
  watch) ;;
  *) echo "usage: $0 [push|watch]" >&2; exit 2 ;;
esac

ID=$(q run list --repo "$MIRROR" --limit 1 --json databaseId \
     | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0]["databaseId"] if r else "")')
[ -n "$ID" ] || { echo "no runs on $MIRROR" >&2; exit 1; }
echo "run $ID  ·  https://github.com/$MIRROR/actions/runs/$ID"

while :; do
  S=$(q run list --repo "$MIRROR" --limit 1 --json status,conclusion \
      | python3 -c 'import json,sys; r=json.load(sys.stdin)[0]; print(r["status"], r["conclusion"] or "-")')
  set -- $S
  [ -t 1 ] && printf '\r  %-12s %-10s' "$1" "$2"
  [ "$1" = completed ] && break
  sleep 20
done
echo; echo

q api "repos/$MIRROR/actions/runs/$ID/jobs" \
  --jq '.jobs[] | "  \(.conclusion // .status)\t\(.name)"' | expand -t 14

FAILED=$(q api "repos/$MIRROR/actions/runs/$ID/jobs" --jq '[.jobs[] | select(.conclusion=="failure")] | length')
if [ "${FAILED:-0}" != 0 ]; then
  echo
  echo "first failing step per failed job:"
  q api "repos/$MIRROR/actions/runs/$ID/jobs" \
    --jq '.jobs[] | select(.conclusion=="failure") | "  \(.name): \([.steps[] | select(.conclusion=="failure") | .name] | join(", "))"'
fi
