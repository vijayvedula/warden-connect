#!/usr/bin/env bash
# The inventory drill: find MCP servers nobody registered, from repository config alone.
#
#     scripts/inventory-drill.sh
#
# ## Why this exists
#
# This is rung 1 of the adoption ladder, and the only command in the product that answers a
# question without anything being provisioned first — no control plane, no state log, no signing
# key, no volume, no lock, and nothing for any other team to do. A bank's first question is not
# "is this contracted?" but "what have we got?", and until this existed nothing answered it.
#
# It reads **repository configuration**, not the network, for a reason worth stating once: a
# **stdio** MCP server is a command a client spawns and has no port at all, so a network scan sees
# the HTTP ones and misses the majority. Config also answers a second question free — the repo that
# declares a server is the repo that *consumes* it, so a scan yields the consumer→provider pair,
# which is exactly what a contract needs.
#
# ## What it proves
#
#   1  the three config shapes the ecosystem actually uses are all read — Claude/Cursor's
#      `mcpServers`, VS Code's `servers`, and VS Code's `mcp.servers` wrapper. A scanner that read
#      one would report an empty estate for an organisation standardised on another;
#   2  servers are grouped by TARGET, not by the name a team chose, so two teams naming one server
#      differently are one row and two teams naming different servers `mcp` are two;
#   3  stdio servers are found and counted — the number that justifies reading repos at all;
#   4  **an unreadable host is not an empty estate.** A shim that fails reports a failure, not a
#      clean bill of health. This is the phase that matters: the alternative is a report that says
#      "no MCP servers" because a token expired.
#
# ## What it does not do
#
# **Nothing is probed.** Reading a config is passive; speaking `initialize` and `tools/list` to
# somebody else's service is not, and doing it to forty servers because a scan was convenient is
# not a default. A finding is evidence that somebody wrote a server down — not that it exists, runs
# or is reachable.
#
# Requires: cargo (built binaries), python3.
# Exit 0 the inventory works · 1 it does not · 2 setup.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
command -v python3 >/dev/null || { echo "need python3" >&2; exit 2; }
if ! cargo build --release --workspace --quiet 2>&1; then
    echo "the workspace does not build; the drill would be testing nothing" >&2
    exit 2
fi
CONNECT="$REPO/target/release/connect"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

bold "inventory drill"
step "work dir  $WORK"

# --- a stand-in source host -------------------------------------------------
#
# Serves four repositories out of a directory tree, in the three config shapes plus one repo with
# no MCP config at all. `--fail` makes every answer an error, which is phase 4.
# Every directory before any heredoc: an earlier version created the nested ones afterwards, so
# three of the four config files were never written and the drill measured a one-repo estate.
mkdir -p estate/bank-recon-bot \
         estate/bank-ledger-ui/.vscode \
         estate/bank-treasury/.cursor \
         estate/bank-docs/.claude

cat > estate/bank-recon-bot/.mcp.json <<'CFG'
{
  "mcpServers": {
    "payments": {"command": "npx", "args": ["-y", "@acme/mcp-payments"]},
    "ledger":   {"command": "npx", "args": ["-y", "@acme/mcp-ledger"]}
  }
}
CFG

# The same payments server, under a different local name. One server, two consumers.
cat > estate/bank-ledger-ui/.vscode/mcp.json <<'CFG'
{
  "servers": {
    "payments-mcp": {"command": "npx", "args": ["-y", "@acme/mcp-payments"]}
  }
}
CFG

# VS Code's other shape: nested under `mcp`. And an HTTP server, which a network scan could see.
cat > estate/bank-treasury/.cursor/mcp.json <<'CFG'
{
  "mcp": {
    "servers": {
      "fx": {"url": "https://fx.treasury.internal/mcp"}
    }
  }
}
CFG

# A repo with JSON that is nothing to do with MCP. Must not become a finding, and must not fail the
# scan: most repositories look like this.
cat > estate/bank-docs/.claude/settings.json <<'CFG'
{"permissions": {"allow": ["Bash(git status)"]}}
CFG

cat > shim.py <<'SHIM'
#!/usr/bin/env python3
"""A stand-in source host, serving repositories out of ./estate.

`--fail` makes every op an error, which is how the drill checks that an unreadable host reports a
failure rather than an empty estate.
"""
import base64, json, os, sys

if "--fail" in sys.argv:
    print("the source host is unreachable", file=sys.stderr)
    sys.exit(1)

q = json.loads(sys.stdin.read())
op = q.get("op")
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "estate")

if op == "repos":
    names = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)))
    print(json.dumps({"repos": [f"bank/{n.removeprefix('bank-')}" for n in names]}))
elif op == "file":
    repo = q["repo"].split("/", 1)[1]
    path = os.path.join(root, f"bank-{repo}", q["path"])
    if os.path.isfile(path):
        with open(path, "rb") as fh:
            print(json.dumps({"content_b64": base64.b64encode(fh.read()).decode()}))
    else:
        # Explicit absence. Not an error: a scan asks about a dozen speculative paths per repo.
        print(json.dumps({"absent": True}))
else:
    sys.exit(2)
SHIM

SHIM_ARGS=(--shim "python3 $WORK/shim.py" --shim-label stub --org bank)

# --- 1 · every config shape is read ------------------------------------------
bold "1 · the three shapes the ecosystem uses"
OUT="$("$CONNECT" inventory "${SHIM_ARGS[@]}" 2>/dev/null)"
JSON="$("$CONNECT" inventory "${SHIM_ARGS[@]}" --json 2>/dev/null)"
read -r SERVERS STDIO REPOS CONFIGS <<<"$(printf '%s' "$JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
targets = {f["declaration"]["target"] for f in d["findings"]}
stdio = {f["declaration"]["target"] for f in d["findings"]
         if f["declaration"]["transport"] == "stdio"}
print(len(targets), len(stdio), d["repos_scanned"], d["configs_read"])')"

[ "$REPOS" = "4" ] && ok "scanned 4 repositories" \
                   || bad "scanned $REPOS repositories, expected 4"
[ "$CONFIGS" = "4" ] && ok "     read 4 config files, one per repo" \
                     || bad "     read $CONFIGS config files, expected 4"
if [ "$SERVERS" = "3" ]; then
    ok "     found 3 distinct servers across three different config shapes"
else
    bad "     found $SERVERS distinct servers, expected 3 (payments, ledger, fx)"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -12
fi

# --- 2 · grouped by target, not by the name a team chose ---------------------
bold "2 · one server, two names, two repos"
if printf '%s' "$OUT" | grep -q "2 consumers"; then
    ok "@acme/mcp-payments is one server with two consumers, not two servers"
    printf '%s' "$OUT" | grep -A2 "more than one repository" | tail -1 | sed 's/^/       /'
else
    bad "the shared server was not identified — grouping is probably by name, not target"
    printf '%s\n' "$OUT" | sed 's/^/       /' | head -14
fi

# --- 3 · stdio, which no network scan could see ------------------------------
bold "3 · stdio servers"
if [ "$STDIO" = "2" ]; then
    ok "2 of the 3 are stdio — spawned commands with no port at all"
else
    bad "counted $STDIO stdio servers, expected 2"
fi
printf '%s' "$OUT" | grep -q "nothing here was probed\|Nothing here was probed" \
    && ok "     and the report says nothing was probed" \
    || bad "     the report does not say that nothing was probed"

# --- 4 · an unreadable host is not an empty estate ---------------------------
bold "4 · the shim fails"
# The phase that matters. A scan that reported "no MCP servers" because a token expired would be
# worse than no scan: it is a clean bill of health manufactured from a permissions error.
BROKEN="$("$CONNECT" inventory --shim "python3 $WORK/shim.py --fail" --shim-label stub \
    --org bank 2>&1)"
RC=$?
if [ "$RC" -ne 0 ] && ! printf '%s' "$BROKEN" | grep -q "found      0 distinct"; then
    ok "reported a failure (exit $RC), not an empty estate"
    printf '%s' "$BROKEN" | grep -m1 "connect:" | cut -c1-100 | sed 's/^/       /'
else
    bad "an unreadable source host was reported as an estate with no MCP servers (exit $RC)"
    printf '%s\n' "$BROKEN" | sed 's/^/       /' | head -6
fi

# And the honest middle case: a host that returns no repositories at all.
mkdir -p empty/estate
cat > empty/shim.py <<'SHIM'
import json, sys
q = json.loads(sys.stdin.read())
print(json.dumps({"repos": []} if q.get("op") == "repos" else {"absent": True}))
SHIM
NONE="$("$CONNECT" inventory --shim "python3 $WORK/empty/shim.py" --shim-label stub \
    --org bank 2>&1)"
if printf '%s' "$NONE" | grep -q "NOTHING TO SCAN"; then
    ok "     and no repositories reads as NOTHING TO SCAN, not as nothing found"
else
    bad "     an empty repository list was reported as an estate with no servers"
    printf '%s\n' "$NONE" | sed 's/^/       /' | head -6
fi

echo
if [ "$fail" -eq 0 ]; then
    bold "DRILL PASSED — an inventory, with nothing provisioned"
    cat <<'NOTE'
No control plane, no state log, no key, no volume, no lock, and nothing asked of any other team.
A finding is evidence somebody wrote a server down — not that it exists, runs or is reachable.
Nothing was probed.
NOTE
    exit 0
fi
bold "DRILL FAILED"
exit 1
