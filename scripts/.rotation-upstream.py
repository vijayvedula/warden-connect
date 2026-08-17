#!/usr/bin/env python3
"""A minimal MCP upstream for the rotation drill: one tool, `alpha`.

Its own file rather than an inline heredoc so the drill script stays readable, and because a
nested heredoc sharing a delimiter is a mistake this session already made once.
"""
import json
import sys

# Parameterised so more than one drill can share it, and so a drill's declared surface and
# its upstream cannot silently disagree — which is exactly what happened on the attestation
# drill's first run: the contract pinned `get_balance`, the upstream declared `alpha`, and the
# mediator refused with WC-3108. The pin was doing its job; the harness was lying to it.
#
# The description matters too. It is inside the pinned digest, so a drill that sets the tool
# names but not the descriptions gets a pin mismatch for a reason that reads like a bug.
import os

_spec = os.environ.get("UPSTREAM_TOOLS", "alpha=The contracted tool.")
TOOLS = [
    {"name": name, "description": desc}
    for name, _, desc in (part.partition("=") for part in _spec.split("|"))
]

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    mid, method = msg.get("id"), msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "rotation-drill-upstream", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        result = {"content": [{"type": "text",
                               "text": "executed " + msg["params"]["name"]}], "isError": False}
    else:
        result = {}
    if mid is not None:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\n")
        sys.stdout.flush()
