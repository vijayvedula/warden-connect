#!/usr/bin/env python3
"""A minimal MCP upstream for the rotation drill: one tool, `alpha`.

Its own file rather than an inline heredoc so the drill script stays readable, and because a
nested heredoc sharing a delimiter is a mistake this session already made once.
"""
import json
import sys

TOOLS = [{"name": "alpha", "description": "The contracted tool."}]

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
