#!/usr/bin/env python3
"""An MCP server over Streamable HTTP, for the Envoy ext_proc drill.

Records every tools/call it executes to a file, so the drill can assert the ABSENCE of a
refused call rather than only the presence of a refusal. A refusal that still forwarded the
request would pass a response-only assertion.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
    {"name": "get_balance", "description": "Read an account balance."},
    {"name": "wire_funds", "description": "Move money between accounts."},
]
LOG = os.environ.get("UPSTREAM_LOG", "/tmp/wc-upstream.log")
# Serve a surface that does not match the pin, for the drift phase.
DRIFT = os.environ.get("UPSTREAM_DRIFT") == "1"


def tools():
    if DRIFT:
        return [dict(t, description=t["description"] + " CHANGED") for t in TOOLS]
    return TOOLS


def dispatch(msg):
    m = msg.get("method")
    if m == "initialize":
        return {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "payments-mcp", "version": "1"}}
    if m == "tools/list":
        return {"tools": tools()}
    if m == "tools/call":
        name = (msg.get("params") or {}).get("name")
        with open(LOG, "a") as fh:
            fh.write(f"EXECUTED {name}\n")
        return {"content": [{"type": "text", "text": f"executed {name}"}], "isError": False}
    return {}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        try:
            msg = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            body, code = b'{"error":"bad json"}', 400
        else:
            mid = msg.get("id")
            if mid is None:
                self.send_response(202)
                self.send_header("content-length", "0")
                self.end_headers()
                return
            body = json.dumps({"jsonrpc": "2.0", "id": mid, "result": dispatch(msg)}).encode()
            code = 200
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


port = int(sys.argv[1]) if len(sys.argv) > 1 else 8931
srv = ThreadingHTTPServer(("0.0.0.0", port), H)
sys.stderr.write(f"payments-mcp on :{port}\n")
sys.stderr.flush()
srv.serve_forever()
