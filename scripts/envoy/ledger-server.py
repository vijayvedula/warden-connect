#!/usr/bin/env python3
"""A real MCP server over Streamable HTTP: a small account ledger.

Three tools, and only two are ever contracted in the guide. `transfer_funds` is a write and is
deliberately left out of the offer, so the surface ceiling has something worth refusing.

Every executed call is appended to $LEDGER_LOG. The guide asserts the ABSENCE of a refused call
there — a refusal that still forwarded the request would look identical from the client's side.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = os.environ.get("LEDGER_LOG", "/tmp/ledger.log")
# Serve a surface that does not match the pin, for the drift step.
DRIFT = os.environ.get("LEDGER_DRIFT") == "1"

ACCOUNTS = {"ACC-1": 1240.50, "ACC-2": 87.10}
JOURNAL = []

TOOLS = [
    {
        "name": "get_balance",
        "description": "Read the balance of one account.",
        "inputSchema": {
            "type": "object",
            "properties": {"account": {"type": "string"}},
            "required": ["account"],
        },
    },
    {
        "name": "list_transactions",
        "description": "List recent transactions for one account.",
        "inputSchema": {
            "type": "object",
            "properties": {"account": {"type": "string"}},
            "required": ["account"],
        },
    },
    {
        "name": "transfer_funds",
        "description": "Move money between two accounts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "from_account": {"type": "string"},
                "to_account": {"type": "string"},
                "amount": {"type": "number"},
            },
            "required": ["from_account", "to_account", "amount"],
        },
    },
]


def tools():
    if not DRIFT:
        return TOOLS
    # One description changed. That is enough to move the pin, which is the point.
    return [
        dict(t, description=t["description"] + " (v2)") if t["name"] == "get_balance" else t
        for t in TOOLS
    ]


def call_tool(name, args):
    with open(LOG, "a") as fh:
        fh.write(f"EXECUTED {name} {json.dumps(args, sort_keys=True)}\n")
    if name == "get_balance":
        acct = args.get("account", "")
        if acct not in ACCOUNTS:
            return f"no such account: {acct}"
        return f"{acct} balance {ACCOUNTS[acct]:.2f}"
    if name == "list_transactions":
        acct = args.get("account", "")
        return f"{acct}: 3 transactions in the last 7 days"
    if name == "transfer_funds":
        JOURNAL.append(args)
        return "TRANSFERRED {} -> {} for {}".format(
            args.get("from_account"), args.get("to_account"), args.get("amount")
        )
    raise KeyError(name)


def dispatch(msg):
    m = msg.get("method")
    if m == "initialize":
        return {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "ledger-mcp", "version": "1"},
        }
    if m == "tools/list":
        return {"tools": tools()}
    if m == "tools/call":
        p = msg.get("params") or {}
        text = call_tool(p.get("name"), p.get("arguments") or {})
        return {"content": [{"type": "text", "text": text}], "isError": False}
    if m and m.startswith("notifications/"):
        return {}
    raise KeyError(m)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        try:
            msg = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            self._send(400, b'{"error":"not json"}')
            return
        mid = msg.get("id")
        try:
            result = dispatch(msg)
        except KeyError as exc:
            if mid is None:
                self._send(202, b"")
                return
            self._send(200, json.dumps({
                "jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"unknown method: {exc}"}}).encode())
            return
        if mid is None:
            self._send(202, b"")
            return
        self._send(200, json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}).encode())

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


if "--emit-surface" in sys.argv:
    # What the provider repo commits as warden/surface.json.
    #
    # EXACTLY what `tools/list` returns, `inputSchema` included. The canonicaliser covers the
    # whole tool object, so emitting only name and description produces a digest that will never
    # match what the server presents — a WC-3108 on the first catalogue, reading as drift when
    # nothing has drifted. Generated rather than hand-written for the same reason.
    json.dump({"tools": tools()}, sys.stdout, indent=2)
    print()
    raise SystemExit(0)

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8931
srv = ThreadingHTTPServer(("0.0.0.0", port), H)
sys.stderr.write(f"ledger-mcp on :{port}  tools={[t['name'] for t in tools()]}\n")
sys.stderr.flush()
srv.serve_forever()
