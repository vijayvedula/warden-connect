#!/usr/bin/env python3
"""An MCP server over Streamable HTTP, for the HTTP-mode drill.

The stdio sibling is `.rotation-upstream.py`, and the tool surface is read from the same
`UPSTREAM_TOOLS` variable in the same format so a drill cannot declare one surface to the
contract and another to the upstream — that mistake costs a `WC-3108` that reads like a bug in
the pin rather than in the harness.

Two switches, both of which exist to make mediator behaviour observable rather than assumed:

  UPSTREAM_SSE=1        answer with `text/event-stream` instead of `application/json`, and pad
                        the stream with a progress notification and a comment ahead of the
                        result. A parser that takes the first frame, or that cannot skip a
                        notification, fails here rather than in production.
  UPSTREAM_STRICT_SESSION=1
                        hand out an `Mcp-Session-Id` at initialize and REFUSE any later request
                        that does not echo it. Without this the mediator's session handling is
                        carried by nothing: it would look identical whether it echoed the id or
                        dropped it on the floor.

The bound port is written to argv[1] so the drill can take an ephemeral port. A fixed port is
the standard way for one CI job to fail because another still holds it.
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_spec = os.environ.get("UPSTREAM_TOOLS", "alpha=The contracted tool.")
TOOLS = [
    {"name": name, "description": desc}
    for name, _, desc in (part.partition("=") for part in _spec.split("|"))
]
SSE = os.environ.get("UPSTREAM_SSE") == "1"
STRICT = os.environ.get("UPSTREAM_STRICT_SESSION") == "1"
SESSION = "sess-drill-0001"

_seen = threading.Lock()
SEEN_HEADERS = []


def dispatch(msg):
    """The JSON-RPC half, identical in behaviour to the stdio upstream."""
    method = msg.get("method")
    if method == "initialize":
        return {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "http-drill-upstream", "version": "1"},
        }
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        return {
            "content": [{"type": "text", "text": "executed " + msg["params"]["name"]}],
            "isError": False,
        }
    return {}


def sse_body(frame):
    """One result frame, deliberately preceded by noise a correct parser must ignore.

    The result is pretty-printed and each of its lines sent as its own `data:` field. That is
    what multi-line `data` is actually for — the payload contains newlines — and rejoining with
    a newline, per the spec, reproduces it exactly.

    Splitting at an arbitrary byte instead is what the first version of this stub did, and the
    drill failed: half a JSON token, then a newline, then the rest is not valid JSON, and the
    parser was right to reject it. The bug was in the server, which is worth recording because
    the failure read exactly like a broken parser.
    """
    notice = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress",
                         "params": {"progress": 1}})
    lines = "".join(
        f"data: {line}\n" for line in json.dumps(frame, indent=1).split("\n")
    )
    return (
        ": keep-alive comment\n"
        "\n"
        "event: message\n"
        f"data: {notice}\n"
        "\n"
        "retry: 3000\n"
        "id: 7\n"
        "event: message\n"
        f"{lines}"
        "\n"
    )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def _send(self, code, ctype, body):
        raw = body.encode()
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(raw)))
        if self.headers.get("mcp-session-id") is None:
            self.send_header("mcp-session-id", SESSION)
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        try:
            msg = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self._send(400, "text/plain", "not json")
            return
        with _seen:
            SEEN_HEADERS.append(
                {k.lower(): v for k, v in self.headers.items()} | {"_method": msg.get("method")}
            )

        mid = msg.get("id")
        if STRICT and msg.get("method") != "initialize":
            if self.headers.get("mcp-session-id") != SESSION:
                # A JSON-RPC error rather than a 400: the mediator must surface the reason, and
                # a transport-level failure would be indistinguishable from an unreachable host.
                frame = {"jsonrpc": "2.0", "id": mid,
                         "error": {"code": -32001, "message": "Mcp-Session-Id was not echoed"}}
                self._send(200, "application/json", json.dumps(frame))
                return

        if mid is None:
            # A notification. 202 with no body is what the spec calls for, and is the case that
            # would hang a client waiting for a frame that is never coming.
            self.send_response(202)
            self.send_header("content-length", "0")
            self.end_headers()
            return

        frame = {"jsonrpc": "2.0", "id": mid, "result": dispatch(msg)}
        if SSE:
            self._send(200, "text/event-stream", sse_body(frame))
        else:
            self._send(200, "application/json", json.dumps(frame))

    def do_GET(self):
        if self.path == "/headers":
            with _seen:
                body = json.dumps(SEEN_HEADERS)
            self._send(200, "application/json", body)
        else:
            self._send(405, "text/plain", "post only")


srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
if len(sys.argv) > 1:
    with open(sys.argv[1], "w") as fh:
        fh.write(str(srv.server_address[1]))
srv.serve_forever()
