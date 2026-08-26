#!/usr/bin/env python3
"""A real MCP client over Streamable HTTP, presenting a client certificate.

    mcp_client.py list
    mcp_client.py call get_balance '{"account":"ACC-1"}'

Why a client certificate and not a bearer token: at the gateway the caller's identity IS its
mTLS peer certificate. Envoy verifies it, puts the SPIFFE id from the URI SAN into
`x-forwarded-client-cert`, and the verifier reads it from there. A client that cannot present
one has no identity, matches no contract, and is refused — which is correct, and is why this
script exists rather than curl in the guide.

Deliberately small and dependency-free: the point is to show what any MCP client has to do to
sit behind this gateway, not to be a client library.
"""
import json
import os
import ssl
import sys
import urllib.request

URL = os.environ.get("MCP_URL", "https://localhost:10000/mcp")
CERT = os.environ.get("MCP_CLIENT_CERT", "certs/client.crt")
KEY = os.environ.get("MCP_CLIENT_KEY", "certs/client.key")
CA = os.environ.get("MCP_CA", "certs/ca.crt")

_next_id = [0]
_session = [None]


def rpc(method, params=None):
    _next_id[0] += 1
    frame = {"jsonrpc": "2.0", "id": _next_id[0], "method": method}
    if params is not None:
        frame["params"] = params

    ctx = ssl.create_default_context(cafile=CA)
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)

    req = urllib.request.Request(
        URL,
        data=json.dumps(frame).encode(),
        headers={
            "content-type": "application/json",
            # Both, because a server may answer either.
            "accept": "application/json, text/event-stream",
        },
        method="POST",
    )
    if _session[0]:
        req.add_header("mcp-session-id", _session[0])

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            sid = resp.headers.get("mcp-session-id")
            if sid:
                _session[0] = sid
            body = resp.read().decode()
    except urllib.error.HTTPError as e:
        # A refusal from the verifier arrives as HTTP 200 with a JSON-RPC error, so anything
        # here is a transport-level failure — Envoy itself, or no verifier at all.
        return {"transport_error": f"HTTP {e.code}", "body": e.read().decode()[:300]}
    except Exception as e:
        return {"transport_error": f"{type(e).__name__}: {e}"}

    if not body:
        return {"transport_error": "empty response"}
    try:
        return json.loads(body)
    except ValueError:
        return {"transport_error": "not JSON", "body": body[:300]}


def show(frame):
    if "transport_error" in frame:
        print(f"TRANSPORT  {frame['transport_error']}")
        if frame.get("body"):
            print(f"           {frame['body']}")
        return 2
    if "error" in frame:
        err = frame["error"]
        code = (err.get("data") or {}).get("code", "")
        print(f"REFUSED    {code or err.get('code')}  {err.get('message', '')}")
        return 1
    result = frame.get("result", {})
    if "tools" in result:
        print("TOOLS      " + ", ".join(sorted(t["name"] for t in result["tools"])))
    else:
        for block in result.get("content", []):
            if block.get("type") == "text":
                print(f"OK         {block['text']}")
        if result.get("isError"):
            return 1
    return 0


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    # Every MCP session opens with initialize. The verifier's pin ledger is filled by the
    # tools/list that any well-behaved client sends next, which is why `list` is the first
    # thing the guide runs.
    rpc("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "ledger-cli", "version": "1"},
    })
    verb = sys.argv[1]
    if verb == "list":
        sys.exit(show(rpc("tools/list")))
    if verb == "call":
        name = sys.argv[2]
        args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        sys.exit(show(rpc("tools/call", {"name": name, "arguments": args})))
    sys.exit(f"unknown verb {verb!r}; use list or call")


main()
