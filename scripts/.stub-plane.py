#!/usr/bin/env python3
"""A control plane just real enough for a binding to pull from.

The Envoy drill proves the plane end of containment against a real `connect serve`. What a Kong
drill needs to prove is the BINDING end: that a worker's background refresher pulls, applies a
revocation, and that the request path sees the result. Standing up a whole estate to test that
would be testing the plane twice and the binding once.

Serves three endpoints from files:
    GET  /v1/mediators/<id>/contracts   the set, from c.jws
    GET  /v1/revocations?since=N        empty until ARM_FILE exists, then the signed delta
    POST /v1/mediators/<id>/ack         accepted

Usage: .stub-plane.py PORT FIXTURE_DIR ARM_FILE
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
FIX = sys.argv[2]
ARM = sys.argv[3]


def read(name):
    with open(os.path.join(FIX, name)) as fh:
        return fh.read().strip()


class Plane(BaseHTTPRequestHandler):
    def _json(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path.endswith("/contracts"):
            jws = read("c.jws")
            cid = json.loads(
                __import__("base64").urlsafe_b64decode(
                    jws.split(".")[1] + "=" * (-len(jws.split(".")[1]) % 4)
                )
            )["cid"]
            return self._json(200, {
                "seq": 1,
                "set_hash": "sha256:stub",
                "active": [{"cid": cid, "jws": jws}],
                "removed": [],
            })
        if path == "/v1/revocations":
            # Empty until armed. An empty feed is a real answer — "nothing is revoked" — and is
            # what lets the drill show the SAME call working and then refused.
            if os.path.exists(ARM):
                return self._json(200, json.loads(read("revocations.json")))
            return self._json(200, {
                "since": 0, "head_seq": 0, "head_digest": "sha256:stub", "events": [],
            })
        return self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length", 0))
        self.rfile.read(length)
        return self._json(200, {"ok": True})

    def log_message(self, *_):
        pass


# Threading, not the plain HTTPServer this started as. Every nginx worker runs its own refresh
# thread, so N workers poll this concurrently; a single-threaded server hands them out one at a
# time and a client holding a connection stalls the rest. That is not a hypothetical -- it failed
# CI as "the contract was still honoured after the party was revoked", because the worker that
# served the probe was the one whose poll was still queued behind another worker's. The drill was
# reporting the enforcement point as broken when the fault was in the drill's own control plane.
# 0.0.0.0, not 127.0.0.1, and for the same reason `envoy/ledger-server.py` already does it. The
# container reaches this through `host.docker.internal`, which resolves to the bridge gateway
# address on Linux; a socket bound to loopback refuses that connection. On Docker Desktop it
# works either way, which is why binding to loopback passed here and failed in CI -- as
# "the contract was still honoured after the party was revoked", i.e. as an enforcement defect.
ThreadingHTTPServer(("0.0.0.0", PORT), Plane).serve_forever()  # noqa: S104
