#!/usr/bin/env python3
"""Ask for a connection, and handle all three outcomes.

    WARDEN_CONNECT_TOKEN=... python3 examples/01_request_a_connection.py

The point of this example is the `else` branch. A connection crossing a trust boundary is
*supposed* to reach a human, so "awaiting approval" is the normal path, not an error — and
code that treats it as one will look correct in a demo estate where everything is
same-zone and fail on the first partner connection.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from warden_connect import Connect, ConnectError  # noqa: E402

CP = os.environ.get("WARDEN_CONNECT_URL", "http://127.0.0.1:8787")

cp = Connect(CP)  # token from WARDEN_CONNECT_TOKEN

try:
    outcome = cp.request_connection(
        from_="spiffe://org/ns/agents/sa/recon",
        to="spiffe://org/ns/tools/sa/payments",
        tools=["get_balance", "list_transactions"],
        justification="nightly ledger reconciliation, ticket OPS-4182",
        requester="human:vijay",
        ttl_secs=30 * 86_400,
        # Required in practice: a contract addressed to no mediator is a permission with
        # no enforcement point, and its `aud` is what stops it being replayed elsewhere.
        mediators=["warden:mediator:apac-ops"],
    )
except ConnectError as exc:
    # The WC-* code is the useful part. WC-2003 means a party is registered but not active;
    # WC-3012 means no mediator was named. Both are configuration, not outage.
    print(f"refused: {exc.code} {exc.detail}", file=sys.stderr)
    raise SystemExit(1)

if outcome.issued:
    print(f"issued {outcome.cid}")
    if outcome.replayed:
        print("  (this was a replay of an earlier identical request — nothing new happened)")

elif outcome.awaiting_approval:
    # The normal path for anything a policy bar routes to a human.
    print(f"awaiting approval: {outcome.request_id}")
    print("  approve it with an approver's own key, never the service's:")
    print(f"  connect approve {outcome.request_id} --by human:cecil \\")
    print("      --approver-key ~/.keys/cecil.pem --issuer-key ... --kid ...")

else:
    # Denied. The trace says which rule fired, which is the difference between "fix the
    # request" and "read every policy file".
    print(f"denied: {outcome.reason}")
    for step in outcome.trace:
        print(f"  · {step}")
    raise SystemExit(3)
