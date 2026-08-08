#!/usr/bin/env python3
"""Report what an operator would actually want to know before a change window.

    WARDEN_CONNECT_TOKEN=... python3 examples/02_estate_posture.py

Three questions, in the order they matter:

  1 · is any containment order unconfirmed?  Unconfirmed is not contained.
  2 · what expires soon?                     An expiry nobody renewed is an outage.
  3 · what is unattested?                    In enforce mode those cannot connect.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from warden_connect import Connect, ConnectError  # noqa: E402

cp = Connect(os.environ.get("WARDEN_CONNECT_URL", "http://127.0.0.1:8787"))

if not cp.ready():
    # Readiness is about being able to *decide*, not about being up. A control plane that
    # booted with an unloadable policy is healthy and not ready.
    print("control plane is not ready — it cannot decide", file=sys.stderr)
    raise SystemExit(2)

try:
    mediators = cp.mediators()
    unconfirmed = mediators.get("unconfirmed") or []
    if unconfirmed:
        # Loudest first, deliberately. This is the one state where every dashboard says a
        # party was cut off and the party is still working.
        print(f"!! {len(unconfirmed)} mediator(s) have NOT confirmed a containment order")
        for m in unconfirmed:
            print(f"   {m}")
    else:
        print("containment: every order confirmed")

    posture = cp.posture()

    def count(key):
        """`/v1/posture` returns the *ids* under each heading, not a tally.

        That is the more useful shape — an operator wants to know *which* party is
        unattested — but printing a list where a number belongs produces a line nobody can
        read, so the summary counts and the detail follows.
        """
        value = posture.get(key)
        return len(value) if isinstance(value, list) else (value or 0)

    print(
        f"entities: {count('total')} total · "
        f"{count('unattested')} unattested · "
        f"{count('degraded')} degraded · "
        f"{count('quarantined')} quarantined"
    )
    for heading in ("unattested", "quarantined", "reattest_overdue"):
        ids = posture.get(heading)
        if isinstance(ids, list) and ids:
            print(f"  {heading}:")
            for entity_id in ids[:10]:
                print(f"    {entity_id}")
            if len(ids) > 10:
                print(f"    … and {len(ids) - 10} more")

    live = cp.connections()
    print(f"contracts: {len(live)} live")

except ConnectError as exc:
    print(f"{exc.code or exc.status}: {exc.detail}", file=sys.stderr)
    raise SystemExit(1)
