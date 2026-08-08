#!/usr/bin/env python3
"""Contain a party, and read the answer honestly.

    WARDEN_CONNECT_TOKEN=... python3 examples/03_contain_a_party.py urn:wc:...

Needs `connect.secops`. The important part is the last block: the registry transition is
the control plane's own state, and the party keeps working until every mediator holding one
of its contracts stops honouring it. **Unconfirmed is not contained.**
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from warden_connect import Connect, ConnectError  # noqa: E402

if len(sys.argv) < 2:
    raise SystemExit("usage: 03_contain_a_party.py <entity-id> [reason]")

target = sys.argv[1]
reason = sys.argv[2] if len(sys.argv) > 2 else "suspected credential compromise"

cp = Connect(os.environ.get("WARDEN_CONNECT_URL", "http://127.0.0.1:8787"))

try:
    result = cp.quarantine(target, reason=reason)
except ConnectError as exc:
    print(f"quarantine refused: {exc.code} {exc.detail}", file=sys.stderr)
    raise SystemExit(1)

print(f"quarantined {target}")
print(f"  contracts revoked : {len(result.get('revoked', []))}")
print(f"  services impacted : {result.get('impacted_services') or 'none recorded'}")

# The quarantine response is the control plane's own state: which contracts it revoked and
# which services that touched. It does **not** say whether any mediator heard, because at
# the moment it answers, none of them have — the fan-out is asynchronous and acknowledgement
# arrives afterwards. So the honest script asks separately.
mediators = cp.mediators()
unconfirmed = mediators.get("unconfirmed") or []
known = mediators.get("mediators") or []

if not known:
    # A control plane with no mediators records the quarantine and reaches nothing. This is
    # the control-plane-only topology and it is a supported deployment — but it is not
    # containment, and a script that printed "quarantined" and stopped would imply it was.
    print("  NOTHING ENFORCES THIS: no mediators are configured")
    raise SystemExit(4)

if unconfirmed:
    print(f"  STILL UNCONFIRMED : {len(unconfirmed)} — the party may still be reachable")
    for m in unconfirmed:
        print(f"    {m}")
    print("  poll again, or chase with `connect mediators`; unconfirmed is not contained")
    raise SystemExit(4)

print(f"  every one of {len(known)} mediator(s) confirmed — the party is contained")
