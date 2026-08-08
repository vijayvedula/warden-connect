# warden-connect-sdk

A client for the **warden-connect control-plane API**: register parties, request and approve
connections, read estate posture, contain a party.

```sh
pip install -e sdk/python          # from a checkout
```

```python
from warden_connect import Connect

cp = Connect("https://connect.internal")        # token from WARDEN_CONNECT_TOKEN
outcome = cp.request_connection(
    from_="spiffe://org/ns/agents/sa/recon",
    to="spiffe://org/ns/tools/sa/payments",
    tools=["get_balance"],
    justification="nightly reconciliation, ticket OPS-4182",
    requester="human:vijay",
    mediators=["warden:mediator:apac-ops"],
)

if outcome.awaiting_approval:
    print("a human has to approve", outcome.request_id)
```

Runnable examples: [`examples/`](../../examples).

## Why only the control plane

For the **mediator** an SDK matters least: it compiles into the proxy by design (§8.3), so
you deploy it rather than call it. For the **control-plane API** it matters most — that is
the surface a platform team integrates against: a portal raising connection requests, a CI
job registering a new service, a SOC runbook containing a party.

## No dependencies

`urllib`, not `requests`. A platform team's first question about a new SDK is what it drags
into their image, and *nothing* is the answer that gets it approved.

## Three things this client will not hide from you

**A connection request has three outcomes.** Issued, awaiting approval, denied — modelled as
data, not as return-or-raise. Anything crossing a trust boundary is *supposed* to reach a
human, so treating that as an error would make the normal path look like a failure.

**A replay is a 200.** Every mutating call carries an idempotency key; reuse the same key on
a retry or you make a second request, which for `POST /v1/connections` means a second
contract. The control plane replays the cached response with status **200** rather than the
original 201/202, so `Outcome` reads what happened out of the *body* and `Outcome.replayed`
tells you it was a replay. The first version of this client keyed off the status alone, and a
caller retrying a timeout would have seen `issued`, `awaiting_approval` and `denied` all
false — and concluded nothing had happened while a human was already looking at the request.

**`WC-*` codes survive.** `ConnectError.code` is the code the control plane returned, not a
re-interpretation into an exception hierarchy this SDK invented. It is what an operator greps
for and what the alert rules in [observability.md](../../docs/observability.md) group by.

## What it cannot do, on purpose

**Sign an approval.** `approve()` records a decision; it cannot mint the approver's
signature, because that needs a private key this client must never hold. Approval proofs are
minted by `connect approve --approver-key` / `--approver-signer`, on the approver's own
machine or against their token. See [key-custody.md](../../docs/key-custody.md): an approver
key the service could reach makes dual control theatre, and afterwards the evidence chain
cannot tell the difference.

**Mint or verify a contract.** Verification is the conformance kit's territory — see
[conformance.md](../../docs/conformance.md) — and a Python verifier here would be a second
implementation of the eleven checks with no vectors run against it.

## Roles

Every route except `/healthz`, `/readyz`, `/metrics` and `/v1/jwks.json` needs a bearer
token, and each needs a role:

| Method | Role |
|---|---|
| `entities`, `entity`, `posture`, `connections`, `requests`, `mediators` | `connect.read` |
| `activate` | `connect.register` |
| `request_connection` | `connect.request` |
| `approve`, `deny` | `connect.approve` |
| `quarantine` | `connect.secops` |

`warden_connect.ROLES` has the names, so a caller can check its own configuration rather
than discovering a missing role from a 403 during an incident.

## Licence

[FSL-1.1-ALv2](LICENSE), converting to [Apache 2.0](LICENSE-APACHE) two years after each
release — the same terms as the rest of the repository.
