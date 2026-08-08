"""A client for the warden-connect control-plane API (production-readiness P2 #17).

    from warden_connect import Connect

    cp = Connect("https://connect.internal", token=os.environ["WC_TOKEN"])
    outcome = cp.request_connection(
        from_="spiffe://org/ns/agents/sa/recon",
        to="spiffe://org/ns/tools/sa/payments",
        tools=["get_balance"],
        justification="nightly reconciliation",
        requester="human:vijay",
        ttl_secs=30 * 86_400,
    )
    if outcome.awaiting_approval:
        print("a human has to approve", outcome.request_id)

# Why this exists, and why only for the control plane

P2 #17 put it precisely: for the *mediator* an SDK matters least, because it compiles into
the proxy by design (§8.3) — you do not call it, you deploy it. For the **control-plane API**
it matters most, because that is the surface a platform team integrates against: a portal
that raises connection requests, a CI job that registers a new service, a SOC runbook that
quarantines a party.

So there is one client, for one surface, and no attempt at an SDK for the data plane.

# Only the standard library

`urllib`, not `requests`. §8.3's dependency argument is about what a *build* of this
component pulls in and a Python client is not that — but a platform team's first question
about a new SDK is what it drags into their image, and "nothing" is the answer that gets it
approved. The cost is about forty lines of plumbing, which is cheaper than the conversation.

# What this client refuses to hide

Three things it would be easy to paper over and which you would then get wrong in
production:

* **Every mutating call needs an idempotency key.** Generated for you if you do not supply
  one, and *reused verbatim on retry*, because that is the entire point — a retry with a
  fresh key is a second request, and for `POST /v1/connections` that means a second
  contract. A replay comes back as **200** rather than the original status, so `Outcome`
  reads what happened out of the *body*; `Outcome.replayed` tells you it was a replay.
* **A connection request has three outcomes, not two.** Issued, awaiting approval, or
  denied. A client that returned a contract or raised an exception would make "a human must
  look at this" indistinguishable from a failure, and that is the normal path for anything
  crossing a trust boundary.
* **`WC-*` codes survive.** `ConnectError.code` is the code the control plane returned, not
  a re-interpretation. It is what an operator greps for and what the alert rules in
  `docs/observability.md` group by.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "Connect",
    "ConnectError",
    "Outcome",
    "ROLES",
    "__version__",
]

__version__ = "0.1.0"

#: The roles a token can hold, as `api::roles` defines them. Listed so a caller can check
#: their own configuration rather than discovering a missing role from a 403 at 03:00.
ROLES = {
    "read": "connect.read",
    "register": "connect.register",
    "request": "connect.request",
    "approve": "connect.approve",
    "secops": "connect.secops",
    "mediator": "connect.mediator",
    "compliance": "connect.compliance",
}


class ConnectError(Exception):
    """A control-plane refusal, carrying the `WC-*` code it refused with.

    The code is the useful part and is deliberately not translated into an exception
    hierarchy: `WC-3109` (posture not attested) and `WC-4001` (no contract) are both
    "refused", and a caller that wants to tell them apart wants the code, not a class name
    that this SDK invented.
    """

    def __init__(self, status: int, code: str | None, detail: str, body: Any = None):
        self.status = status
        self.code = code
        self.detail = detail
        self.body = body
        shown = f"{code} " if code else ""
        super().__init__(f"HTTP {status}: {shown}{detail}")


@dataclass
class Outcome:
    """What a connection request came to.

    Exactly one of the three is true. Modelled as data rather than as a return-or-raise so
    that "a human must approve this" is a normal result — it is the expected path for any
    connection crossing a trust boundary, and an SDK that raised on it would push every
    caller into using exceptions for control flow.
    """

    status: int
    body: dict = field(default_factory=dict)

    @property
    def replayed(self) -> bool:
        """True when the control plane replayed a cached response for this idempotency key.

        A replay returns **200**, not the status the original call returned. That is correct
        — nothing happened on this call — and it is the trap this class exists to absorb.
        """
        return self.status == 200

    @property
    def issued(self) -> bool:
        """A contract was minted."""
        return self._outcome() == "issued"

    @property
    def awaiting_approval(self) -> bool:
        """A human has to approve it. Not an error."""
        return self._outcome() == "awaiting_approval"

    @property
    def denied(self) -> bool:
        """Policy refused it outright."""
        return self._outcome() == "denied"

    def _outcome(self) -> str:
        """What happened, from the **body** first and the status only as a fallback.

        Read from the body because a replay changes the status and not the meaning. The first
        version of this class keyed all three properties off the status alone, so a caller
        who retried a timed-out request got `200`, saw `issued`, `awaiting_approval` and
        `denied` all false — three impossible answers at once, per this class's own
        docstring — and would reasonably conclude nothing had happened. In fact the request
        had been accepted and a human was already looking at it.
        """
        stated = self.body.get("outcome")
        if stated in ("issued", "awaiting_approval", "denied"):
            return stated
        # A 201 carries the minted contract and no `outcome` field.
        if self.status == 201 or self.body.get("cid"):
            return "issued"
        if self.status == 202:
            return "awaiting_approval"
        if self.status == 403:
            return "denied"
        return "unknown"

    @property
    def cid(self) -> str | None:
        """The connection id, once there is one."""
        return self.body.get("cid") or self.body.get("record", {}).get("cid")

    @property
    def request_id(self) -> str | None:
        """The pending request's id, when a human has to look at it."""
        return self.body.get("request", {}).get("id")

    @property
    def reason(self) -> str | None:
        """Why it was denied."""
        return self.body.get("reason")

    @property
    def trace(self) -> list:
        """The policy decisions behind a denial, in order.

        Surfaced because "denied" without the trace sends an operator to read policy files;
        with it they can see which rule fired.
        """
        return self.body.get("trace") or []


class Connect:
    """A control-plane client.

    One connection per call, no pooling: this API is used at human and CI rates — a
    registration, an approval, a quarantine — not in a hot loop, and a pool would be
    complexity bought for a load that does not exist.
    """

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        *,
        timeout: float = 30.0,
        tenant: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        # An explicit token wins; otherwise the environment, which is how a CI job supplies
        # one. Never a file path: a token read from disk by a client library is a credential
        # whose lifetime nobody is tracking.
        self.token = token or os.environ.get("WARDEN_CONNECT_TOKEN")
        self.timeout = timeout
        self.tenant = tenant

    # -- reads ---------------------------------------------------------------

    def entities(self) -> list:
        """Every registered party. Needs `connect.read`."""
        return self._get("/v1/entities").get("entities", [])

    def entity(self, entity_id: str) -> dict:
        """One party, by id."""
        return self._get(f"/v1/entities/{urllib.parse.quote(entity_id, safe='')}")

    def posture(self, *, unattested: bool = False, expiring: bool = False) -> dict:
        """The estate's posture. `unattested` and `expiring` are the two an operator asks
        for by name."""
        query = {}
        if unattested:
            query["unattested"] = "true"
        if expiring:
            query["expiring"] = "true"
        return self._get("/v1/posture", query)

    def connections(self) -> list:
        """Live contracts."""
        return self._get("/v1/connections").get("connections", [])

    def connection(self, cid: str) -> dict:
        """One contract, by connection id."""
        return self._get(f"/v1/connections/{urllib.parse.quote(cid, safe='')}")

    def requests(self, *, all_: bool = False) -> list:
        """Connection requests. Pending by default; `all_` includes settled ones."""
        return self._get("/v1/requests", {"all": "true"} if all_ else None).get(
            "requests", []
        )

    def mediators(self) -> dict:
        """Mediator acknowledgement state.

        Worth alerting on rather than polling by hand: an unconfirmed mediator past its
        deadline means a containment order has not landed, and **unconfirmed is not
        contained**. See `docs/observability.md`.
        """
        return self._get("/v1/mediators")

    def jwks(self) -> dict:
        """The issuer's public key set. Unauthenticated by design — it is public."""
        return self._get("/v1/jwks.json", auth=False)

    def healthy(self) -> bool:
        """Liveness. Unauthenticated, so a probe needs no credential."""
        try:
            return self._get("/healthz", auth=False).get("status") == "ok"
        except ConnectError:
            return False

    def ready(self) -> bool:
        """Readiness — about being able to *decide*, not about being up.

        A control plane that has booted with an unloadable policy is healthy and not ready,
        and those are different questions.
        """
        try:
            self._get("/readyz", auth=False)
            return True
        except ConnectError:
            return False

    # -- writes --------------------------------------------------------------

    def request_connection(
        self,
        *,
        from_: str,
        to: str,
        tools: list | None = None,
        justification: str,
        requester: str,
        ttl_secs: int | None = None,
        skills: list | None = None,
        resources: list | None = None,
        data_classes: list | None = None,
        jurisdictions: list | None = None,
        mediators: list | None = None,
        idempotency_key: str | None = None,
    ) -> Outcome:
        """Ask for a connection. Needs `connect.request`.

        `justification` and `requester` are required by the API, not by this client: a
        connection with no accountable human and no stated reason is what the whole
        approval trail exists to prevent.

        **`mediators` is effectively required too.** Omit it and the control plane refuses
        with `WC-3012` — *a contract must name at least one mediator; there is nowhere to
        enforce it*. That is not a validation quirk: a contract addressed to no mediator is
        a permission with no enforcement point, and its `aud` is what stops it being
        replayed at a different one. Left as an optional argument because a deployment may
        set a default, and defaulting it here would invent an audience.

        Returns an `Outcome` — issued, awaiting approval, or denied. A transport failure or
        a refusal that is *not* one of those three (a malformed request, a missing mediator)
        raises `ConnectError` carrying the `WC-*` code.
        """
        body = {
            "from": from_,
            "to": to,
            "tools": tools or [],
            "justification": justification,
            "requester": requester,
        }
        for key, value in [
            ("ttl_secs", ttl_secs),
            ("skills", skills),
            ("resources", resources),
            ("data_classes", data_classes),
            ("jurisdictions", jurisdictions),
            ("mediators", mediators),
        ]:
            if value is not None:
                body[key] = value

        status, payload = self._post(
            "/v1/connections", body, idempotency_key, allow=(201, 202, 403)
        )
        return Outcome(status=status, body=payload)

    def approve(
        self,
        request_id: str,
        *,
        by: str,
        ticket: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """Approve a pending request. Needs `connect.approve`.

        This client cannot produce the approver's **signature** — that is a private key it
        must never hold. The API's approval route records the decision; an approval proof
        signed by an approver's key is minted by `connect approve` with
        `--approver-key`/`--approver-signer`, on the approver's own machine or against their
        token. See `docs/key-custody.md`: an approver key that the service could reach makes
        dual control theatre.
        """
        body: dict = {"by": by}
        if ticket:
            body["ticket"] = ticket
        _, payload = self._post(
            f"/v1/requests/{urllib.parse.quote(request_id, safe='')}/approve",
            body,
            idempotency_key,
        )
        return payload

    def deny(
        self,
        request_id: str,
        *,
        reason: str,
        by: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """Refuse a pending request. Needs `connect.approve`."""
        body: dict = {"reason": reason}
        if by:
            body["by"] = by
        _, payload = self._post(
            f"/v1/requests/{urllib.parse.quote(request_id, safe='')}/deny",
            body,
            idempotency_key,
        )
        return payload

    def activate(
        self, entity_id: str, *, why: str | None = None, idempotency_key: str | None = None
    ) -> dict:
        """Admit a registered party. Needs `connect.register`."""
        body = {"why": why} if why else {}
        _, payload = self._post(
            f"/v1/entities/{urllib.parse.quote(entity_id, safe='')}/activate",
            body,
            idempotency_key,
        )
        return payload

    def quarantine(
        self,
        entity_id: str,
        *,
        reason: str,
        approvers: list | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """Contain a party. Needs `connect.secops`.

        The response reports which mediators have **confirmed**. Read it: the registry
        transition is this control plane's own state, and the party keeps working until
        every mediator holding one of its contracts stops honouring it. Unconfirmed is not
        contained.
        """
        # `party`, not `id`. Found by running examples/03 against a live control plane:
        # the API answered `WC-4008 "party" is required and must be a string`, and a client
        # that sent the wrong field name would have failed every quarantine an operator
        # attempted through it — at exactly the moment that matters least for discovering it.
        body: dict = {"party": entity_id, "reason": reason}
        if approvers:
            body["approvers"] = approvers
        _, payload = self._post("/v1/quarantine", body, idempotency_key)
        return payload

    # -- plumbing ------------------------------------------------------------

    def _headers(self, auth: bool = True) -> dict:
        headers = {"accept": "application/json"}
        if auth:
            if not self.token:
                raise ConnectError(
                    0,
                    None,
                    "no token: pass token= or set WARDEN_CONNECT_TOKEN. Every route except "
                    "/healthz, /readyz, /metrics and /v1/jwks.json needs one",
                )
            headers["authorization"] = f"Bearer {self.token}"
        if self.tenant:
            headers["x-warden-tenant"] = self.tenant
        return headers

    def _get(self, path: str, query: dict | None = None, auth: bool = True) -> dict:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        request = urllib.request.Request(url, headers=self._headers(auth), method="GET")
        status, payload = self._send(request)
        if status >= 400:
            raise self._error(status, payload)
        return payload if isinstance(payload, dict) else {"body": payload}

    def _post(
        self,
        path: str,
        body: dict,
        idempotency_key: str | None,
        allow: tuple = (200, 201, 202),
    ) -> tuple:
        headers = self._headers()
        headers["content-type"] = "application/json"
        # Generated if absent. Passing the *same* key on a retry is what makes a retry safe:
        # the control plane replays the original response rather than acting twice, and for
        # `POST /v1/connections` acting twice means a second contract. A caller retrying a
        # timeout must reuse the key, which is why it is returned to them via the argument
        # rather than hidden.
        headers["idempotency-key"] = idempotency_key or str(uuid.uuid4())

        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(body).encode(),
            headers=headers,
            method="POST",
        )
        status, payload = self._send(request)
        if status not in allow and status >= 400:
            raise self._error(status, payload)
        return status, payload if isinstance(payload, dict) else {"body": payload}

    def _send(self, request: urllib.request.Request) -> tuple:
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, _decode(response.read())
        except urllib.error.HTTPError as exc:
            # A refusal is a result, not a transport failure, so the body is read and the
            # status returned. Losing the body here would lose the WC-* code.
            return exc.code, _decode(exc.read())
        except urllib.error.URLError as exc:
            raise ConnectError(0, None, f"{self.base_url} unreachable: {exc.reason}") from exc

    @staticmethod
    def _error(status: int, payload: Any) -> ConnectError:
        if isinstance(payload, dict):
            code = payload.get("code")
            detail = payload.get("detail") or payload.get("error") or json.dumps(payload)
        else:
            code, detail = None, str(payload)
        return ConnectError(status, code, detail, payload)


def _decode(raw: bytes) -> Any:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # `/metrics` is Prometheus text. Returning it rather than raising means a caller can
        # scrape through this client without a second HTTP path.
        return raw.decode("utf-8", "replace")
