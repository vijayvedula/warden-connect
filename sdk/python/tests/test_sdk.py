"""The SDK's own tests, needing no control plane.

    cd sdk/python && python3 -m pytest -q

Before this existed the SDK's verification was "the examples run against a live control
plane", which `docs/limitations.md` recorded as a gap. That is an integration test, it needs
a running estate, keys and an approver registry, and it therefore never ran in CI — so the
client's logic was unverified in exactly the place a client's logic is subtle: what a status
code means, whether a retry is safe, and whether a refusal keeps its `WC-*` code.

Everything here stubs `Connect._send`, so these are tests of *this library's decisions*.
Whether the control plane agrees is the examples' job and the Rust suite's, and neither is
replaced by this.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from warden_connect import ROLES, Connect, ConnectError, Outcome  # noqa: E402


# ---------------------------------------------------------------------------
# A stub transport
# ---------------------------------------------------------------------------


class Recorder:
    """Captures the request the client would have sent, and replies with a canned tuple."""

    def __init__(self, reply=(200, {})):
        self.reply = reply
        self.sent = []

    def __call__(self, request):
        self.sent.append(request)
        return self.reply

    @property
    def last(self):
        return self.sent[-1]

    def header(self, name: str) -> str | None:
        # urllib lower-cases and title-cases header names on the way in, so ask it rather
        # than the dict — otherwise the test asserts against a spelling the wire never sees.
        return self.last.get_header(name.capitalize())

    def body(self) -> dict:
        return json.loads(self.last.data.decode())


def client(recorder: Recorder, **kwargs) -> Connect:
    c = Connect("https://cp.example", token="t0k", **kwargs)
    c._send = recorder  # noqa: SLF001 — the seam these tests exist to use
    return c


# ---------------------------------------------------------------------------
# Outcome — the class a real defect lived in
# ---------------------------------------------------------------------------


def test_a_replayed_request_still_reports_what_happened():
    """The defect this class was rewritten for, pinned.

    A caller retries a timed-out request with the same idempotency key. The control plane
    replays the original response and returns **200**, not the 202 the first call returned.
    Keying the three properties off the status alone made `issued`, `awaiting_approval` and
    `denied` all false at once — three impossible answers — and a caller would reasonably
    conclude nothing had happened when in fact a human was already reviewing it.
    """
    replayed = Outcome(status=200, body={"outcome": "awaiting_approval",
                                        "request": {"id": "req_abc"}})
    assert replayed.replayed
    assert replayed.awaiting_approval
    assert not replayed.issued
    assert not replayed.denied
    assert replayed.request_id == "req_abc"
    # The property that makes the bug impossible rather than merely fixed: exactly one of
    # the three is true, on every shape below.
    for outcome in [
        Outcome(status=200, body={"outcome": "issued", "cid": "conn_1"}),
        Outcome(status=200, body={"outcome": "denied", "reason": "no"}),
        Outcome(status=201, body={"cid": "conn_2"}),
        Outcome(status=202, body={"request": {"id": "req_1"}}),
        Outcome(status=403, body={"reason": "zone bar"}),
    ]:
        flags = [outcome.issued, outcome.awaiting_approval, outcome.denied]
        assert sum(flags) == 1, f"{outcome.status} {outcome.body} -> {flags}"


def test_the_body_wins_over_the_status():
    """A 200 that says `denied` is denied. The status is the fallback, not the source."""
    assert Outcome(status=200, body={"outcome": "denied"}).denied
    assert not Outcome(status=200, body={"outcome": "denied"}).issued


def test_an_unrecognised_shape_claims_nothing():
    """Three falses are correct *here* — the client genuinely does not know. What must not
    happen is guessing `issued`."""
    unknown = Outcome(status=204, body={})
    assert not (unknown.issued or unknown.awaiting_approval or unknown.denied)


def test_accessors_do_not_raise_on_a_sparse_body():
    """Every accessor is reached from an error path, where the body is whatever arrived."""
    empty = Outcome(status=500, body={})
    assert empty.cid is None
    assert empty.request_id is None
    assert empty.reason is None
    assert empty.trace == []
    # A cid nested under `record`, which is the mint response's shape.
    assert Outcome(status=201, body={"record": {"cid": "conn_9"}}).cid == "conn_9"


# ---------------------------------------------------------------------------
# Idempotency — the thing that makes a retry safe
# ---------------------------------------------------------------------------


def test_a_key_is_generated_when_the_caller_gives_none():
    r = Recorder((202, {"outcome": "awaiting_approval"}))
    c = client(r)
    c.request_connection(from_="a", to="b", tools=["t"], justification="j", requester="human:p")
    key = r.header("idempotency-key")
    assert key, "a mutating call with no key would not be safe to retry"
    assert len(key) >= 16


def test_the_callers_key_is_used_verbatim_so_a_retry_replays():
    """The whole point: the *same* key on a retry is what makes the control plane replay
    instead of minting a second contract. If the client silently generated its own, a
    caller's retry would act twice."""
    r = Recorder((202, {"outcome": "awaiting_approval"}))
    c = client(r)
    for _ in range(2):
        c.request_connection(
            from_="a", to="b", tools=["t"], justification="j",
            requester="human:p", idempotency_key="mine-1",
        )
    assert [x.get_header("Idempotency-key") for x in r.sent] == ["mine-1", "mine-1"]


def test_generated_keys_differ_between_distinct_calls():
    """Two separate requests must not collide, or the second would replay the first's
    response and the caller would believe a connection existed that does not."""
    r = Recorder((202, {"outcome": "awaiting_approval"}))
    c = client(r)
    for _ in range(2):
        c.request_connection(from_="a", to="b", tools=["t"], justification="j",
                             requester="human:p")
    keys = [x.get_header("Idempotency-key") for x in r.sent]
    assert keys[0] != keys[1]


def test_a_get_carries_no_idempotency_key():
    r = Recorder((200, {"entities": []}))
    client(r).entities()
    assert r.last.get_method() == "GET"
    assert r.header("idempotency-key") is None


# ---------------------------------------------------------------------------
# Requests: method, path, and what lands in the body
# ---------------------------------------------------------------------------


def test_the_request_body_carries_the_accountability_fields():
    """`justification` and `requester` are required by the API. A client that dropped
    them would turn a clear server-side refusal into a confusing one."""
    r = Recorder((202, {"outcome": "awaiting_approval"}))
    client(r).request_connection(
        from_="spiffe://o/a", to="spiffe://o/b", tools=["get_balance"],
        justification="nightly recon", requester="human:priya@org", ttl_secs=604800,
    )
    body = r.body()
    assert body["justification"] == "nightly recon"
    assert body["requester"] == "human:priya@org"
    assert body["ttl_secs"] == 604800
    assert r.last.full_url == "https://cp.example/v1/connections"


def test_an_entity_id_is_escaped_into_the_path():
    """A SPIFFE id has slashes. Interpolating it raw would address a different route."""
    r = Recorder((200, {}))
    client(r).entity("spiffe://org/ns/agents/sa/recon")
    assert "spiffe%3A%2F%2Forg%2Fns%2Fagents%2Fsa%2Frecon" in r.last.full_url
    assert "/v1/entities/spiffe://" not in r.last.full_url


def test_query_flags_are_only_sent_when_asked_for():
    r = Recorder((200, {}))
    c = client(r)
    c.posture()
    assert "?" not in r.last.full_url
    c.posture(unattested=True)
    assert "unattested=true" in r.last.full_url


# ---------------------------------------------------------------------------
# Errors — a refusal must keep its WC-* code
# ---------------------------------------------------------------------------


def test_a_refusal_keeps_its_wc_code_and_detail():
    """The code is the machine-readable half. A client that surfaced only the HTTP status
    would send an operator to read logs for something the response already said."""
    r = Recorder((403, {"code": "WC-3011", "detail": "default deny", "trace": ["zone-bar"]}))
    with pytest.raises(ConnectError) as raised:
        client(r).entities()
    err = raised.value
    assert err.status == 403
    assert err.code == "WC-3011"
    assert "default deny" in err.detail
    assert err.body["trace"] == ["zone-bar"]


def test_an_error_body_that_is_not_json_still_raises_usefully():
    r = Recorder((502, {"body": "<html>gateway</html>"}))
    with pytest.raises(ConnectError) as raised:
        client(r).entities()
    assert raised.value.status == 502


def test_a_missing_token_names_the_two_ways_to_supply_one(monkeypatch):
    monkeypatch.delenv("WARDEN_CONNECT_TOKEN", raising=False)
    c = Connect("https://cp.example")
    with pytest.raises(ConnectError) as raised:
        c.entities()
    detail = raised.value.detail
    assert "WARDEN_CONNECT_TOKEN" in detail and "token=" in detail


def test_an_unauthenticated_route_works_without_a_token(monkeypatch):
    """`/healthz`, `/readyz` and `/v1/jwks.json` are public, so a probe needs no
    credential. If these demanded a token, a Kubernetes liveness probe would need one."""
    monkeypatch.delenv("WARDEN_CONNECT_TOKEN", raising=False)
    r = Recorder((200, {"status": "ok"}))
    c = Connect("https://cp.example")
    c._send = r  # noqa: SLF001
    assert c.healthy() is True
    assert r.header("authorization") is None


def test_healthy_is_false_rather_than_an_exception_when_the_plane_is_down():
    """A probe helper that raised would make every caller wrap it in try/except."""
    def unreachable(_request):
        raise ConnectError(0, None, "unreachable")

    c = Connect("https://cp.example", token="t")
    c._send = unreachable  # noqa: SLF001
    assert c.healthy() is False
    assert c.ready() is False


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------


def test_an_explicit_token_beats_the_environment(monkeypatch):
    monkeypatch.setenv("WARDEN_CONNECT_TOKEN", "from-env")
    assert Connect("https://c", token="explicit").token == "explicit"
    assert Connect("https://c").token == "from-env"


def test_the_tenant_header_is_sent_only_when_set():
    r = Recorder((200, {}))
    client(r).entities()
    assert r.header("x-warden-tenant") is None
    r2 = Recorder((200, {}))
    client(r2, tenant="apac").entities()
    assert r2.header("x-warden-tenant") == "apac"


def test_a_trailing_slash_on_the_base_url_does_not_double_up():
    r = Recorder((200, {}))
    c = Connect("https://cp.example/", token="t")
    c._send = r  # noqa: SLF001
    c.entities()
    assert r.last.full_url == "https://cp.example/v1/entities"


# ---------------------------------------------------------------------------
# The role names, against the server that enforces them
# ---------------------------------------------------------------------------


def test_the_sdk_role_names_match_the_ones_the_server_enforces():
    """A client shipping a role string the API does not know produces a 403 that reads
    like a permissions problem and is a typo. Checked against the Rust constants rather
    than against a second copy of the list, because two copies is how they drift.

    Skipped outside a checkout — the packaged wheel has no Rust source beside it.
    """
    api = pathlib.Path(__file__).resolve().parents[3] / "crates/wc-control/src/api.rs"
    if not api.is_file():
        pytest.skip("not running from a checkout")
    source = api.read_text()
    for role in ROLES.values():
        assert f'"{role}"' in source, f"the API knows no role {role!r}"
