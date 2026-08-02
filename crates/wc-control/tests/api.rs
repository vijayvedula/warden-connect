//! The HTTP surface, driven over a real socket.
//!
//! Handler-level tests would miss the things that actually break an API: routing,
//! header case, percent-encoded ids in a path, status codes, and whether an
//! idempotency replay really replays. So these bind a port and speak HTTP.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

use wc_control::api::{roles, Api, ControlPlane};
use wc_control::cpolicy::ConnectPolicy;
use wc_control::evidence::Evidence;
use wc_control::http::{self, Shutdown};
use wc_control::issuance::{self, ApproverRegistry};
use wc_control::registry::Registry;
use wc_control::store::{Actor, RepinCause, Store};
use wc_core::contract::{Algorithm, IssuerKey};
use wc_core::error::Mode;
use wc_core::model::{
    Entity, EntityId, HumanRef, Kind, Lifecycle, Pin, Posture, Tier, ZoneId, PIN_ALG,
};

const ISSUER_PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");
const APPROVER_PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_anchor_priv.pem");
const APPROVER_PUB: &[u8] = include_bytes!("../../../fixtures/keys/test_anchor_pub.pem");

const NOW: u64 = 1_785_312_500;
const MEDIATOR: &str = "warden:mediator:apac-ops";

const ADMIN: &str = "tok-admin";
const READER: &str = "tok-reader";
const MEDIATOR_TOKEN: &str = "tok-mediator";

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn now() -> u64 {
    NOW
}

struct TmpDir(std::path::PathBuf);
impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("wc-api-{}-{tag}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        TmpDir(p)
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// A tiny HTTP client, so the tests exercise the wire
// ---------------------------------------------------------------------------

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn call(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    idempotency: Option<&str>,
    body: Option<Value>,
) -> Reply {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let payload = body.map(|b| b.to_string()).unwrap_or_default();

    let mut head = format!("{method} {path} HTTP/1.1\r\nhost: localhost\r\n");
    if let Some(token) = token {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(key) = idempotency {
        head.push_str(&format!("Idempotency-Key: {key}\r\n"));
    }
    head.push_str(&format!("content-length: {}\r\n\r\n", payload.len()));

    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(payload.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();

    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    Reply {
        status,
        headers,
        body: body.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

fn priya() -> HumanRef {
    HumanRef::new("human:priya@org").unwrap()
}
fn cecil() -> HumanRef {
    HumanRef::new("human:cecil@org").unwrap()
}
fn agent_id() -> EntityId {
    EntityId::new("spiffe://org/ns/agents/sa/recon-bot-7").unwrap()
}
fn ledger_id() -> EntityId {
    EntityId::new("spiffe://org/ns/tools/sa/ledger-mcp").unwrap()
}
fn payments_id() -> EntityId {
    EntityId::new("spiffe://org/ns/tools/sa/payments-mcp").unwrap()
}

fn pin(items: &[&str]) -> Pin {
    Pin {
        alg: PIN_ALG.to_string(),
        manifest: "sha256:m1".to_string(),
        items: items
            .iter()
            .map(|n| ((*n).to_string(), format!("sha256:{n}")))
            .collect(),
        pinned_at: NOW - 1_000,
    }
}

fn policy() -> ConnectPolicy {
    ConnectPolicy::parse(&format!(
        r#"
default = "require_approval"
version = "connect-policy@api"

[[zone]]
id = "internal.apac-ops"
trust = "internal"
[[zone]]
id = "internal.ledger"
trust = "internal"
[[zone]]
id = "internal.payments"
trust = "internal"

[standing]
reviewed_at = {}
review_every = "90d"

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
callee_tier = {{ op = "gt", value = 2 }}
surface = {{ write = false }}
decision = "allow"
ttl_max = "30d"

[[rules]]
callee_tier = {{ op = "lt", value = 3 }}
decision = "require_approval"
approver_role = "security.architect"
reason = "a sensitive callee needs a security architect"
"#,
        NOW - 86_400
    ))
    .unwrap()
}

/// A running control plane, with two servers and an agent already active.
struct Harness {
    port: u16,
    shutdown: Arc<Shutdown>,
    _tmp: TmpDir,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.request();
        // Unblock the accept loop so the thread can observe the shutdown flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn harness(tag: &str) -> Harness {
    let tmp = TmpDir::new(tag);
    let (mut store, _) = Store::open(tmp.0.join("state")).unwrap();
    let actor = Actor::Human { id: priya() };

    for (id, kind, zone, tier, items) in [
        (
            agent_id(),
            Kind::Agent,
            "internal.apac-ops",
            Tier::TWO,
            vec![],
        ),
        (
            ledger_id(),
            Kind::McpServer,
            "internal.ledger",
            Tier::THREE,
            vec!["get_balance", "list_transactions"],
        ),
        (
            payments_id(),
            Kind::McpServer,
            "internal.payments",
            Tier::ONE,
            vec!["get_balance", "wire_funds"],
        ),
    ] {
        let mut e = Entity::pending(
            id.clone(),
            kind,
            priya(),
            ZoneId::new(zone).unwrap(),
            tier,
            NOW - 2_000,
        );
        e.service = Some("payments-recon".to_string());
        e.endpoint = Some(format!("https://{}.internal/mcp", id.as_str().len()));
        {
            let mut reg: Registry<'_> = store.registry(actor.clone(), NOW - 2_000);
            reg.put(e).unwrap();
            reg.transition(&id, Lifecycle::Active, "admitted").unwrap();
            reg.set_posture(&id, Posture::Attested, 95).unwrap();
        }
        if !items.is_empty() {
            store
                .registry(actor.clone(), NOW - 1_500)
                .repin(&id, pin(&items), RepinCause::Admission)
                .unwrap();
        }
    }
    store.log.sync().unwrap();

    let evidence = Evidence::open(tmp.0.join("evidence")).unwrap();
    let signer = IssuerKey::ec_pem("wc-test-es256", ISSUER_PRIV, Algorithm::ES256).unwrap();

    let mut approvers = ApproverRegistry::new();
    approvers
        .add_ec(
            &cecil(),
            APPROVER_PUB,
            Algorithm::ES256,
            &["security.architect"],
        )
        .unwrap();

    let cp = ControlPlane::new(
        store,
        evidence,
        policy(),
        signer,
        "https://connect.internal/t/apac",
        now,
    )
    .with_mode(Mode::Observe)
    .with_approvers(approvers)
    .with_jwks(r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"wc-test-es256"}]}"#)
    .with_token(
        ADMIN,
        &[
            roles::READ,
            roles::REGISTER,
            roles::REQUEST,
            roles::APPROVE,
            roles::SECOPS,
            roles::COMPLIANCE,
        ],
    )
    .with_token(READER, &[roles::READ])
    .with_token(MEDIATOR_TOKEN, &[roles::MEDIATOR]);

    let api = Arc::new(Api(Arc::new(cp)));
    let shutdown = Arc::new(Shutdown::default());
    let (tx, rx) = std::sync::mpsc::channel();
    let serve_shutdown = Arc::clone(&shutdown);

    std::thread::spawn(move || {
        let _ = http::serve("127.0.0.1:0", api, serve_shutdown, |addr| {
            let _ = tx.send(addr.port());
        });
    });
    let port = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the server must bind");

    Harness {
        port,
        shutdown,
        _tmp: tmp,
    }
}

// ---------------------------------------------------------------------------
// Unauthenticated surface
// ---------------------------------------------------------------------------

#[test]
fn health_and_readiness_need_no_token() {
    let h = harness("health");
    let health = call(h.port, "GET", "/healthz", None, None, None);
    assert_eq!(health.status, 200);
    assert_eq!(health.json()["status"], "ok");

    // Readiness is about being able to decide, not about being up.
    let ready = call(h.port, "GET", "/readyz", None, None, None);
    assert_eq!(ready.status, 200);
    assert_eq!(ready.json()["policy"], "connect-policy@api");
}

#[test]
fn metrics_are_served_as_prometheus_text() {
    let h = harness("metrics");
    call(h.port, "GET", "/v1/entities", Some(READER), None, None);
    let reply = call(h.port, "GET", "/metrics", None, None, None);
    assert_eq!(reply.status, 200);
    assert!(reply
        .header("content-type")
        .unwrap()
        .starts_with("text/plain"));
    assert!(reply.body.contains("wc_api_requests_total"));
    assert!(reply.body.contains("wc_entities 3"));
}

#[test]
fn the_public_key_set_is_public() {
    let h = harness("jwks");
    let reply = call(h.port, "GET", "/v1/jwks.json", None, None, None);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["keys"][0]["kid"], "wc-test-es256");
}

// ---------------------------------------------------------------------------
// Authentication and authorisation
// ---------------------------------------------------------------------------

#[test]
fn an_unauthenticated_request_never_reaches_a_handler() {
    let h = harness("noauth");
    for (method, path) in [
        ("GET", "/v1/entities"),
        ("GET", "/v1/posture"),
        ("POST", "/v1/connections"),
        ("GET", "/v1/mediators/x/contracts"),
    ] {
        let reply = call(h.port, method, path, None, Some("k1"), Some(json!({})));
        assert_eq!(reply.status, 401, "{method} {path}");
        assert_eq!(reply.json()["code"], "WC-1001");
    }
}

#[test]
fn an_unknown_token_is_refused() {
    let h = harness("badtoken");
    let reply = call(h.port, "GET", "/v1/entities", Some("nope"), None, None);
    assert_eq!(reply.status, 401);
}

#[test]
fn a_role_is_required_per_route() {
    let h = harness("roles");
    // The reader may read...
    assert_eq!(
        call(h.port, "GET", "/v1/entities", Some(READER), None, None).status,
        200
    );
    // ...but not contain a party, nor pull contract sets.
    let quarantine = call(
        h.port,
        "POST",
        "/v1/quarantine",
        Some(READER),
        Some("k1"),
        Some(json!({"party": agent_id().as_str(), "reason": "x"})),
    );
    assert_eq!(quarantine.status, 403);
    assert_eq!(quarantine.json()["code"], "WC-3020");

    assert_eq!(
        call(
            h.port,
            "GET",
            "/v1/mediators/m1/contracts",
            Some(READER),
            None,
            None
        )
        .status,
        403
    );
    // And a mediator token cannot read the estate.
    assert_eq!(
        call(
            h.port,
            "GET",
            "/v1/entities",
            Some(MEDIATOR_TOKEN),
            None,
            None
        )
        .status,
        403
    );
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

#[test]
fn entities_list_and_resolve_by_percent_encoded_id() {
    let h = harness("entities");
    let list = call(h.port, "GET", "/v1/entities", Some(READER), None, None);
    assert_eq!(list.status, 200);
    assert_eq!(list.json()["count"], 3);

    // A SPIFFE id in a path segment has to be percent-encoded by the client and
    // decoded by the server, or every id lookup 404s.
    let encoded = agent_id().as_str().replace(':', "%3A").replace('/', "%2F");
    let one = call(
        h.port,
        "GET",
        &format!("/v1/entities/{encoded}"),
        Some(READER),
        None,
        None,
    );
    assert_eq!(one.status, 200);
    assert_eq!(one.json()["id"], agent_id().as_str());
    assert_eq!(one.json()["tier"], 2);
}

#[test]
fn an_entity_record_never_leaks_the_endpoint() {
    // Reachability is granted by a contract, not by a lookup (§8.5.6).
    let h = harness("noendpoint");
    let list = call(h.port, "GET", "/v1/entities", Some(READER), None, None);
    assert!(!list.body.contains("endpoint"), "{}", list.body);
}

#[test]
fn an_unknown_entity_is_a_404_and_a_malformed_id_is_a_422() {
    let h = harness("missing");
    let encoded = "spiffe%3A%2F%2Forg%2Fns%2Fnope";
    assert_eq!(
        call(
            h.port,
            "GET",
            &format!("/v1/entities/{encoded}"),
            Some(READER),
            None,
            None
        )
        .status,
        404
    );
    // The code table's own HTTP status is used rather than a per-handler guess.
    let bad = call(
        h.port,
        "GET",
        "/v1/entities/not-an-id",
        Some(READER),
        None,
        None,
    );
    assert_eq!(bad.status, 422);
    assert_eq!(bad.json()["code"], "WC-2005");
}

#[test]
fn posture_summarises_the_estate() {
    let h = harness("posture");
    let reply = call(h.port, "GET", "/v1/posture", Some(READER), None, None);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["total"], 3);
    // Everything was attested in the fixture.
    assert_eq!(reply.json()["unattested"].as_array().unwrap().len(), 0);
}

#[test]
fn an_unknown_route_is_a_404_not_a_hang() {
    let h = harness("route");
    let reply = call(h.port, "GET", "/v1/nope", Some(READER), None, None);
    assert_eq!(reply.status, 404);
}

// ---------------------------------------------------------------------------
// Issuance over HTTP
// ---------------------------------------------------------------------------

fn request_body(callee: &EntityId, tools: &[&str]) -> Value {
    json!({
        "from": agent_id().as_str(),
        "to": callee.as_str(),
        "tools": tools,
        "data_classes": ["internal"],
        "jurisdictions": ["SG"],
        "ttl_secs": 30 * 86_400,
        "justification": "APAC daily reconciliation",
        "requester": priya().as_str(),
        "mediators": [MEDIATOR],
    })
}

#[test]
fn a_low_risk_request_mints_and_returns_the_artifact() {
    let h = harness("mint");
    let reply = call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("mint-1"),
        Some(request_body(
            &ledger_id(),
            &["get_balance", "list_transactions"],
        )),
    );
    assert_eq!(reply.status, 201, "{}", reply.body);
    let body = reply.json();
    assert_eq!(body["outcome"], "issued");
    assert_eq!(body["approval_mode"], "StandingPolicy");
    assert_eq!(body["aud"][0], MEDIATOR);

    // The artifact comes back on the wire, so a client can hand it to a mediator
    // without a second round trip.
    let jws = body["artifacts"][0]["jws"].as_str().unwrap();
    assert_eq!(jws.split('.').count(), 3);
}

#[test]
fn a_sensitive_request_is_accepted_but_not_complete() {
    let h = harness("escalate");
    let reply = call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("esc-1"),
        Some(request_body(&payments_id(), &["get_balance"])),
    );
    // 202, not 201: accepted, awaiting a human.
    assert_eq!(reply.status, 202, "{}", reply.body);
    let body = reply.json();
    assert_eq!(body["outcome"], "awaiting_approval");
    assert_eq!(body["request"]["approver_role"], "security.architect");
    assert!(body["request"]["digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    // And it shows up in the queue.
    let queue = call(h.port, "GET", "/v1/requests", Some(READER), None, None);
    assert_eq!(queue.json()["count"], 1);
}

#[test]
fn a_request_the_callee_cannot_satisfy_is_422() {
    let h = harness("subset");
    let reply = call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("bad-1"),
        Some(request_body(&ledger_id(), &["get_balance", "invent_money"])),
    );
    assert_eq!(reply.status, 422, "{}", reply.body);
    assert_eq!(reply.json()["code"], "WC-3010");
    assert!(reply.json()["detail"]
        .as_str()
        .unwrap()
        .contains("invent_money"));
}

#[test]
fn the_approval_round_trip_mints() {
    let h = harness("approve");
    let escalated = call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("esc-2"),
        Some(request_body(&payments_id(), &["get_balance"])),
    );
    assert_eq!(escalated.status, 202);
    let request_id = escalated.json()["request"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // The approver signs in their own client; only the signature reaches the API.
    let queue = call(h.port, "GET", "/v1/requests", Some(READER), None, None);
    let pending: wc_control::issuance::PendingRequest = serde_json::from_value(json!({
        "id": request_id,
        "caller": agent_id().as_str(),
        "callee": payments_id().as_str(),
        "surface": {"tools": ["get_balance"], "skills": [], "resources": []},
        "terms": queue.json()["requests"][0]["terms"].clone(),
        "ttl_secs": queue.json()["requests"][0]["ttl_secs"],
        "justification": "APAC daily reconciliation",
        "requester": priya().as_str(),
        "mediators": [MEDIATOR],
        "approver_role": "security.architect",
        "dual_control": false,
        "policy_version": "connect-policy@api",
        "policy_reason": "",
        "policy_trace": "",
        "created_at": NOW,
        "expires_at": NOW + 72 * 3_600,
        "status": "pending",
    }))
    .expect("the pending shape must round-trip");

    // Reconstructing it must reproduce the same digest the API published, or the
    // approver would be signing something different from what was shown.
    assert_eq!(
        pending.digest(),
        escalated.json()["request"]["digest"].as_str().unwrap(),
        "the published digest must be reproducible by a client"
    );

    let approver_key =
        IssuerKey::ec_pem(cecil().as_str(), APPROVER_PRIV, Algorithm::ES256).unwrap();
    let jws = issuance::sign_approval(&pending, &approver_key, Some("RISK-4471"), NOW).unwrap();

    let approved = call(
        h.port,
        "POST",
        &format!("/v1/requests/{request_id}/approve"),
        Some(ADMIN),
        Some("apr-1"),
        Some(json!({"approvals": [{"by": cecil().as_str(), "jws": jws}]})),
    );
    assert_eq!(approved.status, 201, "{}", approved.body);
    assert_eq!(approved.json()["approval_mode"], "Human");
}

#[test]
fn a_request_can_be_denied() {
    let h = harness("deny");
    let escalated = call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("esc-3"),
        Some(request_body(&payments_id(), &["get_balance"])),
    );
    let id = escalated.json()["request"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let denied = call(
        h.port,
        "POST",
        &format!("/v1/requests/{id}/deny"),
        Some(ADMIN),
        Some("den-1"),
        Some(json!({"reason": "not justified"})),
    );
    assert_eq!(denied.status, 200, "{}", denied.body);
    assert_eq!(denied.json()["status"], "Denied");
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

#[test]
fn a_mutating_route_requires_an_idempotency_key() {
    let h = harness("idem-required");
    let reply = call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        None,
        Some(request_body(&ledger_id(), &["get_balance"])),
    );
    assert_eq!(reply.status, 400);
    assert!(reply.json()["detail"]
        .as_str()
        .unwrap()
        .contains("Idempotency-Key"));
}

#[test]
fn a_replay_with_the_same_key_returns_the_first_response() {
    let h = harness("idem-replay");
    let body = request_body(&ledger_id(), &["get_balance"]);
    let first = call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("same"),
        Some(body.clone()),
    );
    assert_eq!(first.status, 201);
    let cid = first.json()["cid"].as_str().unwrap().to_string();

    let second = call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("same"),
        Some(body),
    );
    assert_eq!(second.status, 200);
    assert_eq!(second.header("idempotent-replay"), Some("true"));
    assert_eq!(second.json()["cid"].as_str().unwrap(), cid);

    // Exactly one contract exists: a retry did not double-issue.
    let list = call(h.port, "GET", "/v1/connections", Some(READER), None, None);
    assert_eq!(list.json()["count"], 1);
}

#[test]
fn the_same_key_with_a_different_body_is_a_conflict() {
    // That is a client reusing a key, not a retry — and silently applying it would
    // be the worst of both readings.
    let h = harness("idem-conflict");
    call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("dup"),
        Some(request_body(&ledger_id(), &["get_balance"])),
    );
    let conflicting = call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("dup"),
        Some(request_body(&ledger_id(), &["list_transactions"])),
    );
    assert_eq!(conflicting.status, 409);
    assert_eq!(conflicting.json()["code"], "WC-2002");
}

// ---------------------------------------------------------------------------
// The data plane: distribution and acknowledgement
// ---------------------------------------------------------------------------

#[test]
fn a_mediator_pulls_only_the_contracts_addressed_to_it() {
    let h = harness("pull");
    call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("pull-1"),
        Some(request_body(&ledger_id(), &["get_balance"])),
    );

    let mine = call(
        h.port,
        "GET",
        &format!("/v1/mediators/{}/contracts", MEDIATOR.replace(':', "%3A")),
        Some(MEDIATOR_TOKEN),
        None,
        None,
    );
    assert_eq!(mine.status, 200, "{}", mine.body);
    let body = mine.json();
    assert_eq!(body["active"].as_array().unwrap().len(), 1);
    assert!(body["set_hash"].as_str().unwrap().starts_with("sha256:"));

    // Another mediator gets an empty set, not somebody else's contracts.
    let theirs = call(
        h.port,
        "GET",
        "/v1/mediators/warden%3Amediator%3Aemea-ops/contracts",
        Some(MEDIATOR_TOKEN),
        None,
        None,
    );
    assert_eq!(theirs.json()["active"].as_array().unwrap().len(), 0);
}

#[test]
fn a_revoked_contract_is_named_in_removed_rather_than_simply_absent() {
    // A mediator must be told to drop it, not left to infer absence from a set it
    // might have fetched partially.
    let h = harness("removed");
    let issued = call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("rm-1"),
        Some(request_body(&ledger_id(), &["get_balance"])),
    );
    let cid = issued.json()["cid"].as_str().unwrap().to_string();

    let quarantined = call(
        h.port,
        "POST",
        "/v1/quarantine",
        Some(ADMIN),
        Some("q-1"),
        Some(json!({"party": ledger_id().as_str(), "reason": "SOC-2291"})),
    );
    assert_eq!(quarantined.status, 202, "{}", quarantined.body);
    assert_eq!(quarantined.json()["revoked"][0], cid);

    let set = call(
        h.port,
        "GET",
        &format!("/v1/mediators/{}/contracts", MEDIATOR.replace(':', "%3A")),
        Some(MEDIATOR_TOKEN),
        None,
        None,
    );
    assert_eq!(set.json()["active"].as_array().unwrap().len(), 0);
    assert_eq!(set.json()["removed"][0], cid);
}

#[test]
fn a_mediator_that_has_not_acked_is_reported_unconfirmed() {
    let h = harness("ack");
    call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("ack-1"),
        Some(request_body(&ledger_id(), &["get_balance"])),
    );

    let before = call(h.port, "GET", "/v1/mediators", Some(READER), None, None);
    assert_eq!(before.json()["unconfirmed"], 1);
    assert_eq!(before.json()["mediators"][0]["confirmed"], false);
    assert!(before.body.contains("never as contained"));

    let set = call(
        h.port,
        "GET",
        &format!("/v1/mediators/{}/contracts", MEDIATOR.replace(':', "%3A")),
        Some(MEDIATOR_TOKEN),
        None,
        None,
    );
    let acked = call(
        h.port,
        "POST",
        &format!("/v1/mediators/{}/ack", MEDIATOR.replace(':', "%3A")),
        Some(MEDIATOR_TOKEN),
        None,
        Some(json!({
            "set_hash": set.json()["set_hash"],
            "seq": set.json()["seq"],
            "revoked": [],
            "aborted": 0,
        })),
    );
    assert_eq!(acked.status, 204);
    assert!(acked.body.is_empty());

    let after = call(h.port, "GET", "/v1/mediators", Some(READER), None, None);
    assert_eq!(after.json()["unconfirmed"], 0);
    assert_eq!(after.json()["mediators"][0]["confirmed"], true);
}

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_body_is_rejected_with_a_code() {
    let h = harness("malformed");
    let mut stream = TcpStream::connect(("127.0.0.1", h.port)).unwrap();
    let body = "{not json";
    let head = format!(
        "POST /v1/connections HTTP/1.1\r\nhost: x\r\nAuthorization: Bearer {ADMIN}\r\n\
         Idempotency-Key: mal-1\r\ncontent-length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("WC-4008"), "{text}");
}

#[test]
fn the_evidence_head_is_readable_for_an_export() {
    let h = harness("head");
    call(
        h.port,
        "POST",
        "/v1/connections",
        Some(ADMIN),
        Some("head-1"),
        Some(request_body(&ledger_id(), &["get_balance"])),
    );
    let reply = call(h.port, "GET", "/v1/audit/verify", Some(ADMIN), None, None);
    assert_eq!(reply.status, 200);
    assert!(reply.json()["head_seq"].as_u64().unwrap() > 0);
    assert!(!reply.json()["head_hash"].as_str().unwrap().is_empty());
}

#[test]
fn concurrent_requests_are_all_answered() {
    // Thread-per-request plus a single-writer store: reads and writes must not
    // deadlock each other.
    let h = harness("concurrent");
    let port = h.port;
    let handles: Vec<_> = (0..12)
        .map(|i| {
            std::thread::spawn(move || {
                if i % 3 == 0 {
                    call(
                        port,
                        "POST",
                        "/v1/connections",
                        Some(ADMIN),
                        Some(&format!("c-{i}")),
                        Some(request_body(&ledger_id(), &["get_balance"])),
                    )
                    .status
                } else {
                    call(port, "GET", "/v1/entities", Some(READER), None, None).status
                }
            })
        })
        .collect();

    for handle in handles {
        let status = handle.join().unwrap();
        assert!(
            (200..300).contains(&status),
            "every concurrent request must be answered, got {status}"
        );
    }
}
