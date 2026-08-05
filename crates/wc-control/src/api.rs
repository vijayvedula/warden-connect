//! The control-plane HTTP surface (`docs/08-lld.md` §8.5.10).
//!
//! Everything the CLI does, over `/v1` — so CI, a portal and the mediators do not
//! have to shell out. Plus the two endpoints the data plane needs: a contract-set
//! delta to pull, and an ACK to post back.
//!
//! # Authentication
//!
//! Bearer tokens mapped to roles, from configuration. Deliberately simple and
//! deliberately explicit: the LLD's end state is a verified Warden session token
//! with an AuthZEN passthrough (§7.6), and pretending a half-built JWT scheme is
//! that would be worse than naming the gap. What *is* final is the shape — every
//! route declares the role it needs, and an unauthenticated request never reaches a
//! handler.
//!
//! # Idempotency
//!
//! Every mutating route requires an `Idempotency-Key`. A replay with the same key
//! and the same body returns the first response; the same key with a *different*
//! body is a conflict, because that is a client bug rather than a retry.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde_json::{json, Value};

use wc_core::contract::{ContractStatus, IssuerKey, Surface, Terms};
use wc_core::error::{Code, Mode, Result, WcError};
use wc_core::model::{Entity, EntityId, HumanRef, Lifecycle, Posture};
use wc_core::util::sha256_hex;

use crate::cpolicy::ConnectPolicy;
use crate::evidence::Evidence;
use crate::http::{self, Request, Response};
use crate::issuance::{
    ApprovalProof, ApproverRegistry, Issued, Issuer, Outcome, PendingRequest, RequestInput,
    RequestStatus,
};
use crate::store::{Actor, Store};

/// Roles the surface recognises.
pub mod roles {
    /// Read the estate.
    pub const READ: &str = "connect.read";
    /// Register and admit parties.
    pub const REGISTER: &str = "connect.register";
    /// Request and renew connections.
    pub const REQUEST: &str = "connect.request";
    /// Approve or deny a request.
    pub const APPROVE: &str = "connect.approve";
    /// Contain a party.
    pub const SECOPS: &str = "connect.secops";
    /// Pull contract sets and post acknowledgements.
    pub const MEDIATOR: &str = "connect.mediator";
    /// Produce registers and evidence exports.
    pub const COMPLIANCE: &str = "connect.compliance";
}

/// How long an idempotency record is kept.
pub const IDEMPOTENCY_TTL_SECS: u64 = 24 * 3_600;

/// A caller's identity and authority.
#[derive(Debug, Clone)]
pub struct Caller {
    /// Who they are.
    pub subject: String,
    /// What they may do.
    pub roles: Vec<String>,
}

impl Caller {
    /// Whether this caller holds a role.
    #[must_use]
    pub fn holds(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// What a mediator last confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatorAck {
    /// Set hash the mediator applied.
    pub set_hash: String,
    /// Sequence it applied.
    pub seq: u64,
    /// When it acked.
    pub at: u64,
    /// Connections it reports as cut.
    pub revoked: Vec<String>,
    /// In-flight calls it aborted.
    pub aborted: u64,
}

/// Request counters, rendered at `/metrics`.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Requests served.
    pub requests: AtomicU64,
    /// Requests refused for lack of a role or a token.
    pub denied: AtomicU64,
    /// Contracts minted.
    pub minted: AtomicU64,
    /// Requests routed to a human.
    pub escalated: AtomicU64,
    /// Idempotent replays served from the cache.
    pub replays: AtomicU64,
    /// Contract-set pulls served.
    pub pulls: AtomicU64,
}

impl Metrics {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Everything a request handler needs.
pub struct ControlPlane {
    /// State, single-writer behind a mutex.
    pub store: Mutex<Store>,
    /// The evidence chain.
    pub evidence: Mutex<Evidence>,
    /// Connection policy, swappable for a hot reload.
    pub policy: RwLock<Arc<ConnectPolicy>>,
    /// Contract signing key.
    pub signer: IssuerKey,
    /// Who may approve.
    pub approvers: ApproverRegistry,
    /// Issuer URL stamped into artifacts.
    pub iss: String,
    /// Enforce or observe.
    pub mode: Mode,
    /// Bearer token → roles.
    pub tokens: HashMap<String, Vec<String>>,
    /// Public JWKS served at `/v1/jwks.json`, as pre-rendered JSON.
    pub jwks: String,
    /// Mediator acknowledgements.
    pub acks: Mutex<HashMap<String, MediatorAck>>,
    /// The signed revocation feed, served to mediators at `/v1/revocations`.
    ///
    /// Optional because a control plane can run without one — and when it does,
    /// the endpoint says so rather than serving an empty feed. An empty feed and
    /// no feed are different answers: the first means "nothing is revoked", the
    /// second means "this control plane cannot tell you".
    pub revocations: Option<Mutex<crate::contain::RevocationFeed>>,
    /// Counters.
    pub metrics: Metrics,
    /// Idempotency records: key → (expiry, body hash, response body).
    idempotency: Mutex<HashMap<String, (u64, String, String)>>,
    /// Injected clock.
    now: fn() -> u64,
}

impl std::fmt::Debug for ControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlane")
            .field("iss", &self.iss)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl ControlPlane {
    /// Assemble a control plane.
    pub fn new(
        store: Store,
        evidence: Evidence,
        policy: ConnectPolicy,
        signer: IssuerKey,
        iss: &str,
        now: fn() -> u64,
    ) -> ControlPlane {
        ControlPlane {
            revocations: None,
            store: Mutex::new(store),
            evidence: Mutex::new(evidence),
            policy: RwLock::new(Arc::new(policy)),
            signer,
            approvers: ApproverRegistry::new(),
            iss: iss.to_string(),
            mode: Mode::Observe,
            tokens: HashMap::new(),
            jwks: r#"{"keys":[]}"#.to_string(),
            acks: Mutex::new(HashMap::new()),
            metrics: Metrics::default(),
            idempotency: Mutex::new(HashMap::new()),
            now,
        }
    }

    /// Register a bearer token and the roles it carries.
    #[must_use]
    pub fn with_token(mut self, token: &str, roles: &[&str]) -> ControlPlane {
        self.tokens.insert(
            token.to_string(),
            roles.iter().map(|r| (*r).to_string()).collect(),
        );
        self
    }

    /// Set the approver registry.
    #[must_use]
    pub fn with_approvers(mut self, approvers: ApproverRegistry) -> ControlPlane {
        self.approvers = approvers;
        self
    }

    /// Set the mode.
    #[must_use]
    pub fn with_mode(mut self, mode: Mode) -> ControlPlane {
        self.mode = mode;
        self
    }

    /// Publish a JWKS document.
    #[must_use]
    pub fn with_jwks(mut self, jwks: &str) -> ControlPlane {
        self.jwks = jwks.to_string();
        self
    }

    /// Replace the live policy — a hot reload.
    ///
    /// A policy with lint errors is refused and the last-known-good is kept
    /// (§8.13, `WC-8001`): a control plane that swallows a broken policy is one
    /// that silently stops enforcing what an operator thinks it enforces.
    pub fn reload_policy(&self, candidate: ConnectPolicy) -> Result<()> {
        let report = candidate.lint();
        if !report.is_usable() {
            return Err(WcError::with_detail(
                Code::POLICY_INVALID,
                format!(
                    "keeping last-known-good: {} error(s): {}",
                    report.errors.len(),
                    report.errors.join("; ")
                ),
            ));
        }
        let mut live = match self.policy.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *live = Arc::new(candidate);
        Ok(())
    }

    fn policy(&self) -> Arc<ConnectPolicy> {
        match self.policy.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Resolve a bearer token to a caller.
    fn authenticate(&self, req: &Request) -> Option<Caller> {
        let token = req.bearer()?;
        let roles = self.tokens.get(token)?;
        Some(Caller {
            subject: format!("token:{}", &sha256_hex(token)[..12]),
            roles: roles.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// The router. Wrapping `ControlPlane` so it can be an `http::Handler`.
#[derive(Debug)]
pub struct Api(pub Arc<ControlPlane>);

impl http::Handler for Api {
    fn handle(&self, req: &Request) -> Response {
        let cp = &self.0;
        Metrics::bump(&cp.metrics.requests);

        // Unauthenticated: liveness and the public key set. Nothing here reveals
        // anything about the estate.
        match (req.method.as_str(), req.segments().as_slice()) {
            ("GET", ["healthz"]) => return Response::json(200, r#"{"status":"ok"}"#),
            ("GET", ["readyz"]) => return ready(cp),
            ("GET", ["metrics"]) => return metrics(cp),
            ("GET", ["v1", "jwks.json"]) => {
                return Response::json(200, cp.jwks.clone());
            }
            _ => {}
        }

        let Some(caller) = cp.authenticate(req) else {
            Metrics::bump(&cp.metrics.denied);
            return error(
                401,
                Code::IDENTITY_UNVERIFIABLE,
                "a bearer token is required",
            );
        };

        match route(cp, &caller, req) {
            Ok(response) => response,
            Err(e) => from_error(&e),
        }
    }
}

/// Dispatch an authenticated request.
fn route(cp: &Arc<ControlPlane>, caller: &Caller, req: &Request) -> Result<Response> {
    let segments = req.segments();
    match (req.method.as_str(), segments.as_slice()) {
        // --- registry ---
        ("GET", ["v1", "entities"]) => {
            require_role(cp, caller, roles::READ)?;
            list_entities(cp)
        }
        ("GET", ["v1", "entities", id]) => {
            require_role(cp, caller, roles::READ)?;
            get_entity(cp, id)
        }
        ("POST", ["v1", "entities", id, "activate"]) => {
            require_role(cp, caller, roles::REGISTER)?;
            idempotent(cp, req, |cp| activate_entity(cp, caller, id))
        }
        ("GET", ["v1", "posture"]) => {
            require_role(cp, caller, roles::READ)?;
            posture(cp, req)
        }

        // --- connections ---
        ("POST", ["v1", "connections"]) => {
            require_role(cp, caller, roles::REQUEST)?;
            idempotent(cp, req, |cp| create_connection(cp, caller, req))
        }
        ("GET", ["v1", "connections"]) => {
            require_role(cp, caller, roles::READ)?;
            list_connections(cp)
        }
        ("GET", ["v1", "connections", cid]) => {
            require_role(cp, caller, roles::READ)?;
            get_connection(cp, cid)
        }
        ("GET", ["v1", "requests"]) => {
            require_role(cp, caller, roles::READ)?;
            list_requests(cp, req)
        }
        ("POST", ["v1", "requests", id, "approve"]) => {
            require_role(cp, caller, roles::APPROVE)?;
            idempotent(cp, req, |cp| approve_request(cp, caller, id, req))
        }
        ("POST", ["v1", "requests", id, "deny"]) => {
            require_role(cp, caller, roles::APPROVE)?;
            idempotent(cp, req, |cp| deny_request(cp, caller, id, req))
        }

        // --- containment ---
        ("POST", ["v1", "quarantine"]) => {
            require_role(cp, caller, roles::SECOPS)?;
            idempotent(cp, req, |cp| quarantine(cp, caller, req))
        }

        // --- the data plane ---
        ("GET", ["v1", "mediators", mid, "contracts"]) => {
            require_role(cp, caller, roles::MEDIATOR)?;
            contract_set(cp, mid, req)
        }
        ("POST", ["v1", "mediators", mid, "ack"]) => {
            require_role(cp, caller, roles::MEDIATOR)?;
            record_ack(cp, mid, req)
        }
        ("GET", ["v1", "mediators"]) => {
            require_role(cp, caller, roles::READ)?;
            mediator_status(cp)
        }
        ("GET", ["v1", "revocations"]) => {
            require_role(cp, caller, roles::MEDIATOR)?;
            revocation_feed(cp, req)
        }

        // --- evidence ---
        ("GET", ["v1", "audit", "verify"]) => {
            require_role(cp, caller, roles::COMPLIANCE)?;
            audit_verify(cp)
        }

        ("GET" | "POST" | "PUT" | "DELETE" | "PATCH", _) => Ok(error(
            404,
            Code::ENTITY_NOT_FOUND,
            &format!("no route for {} {}", req.method, req.path),
        )),
        _ => Ok(error(405, Code::FRAME_MALFORMED, "unsupported method")),
    }
}

fn require_role(cp: &Arc<ControlPlane>, caller: &Caller, role: &str) -> Result<()> {
    if caller.holds(role) {
        return Ok(());
    }
    Metrics::bump(&cp.metrics.denied);
    Err(WcError::with_detail(
        Code::APPROVER_ROLE_MISSING,
        format!("this route needs {role:?}"),
    ))
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

/// Wrap a mutating handler so a retry cannot double-apply it.
///
/// The same key with the same body replays the first response. The same key with a
/// *different* body is `409`: that is a client reusing a key, not a retry, and
/// silently applying it would be the worst of both readings.
fn idempotent(
    cp: &Arc<ControlPlane>,
    req: &Request,
    handler: impl FnOnce(&Arc<ControlPlane>) -> Result<Response>,
) -> Result<Response> {
    let Some(key) = req.header("idempotency-key").map(str::to_string) else {
        return Ok(error(
            400,
            Code::FRAME_MALFORMED,
            "an Idempotency-Key header is required on mutating requests",
        ));
    };
    let body_hash = sha256_hex(&String::from_utf8_lossy(&req.body));
    let now = (cp.now)();

    {
        let mut cache = lock(&cp.idempotency);
        cache.retain(|_, (expiry, _, _)| *expiry > now);
        if let Some((_, seen_hash, response)) = cache.get(&key) {
            if seen_hash == &body_hash {
                Metrics::bump(&cp.metrics.replays);
                return Ok(
                    Response::json(200, response.clone()).with_header("idempotent-replay", "true")
                );
            }
            return Ok(error(
                409,
                Code::ENTITY_DUPLICATE,
                "this Idempotency-Key was used with a different body",
            ));
        }
    }

    let response = handler(cp)?;
    if (200..300).contains(&response.status) {
        let body = String::from_utf8_lossy(&response.body).into_owned();
        lock(&cp.idempotency).insert(key, (now + IDEMPOTENCY_TTL_SECS, body_hash, body));
    }
    Ok(response)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// ---------------------------------------------------------------------------
// Handlers — reads
// ---------------------------------------------------------------------------

fn ready(cp: &Arc<ControlPlane>) -> Response {
    // Readiness is about being able to *decide*, not about being up: a control
    // plane with no usable policy must not claim it can issue.
    let policy = cp.policy();
    let report = policy.lint();
    if report.is_usable() {
        Response::json(
            200,
            json!({"status": "ready", "policy": policy.version}).to_string(),
        )
    } else {
        Response::json(
            503,
            json!({"status": "not_ready", "errors": report.errors}).to_string(),
        )
    }
}

fn metrics(cp: &Arc<ControlPlane>) -> Response {
    let m = &cp.metrics;
    let store = lock(&cp.store);
    let entities = store.projection.entities.len();
    let contracts = store
        .projection
        .contracts
        .values()
        .filter(|c| c.status == ContractStatus::Active)
        .count();
    let pending = store
        .projection
        .requests
        .values()
        .filter(|r| r.status == RequestStatus::Pending)
        .count();
    drop(store);

    let acks = lock(&cp.acks).len();
    let body = format!(
        "# warden-connect control plane\n\
         wc_api_requests_total {}\n\
         wc_api_denied_total {}\n\
         wc_api_replays_total {}\n\
         wc_contract_pulls_total {}\n\
         wc_contracts_minted_total {}\n\
         wc_requests_escalated_total {}\n\
         wc_entities {entities}\n\
         wc_contracts_active {contracts}\n\
         wc_requests_pending {pending}\n\
         wc_mediators_acked {acks}\n",
        m.requests.load(Ordering::Relaxed),
        m.denied.load(Ordering::Relaxed),
        m.replays.load(Ordering::Relaxed),
        m.pulls.load(Ordering::Relaxed),
        m.minted.load(Ordering::Relaxed),
        m.escalated.load(Ordering::Relaxed),
    );
    Response::text(200, body)
}

fn entity_json(e: &Entity) -> Value {
    json!({
        "id": e.id.as_str(),
        "kind": format!("{:?}", e.kind),
        "owner": e.owner.as_str(),
        "service": e.service,
        "tier": e.tier.as_u8(),
        "zone": e.zone.as_str(),
        "trust_level": format!("{:?}", e.zone.trust_level()),
        "posture": format!("{:?}", e.posture),
        "lifecycle": format!("{:?}", e.lifecycle),
        "data_classes": e.data_classes,
        "jurisdictions": e.jurisdictions,
        // Never the endpoint: reachability is granted by a contract, not by a
        // lookup, so discovery must not hand out addresses (§8.5.6).
        "pin": { "alg": e.pin.alg, "manifest": e.pin.manifest, "items": e.pin.items.len() },
        "reattest_every": e.reattest_every,
    })
}

fn list_entities(cp: &Arc<ControlPlane>) -> Result<Response> {
    let store = lock(&cp.store);
    let mut rows: Vec<&Entity> = store.projection.entities.values().collect();
    rows.sort_unstable_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    let body = json!({
        "entities": rows.iter().map(|e| entity_json(e)).collect::<Vec<_>>(),
        "count": rows.len(),
    });
    Ok(Response::json(200, body.to_string()))
}

fn get_entity(cp: &Arc<ControlPlane>, id: &str) -> Result<Response> {
    let entity_id = EntityId::new(id)?;
    let store = lock(&cp.store);
    match store.projection.entities.get(&entity_id) {
        Some(e) => Ok(Response::json(200, entity_json(e).to_string())),
        None => Ok(error(404, Code::ENTITY_NOT_FOUND, "no such entity")),
    }
}

fn posture(cp: &Arc<ControlPlane>, req: &Request) -> Result<Response> {
    let now = req.param_u64("now").unwrap_or_else(|| (cp.now)());
    let store = lock(&cp.store);
    let all: Vec<&Entity> = store.projection.entities.values().collect();

    let by_posture = |want: Posture| -> Vec<&str> {
        all.iter()
            .filter(|e| e.posture == want)
            .map(|e| e.id.as_str())
            .collect()
    };
    let overdue: Vec<&str> = all
        .iter()
        .filter(|e| e.lifecycle == Lifecycle::Active && e.reattest_overdue(now))
        .map(|e| e.id.as_str())
        .collect();

    Ok(Response::json(
        200,
        json!({
            "total": all.len(),
            "unattested": by_posture(Posture::Unattested),
            "degraded": by_posture(Posture::Degraded),
            "quarantined": by_posture(Posture::Quarantined),
            "reattest_overdue": overdue,
        })
        .to_string(),
    ))
}

fn list_connections(cp: &Arc<ControlPlane>) -> Result<Response> {
    let store = lock(&cp.store);
    let mut rows: Vec<_> = store.projection.contracts.values().collect();
    rows.sort_unstable_by(|a, b| a.cid.as_str().cmp(b.cid.as_str()));
    Ok(Response::json(
        200,
        json!({
            "connections": rows.iter().map(|c| json!({
                "cid": c.cid.as_str(),
                "status": format!("{:?}", c.status),
                "caller": c.caller.as_str(),
                "callee": c.callee.as_str(),
                "surface": c.surface.items(),
                "exp": c.exp,
                "approval_mode": format!("{:?}", c.approval.mode),
                "policy_version": c.policy_version,
            })).collect::<Vec<_>>(),
            "count": rows.len(),
        })
        .to_string(),
    ))
}

fn get_connection(cp: &Arc<ControlPlane>, cid: &str) -> Result<Response> {
    let store = lock(&cp.store);
    match store
        .projection
        .contracts
        .values()
        .find(|c| c.cid.as_str() == cid)
    {
        Some(record) => Ok(Response::json(
            200,
            serde_json::to_string(record).unwrap_or_else(|_| "{}".to_string()),
        )),
        None => Ok(error(404, Code::CONTRACT_NOT_FOUND, "no such connection")),
    }
}

/// A pending request, in full.
///
/// The complete surface, terms and mediator list are published deliberately: an
/// approver signs a digest that covers all of them, so a client that cannot
/// reproduce the digest cannot verify it is signing what it was shown — and the
/// whole point of a signed approval is that it binds to exactly that.
fn request_json(r: &PendingRequest) -> Value {
    json!({
        "id": r.id,
        "status": format!("{:?}", r.status),
        "caller": r.caller.as_str(),
        "callee": r.callee.as_str(),
        "surface": r.surface.items(),
        "resources": r.surface.resources,
        "terms": r.terms,
        "mediators": r.mediators,
        "created_at": r.created_at,
        "ttl_secs": r.ttl_secs,
        "justification": r.justification,
        "requester": r.requester.as_str(),
        "approver_role": r.approver_role,
        "dual_control": r.dual_control,
        "digest": r.digest(),
        "expires_at": r.expires_at,
        "policy_version": r.policy_version,
        "reason": r.policy_reason,
        "trace": r.policy_trace,
    })
}

fn list_requests(cp: &Arc<ControlPlane>, req: &Request) -> Result<Response> {
    let all = req.param("all").is_some();
    let store = lock(&cp.store);
    let mut rows: Vec<&PendingRequest> = store
        .projection
        .requests
        .values()
        .filter(|r| all || r.status == RequestStatus::Pending)
        .collect();
    rows.sort_unstable_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    Ok(Response::json(
        200,
        json!({
            "requests": rows.iter().map(|r| request_json(r)).collect::<Vec<_>>(),
            "count": rows.len(),
        })
        .to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Handlers — writes
// ---------------------------------------------------------------------------

fn body_json(req: &Request) -> Result<Value> {
    if req.body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&req.body)
        .map_err(|e| WcError::with_detail(Code::FRAME_MALFORMED, "body is not JSON").with_source(e))
}

fn field<'a>(body: &'a Value, name: &str) -> Result<&'a str> {
    body.get(name).and_then(Value::as_str).ok_or_else(|| {
        WcError::with_detail(
            Code::FRAME_MALFORMED,
            format!("{name:?} is required and must be a string"),
        )
    })
}

fn string_list(body: &Value, name: &str) -> Vec<String> {
    body.get(name)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn actor_for(caller: &Caller) -> Actor {
    Actor::Service {
        id: caller.subject.clone(),
    }
}

fn activate_entity(cp: &Arc<ControlPlane>, caller: &Caller, id: &str) -> Result<Response> {
    let entity_id = EntityId::new(id)?;
    let now = (cp.now)();
    let mut store = lock(&cp.store);
    store.registry(actor_for(caller), now).transition(
        &entity_id,
        Lifecycle::Active,
        "activated over the api",
    )?;
    Ok(Response::json(
        200,
        json!({"id": entity_id.as_str(), "lifecycle": "Active"}).to_string(),
    ))
}

fn issued_json(issued: &Issued) -> Value {
    json!({
        "outcome": "issued",
        "cid": issued.record.cid.as_str(),
        "jti": issued.record.jti.as_str(),
        "surface": issued.record.surface.items(),
        "surface_digest": issued.record.surface_digest,
        "aud": issued.record.aud,
        "exp": issued.record.exp,
        "approval_mode": format!("{:?}", issued.record.approval.mode),
        "policy_version": issued.record.policy_version,
        "evidence_seq": issued.evidence_seq,
        "artifacts": issued.artifacts.iter()
            .map(|(aud, jws)| json!({"aud": aud, "jws": jws}))
            .collect::<Vec<_>>(),
    })
}

/// Run a closure with an issuer built over the live state.
fn with_issuer<T>(
    cp: &Arc<ControlPlane>,
    caller: &Caller,
    f: impl FnOnce(&mut Issuer<'_>) -> Result<T>,
) -> Result<T> {
    let policy = cp.policy();
    let mut store = lock(&cp.store);
    let mut evidence = lock(&cp.evidence);
    let mut issuer = Issuer::new(
        &mut store,
        &mut evidence,
        &policy,
        &cp.signer,
        &cp.iss,
        (cp.now)(),
        actor_for(caller),
    );
    issuer.mode = cp.mode;
    f(&mut issuer)
}

fn create_connection(cp: &Arc<ControlPlane>, caller: &Caller, req: &Request) -> Result<Response> {
    let body = body_json(req)?;
    let input = RequestInput {
        caller: EntityId::new(field(&body, "from")?)?,
        callee: EntityId::new(field(&body, "to")?)?,
        surface: Surface {
            tools: string_list(&body, "tools"),
            skills: string_list(&body, "skills"),
            resources: string_list(&body, "resources"),
        },
        terms: Terms {
            data_classes: string_list(&body, "data_classes"),
            jurisdictions: string_list(&body, "jurisdictions"),
            ..Default::default()
        },
        ttl_secs: body
            .get("ttl_secs")
            .and_then(Value::as_u64)
            .unwrap_or(30 * 86_400),
        justification: field(&body, "justification")?.to_string(),
        requester: HumanRef::new(field(&body, "requester")?)?,
        mediators: string_list(&body, "mediators"),
    };

    let outcome = with_issuer(cp, caller, |issuer| issuer.request(&input))?;
    match outcome {
        Outcome::Issued(issued) => {
            Metrics::bump(&cp.metrics.minted);
            Ok(Response::json(201, issued_json(&issued).to_string()))
        }
        Outcome::AwaitingApproval(pending) => {
            Metrics::bump(&cp.metrics.escalated);
            // 202: accepted, not complete. A client polls or waits for the approver.
            Ok(Response::json(
                202,
                json!({"outcome": "awaiting_approval", "request": request_json(&pending)})
                    .to_string(),
            ))
        }
        Outcome::Denied { reason, trace } => Ok(Response::json(
            403,
            json!({"outcome": "denied", "reason": reason, "trace": trace}).to_string(),
        )),
    }
}

fn approve_request(
    cp: &Arc<ControlPlane>,
    caller: &Caller,
    id: &str,
    req: &Request,
) -> Result<Response> {
    let body = body_json(req)?;
    let entries = body
        .get("approvals")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            WcError::with_detail(
                Code::FRAME_MALFORMED,
                "\"approvals\" must be an array of {by, jws}",
            )
        })?;

    let mut proofs = Vec::new();
    for entry in entries {
        proofs.push(ApprovalProof {
            by: HumanRef::new(field(entry, "by")?)?,
            jws: field(entry, "jws")?.to_string(),
        });
    }

    // The control plane only ever *verifies*: signing happens in the approver's own
    // client, so a compromised control plane cannot manufacture an approval.
    let approvers = &cp.approvers;
    let issued = with_issuer(cp, caller, |issuer| issuer.approve(id, &proofs, approvers))?;
    Metrics::bump(&cp.metrics.minted);
    Ok(Response::json(201, issued_json(&issued).to_string()))
}

fn deny_request(
    cp: &Arc<ControlPlane>,
    caller: &Caller,
    id: &str,
    req: &Request,
) -> Result<Response> {
    let body = body_json(req)?;
    let reason = field(&body, "reason")?.to_string();
    with_issuer(cp, caller, |issuer| issuer.deny(id, &reason))?;
    Ok(Response::json(
        200,
        json!({"request": id, "status": "Denied"}).to_string(),
    ))
}

fn quarantine(cp: &Arc<ControlPlane>, caller: &Caller, req: &Request) -> Result<Response> {
    let body = body_json(req)?;
    let party = EntityId::new(field(&body, "party")?)?;
    let reason = field(&body, "reason")?.to_string();
    let approvers: Vec<HumanRef> = string_list(&body, "approvers")
        .into_iter()
        .map(HumanRef::new)
        .collect::<Result<Vec<_>>>()?;

    let now = (cp.now)();
    let outcome = {
        let mut store = lock(&cp.store);
        store
            .registry(actor_for(caller), now)
            .quarantine(&party, &reason, &approvers)?
    };

    {
        let mut evidence = lock(&cp.evidence);
        evidence.record(
            &crate::evidence::LifecycleEvent::new(
                crate::evidence::EventKind::Quarantine,
                caller.subject.clone(),
            )
            .with_entities([party.as_str()])
            .with_reason(reason)
            .with_detail(json!({
                "revoked": outcome.revoked.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                "impacted_services": outcome.impacted_services,
            })),
            now,
        )?;
    }

    Ok(Response::json(
        202,
        json!({
            "party": outcome.party.as_str(),
            "revoked": outcome.revoked.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            "impacted_services": outcome.impacted_services,
        })
        .to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Handlers — the data plane
// ---------------------------------------------------------------------------

/// The contract set a mediator should hold (§8.7.9).
///
/// Pull, not push: a distribution failure is then *visible* as ACK lag rather than
/// silently lost. `since` lets a mediator skip work it already has, but the set is
/// always complete — a delta that could drift out of sync would be a worse trade
/// than re-sending a few kilobytes.
fn contract_set(cp: &Arc<ControlPlane>, mediator: &str, req: &Request) -> Result<Response> {
    Metrics::bump(&cp.metrics.pulls);
    let since = req.param_u64("since").unwrap_or(0);
    let now = (cp.now)();

    let store = lock(&cp.store);
    let mut live: Vec<_> = store
        .projection
        .contracts
        .values()
        .filter(|c| c.aud.iter().any(|a| a == mediator))
        .collect();
    live.sort_unstable_by(|a, b| a.cid.as_str().cmp(b.cid.as_str()));

    let seq = store.projection.seq;
    let active: Vec<&&wc_core::contract::ContractRecord> = live
        .iter()
        .filter(|c| c.status == ContractStatus::Active && now < c.exp)
        .collect();
    // A revoked or expired contract is named explicitly, so a mediator drops it
    // rather than inferring absence from a set it might have fetched partially.
    let removed: Vec<&str> = live
        .iter()
        .filter(|c| c.status != ContractStatus::Active || now >= c.exp)
        .map(|c| c.cid.as_str())
        .collect();

    let mut digest_input = String::new();
    for c in &active {
        digest_input.push_str(c.cid.as_str());
        digest_input.push('\n');
    }
    let set_hash = format!("sha256:{}", sha256_hex(&digest_input));

    Ok(Response::json(
        200,
        json!({
            "mediator": mediator,
            "seq": seq,
            "since": since,
            "set_hash": set_hash,
            "full": true,
            "active": active.iter().map(|c| json!({
                "cid": c.cid.as_str(),
                "jti": c.jti.as_str(),
                "caller": c.caller.as_str(),
                "callee": c.callee.as_str(),
                "surface": c.surface.items(),
                "exp": c.exp,
                "jws_sha256": c.jws_sha256,
                // The artifact itself, not just its digest: a mediator verifies the
                // signed document, and a set that only described it would be
                // unusable.
                "jws": store.read_artifact(c.cid.as_str(), mediator),
            })).collect::<Vec<_>>(),
            "removed": removed,
        })
        .to_string(),
    ))
}

/// Record a mediator's acknowledgement.
fn record_ack(cp: &Arc<ControlPlane>, mediator: &str, req: &Request) -> Result<Response> {
    let body = body_json(req)?;
    let ack = MediatorAck {
        set_hash: field(&body, "set_hash")?.to_string(),
        seq: body.get("seq").and_then(Value::as_u64).unwrap_or(0),
        at: (cp.now)(),
        revoked: string_list(&body, "revoked"),
        aborted: body.get("aborted").and_then(Value::as_u64).unwrap_or(0),
    };
    lock(&cp.acks).insert(mediator.to_string(), ack);
    Ok(Response::empty(204))
}

/// Serve the signed revocation feed from `since`.
///
/// Every entry carries its own signature, so a mediator verifies each one against
/// the revocation key it was configured with. That is what makes a compromised
/// control plane unable to forge a cut — and equally unable to hide one, because
/// the sequence is contiguous and a gap is visible to the puller.
fn revocation_feed(cp: &Arc<ControlPlane>, req: &Request) -> Result<Response> {
    let Some(feed) = &cp.revocations else {
        // Not an empty feed. A mediator must be able to tell "nothing is revoked"
        // from "this control plane has no feed", because the second one means it
        // should not treat the absence of revocations as reassurance.
        return Err(WcError::with_detail(
            Code::REVOCATION_FEED_UNWRITABLE,
            "this control plane serves no revocation feed",
        ));
    };
    let since = req
        .query
        .get("since")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let feed = lock(feed);
    let events: Vec<Value> = feed
        .since(since)
        .into_iter()
        .map(|e| json!({ "event": e.event, "jws": e.jws, "kid": e.kid }))
        .collect();
    Ok(Response::json(
        200,
        json!({
            "since": since,
            "head_seq": feed.next_seq() - 1,
            "head_digest": feed.head_digest(),
            "events": events,
        })
        .to_string(),
    ))
}

/// Which mediators have confirmed, and which have not.
///
/// A mediator that has not acked is reported as **unconfirmed**, never as
/// contained (§8.7.7). Absence of a confirmation is not a confirmation.
fn mediator_status(cp: &Arc<ControlPlane>) -> Result<Response> {
    let now = (cp.now)();
    let store = lock(&cp.store);
    let mut expected: Vec<String> = store
        .projection
        .contracts
        .values()
        .flat_map(|c| c.aud.clone())
        .collect();
    drop(store);
    expected.sort_unstable();
    expected.dedup();

    let acks = lock(&cp.acks);
    let rows: Vec<Value> = expected
        .iter()
        .map(|mediator| match acks.get(mediator) {
            Some(ack) => json!({
                "mediator": mediator,
                "confirmed": true,
                "set_hash": ack.set_hash,
                "seq": ack.seq,
                "lag_secs": now.saturating_sub(ack.at),
                "revoked": ack.revoked,
                "aborted": ack.aborted,
            }),
            None => json!({
                "mediator": mediator,
                "confirmed": false,
                "why": "no acknowledgement received; treated as unconfirmed, never as contained",
            }),
        })
        .collect();

    let unconfirmed = rows
        .iter()
        .filter(|r| r["confirmed"] == json!(false))
        .count();
    Ok(Response::json(
        200,
        json!({"mediators": rows, "unconfirmed": unconfirmed}).to_string(),
    ))
}

fn audit_verify(cp: &Arc<ControlPlane>) -> Result<Response> {
    let evidence = lock(&cp.evidence);
    let (seq, hash) = evidence.head();
    drop(evidence);
    Ok(Response::json(
        200,
        json!({"head_seq": seq, "head_hash": hash}).to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn error(status: u16, code: Code, detail: &str) -> Response {
    Response::json(
        status,
        json!({"error": code.summary(), "code": code.to_string(), "detail": detail}).to_string(),
    )
}

/// Map a domain error onto an HTTP response, using the code table's own status
/// rather than a per-handler guess (§8.11).
fn from_error(e: &WcError) -> Response {
    let status = e
        .code()
        .spec()
        .and_then(|s| s.http)
        .unwrap_or(match e.code().category() {
            wc_core::error::Category::Verification => 403,
            _ => 400,
        });
    error(status, e.code(), e.detail())
}
