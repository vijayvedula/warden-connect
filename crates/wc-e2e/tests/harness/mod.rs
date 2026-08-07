//! A real estate, driven through the same APIs an operator uses.
//!
//! The point of an end-to-end tier is that it exercises the seams. So nothing
//! here reaches inside a module to arrange state: entities are registered through
//! `admission`, contracts are minted through `Issuer`, artifacts are read back
//! from the store, and the mediator verifies bytes the issuer actually signed.
//!
//! If a scenario can be made to pass by adjusting the harness, the harness is
//! wrong.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};

use warden::jsonrpc::{Request, Response};
use warden::upstream::Upstream;

use wc_control::admission::{self, AdmissionRequest, Declared, InlineSurface};
use wc_control::cpolicy::{ConnectPolicy, StandingState};
use wc_control::evidence::Evidence;
use wc_control::issuance::{ApprovalProof, ApproverRegistry, Issuer, Outcome, RequestInput};
use wc_control::store::{Actor, Store};
use wc_core::canon::SurfaceKind;
use wc_core::contract::{Algorithm, IssuerKey, IssuerKeys, Surface, Terms};
use wc_core::error::Mode;
use wc_core::model::{Entity, EntityId, HumanRef, Kind, Lifecycle, Posture, ZoneId};

pub const PRIV: &[u8] = include_bytes!("../../../../fixtures/keys/test_issuer_es256_priv.pem");
pub const PUB: &[u8] = include_bytes!("../../../../fixtures/keys/test_issuer_es256_pub.pem");
pub const APPROVER_PRIV: &[u8] = include_bytes!("../../../../fixtures/keys/test_anchor_priv.pem");
pub const APPROVER_PUB: &[u8] = include_bytes!("../../../../fixtures/keys/test_anchor_pub.pem");

pub const KID: &str = "wc-e2e-es256";
pub const MEDIATOR: &str = "warden:mediator:apac-ops";
pub const NOW: u64 = 1_785_312_500;
pub const DAY: u64 = 86_400;

// ---------------------------------------------------------------------------
// A scratch root that cleans up after itself
// ---------------------------------------------------------------------------

pub struct Root {
    pub dir: PathBuf,
}

impl Root {
    pub fn new(label: &str) -> Root {
        let dir = std::env::temp_dir().join(format!(
            "wc-e2e-{label}-{}-{:x}",
            std::process::id(),
            label.bytes().map(u64::from).sum::<u64>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch root");
        Root { dir }
    }

    pub fn state(&self) -> PathBuf {
        self.dir.join("state")
    }

    pub fn evidence(&self) -> PathBuf {
        self.dir.join("evidence")
    }

    pub fn chain_text(&self) -> String {
        std::fs::read_to_string(self.evidence().join("chain.jsonl")).unwrap_or_default()
    }

    /// Every event kind in the chain, in order. What an auditor would read.
    pub fn chain_kinds(&self) -> Vec<String> {
        self.chain_text()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter_map(|v| v.get("kind").and_then(Value::as_str).map(str::to_string))
            .collect()
    }

    /// Every chain entry, parsed. What an auditor reads.
    pub fn chain_entries(&self) -> Vec<Value> {
        self.chain_text()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .collect()
    }

    pub fn chain_has(&self, kind: &str) -> bool {
        self.chain_kinds().iter().any(|k| k == kind)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// Keys and approvers
// ---------------------------------------------------------------------------

pub fn signer() -> IssuerKey {
    IssuerKey::ec_pem(KID, PRIV, Algorithm::ES256).expect("issuer key")
}

pub fn verifier() -> IssuerKeys {
    let mut keys = IssuerKeys::new();
    keys.add_ec_pem(KID, PUB, Algorithm::ES256)
        .expect("verifier");
    keys
}

pub fn cecil() -> HumanRef {
    HumanRef::new("human:cecil@org").expect("approver")
}

pub fn dana() -> HumanRef {
    HumanRef::new("human:dana@org").expect("second approver")
}

pub fn priya() -> HumanRef {
    HumanRef::new("human:priya@org").expect("owner")
}

/// Both approvers hold every role the scenarios need, so a test that fails does
/// so for the reason it is named after rather than for a missing role.
pub fn approvers() -> ApproverRegistry {
    let mut r = ApproverRegistry::new();
    for who in [cecil(), dana()] {
        r.add_ec(
            &who,
            APPROVER_PUB,
            Algorithm::ES256,
            &[
                "security.architect",
                "payments.controller",
                "connect.secops",
            ],
        )
        .expect("approver registration");
    }
    r
}

pub fn approver_key(who: &HumanRef) -> IssuerKey {
    IssuerKey::ec_pem(who.as_str(), APPROVER_PRIV, Algorithm::ES256).expect("approver key")
}

// ---------------------------------------------------------------------------
// Surfaces
// ---------------------------------------------------------------------------

/// A tool-server surface with `n` tools, the first two read-only.
pub fn surface_of(n: usize) -> Value {
    let mut tools = vec![
        json!({"name": "get_balance", "description": "Return the cleared balance for an account.",
               "inputSchema": {"type": "object", "properties": {"account_id": {"type": "string"}}}}),
        json!({"name": "list_transactions", "description": "List transactions between two dates.",
               "inputSchema": {"type": "object", "properties": {"from": {"type": "string"}}}}),
    ];
    for i in 2..n {
        tools.push(json!({
            "name": format!("op_{i:02}"),
            "description": format!("Operation {i} against the ledger."),
            "inputSchema": {"type": "object"}
        }));
    }
    json!({ "tools": tools })
}

pub fn agent_card() -> Value {
    json!({
        "name": "recon-agent",
        "description": "Nightly ledger reconciliation.",
        "version": "2.4.1",
        "skills": [{"id": "reconcile", "description": "Reconcile the ledger."}]
    })
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// A reviewed policy: internal read-only tier ≥ 3 is standing; tier ≤ 2 needs an
/// architect; the partner zone carries the elevated bar; the vault is never
/// reachable.
pub fn policy() -> ConnectPolicy {
    ConnectPolicy::parse(&format!(
        r#"
default = "require_approval"
version = "e2e-policy@v1"
strict_crossings = true

[[crossing]]
crossing = "egress"
from = "internal.apac-ops"
to = "partner.acme"

[[zone]]
id = "internal.apac-ops"
trust = "internal"
[[zone]]
id = "internal.payments"
trust = "internal"
[[zone]]
id = "internal.vault"
trust = "internal"
[[zone]]
id = "partner.acme"
trust = "partner"
assurance = {{ identity = "required", provenance = "required", ttl_max = "7d", approval = "human", oversight = "required", max_delegation_depth = 1 }}

[standing]
reviewed_at = {reviewed}
review_every = "90d"
max_share = 0.9
share_min_sample = 20
min_callee_tier = 3
allow_write = false
max_tools = 8

[[rules]]
callee_zone = "internal.vault"
decision = "deny"
reason = "the vault is never connectable"

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
        reviewed = NOW - 30 * DAY
    ))
    .expect("policy parses")
}

// ---------------------------------------------------------------------------
// The estate
// ---------------------------------------------------------------------------

pub struct Estate {
    pub root: Root,
    pub store: Store,
    pub evidence: Evidence,
    pub policy: ConnectPolicy,
    pub now: u64,
}

impl Estate {
    pub fn new(label: &str) -> Estate {
        Estate::with_event_sinks(label, Vec::new())
    }

    /// The same estate with evidence sinks attached from the start.
    ///
    /// From the start rather than added later, because `chain.jsonl` is
    /// single-writer: a second `Evidence::open` on a live estate is refused, and
    /// rightly so.
    pub fn with_event_sinks(
        label: &str,
        sinks: Vec<Arc<dyn wc_control::sink::EventSink>>,
    ) -> Estate {
        let root = Root::new(label);
        let (store, report) = Store::open(root.state()).expect("store opens");
        assert!(report.is_clean(), "a fresh store must rebuild clean");
        let evidence = Evidence::open(root.evidence())
            .expect("chain opens")
            .with_event_sinks(sinks);
        Estate {
            root,
            store,
            evidence,
            policy: policy(),
            now: NOW,
        }
    }

    /// The state log's first segment, as a failure-injection scenario needs it.
    pub fn state_log(&self) -> PathBuf {
        self.root.state().join(format!(
            "{}-000001.jsonl",
            wc_control::store::STATE_LOG_NAME
        ))
    }

    /// Register a party through the real admission pipeline.
    ///
    /// Observe mode, because the P0 verifiers are honest stand-ins: every scenario
    /// that cares about attestation sets the posture explicitly afterwards, and
    /// says so.
    pub fn register(
        &mut self,
        id: &str,
        kind: Kind,
        zone: &str,
        raw_surface: &Value,
        surface_kind: SurfaceKind,
        service: Option<&str>,
    ) -> Entity {
        let request = AdmissionRequest {
            kind,
            id: Some(EntityId::new(id).expect("entity id")),
            card: (surface_kind == SurfaceKind::A2aCard).then(|| raw_surface.clone()),
            endpoint: (surface_kind == SurfaceKind::McpTools)
                .then(|| format!("https://{}/mcp", id.replace(['/', ':'], "-"))),
            attestation: Vec::new(),
            owner: priya(),
            zone: ZoneId::new(zone).expect("zone"),
            declared: Declared {
                data_classes: vec!["financial".to_string()],
                jurisdictions: vec!["SG".to_string()],
                requested_tier: None,
                service: service.map(str::to_string),
            },
            mode: Mode::Observe,
        };
        let source = InlineSurface::new(surface_kind, raw_surface.clone());
        let ctx = admission::observe_ctx(&source, self.now);
        let outcome = admission::admit(&request, &ctx).expect("admission");

        let entity = self
            .store
            .registry(self.actor(), self.now)
            .put(outcome.entity)
            .expect("registry write");
        self.evidence
            .record(
                &wc_control::evidence::LifecycleEvent::new(
                    wc_control::evidence::EventKind::Register,
                    priya().as_str(),
                )
                .with_entities([entity.id.as_str()]),
                self.now,
            )
            .expect("chain append");
        entity
    }

    pub fn actor(&self) -> Actor {
        Actor::Human { id: priya() }
    }

    /// Activate and mark attested — what a real deployment reaches after the
    /// attestation verifiers are configured. Scenarios that test admission itself
    /// do not call this.
    pub fn activate(&mut self, id: &EntityId) {
        let mut reg = self.store.registry(self.actor(), self.now);
        reg.transition(id, Lifecycle::Active, "e2e")
            .expect("activate");
        reg.set_posture(id, Posture::Attested, 95).expect("posture");
    }

    /// Quarantine through the real containment path. There is deliberately no way
    /// to reach `Posture::Quarantined` with `set_posture` — the registry refuses it,
    /// because quarantine revokes contracts and a posture write would not.
    pub fn quarantine(
        &mut self,
        id: &EntityId,
        reason: &str,
    ) -> wc_control::registry::QuarantineOutcome {
        self.store
            .registry(self.actor(), self.now)
            .quarantine(id, reason, &[])
            .expect("quarantine")
    }

    pub fn set_posture(&mut self, id: &EntityId, posture: Posture, score: u8) {
        self.store
            .registry(self.actor(), self.now)
            .set_posture(id, posture, score)
            .expect("posture");
    }

    pub fn entity(&self, id: &EntityId) -> Entity {
        self.store
            .projection
            .entities
            .get(id)
            .cloned()
            .unwrap_or_else(|| panic!("{id} is not registered"))
    }

    pub fn standing(&self) -> StandingState {
        let contracts = &self.store.projection.contracts;
        StandingState {
            active_contracts: contracts.len(),
            standing_contracts: contracts
                .values()
                .filter(|c| c.approval.mode == wc_core::contract::ApprovalMode::StandingPolicy)
                .count(),
            issued_in_window: 0,
        }
    }

    fn issuer<'a>(&'a mut self, key: &'a IssuerKey) -> Issuer<'a> {
        Issuer::new(
            &mut self.store,
            &mut self.evidence,
            &self.policy,
            key,
            "https://connect.e2e/t/apac",
            self.now,
            Actor::Human { id: priya() },
        )
    }

    /// Ask for a connection. Returns the outcome so a scenario can assert whether
    /// standing policy issued it or a human was required.
    pub fn request(
        &mut self,
        caller: &EntityId,
        callee: &EntityId,
        tools: &[&str],
        ttl: u64,
    ) -> Outcome {
        self.try_request(caller, callee, tools, ttl)
            .expect("request evaluates")
    }

    /// The same, keeping the error. Failure-injection scenarios need the code the
    /// issuer refused with, and — more importantly — need to go on to assert that
    /// nothing partial survived the refusal.
    pub fn try_request(
        &mut self,
        caller: &EntityId,
        callee: &EntityId,
        tools: &[&str],
        ttl: u64,
    ) -> wc_core::error::Result<Outcome> {
        let key = signer();
        let input = RequestInput {
            caller: caller.clone(),
            callee: callee.clone(),
            surface: Surface {
                tools: tools.iter().map(|t| (*t).to_string()).collect(),
                ..Default::default()
            },
            terms: Terms {
                data_classes: vec!["financial".to_string()],
                jurisdictions: vec!["SG".to_string()],
                ..Default::default()
            },
            ttl_secs: ttl,
            justification: "e2e scenario".to_string(),
            requester: priya(),
            mediators: vec![MEDIATOR.to_string()],
        };
        // The issuer borrows the store and the chain, so it is built and dropped
        // per call rather than held.
        let policy = self.policy.clone();
        let now = self.now;
        let mut issuer = Issuer::new(
            &mut self.store,
            &mut self.evidence,
            &policy,
            &key,
            "https://connect.e2e/t/apac",
            now,
            Actor::Human { id: priya() },
        );
        issuer.request(&input)
    }

    /// Approve a pending request with one or two humans.
    pub fn approve(&mut self, request_id: &str, who: &[HumanRef]) -> wc_control::issuance::Issued {
        let key = signer();
        let registry = approvers();
        let policy = self.policy.clone();
        let now = self.now;
        let mut issuer = Issuer::new(
            &mut self.store,
            &mut self.evidence,
            &policy,
            &key,
            "https://connect.e2e/t/apac",
            now,
            Actor::Human { id: priya() },
        );
        let pending = issuer.pending_request(request_id).expect("pending request");
        let proofs: Vec<ApprovalProof> = who
            .iter()
            .map(|h| ApprovalProof {
                by: h.clone(),
                jws: wc_control::issuance::sign_approval(
                    &pending,
                    &approver_key(h),
                    Some("RISK-E2E"),
                    now,
                )
                .expect("approval signature"),
            })
            .collect();
        issuer
            .approve(request_id, &proofs, &registry)
            .expect("approval mints")
    }

    /// Request and, if a human is needed, approve — the shortest path to a live
    /// contract.
    pub fn connect(
        &mut self,
        caller: &EntityId,
        callee: &EntityId,
        tools: &[&str],
        ttl: u64,
    ) -> wc_control::issuance::Issued {
        match self.request(caller, callee, tools, ttl) {
            Outcome::Issued(issued) => issued,
            Outcome::AwaitingApproval(req) => self.approve(&req.id, &[cecil(), dana()]),
            Outcome::Denied { reason, trace } => {
                panic!("policy denied a connection the scenario expected: {reason} [{trace}]")
            }
        }
    }

    /// The artifact the issuer persisted, read back from the store — the same
    /// bytes a pulling mediator receives.
    pub fn artifact(&self, cid: &str) -> String {
        self.store
            .read_artifact(cid, MEDIATOR)
            .unwrap_or_else(|| panic!("no stored artifact for {cid}"))
    }
}

// ---------------------------------------------------------------------------
// A stub MCP server that records what it was actually asked
// ---------------------------------------------------------------------------

/// A handle the test keeps after the server is moved into the gate.
///
/// The negative assertion every filtering claim rests on lives here: not "the
/// agent could not see it" but **"the upstream never ran it"**.
#[derive(Clone, Default)]
pub struct Recorder(Arc<std::sync::Mutex<Record>>);

#[derive(Default)]
pub struct Record {
    pub methods: Vec<String>,
    pub executed: Vec<String>,
}

impl Recorder {
    pub fn methods(&self) -> Vec<String> {
        self.0.lock().expect("recorder").methods.clone()
    }

    /// Tool names the upstream actually executed.
    pub fn executed(&self) -> Vec<String> {
        self.0.lock().expect("recorder").executed.clone()
    }

    pub fn ran(&self, tool: &str) -> usize {
        self.executed().iter().filter(|t| *t == tool).count()
    }
}

pub struct StubServer {
    tools: Vec<Value>,
    recorder: Recorder,
}

impl StubServer {
    pub fn new(surface: &Value) -> (StubServer, Recorder) {
        let recorder = Recorder::default();
        (
            StubServer {
                tools: surface["tools"].as_array().cloned().unwrap_or_default(),
                recorder: recorder.clone(),
            },
            recorder,
        )
    }

    /// Replace the surface mid-flight — a rug-pull, from the mediator's point of
    /// view.
    pub fn set_surface(&mut self, surface: &Value) {
        self.tools = surface["tools"].as_array().cloned().unwrap_or_default();
    }
}

impl Upstream for StubServer {
    fn request(&mut self, req: &Request) -> Response {
        self.recorder
            .0
            .lock()
            .expect("recorder")
            .methods
            .push(req.method.clone());
        match req.method.as_str() {
            "initialize" => Response::ok(
                req.id.clone(),
                json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                       "serverInfo": {"name": "payments-mcp", "version": "1.0.0"}}),
            ),
            "tools/list" => Response::ok(req.id.clone(), json!({"tools": self.tools})),
            "tools/call" => {
                let name = req
                    .params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                self.recorder
                    .0
                    .lock()
                    .expect("recorder")
                    .executed
                    .push(name.clone());
                Response::ok(
                    req.id.clone(),
                    json!({"content": [{"type": "text", "text": format!("{name} ran")}]}),
                )
            }
            other => Response::ok(req.id.clone(), json!({"echo": other})),
        }
    }
}

/// Tool names visible in a `tools/list` response.
pub fn visible_tools(response: &Response) -> Vec<String> {
    response
        .result
        .as_ref()
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The refusal text, wherever the mediator put it.
///
/// A connection refusal is a JSON-RPC error; a *call* refusal is an MCP tool error
/// carried in a successful response, so the agent handles it as a failed call
/// rather than a broken transport. Asserting on `response.error` alone would read a
/// tool denial as a success — which is precisely the mistake a test is for.
pub fn refusal(response: &Response) -> Option<String> {
    if let Some(err) = &response.error {
        return Some(err.message.clone());
    }
    let result = response.result.as_ref()?;
    if result.get("isError").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let text: String = result
        .get("content")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|c| c.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    Some(text)
}

/// Whether the call was allowed through.
pub fn allowed(response: &Response) -> bool {
    refusal(response).is_none()
}

pub fn req(id: u64, method: &str, params: Value) -> Request {
    Request {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(id)),
        method: method.to_string(),
        params,
    }
}

/// Event kind → count, for asserting what the chain recorded.
pub fn kind_counts(kinds: &[String]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for k in kinds {
        *m.entry(k.clone()).or_insert(0) += 1;
    }
    m
}
