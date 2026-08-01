//! The admission pipeline (`docs/08-lld.md` §8.5.4, §8.7.3).
//!
//! Registration is not self-service assertion; it is a **decision**. Seven
//! stages, each with a typed verdict, and the outcome always records what was
//! checked *and what was skipped* — an admission that silently omits provenance
//! is worse than one that says it omitted it.
//!
//! # Stage 2 is unforgiving on purpose
//!
//! Every other stage degrades in observe mode. Surface acquisition does not: if
//! the declared surface cannot be fetched, nothing is pinned and nothing is
//! registered, in either mode (UC-02 A3). There is no "register on trust" — a
//! record with no pin would be an entity whose surface can never be shown to have
//! changed.
//!
//! # Pluggable verifiers
//!
//! Each stage is a trait so the P0 wedge can ship with honest no-op verifiers and
//! P2 can substitute real ones without restructuring. Every no-op reports
//! [`StageVerdict::Skipped`], which propagates into the entity's posture:
//! a party that skipped identity and provenance is [`Posture::Unattested`], not
//! attested-by-default.

use serde_json::{json, Value};

use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::error::{Code, Mode, Result, WcError};
use wc_core::model::{
    Entity, EntityId, HumanRef, Kind, Pin, Posture, ProvRef, Tier, TrustLevel, ZoneId,
};

// ---------------------------------------------------------------------------
// Request and outcome
// ---------------------------------------------------------------------------

/// What the party (or its CI pipeline) declares about itself. Self-asserted, and
/// treated as such: the declaring party is accountable for the assertion, which
/// is exactly how third-party attestations already work.
#[derive(Debug, Clone, Default)]
pub struct Declared {
    /// Data classes this party touches.
    pub data_classes: Vec<String>,
    /// Jurisdictions it operates in.
    pub jurisdictions: Vec<String>,
    /// The most sensitive tier the requester is willing to accept. Admission may
    /// derive something *more* sensitive, and then refuses rather than silently
    /// downgrading.
    pub requested_tier: Option<Tier>,
    /// Business service reference.
    pub service: Option<String>,
}

/// An admission request.
#[derive(Debug, Clone)]
pub struct AdmissionRequest {
    /// Agent, MCP server or A2A agent.
    pub kind: Kind,
    /// Claimed wire identity. Verified at stage 1, never trusted as given.
    pub id: Option<EntityId>,
    /// A signed agent card, where one was supplied.
    pub card: Option<Value>,
    /// MCP endpoint, for servers.
    pub endpoint: Option<String>,
    /// Provenance material — a Sigstore bundle, an in-toto attestation.
    pub attestation: Vec<ProvRef>,
    /// The accountable human. Required by type: invariant 1.
    pub owner: HumanRef,
    /// Trust zone.
    pub zone: ZoneId,
    /// Self-declared metadata.
    pub declared: Declared,
    /// Enforce or observe.
    pub mode: Mode,
}

/// The pipeline stages, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// 1 · workload identity.
    Identity,
    /// 2 · declared-surface acquisition.
    Surface,
    /// 3 · agent-card signature.
    CardSignature,
    /// 4 · build provenance.
    Provenance,
    /// 5 · declared-surface injection screening.
    Screening,
    /// 6 · risk-tier derivation.
    Tier,
    /// 7 · canonicalisation and pinning.
    Pin,
}

impl Stage {
    /// The code raised when this stage fails.
    #[must_use]
    pub const fn failure_code(self) -> Code {
        match self {
            Stage::Identity => Code::IDENTITY_UNVERIFIABLE,
            Stage::Surface => Code::SURFACE_UNOBTAINABLE,
            Stage::CardSignature => Code::CARD_SIGNATURE_INVALID,
            Stage::Provenance => Code::PROVENANCE_UNVERIFIABLE,
            Stage::Screening => Code::SCREENING_BLOCKED,
            Stage::Tier => Code::TIER_EXCEEDS_CEILING,
            Stage::Pin => Code::PIN_WRITE_FAILED,
        }
    }
}

/// How a stage turned out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageVerdict {
    /// Checked and satisfied.
    Passed(String),
    /// Not checked, with the reason. Never silently omitted.
    Skipped(String),
    /// Checked and unsatisfied, but the mode allows continuing with a finding.
    Degraded(String),
}

/// One stage's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageResult {
    /// Which stage.
    pub stage: Stage,
    /// What happened.
    pub verdict: StageVerdict,
}

/// Finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational.
    Low,
    /// Worth an owner's attention.
    Medium,
    /// Blocks in enforce mode.
    High,
    /// Blocks in every mode.
    Critical,
}

/// Something worth recording about a party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The code this finding maps to.
    pub code: Code,
    /// Human detail.
    pub detail: String,
    /// How serious.
    pub severity: Severity,
}

/// The result of a successful admission.
#[derive(Debug, Clone)]
pub struct AdmissionOutcome {
    /// The entity to write to the registry, `Pending` until the caller activates
    /// it. Admission decides; the registry records.
    pub entity: Entity,
    /// Everything noteworthy that did not block.
    pub findings: Vec<Finding>,
    /// Why this tier — shown to the approver, because a tier nobody can explain
    /// gets argued rather than applied.
    pub tier_rationale: String,
    /// Per-stage verdicts, for the evidence record.
    pub stages: Vec<StageResult>,
}

impl AdmissionOutcome {
    /// Whether every stage was actually checked and satisfied.
    #[must_use]
    pub fn fully_attested(&self) -> bool {
        self.stages
            .iter()
            .all(|s| matches!(s.verdict, StageVerdict::Passed(_)))
    }

    /// Stages that were not checked.
    #[must_use]
    pub fn skipped(&self) -> Vec<Stage> {
        self.stages
            .iter()
            .filter(|s| matches!(s.verdict, StageVerdict::Skipped(_)))
            .map(|s| s.stage)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Stage traits
// ---------------------------------------------------------------------------

/// Proof of a party's workload identity.
#[derive(Debug, Clone)]
pub struct IdentityProof {
    /// The authenticated identity.
    pub id: EntityId,
    /// How it was established.
    pub method: String,
    /// False when the identity was merely asserted.
    pub verified: bool,
}

/// Stage 1.
pub trait IdentityVerifier {
    /// Establish the party's wire identity.
    fn verify_identity(&self, req: &AdmissionRequest) -> Result<IdentityProof>;
}

/// A declared surface as fetched.
#[derive(Debug, Clone)]
pub struct FetchedSurface {
    /// Which shape it is.
    pub kind: SurfaceKind,
    /// The raw document.
    pub raw: Value,
    /// Where it came from, for the evidence record.
    pub source: String,
}

/// Stage 2.
pub trait SurfaceSource {
    /// Obtain the declared surface. Failure is fatal in every mode.
    fn fetch_surface(&self, req: &AdmissionRequest) -> Result<FetchedSurface>;
}

/// Stage 3 result.
#[derive(Debug, Clone)]
pub struct CardProof {
    /// Whether a signature was verified.
    pub verified: bool,
    /// How, or why not.
    pub method: String,
}

/// Stage 3.
pub trait CardVerifier {
    /// Verify the agent card's signature.
    fn verify_card(&self, req: &AdmissionRequest, fetched: &FetchedSurface) -> Result<CardProof>;
}

/// Stage 4 result.
#[derive(Debug, Clone)]
pub struct ProvenanceProof {
    /// Whether provenance was verified.
    pub verified: bool,
    /// The references to record.
    pub refs: Vec<ProvRef>,
    /// How, or why not.
    pub method: String,
}

/// Stage 4.
pub trait ProvenanceVerifier {
    /// Verify build provenance for the artifact behind this party.
    fn verify_provenance(&self, req: &AdmissionRequest) -> Result<ProvenanceProof>;
}

/// Stage 5 result.
#[derive(Debug, Clone, Default)]
pub struct ScreenReport {
    /// Whether screening ran at all.
    pub ran: bool,
    /// Whether a block-class detector fired.
    pub blocked: bool,
    /// Everything found.
    pub findings: Vec<Finding>,
    /// Detector ruleset version, so a result is attributable.
    pub ruleset: String,
}

/// Stage 5.
pub trait Screener {
    /// Screen the declared surface for instruction-injection patterns.
    fn screen(&self, fetched: &FetchedSurface) -> Result<ScreenReport>;
}

// ---------------------------------------------------------------------------
// P0 verifiers
// ---------------------------------------------------------------------------

/// Takes the claimed identity at face value and says so.
///
/// `verified: false` means admission raises [`Code::IDENTITY_UNVERIFIABLE`],
/// which fails closed in enforce mode. So this verifier can only ever admit
/// anything in observe mode — which is exactly the P0 wedge.
#[derive(Debug, Default)]
pub struct AssertedIdentity;

impl IdentityVerifier for AssertedIdentity {
    fn verify_identity(&self, req: &AdmissionRequest) -> Result<IdentityProof> {
        let id = req.id.clone().ok_or_else(|| {
            WcError::with_detail(
                Code::IDENTITY_UNVERIFIABLE,
                "no identity supplied and none can be derived",
            )
        })?;
        Ok(IdentityProof {
            id,
            method: "asserted (unverified)".to_string(),
            verified: false,
        })
    }
}

/// A surface supplied inline — a card handed to `connect register agent`, or a
/// manifest captured by CI.
#[derive(Debug)]
pub struct InlineSurface {
    kind: SurfaceKind,
    raw: Value,
}

impl InlineSurface {
    /// Wrap an already-obtained surface document.
    #[must_use]
    pub fn new(kind: SurfaceKind, raw: Value) -> Self {
        InlineSurface { kind, raw }
    }
}

impl SurfaceSource for InlineSurface {
    fn fetch_surface(&self, _req: &AdmissionRequest) -> Result<FetchedSurface> {
        Ok(FetchedSurface {
            kind: self.kind,
            raw: self.raw.clone(),
            source: "inline".to_string(),
        })
    }
}

/// No card signature verification (P0).
#[derive(Debug, Default)]
pub struct UnverifiedCard;

impl CardVerifier for UnverifiedCard {
    fn verify_card(&self, _req: &AdmissionRequest, _f: &FetchedSurface) -> Result<CardProof> {
        Ok(CardProof {
            verified: false,
            method: "card signature verification not configured".to_string(),
        })
    }
}

/// No provenance verification (P0). Records whatever references were supplied
/// without claiming they were checked.
#[derive(Debug, Default)]
pub struct UnverifiedProvenance;

impl ProvenanceVerifier for UnverifiedProvenance {
    fn verify_provenance(&self, req: &AdmissionRequest) -> Result<ProvenanceProof> {
        Ok(ProvenanceProof {
            verified: false,
            refs: req.attestation.clone(),
            method: "provenance verification not configured".to_string(),
        })
    }
}

/// No screening (P0).
#[derive(Debug, Default)]
pub struct NoScreening;

impl Screener for NoScreening {
    fn screen(&self, _f: &FetchedSurface) -> Result<ScreenReport> {
        Ok(ScreenReport {
            ran: false,
            blocked: false,
            findings: Vec::new(),
            ruleset: "none".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// MCP surface acquisition over HTTP
// ---------------------------------------------------------------------------

/// Fetches a server's declared surface with a real MCP handshake:
/// `initialize`, then `tools/list` (§8.5.4 stage 2).
#[derive(Debug, Clone)]
pub struct McpHttpSurface {
    timeout_secs: u64,
    max_bytes: u64,
    protocol_version: String,
}

impl Default for McpHttpSurface {
    fn default() -> Self {
        McpHttpSurface {
            timeout_secs: 10,
            max_bytes: 4 * 1024 * 1024,
            protocol_version: "2025-06-18".to_string(),
        }
    }
}

impl McpHttpSurface {
    /// Override the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// The `initialize` request body.
    #[must_use]
    pub fn initialize_body(&self) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": self.protocol_version,
                "capabilities": {},
                "clientInfo": { "name": "warden-connect-admission", "version": "0.1.0" }
            }
        })
    }

    /// The `tools/list` request body.
    #[must_use]
    pub fn tools_list_body() -> Value {
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} })
    }

    /// Pull the `result` out of a JSON-RPC response, turning an `error` member
    /// into a failure rather than a surface.
    pub fn parse_result(text: &str) -> Result<Value> {
        let parsed: Value = serde_json::from_str(text).map_err(|e| {
            WcError::with_detail(Code::SURFACE_UNOBTAINABLE, "response is not JSON").with_source(e)
        })?;
        if let Some(error) = parsed.get("error") {
            return Err(WcError::with_detail(
                Code::SURFACE_UNOBTAINABLE,
                format!("server returned a JSON-RPC error: {error}"),
            ));
        }
        parsed.get("result").cloned().ok_or_else(|| {
            WcError::with_detail(
                Code::SURFACE_UNOBTAINABLE,
                "response has neither `result` nor `error`",
            )
        })
    }
}

impl SurfaceSource for McpHttpSurface {
    fn fetch_surface(&self, req: &AdmissionRequest) -> Result<FetchedSurface> {
        let endpoint = req.endpoint.as_deref().ok_or_else(|| {
            WcError::with_detail(
                Code::SURFACE_UNOBTAINABLE,
                "an MCP server must declare an endpoint",
            )
        })?;

        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(self.timeout_secs)))
            .max_redirects(0)
            .build()
            .into();

        // 1 · initialize. The session id, if the server issues one, must ride on
        // the follow-up request or a spec-compliant server will reject it.
        let mut resp = agent
            .post(endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .send(self.initialize_body().to_string())
            .map_err(|e| {
                WcError::with_detail(
                    Code::SURFACE_UNOBTAINABLE,
                    format!("{endpoint}: initialize failed"),
                )
                .with_source(e)
            })?;

        let session = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let init_text = read_body(&mut resp, self.max_bytes, endpoint)?;
        McpHttpSurface::parse_result(&init_text)?;

        // 2 · tools/list.
        let mut builder = agent
            .post(endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(id) = &session {
            builder = builder.header("mcp-session-id", id);
        }
        let mut resp = builder
            .send(McpHttpSurface::tools_list_body().to_string())
            .map_err(|e| {
                WcError::with_detail(
                    Code::SURFACE_UNOBTAINABLE,
                    format!("{endpoint}: tools/list failed"),
                )
                .with_source(e)
            })?;
        let list_text = read_body(&mut resp, self.max_bytes, endpoint)?;
        let result = McpHttpSurface::parse_result(&list_text)?;

        Ok(FetchedSurface {
            kind: SurfaceKind::McpTools,
            raw: result,
            source: endpoint.to_string(),
        })
    }
}

fn read_body(
    resp: &mut ureq::http::Response<ureq::Body>,
    max: u64,
    endpoint: &str,
) -> Result<String> {
    resp.body_mut()
        .with_config()
        .limit(max)
        .read_to_string()
        .map_err(|e| {
            WcError::with_detail(
                Code::SURFACE_UNOBTAINABLE,
                format!("{endpoint}: cannot read response body"),
            )
            .with_source(e)
        })
}

// ---------------------------------------------------------------------------
// Tier derivation
// ---------------------------------------------------------------------------

/// Capability classes, most sensitive first (§8.7.3).
const CLASS_1_KEYWORDS: &[&str] = &[
    "transfer",
    "wire",
    "payment",
    "pay",
    "refund",
    "withdraw",
    "settle",
    "delete",
    "drop",
    "destroy",
    "terminate",
    "truncate",
    "revoke",
    "grant",
    "iam",
    "role",
    "permission",
    "policy",
    "exec",
    "eval",
    "shell",
    "command",
    "deploy",
    "provision",
    "rotate_key",
    "credential",
];

const CLASS_2_KEYWORDS: &[&str] = &[
    "send", "email", "sms", "post", "publish", "upload", "export", "share", "write", "create",
    "update", "insert", "patch", "put", "notify", "webhook", "invite", "comment", "message",
];

const CLASS_3_KEYWORDS: &[&str] = &[
    "read", "get", "list", "fetch", "query", "search", "describe", "lookup", "balance", "history",
];

/// Indicative data-residency groups. Declaring jurisdictions in more than one
/// group escalates the tier.
///
/// The default is deliberately coarse and **configurable**: a real estate's
/// residency boundaries are a legal question, not a library constant.
pub const DEFAULT_RESIDENCY_GROUPS: &[&[&str]] = &[
    &[
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT",
        "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO",
    ],
    &["GB"],
    &["US", "CA"],
    &["AU", "NZ"],
    &["SG", "MY", "HK", "JP", "KR", "TW"],
    &["IN"],
    &["CN"],
    &["AE", "SA", "QA"],
    &["BR", "MX", "AR"],
    &["ZA", "NG", "KE"],
];

/// Tunables for tier derivation.
#[derive(Debug, Clone)]
pub struct TierRules {
    /// Residency groups; spanning more than one escalates.
    pub residency_groups: &'static [&'static [&'static str]],
}

impl Default for TierRules {
    fn default() -> Self {
        TierRules {
            residency_groups: DEFAULT_RESIDENCY_GROUPS,
        }
    }
}

/// The capability class of one declared item, 1 (most sensitive) to 4.
///
/// Annotations are the callee's self-assessment: `destructiveHint` may **raise**
/// severity, `readOnlyHint` may only lower it for items whose names do not
/// already say otherwise. A tool called `wire_funds` that claims to be read-only
/// is not read-only.
#[must_use]
pub fn capability_class(name: &str, item: &Value) -> u8 {
    let haystack = format!(
        "{} {}",
        name.to_ascii_lowercase(),
        item.get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase()
    );

    let annotations = item.get("annotations");
    let destructive = annotations
        .and_then(|a| a.get("destructiveHint"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let read_only = annotations
        .and_then(|a| a.get("readOnlyHint"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let name_lower = name.to_ascii_lowercase();
    let mut class = if CLASS_1_KEYWORDS.iter().any(|k| name_lower.contains(k)) {
        1
    } else if CLASS_2_KEYWORDS.iter().any(|k| name_lower.contains(k)) {
        2
    } else if CLASS_3_KEYWORDS.iter().any(|k| name_lower.contains(k)) {
        3
    } else if CLASS_1_KEYWORDS.iter().any(|k| haystack.contains(k)) {
        // The name said nothing, but the description describes money movement or
        // destruction. Trust the more alarming signal.
        1
    } else {
        // Unmapped is class 2, not 4: an unclassified capability is treated as
        // significant until someone classifies it.
        2
    };

    if destructive {
        class = class.min(1);
    }
    if read_only && class >= 3 {
        class = 3;
    }
    class
}

/// Base tier implied by a data class.
fn data_class_tier(class: &str) -> u8 {
    match class.to_ascii_lowercase().as_str() {
        "restricted" | "pii" | "phi" | "pci" | "secret" => 1,
        "confidential" => 2,
        "internal" => 3,
        "public" => 4,
        // An unrecognised data class is significant until classified.
        _ => 2,
    }
}

/// Whether an item's shape is unbounded — a wildcard name, or a schema that
/// accepts arbitrary properties.
fn is_unbounded(name: &str, item: &Value) -> bool {
    if name.contains('*') || name.contains('?') {
        return true;
    }
    let schema = item.get("inputSchema");
    let additional = schema
        .and_then(|s| s.get("additionalProperties"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let has_properties = schema
        .and_then(|s| s.get("properties"))
        .and_then(Value::as_object)
        .is_some_and(|p| !p.is_empty());
    additional && !has_properties
}

/// Derive the risk tier, with the rationale that will be shown to an approver.
///
/// `tier = min(data-class base, capability class)`, then one step more sensitive
/// for an external zone, an unbounded surface, or jurisdictions spanning more than
/// one residency group.
#[must_use]
pub fn derive_tier(
    declared: &Declared,
    fetched: &FetchedSurface,
    zone: &ZoneId,
    rules: &TierRules,
) -> (Tier, String) {
    let mut why: Vec<String> = Vec::new();

    let base = declared
        .data_classes
        .iter()
        .map(|c| data_class_tier(c))
        .min()
        .unwrap_or(2);
    if declared.data_classes.is_empty() {
        why.push("no data classes declared, treated as tier 2".to_string());
    } else {
        why.push(format!(
            "data classes {:?} imply tier {base}",
            declared.data_classes
        ));
    }

    let items = surface_items(fetched);
    let mut cap = 4u8;
    let mut cap_item = String::new();
    let mut unbounded = false;
    for (name, item) in &items {
        let class = capability_class(name, item);
        if class < cap {
            cap = class;
            cap_item = name.clone();
        }
        if is_unbounded(name, item) {
            unbounded = true;
        }
    }
    if items.is_empty() {
        cap = 4;
        why.push("no declared items".to_string());
    } else {
        why.push(format!(
            "{} declared items; most sensitive is {cap_item:?} at capability class {cap}",
            items.len()
        ));
    }

    let mut tier = base.min(cap);

    if zone.trust_level() != TrustLevel::Internal {
        tier = tier.saturating_sub(1).max(1);
        why.push(format!(
            "zone {zone} is {:?}, escalated one step",
            zone.trust_level()
        ));
    }
    if unbounded {
        tier = tier.saturating_sub(1).max(1);
        why.push("an unbounded or wildcard item, escalated one step".to_string());
    }
    if spans_residency_groups(&declared.jurisdictions, rules) {
        tier = tier.saturating_sub(1).max(1);
        why.push(format!(
            "jurisdictions {:?} span more than one residency group, escalated one step",
            declared.jurisdictions
        ));
    }

    let tier = tier.clamp(1, 4);
    // `tier` is in 1..=4 by construction, so this cannot fail; fall back to the
    // most sensitive tier rather than panicking if that ever stops being true.
    let tier = Tier::new(tier).unwrap_or(Tier::ONE);
    why.push(format!("derived {tier}"));
    (tier, why.join("; "))
}

/// Item name → item document, for whichever surface shape this is.
fn surface_items(fetched: &FetchedSurface) -> Vec<(String, Value)> {
    let array = match fetched.kind {
        SurfaceKind::McpTools => fetched
            .raw
            .get("tools")
            .and_then(Value::as_array)
            .or_else(|| fetched.raw.as_array()),
        SurfaceKind::A2aCard => fetched.raw.get("skills").and_then(Value::as_array),
    };
    array
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let name = item
                        .get("name")
                        .or_else(|| item.get("id"))
                        .and_then(Value::as_str)?;
                    Some((name.to_string(), item.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn spans_residency_groups(jurisdictions: &[String], rules: &TierRules) -> bool {
    let mut groups: Vec<usize> = jurisdictions
        .iter()
        .filter_map(|j| {
            let upper = j.to_ascii_uppercase();
            rules
                .residency_groups
                .iter()
                .position(|group| group.contains(&upper.as_str()))
        })
        .collect();
    groups.sort_unstable();
    groups.dedup();
    groups.len() > 1
}

// ---------------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------------

/// The verifiers and settings admission runs with.
pub struct AdmissionCtx<'a> {
    /// Stage 1.
    pub identity: &'a dyn IdentityVerifier,
    /// Stage 2.
    pub surface: &'a dyn SurfaceSource,
    /// Stage 3.
    pub card: &'a dyn CardVerifier,
    /// Stage 4.
    pub provenance: &'a dyn ProvenanceVerifier,
    /// Stage 5.
    pub screener: &'a dyn Screener,
    /// Canonicalisation limits.
    pub limits: Limits,
    /// Tier tunables.
    pub tier_rules: TierRules,
    /// Wall clock.
    pub now: u64,
}

impl std::fmt::Debug for AdmissionCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionCtx")
            .field("limits", &self.limits)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Run the admission pipeline.
///
/// On success the entity is `Pending`: admission decides, the registry records,
/// and activation is a separate act. Registration is not connectivity.
pub fn admit(req: &AdmissionRequest, ctx: &AdmissionCtx<'_>) -> Result<AdmissionOutcome> {
    let mut stages: Vec<StageResult> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();

    // --- 1 · identity ---
    let identity = ctx.identity.verify_identity(req)?;
    record(
        &mut stages,
        &mut findings,
        Stage::Identity,
        identity.verified,
        &identity.method,
        req.mode,
        Severity::High,
    )?;

    // --- 2 · surface acquisition: fatal in every mode ---
    let fetched = ctx.surface.fetch_surface(req)?;
    stages.push(StageResult {
        stage: Stage::Surface,
        verdict: StageVerdict::Passed(format!("{:?} from {}", fetched.kind, fetched.source)),
    });

    // --- 3 · card signature ---
    let card = ctx.card.verify_card(req, &fetched)?;
    record(
        &mut stages,
        &mut findings,
        Stage::CardSignature,
        card.verified,
        &card.method,
        req.mode,
        Severity::Medium,
    )?;

    // --- 4 · provenance ---
    let provenance = ctx.provenance.verify_provenance(req)?;
    record(
        &mut stages,
        &mut findings,
        Stage::Provenance,
        provenance.verified,
        &provenance.method,
        req.mode,
        Severity::High,
    )?;

    // --- 5 · screening: a block fires in every mode ---
    let screen = ctx.screener.screen(&fetched)?;
    findings.extend(screen.findings.clone());
    if screen.blocked {
        return Err(WcError::with_detail(
            Code::SCREENING_BLOCKED,
            format!(
                "declared surface blocked by screening ruleset {}",
                screen.ruleset
            ),
        ));
    }
    stages.push(StageResult {
        stage: Stage::Screening,
        verdict: if screen.ran {
            StageVerdict::Passed(format!("ruleset {}", screen.ruleset))
        } else {
            StageVerdict::Skipped("screening not configured".to_string())
        },
    });

    // --- 6 · tier ---
    let (tier, tier_rationale) = derive_tier(&req.declared, &fetched, &req.zone, &ctx.tier_rules);
    if let Some(ceiling) = req.declared.requested_tier {
        if tier.is_at_least_as_sensitive_as(ceiling) && tier != ceiling {
            return Err(WcError::with_detail(
                Code::TIER_EXCEEDS_CEILING,
                format!("derived {tier} is more sensitive than the requested {ceiling}: {tier_rationale}"),
            ));
        }
    }
    stages.push(StageResult {
        stage: Stage::Tier,
        verdict: StageVerdict::Passed(tier_rationale.clone()),
    });

    // --- 7 · canonicalise and pin ---
    let pin: Pin = canon::pin(
        fetched.kind,
        &identity.id,
        &fetched.raw,
        &ctx.limits,
        ctx.now,
    )?;
    stages.push(StageResult {
        stage: Stage::Pin,
        verdict: StageVerdict::Passed(format!("{} ({} items)", pin.manifest, pin.items.len())),
    });

    // Posture reflects what was actually verified. Skipping identity or
    // provenance means unattested — never attested-by-default.
    let posture = if identity.verified && card.verified && provenance.verified {
        Posture::Attested
    } else {
        Posture::Unattested
    };

    let mut entity = Entity::pending(
        identity.id,
        req.kind,
        req.owner.clone(),
        req.zone.clone(),
        tier,
        ctx.now,
    );
    entity.service = req.declared.service.clone();
    entity.data_classes = req.declared.data_classes.clone();
    entity.jurisdictions = req.declared.jurisdictions.clone();
    entity.endpoint = req.endpoint.clone();
    entity.provenance = provenance.refs;
    entity.pin = pin;
    entity.posture = posture;
    entity.reattested_at = if posture == Posture::Attested {
        ctx.now
    } else {
        0
    };

    Ok(AdmissionOutcome {
        entity,
        findings,
        tier_rationale,
        stages,
    })
}

/// Record a stage that either passed or did not, applying the mode's fail
/// direction from the code table rather than re-deciding it here.
fn record(
    stages: &mut Vec<StageResult>,
    findings: &mut Vec<Finding>,
    stage: Stage,
    verified: bool,
    method: &str,
    mode: Mode,
    severity: Severity,
) -> Result<()> {
    if verified {
        stages.push(StageResult {
            stage,
            verdict: StageVerdict::Passed(method.to_string()),
        });
        return Ok(());
    }

    let code = stage.failure_code();
    if code.denies_in(mode) {
        return Err(WcError::with_detail(code, method.to_string()));
    }
    findings.push(Finding {
        code,
        detail: method.to_string(),
        severity,
    });
    stages.push(StageResult {
        stage,
        verdict: StageVerdict::Skipped(method.to_string()),
    });
    Ok(())
}

/// The P0 context: honest no-op verifiers plus a supplied surface. Only ever
/// admits in observe mode, because nothing is actually verified.
#[must_use]
pub fn observe_ctx<'a>(surface: &'a dyn SurfaceSource, now: u64) -> AdmissionCtx<'a> {
    AdmissionCtx {
        identity: &AssertedIdentity,
        surface,
        card: &UnverifiedCard,
        provenance: &UnverifiedProvenance,
        screener: &NoScreening,
        limits: Limits::default(),
        tier_rules: TierRules::default(),
        now,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn owner() -> HumanRef {
        HumanRef::new("human:priya@org").unwrap()
    }

    fn zone(s: &str) -> ZoneId {
        ZoneId::new(s).unwrap()
    }

    fn server_id() -> EntityId {
        EntityId::new("spiffe://org/ns/tools/sa/payments-mcp").unwrap()
    }

    fn tools() -> Value {
        json!({"tools": [
            {"name": "get_balance", "description": "Read an account balance.",
             "annotations": {"readOnlyHint": true}},
            {"name": "list_transactions", "description": "List recent transactions."}
        ]})
    }

    fn request(mode: Mode, declared: Declared) -> AdmissionRequest {
        AdmissionRequest {
            kind: Kind::McpServer,
            id: Some(server_id()),
            card: None,
            endpoint: Some("https://payments-mcp.internal/mcp".to_string()),
            attestation: vec![],
            owner: owner(),
            zone: zone("internal.payments"),
            declared,
            mode,
        }
    }

    fn fetched(raw: Value) -> FetchedSurface {
        FetchedSurface {
            kind: SurfaceKind::McpTools,
            raw,
            source: "test".to_string(),
        }
    }

    // --- the pipeline ---

    #[test]
    fn observe_mode_admits_unattested_and_says_what_it_skipped() {
        let source = InlineSurface::new(SurfaceKind::McpTools, tools());
        let ctx = observe_ctx(&source, 1_000);
        let out = admit(&request(Mode::Observe, Declared::default()), &ctx).unwrap();

        assert_eq!(out.entity.posture, Posture::Unattested);
        assert_eq!(out.entity.lifecycle, wc_core::model::Lifecycle::Pending);
        assert!(!out.fully_attested());
        assert_eq!(
            out.skipped(),
            vec![
                Stage::Identity,
                Stage::CardSignature,
                Stage::Provenance,
                Stage::Screening
            ]
        );
        // Each skipped stage leaves a finding, so the gap is visible in evidence.
        assert_eq!(out.findings.len(), 3);
        assert!(out
            .findings
            .iter()
            .any(|f| f.code == Code::IDENTITY_UNVERIFIABLE));
        assert_eq!(out.entity.reattested_at, 0, "never attested");
    }

    #[test]
    fn enforce_mode_refuses_an_unverified_identity() {
        let source = InlineSurface::new(SurfaceKind::McpTools, tools());
        let ctx = observe_ctx(&source, 1_000);
        let err = admit(&request(Mode::Enforce, Declared::default()), &ctx).unwrap_err();
        assert_eq!(err.code(), Code::IDENTITY_UNVERIFIABLE);
    }

    #[test]
    fn a_pin_is_taken_and_registration_grants_nothing() {
        let source = InlineSurface::new(SurfaceKind::McpTools, tools());
        let ctx = observe_ctx(&source, 1_000);
        let out = admit(&request(Mode::Observe, Declared::default()), &ctx).unwrap();

        assert!(out.entity.pin.manifest.starts_with("sha256:"));
        assert_eq!(out.entity.pin.items.len(), 2);
        assert_eq!(out.entity.pin.pinned_at, 1_000);
        // UC-01 postcondition.
        assert!(out.entity.assert_connectable(Mode::Observe).is_err());
    }

    #[test]
    fn an_unobtainable_surface_is_fatal_in_observe_mode_too() {
        /// Stands in for an unreachable endpoint.
        struct Unreachable;
        impl SurfaceSource for Unreachable {
            fn fetch_surface(&self, _r: &AdmissionRequest) -> Result<FetchedSurface> {
                Err(WcError::with_detail(
                    Code::SURFACE_UNOBTAINABLE,
                    "connection refused",
                ))
            }
        }
        // Identity verifies, so the pipeline genuinely reaches stage 2 in both
        // modes rather than stopping at stage 1 in enforce mode.
        let source = Unreachable;
        let ctx = strict_ctx(&source, 1_000);
        for mode in [Mode::Observe, Mode::Enforce] {
            let err = admit(&request(mode, Declared::default()), &ctx).unwrap_err();
            assert_eq!(
                err.code(),
                Code::SURFACE_UNOBTAINABLE,
                "there is no register-on-trust"
            );
        }
    }

    // --- fully-verifying stand-ins, so tests past stage 1 can be reached ---

    struct RealIdentity;
    impl IdentityVerifier for RealIdentity {
        fn verify_identity(&self, req: &AdmissionRequest) -> Result<IdentityProof> {
            Ok(IdentityProof {
                id: req.id.clone().unwrap(),
                method: "x509-svid".to_string(),
                verified: true,
            })
        }
    }

    struct RealCard;
    impl CardVerifier for RealCard {
        fn verify_card(&self, _r: &AdmissionRequest, _f: &FetchedSurface) -> Result<CardProof> {
            Ok(CardProof {
                verified: true,
                method: "jws es256".to_string(),
            })
        }
    }

    struct RealProvenance;
    impl ProvenanceVerifier for RealProvenance {
        fn verify_provenance(&self, _r: &AdmissionRequest) -> Result<ProvenanceProof> {
            Ok(ProvenanceProof {
                verified: true,
                refs: vec![ProvRef {
                    kind: "sigstore-bundle".to_string(),
                    reference: "sha256:abc".to_string(),
                }],
                method: "sigstore offline bundle".to_string(),
            })
        }
    }

    struct CleanScreen;
    impl Screener for CleanScreen {
        fn screen(&self, _f: &FetchedSurface) -> Result<ScreenReport> {
            Ok(ScreenReport {
                ran: true,
                blocked: false,
                findings: vec![],
                ruleset: "screen-rules@v1".to_string(),
            })
        }
    }

    /// Everything verified, so a test can exercise a later stage in either mode.
    fn strict_ctx<'a>(surface: &'a dyn SurfaceSource, now: u64) -> AdmissionCtx<'a> {
        AdmissionCtx {
            identity: &RealIdentity,
            surface,
            card: &RealCard,
            provenance: &RealProvenance,
            screener: &CleanScreen,
            limits: Limits::default(),
            tier_rules: TierRules::default(),
            now,
        }
    }

    #[test]
    fn a_verified_party_is_attested() {
        let source = InlineSurface::new(SurfaceKind::McpTools, tools());
        let ctx = strict_ctx(&source, 5_000);

        let out = admit(&request(Mode::Enforce, Declared::default()), &ctx).unwrap();
        assert_eq!(out.entity.posture, Posture::Attested);
        assert!(out.fully_attested());
        assert!(out.skipped().is_empty());
        assert!(out.findings.is_empty());
        assert_eq!(out.entity.provenance.len(), 1);
        assert_eq!(out.entity.reattested_at, 5_000);
    }

    #[test]
    fn a_screening_block_fires_in_every_mode() {
        struct Blocking;
        impl Screener for Blocking {
            fn screen(&self, _f: &FetchedSurface) -> Result<ScreenReport> {
                Ok(ScreenReport {
                    ran: true,
                    blocked: true,
                    findings: vec![Finding {
                        code: Code::SCREENING_BLOCKED,
                        detail: "zero-width character in description".to_string(),
                        severity: Severity::Critical,
                    }],
                    ruleset: "screen-rules@v1".to_string(),
                })
            }
        }
        let source = InlineSurface::new(SurfaceKind::McpTools, tools());
        let mut ctx = strict_ctx(&source, 1_000);
        ctx.screener = &Blocking;

        for mode in [Mode::Observe, Mode::Enforce] {
            let err = admit(&request(mode, Declared::default()), &ctx).unwrap_err();
            assert_eq!(err.code(), Code::SCREENING_BLOCKED);
        }
    }

    #[test]
    fn a_tier_above_the_requested_ceiling_is_refused() {
        let declared = Declared {
            data_classes: vec!["pii".to_string()],
            requested_tier: Some(Tier::THREE),
            ..Default::default()
        };
        let source = InlineSurface::new(SurfaceKind::McpTools, tools());
        let ctx = observe_ctx(&source, 1_000);
        let err = admit(&request(Mode::Observe, declared), &ctx).unwrap_err();
        assert_eq!(err.code(), Code::TIER_EXCEEDS_CEILING);
        assert!(err.detail().contains("more sensitive"));
    }

    #[test]
    fn declared_metadata_lands_on_the_record() {
        let declared = Declared {
            data_classes: vec!["internal".to_string()],
            jurisdictions: vec!["SG".to_string(), "MY".to_string()],
            requested_tier: None,
            service: Some("payments-recon".to_string()),
        };
        let source = InlineSurface::new(SurfaceKind::McpTools, tools());
        let ctx = observe_ctx(&source, 1_000);
        let out = admit(&request(Mode::Observe, declared), &ctx).unwrap();
        assert_eq!(out.entity.service.as_deref(), Some("payments-recon"));
        assert_eq!(out.entity.jurisdictions.len(), 2);
        assert_eq!(
            out.entity.endpoint.as_deref(),
            Some("https://payments-mcp.internal/mcp")
        );
        assert_eq!(
            out.entity.reattest_every,
            out.entity.tier.reattest_interval_secs()
        );
    }

    // --- capability classes ---

    #[test]
    fn capability_classes_follow_the_name_first() {
        assert_eq!(capability_class("wire_funds", &json!({})), 1);
        assert_eq!(capability_class("delete_database", &json!({})), 1);
        assert_eq!(capability_class("grant_role", &json!({})), 1);
        assert_eq!(capability_class("send_email", &json!({})), 2);
        assert_eq!(capability_class("write_file", &json!({})), 2);
        assert_eq!(capability_class("get_balance", &json!({})), 3);
        assert_eq!(capability_class("list_transactions", &json!({})), 3);
    }

    #[test]
    fn an_unmapped_capability_is_class_two() {
        // Unclassified is significant until someone classifies it.
        assert_eq!(capability_class("frobnicate", &json!({})), 2);
    }

    #[test]
    fn a_description_can_escalate_when_the_name_says_nothing() {
        assert_eq!(
            capability_class(
                "frobnicate",
                &json!({"description": "Transfer funds between ledgers."})
            ),
            1
        );
    }

    #[test]
    fn self_assessment_may_escalate_but_never_launder() {
        // destructiveHint raises severity...
        assert_eq!(
            capability_class(
                "frobnicate",
                &json!({"annotations": {"destructiveHint": true}})
            ),
            1
        );
        // ...but readOnlyHint cannot make money movement look harmless.
        assert_eq!(
            capability_class(
                "wire_funds",
                &json!({"annotations": {"readOnlyHint": true}})
            ),
            1
        );
        assert_eq!(
            capability_class(
                "send_email",
                &json!({"annotations": {"readOnlyHint": true}})
            ),
            2
        );
        // On a genuinely read-shaped tool it is respected.
        assert_eq!(
            capability_class(
                "get_balance",
                &json!({"annotations": {"readOnlyHint": true}})
            ),
            3
        );
    }

    // --- tier derivation ---

    #[test]
    fn tier_takes_the_more_sensitive_of_data_and_capability() {
        let rules = TierRules::default();
        // Public data, but the tool moves money.
        let (tier, why) = derive_tier(
            &Declared {
                data_classes: vec!["public".to_string()],
                ..Default::default()
            },
            &fetched(json!({"tools": [{"name": "wire_funds"}]})),
            &zone("internal.payments"),
            &rules,
        );
        assert_eq!(tier, Tier::ONE);
        assert!(why.contains("capability class 1"));

        // Sensitive data, but read-only tooling.
        let (tier, _) = derive_tier(
            &Declared {
                data_classes: vec!["pii".to_string()],
                ..Default::default()
            },
            &fetched(json!({"tools": [{"name": "get_balance"}]})),
            &zone("internal.payments"),
            &rules,
        );
        assert_eq!(tier, Tier::ONE);

        // Internal data, read-only tooling: the ordinary case.
        let (tier, _) = derive_tier(
            &Declared {
                data_classes: vec!["internal".to_string()],
                ..Default::default()
            },
            &fetched(json!({"tools": [{"name": "get_balance"}]})),
            &zone("internal.payments"),
            &rules,
        );
        assert_eq!(tier, Tier::THREE);
    }

    #[test]
    fn an_external_zone_escalates() {
        let rules = TierRules::default();
        let declared = Declared {
            data_classes: vec!["internal".to_string()],
            ..Default::default()
        };
        let surface = fetched(json!({"tools": [{"name": "get_balance"}]}));

        let (internal, _) = derive_tier(&declared, &surface, &zone("internal.x"), &rules);
        let (partner, why) = derive_tier(&declared, &surface, &zone("partner.acme"), &rules);
        assert_eq!(internal, Tier::THREE);
        assert_eq!(partner, Tier::TWO);
        assert!(why.contains("escalated one step"));
    }

    #[test]
    fn an_unbounded_surface_escalates() {
        let rules = TierRules::default();
        let declared = Declared {
            data_classes: vec!["internal".to_string()],
            ..Default::default()
        };
        let (bounded, _) = derive_tier(
            &declared,
            &fetched(json!({"tools": [{"name": "get_balance",
                "inputSchema": {"properties": {"id": {"type": "string"}}}}]})),
            &zone("internal.x"),
            &rules,
        );
        let (unbounded, why) = derive_tier(
            &declared,
            &fetched(json!({"tools": [{"name": "get_balance",
                "inputSchema": {"additionalProperties": true}}]})),
            &zone("internal.x"),
            &rules,
        );
        assert_eq!(bounded, Tier::THREE);
        assert_eq!(unbounded, Tier::TWO);
        assert!(why.contains("unbounded"));
    }

    #[test]
    fn crossing_a_residency_boundary_escalates() {
        let rules = TierRules::default();
        let surface = fetched(json!({"tools": [{"name": "get_balance"}]}));

        // Same group: no escalation.
        let (same, _) = derive_tier(
            &Declared {
                data_classes: vec!["internal".to_string()],
                jurisdictions: vec!["SG".to_string(), "JP".to_string()],
                ..Default::default()
            },
            &surface,
            &zone("internal.x"),
            &rules,
        );
        assert_eq!(same, Tier::THREE);

        // Different groups: escalate.
        let (crossing, why) = derive_tier(
            &Declared {
                data_classes: vec!["internal".to_string()],
                jurisdictions: vec!["SG".to_string(), "DE".to_string()],
                ..Default::default()
            },
            &surface,
            &zone("internal.x"),
            &rules,
        );
        assert_eq!(crossing, Tier::TWO);
        assert!(why.contains("residency group"));
    }

    #[test]
    fn tier_never_escapes_its_bounds() {
        let rules = TierRules::default();
        // Every escalation at once, starting from the most sensitive tier.
        let (tier, _) = derive_tier(
            &Declared {
                data_classes: vec!["pii".to_string()],
                jurisdictions: vec!["SG".to_string(), "DE".to_string(), "US".to_string()],
                ..Default::default()
            },
            &fetched(
                json!({"tools": [{"name": "wire_*", "inputSchema": {"additionalProperties": true}}]}),
            ),
            &zone("public"),
            &rules,
        );
        assert_eq!(tier, Tier::ONE);

        // Nothing declared, nothing exposed: least sensitive still valid.
        let (tier, why) = derive_tier(
            &Declared {
                data_classes: vec!["public".to_string()],
                ..Default::default()
            },
            &fetched(json!({"tools": []})),
            &zone("internal.x"),
            &rules,
        );
        assert_eq!(tier, Tier::FOUR);
        assert!(why.contains("no declared items"));
    }

    #[test]
    fn a2a_skills_are_read_as_items() {
        let rules = TierRules::default();
        let card = FetchedSurface {
            kind: SurfaceKind::A2aCard,
            raw: json!({"name": "Settlement", "skills": [{"id": "settle_payment"}]}),
            source: "test".to_string(),
        };
        let (tier, why) = derive_tier(
            &Declared {
                data_classes: vec!["internal".to_string()],
                ..Default::default()
            },
            &card,
            &zone("internal.x"),
            &rules,
        );
        assert_eq!(tier, Tier::ONE, "settle is money movement");
        assert!(why.contains("settle_payment"));
    }

    // --- MCP JSON-RPC framing ---

    #[test]
    fn initialize_and_tools_list_bodies_are_well_formed() {
        let source = McpHttpSurface::default();
        let init = source.initialize_body();
        assert_eq!(init["jsonrpc"], "2.0");
        assert_eq!(init["method"], "initialize");
        assert!(init["params"]["protocolVersion"].is_string());

        let list = McpHttpSurface::tools_list_body();
        assert_eq!(list["method"], "tools/list");
    }

    #[test]
    fn json_rpc_results_and_errors_are_distinguished() {
        let ok = McpHttpSurface::parse_result(r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#)
            .unwrap();
        assert!(ok.get("tools").is_some());

        for bad in [
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"no such method"}}"#,
            r#"{"jsonrpc":"2.0","id":2}"#,
            "not json at all",
        ] {
            let err = McpHttpSurface::parse_result(bad).unwrap_err();
            assert_eq!(err.code(), Code::SURFACE_UNOBTAINABLE);
        }
    }

    #[test]
    fn an_mcp_server_without_an_endpoint_is_refused() {
        let mut req = request(Mode::Observe, Declared::default());
        req.endpoint = None;
        let err = McpHttpSurface::default().fetch_surface(&req).unwrap_err();
        assert_eq!(err.code(), Code::SURFACE_UNOBTAINABLE);
    }

    #[test]
    fn the_real_handshake_captures_a_live_surface() {
        // A minimal MCP server: answers `initialize` with a session id, then
        // `tools/list`. Exercises the actual HTTP path, session echo included.
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = std::thread::spawn(move || {
            let mut sessions_echoed = 0;
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());

                let mut length = 0usize;
                let mut saw_session = false;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap_or(0);
                    }
                    if lower.starts_with("mcp-session-id:") {
                        saw_session = true;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                let mut body = vec![0u8; length];
                std::io::Read::read_exact(&mut reader, &mut body).unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap();

                let (payload, extra) = if body["method"] == "initialize" {
                    (
                        json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}),
                        "mcp-session-id: sess-123\r\n",
                    )
                } else {
                    if saw_session {
                        sessions_echoed += 1;
                    }
                    (
                        json!({"jsonrpc":"2.0","id":2,"result":{"tools":[
                            {"name":"get_balance","description":"Read a balance."}
                        ]}}),
                        "",
                    )
                };
                let text = payload.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{extra}connection: close\r\n\r\n{text}",
                    text.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
            sessions_echoed
        });

        let mut req = request(Mode::Observe, Declared::default());
        req.endpoint = Some(format!("http://127.0.0.1:{port}/mcp"));

        let source = McpHttpSurface::default().with_timeout(5);
        let got = source.fetch_surface(&req).unwrap();
        assert_eq!(got.kind, SurfaceKind::McpTools);
        assert_eq!(got.raw["tools"][0]["name"], "get_balance");

        let echoed = handle.join().unwrap();
        assert_eq!(
            echoed, 1,
            "the session id must ride on the follow-up request"
        );
    }
}
