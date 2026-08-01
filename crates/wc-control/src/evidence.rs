//! The evidence facade: lifecycle events → tamper-evident chain → sinks
//! (`docs/08-lld.md` §8.5.8).
//!
//! Every consequential thing the control plane does lands here, in this order:
//!
//! 1. **Blocking sinks first.** If a `blocking` sink is configured and cannot be
//!    reached, the operation does not happen (§7.8). Authority must not exist
//!    without a durable external trail.
//! 2. **Then the chain.** Appended and `fsync`ed, hash-linked to everything before
//!    it.
//! 3. **Then fail-safe sinks.** Best effort; failures are reported to the caller as
//!    warnings rather than errors.
//!
//! That ordering is the design: reversing 1 and 2 would let an issuance complete
//! while its blocking trail failed, which is precisely the gap the regulated
//! configuration exists to close.

use std::path::Path;

use serde_json::{json, Value};

use wc_core::error::{Code, Result, WcError};

use crate::chain::{Chain, ChainReport, Entry, EntryDraft};
use crate::sink::{Delivery, Sink};

// ---------------------------------------------------------------------------
// Event kinds
// ---------------------------------------------------------------------------

/// Everything worth recording, with its OCSF mapping and severity
/// (§8.5.8's table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// An entity was registered.
    Register,
    /// An entity passed admission.
    Admit,
    /// Admission was refused.
    AdmissionDenied,
    /// A capability question was asked.
    Discover,
    /// A connection was requested.
    Request,
    /// A human approved a connection.
    Approve,
    /// A connection request was refused.
    ContractDenied,
    /// A contract was minted.
    Mint,
    /// A contract was renewed.
    Renew,
    /// A contract was revoked.
    Revoke,
    /// A contract was suspended pending re-approval.
    Suspend,
    /// Benign surface drift; the pin was updated.
    DriftBenign,
    /// Material surface drift; contracts were suspended.
    DriftMaterial,
    /// A surface was re-pinned.
    Repin,
    /// A party re-attested.
    Reattest,
    /// A party was contained.
    Quarantine,
    /// Containment was lifted, forcing re-admission.
    QuarantineCleared,
    /// A mediator acknowledged a revocation set.
    MediatorAck,
    /// A mediator failed to acknowledge — reported, never assumed contained.
    MediatorUnconfirmed,
    /// A register or evidence export was produced.
    Export,
    /// A time-boxed emergency connection was issued.
    BreakGlass,
}

impl EventKind {
    /// The dotted name used in the chain and in metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            EventKind::Register => "entity.register",
            EventKind::Admit => "entity.admit",
            EventKind::AdmissionDenied => "entity.admission_denied",
            EventKind::Discover => "discovery.query",
            EventKind::Request => "contract.request",
            EventKind::Approve => "contract.approve",
            EventKind::ContractDenied => "contract.deny",
            EventKind::Mint => "contract.mint",
            EventKind::Renew => "contract.renew",
            EventKind::Revoke => "contract.revoke",
            EventKind::Suspend => "contract.suspend",
            EventKind::DriftBenign => "posture.drift_benign",
            EventKind::DriftMaterial => "posture.drift_material",
            EventKind::Repin => "entity.repin",
            EventKind::Reattest => "posture.reattest",
            EventKind::Quarantine => "quarantine.order",
            EventKind::QuarantineCleared => "quarantine.cleared",
            EventKind::MediatorAck => "mediator.ack",
            EventKind::MediatorUnconfirmed => "mediator.unconfirmed",
            EventKind::Export => "evidence.export",
            EventKind::BreakGlass => "contract.breakglass",
        }
    }

    /// OCSF class uid (§8.5.8).
    #[must_use]
    pub const fn ocsf_class(self) -> u32 {
        match self {
            // Entity Management
            EventKind::Register
            | EventKind::Admit
            | EventKind::Mint
            | EventKind::Renew
            | EventKind::Repin
            | EventKind::Reattest => 3004,
            // Detection Finding
            EventKind::AdmissionDenied
            | EventKind::DriftBenign
            | EventKind::DriftMaterial
            | EventKind::Quarantine
            | EventKind::Revoke
            | EventKind::Suspend => 2004,
            // Account Change
            EventKind::Approve | EventKind::ContractDenied | EventKind::QuarantineCleared => 3001,
            // API Activity
            EventKind::Discover | EventKind::Request | EventKind::Export => 6003,
            // Application Lifecycle
            EventKind::MediatorAck | EventKind::MediatorUnconfirmed | EventKind::BreakGlass => 6002,
        }
    }

    /// Default severity, which the filters key off.
    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            EventKind::Quarantine => Severity::Critical,
            EventKind::DriftMaterial
            | EventKind::MediatorUnconfirmed
            | EventKind::BreakGlass
            | EventKind::Revoke => Severity::High,
            EventKind::AdmissionDenied | EventKind::ContractDenied | EventKind::Suspend => {
                Severity::Medium
            }
            EventKind::Approve
            | EventKind::QuarantineCleared
            | EventKind::DriftBenign
            | EventKind::MediatorAck => Severity::Low,
            _ => Severity::Informational,
        }
    }

    /// Whether this kind records a refusal.
    #[must_use]
    pub const fn is_denial(self) -> bool {
        matches!(self, EventKind::AdmissionDenied | EventKind::ContractDenied)
    }

    /// Whether this kind is a containment action.
    #[must_use]
    pub const fn is_containment(self) -> bool {
        matches!(
            self,
            EventKind::Revoke | EventKind::Quarantine | EventKind::QuarantineCleared
        )
    }

    /// The CAEP event URI, for kinds that belong on a shared-signals stream.
    #[must_use]
    pub const fn caep_event_uri(self) -> Option<&'static str> {
        match self {
            EventKind::Quarantine | EventKind::Revoke => {
                Some("https://schemas.openid.net/secevent/caep/event-type/session-revoked")
            }
            EventKind::DriftMaterial => {
                Some("https://schemas.openid.net/secevent/caep/event-type/credential-change")
            }
            _ => None,
        }
    }
}

/// Event severity, ordered so filters can compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Routine.
    Informational,
    /// Worth a dashboard.
    Low,
    /// Worth an owner's attention.
    Medium,
    /// Worth an alert.
    High,
    /// Worth waking someone.
    Critical,
}

impl Severity {
    /// OCSF `severity_id`.
    #[must_use]
    pub const fn ocsf_id(self) -> u8 {
        match self {
            Severity::Informational => 1,
            Severity::Low => 2,
            Severity::Medium => 3,
            Severity::High => 4,
            Severity::Critical => 5,
        }
    }
}

// ---------------------------------------------------------------------------
// LifecycleEvent
// ---------------------------------------------------------------------------

/// One recordable thing that happened.
#[derive(Debug, Clone)]
pub struct LifecycleEvent {
    /// What kind of thing.
    pub kind: EventKind,
    /// Connection id, where there is one — the correlation root.
    pub cid: Option<String>,
    /// Contract artifact id.
    pub contract_jti: Option<String>,
    /// Entities involved.
    pub entities: Vec<String>,
    /// Who acted.
    pub actor: String,
    /// `allow` | `deny` | `record` | `hold`.
    pub decision: String,
    /// Human reason.
    pub reason: String,
    /// Policy version in force.
    pub policy_version: String,
    /// Kind-specific payload. Must already be redacted.
    pub detail: Value,
    /// Severity override; defaults to the kind's.
    pub severity: Option<Severity>,
}

impl LifecycleEvent {
    /// A new event with sensible defaults.
    #[must_use]
    pub fn new(kind: EventKind, actor: impl Into<String>) -> LifecycleEvent {
        LifecycleEvent {
            kind,
            cid: None,
            contract_jti: None,
            entities: Vec::new(),
            actor: actor.into(),
            decision: if kind.is_denial() { "deny" } else { "record" }.to_string(),
            reason: String::new(),
            policy_version: String::new(),
            detail: Value::Null,
            severity: None,
        }
    }

    /// Attach the correlation root.
    #[must_use]
    pub fn with_cid(mut self, cid: impl Into<String>) -> Self {
        self.cid = Some(cid.into());
        self
    }

    /// Attach the contract artifact id.
    #[must_use]
    pub fn with_contract_jti(mut self, jti: impl Into<String>) -> Self {
        self.contract_jti = Some(jti.into());
        self
    }

    /// Name the entities involved.
    #[must_use]
    pub fn with_entities<I, S>(mut self, entities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.entities = entities.into_iter().map(Into::into).collect();
        self
    }

    /// Set the human reason.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// Record the policy version in force.
    #[must_use]
    pub fn with_policy_version(mut self, version: impl Into<String>) -> Self {
        self.policy_version = version.into();
        self
    }

    /// Attach a kind-specific payload.
    #[must_use]
    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }

    /// Override severity.
    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Effective severity.
    #[must_use]
    pub fn severity(&self) -> Severity {
        self.severity.unwrap_or_else(|| self.kind.severity())
    }

    /// Whether this records a refusal.
    #[must_use]
    pub fn is_denial(&self) -> bool {
        self.kind.is_denial() || self.decision == "deny"
    }

    /// Whether this is a containment action.
    #[must_use]
    pub fn is_containment(&self) -> bool {
        self.kind.is_containment()
    }

    /// The chain draft for this event.
    #[must_use]
    pub fn to_draft(&self) -> EntryDraft {
        EntryDraft {
            kind: self.kind.as_str().to_string(),
            cid: self.cid.clone(),
            contract_jti: self.contract_jti.clone(),
            entities: self.entities.clone(),
            actor: self.actor.clone(),
            decision: self.decision.clone(),
            reason: self.reason.clone(),
            policy_version: self.policy_version.clone(),
            detail: self.detail.clone(),
        }
    }

    /// Project to OCSF.
    #[must_use]
    pub fn to_ocsf(&self, now: u64) -> Value {
        json!({
            "class_uid": self.kind.ocsf_class(),
            "category_uid": 3,
            "activity_id": 1,
            "type_uid": self.kind.ocsf_class() * 100 + 1,
            "time": now,
            "severity_id": self.severity().ocsf_id(),
            "message": if self.reason.is_empty() { self.kind.as_str().to_string() } else { self.reason.clone() },
            "metadata": {
                "product": { "name": "warden-connect", "vendor_name": "warden" },
                "version": "1.1.0",
                "event_code": self.kind.as_str(),
            },
            "actor": { "user": { "uid": self.actor } },
            "status": if self.is_denial() { "Failure" } else { "Success" },
            "unmapped": {
                "cid": self.cid,
                "contract_jti": self.contract_jti,
                "entities": self.entities,
                "decision": self.decision,
                "policy_version": self.policy_version,
                "detail": self.detail,
            }
        })
    }

    /// Project to a CAEP Security Event Token payload (RFC 8417).
    ///
    /// Subject is the affected party; the event URI tells a receiver what to do —
    /// which is how `quarantine agent:rogue-9` cuts sessions in systems that have
    /// never heard of warden-connect.
    #[must_use]
    pub fn to_caep(&self, now: u64) -> Value {
        let uri = self
            .kind
            .caep_event_uri()
            .unwrap_or("https://warden.dev/secevent/connect/lifecycle");
        let subject = self
            .entities
            .first()
            .cloned()
            .unwrap_or_else(|| self.actor.clone());

        json!({
            "iss": "https://connect.internal",
            "iat": now,
            "jti": format!("set_{}", wc_core::util::sha256_hex(&format!("{}{}{}", self.kind.as_str(), subject, now))[..16].to_string()),
            "aud": "shared-signals",
            "sub_id": { "format": "uri", "uri": subject },
            "events": {
                uri: {
                    "event_timestamp": now,
                    "reason_admin": { "en": self.reason.clone() },
                    "initiating_entity": "policy",
                    "warden_connect": {
                        "kind": self.kind.as_str(),
                        "cid": self.cid,
                        "entities": self.entities,
                    }
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// What happened when an event was recorded.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Recorded {
    /// The chain sequence assigned.
    pub seq: u64,
    /// The chain row hash.
    pub row_hash: String,
    /// Sinks that accepted it.
    pub shipped: Vec<String>,
    /// Fail-safe sinks that did not, with the reason. Not fatal, but never hidden.
    pub warnings: Vec<String>,
}

/// The chain plus its sinks.
#[derive(Debug)]
pub struct Evidence {
    chain: Chain,
    sinks: Vec<Sink>,
}

impl Evidence {
    /// Open the evidence chain in `dir`.
    pub fn open(dir: impl AsRef<Path>) -> Result<Evidence> {
        Ok(Evidence {
            chain: Chain::open(dir)?,
            sinks: Vec::new(),
        })
    }

    /// Enable signed checkpoints.
    pub fn with_anchor(
        mut self,
        key_pem: &[u8],
        path: impl Into<std::path::PathBuf>,
        interval: u64,
    ) -> Result<Evidence> {
        self.chain = self.chain.with_anchor(key_pem, path, interval)?;
        Ok(self)
    }

    /// Attach sinks.
    #[must_use]
    pub fn with_sinks(mut self, sinks: Vec<Sink>) -> Evidence {
        self.sinks = sinks;
        self
    }

    /// The current chain head — what an export references so it is verifiable
    /// rather than merely asserted.
    #[must_use]
    pub fn head(&self) -> (u64, String) {
        let (seq, hash) = self.chain.head();
        (seq, hash.to_string())
    }

    /// Whether any configured sink would block an operation.
    #[must_use]
    pub fn has_blocking_sinks(&self) -> bool {
        self.sinks.iter().any(|s| s.delivery == Delivery::Blocking)
    }

    /// Record an event: blocking sinks, then the chain, then fail-safe sinks.
    ///
    /// Returns `Err` if a blocking sink refuses — and in that case **nothing is
    /// appended**, because the operation the caller was about to perform must not
    /// happen either.
    pub fn record(&mut self, event: &LifecycleEvent, now: u64) -> Result<Recorded> {
        let mut shipped: Vec<String> = Vec::new();

        // 1 · blocking sinks, before anything is committed.
        for sink in self
            .sinks
            .iter()
            .filter(|s| s.delivery == Delivery::Blocking)
        {
            if !sink.accepts(event) {
                continue;
            }
            sink.ship(event, now).map_err(|e| {
                WcError::with_detail(
                    Code::BLOCKING_SINK_UNAVAILABLE,
                    format!(
                        "{}: blocking sink {} unavailable, so the operation is refused",
                        event.kind.as_str(),
                        sink.name
                    ),
                )
                .with_source(e)
            })?;
            shipped.push(sink.name.clone());
        }

        // 2 · the authoritative record.
        let entry = self.chain.append(event.to_draft(), now)?;

        // 3 · fail-safe sinks. A failure here is a warning: the chain already holds
        // the authoritative copy, and failing an issuance because a SIEM hiccuped
        // would be its own kind of outage.
        let mut warnings: Vec<String> = Vec::new();
        for sink in self
            .sinks
            .iter()
            .filter(|s| s.delivery == Delivery::FailSafe)
        {
            if !sink.accepts(event) {
                continue;
            }
            match sink.ship(event, now) {
                Ok(()) => shipped.push(sink.name.clone()),
                Err(e) => warnings.push(format!("sink {}: {e}", sink.name)),
            }
        }

        Ok(Recorded {
            seq: entry.seq,
            row_hash: entry.row_hash,
            shipped,
            warnings,
        })
    }

    /// Sign a checkpoint of the current head.
    pub fn checkpoint(&mut self, now: u64) -> Result<Option<String>> {
        self.chain.checkpoint(now)
    }

    /// Verify a chain on disk — `connect audit verify`.
    pub fn verify(dir: impl AsRef<Path>, anchor_pub_pem: Option<&[u8]>) -> Result<ChainReport> {
        Chain::verify(dir, anchor_pub_pem)
    }

    /// Every entry, for export.
    pub fn entries(dir: impl AsRef<Path>) -> Result<Vec<Entry>> {
        Chain::entries(dir)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::chain::{ANCHOR_FILE, CHAIN_FILE};
    use crate::sink::{Filter, Format};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    const PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_anchor_priv.pem");
    const PUB: &[u8] = include_bytes!("../../../fixtures/keys/test_anchor_pub.pem");

    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> TmpDir {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("wc-evid-{}-{tag}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            TmpDir(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mint_event() -> LifecycleEvent {
        LifecycleEvent::new(EventKind::Mint, "human:cecil@org")
            .with_cid("conn_7f3a91c4")
            .with_contract_jti("cx_84be0011")
            .with_entities([
                "spiffe://org/ns/agents/sa/recon-bot-7",
                "spiffe://org/ns/tools/sa/payments-mcp",
            ])
            .with_reason("APAC daily reconciliation")
            .with_policy_version("connect-policy@v37")
            .with_detail(json!({"surface": {"tools": ["get_balance"]}}))
    }

    // --- recording ---

    #[test]
    fn recording_appends_to_the_chain() {
        let tmp = TmpDir::new("record");
        let mut evidence = Evidence::open(tmp.path()).unwrap();

        let first = evidence.record(&mint_event(), 1_000).unwrap();
        assert_eq!(first.seq, 1);
        assert!(!first.row_hash.is_empty());
        assert!(first.warnings.is_empty());
        assert_eq!(evidence.head(), (1, first.row_hash.clone()));

        let second = evidence
            .record(
                &LifecycleEvent::new(EventKind::Discover, "agent:recon-bot-7"),
                1_001,
            )
            .unwrap();
        assert_eq!(second.seq, 2);

        let report = Evidence::verify(tmp.path(), None).unwrap();
        assert!(report.is_intact());
        assert_eq!(report.entries, 2);
    }

    #[test]
    fn the_correlation_root_survives_into_the_chain() {
        // T7.7: `cid` on every evidence row is what makes a multi-agent
        // transaction reconstructable rather than heuristic.
        let tmp = TmpDir::new("cid");
        {
            let mut evidence = Evidence::open(tmp.path()).unwrap();
            evidence.record(&mint_event(), 1_000).unwrap();
        }
        let entries = Evidence::entries(tmp.path()).unwrap();
        assert_eq!(entries[0].cid.as_deref(), Some("conn_7f3a91c4"));
        assert_eq!(entries[0].contract_jti.as_deref(), Some("cx_84be0011"));
        assert_eq!(entries[0].policy_version, "connect-policy@v37");
        // And it is inside the hash, so it cannot be re-attributed later.
        let mut tampered = entries[0].clone();
        tampered.cid = Some("conn_deadbeef".to_string());
        assert!(!tampered.is_intact());
    }

    // --- ordering: blocking before the chain ---

    #[test]
    fn a_failed_blocking_sink_prevents_the_record_entirely() {
        // §7.8: blocking evidence sink unavailable → deny. If the chain were
        // appended first, the operation would look recorded while its external
        // trail failed.
        let tmp = TmpDir::new("blocking");
        let dead = Sink {
            name: "worm".to_string(),
            format: Format::Ocsf,
            transport: crate::sink::Transport::Webhook {
                endpoint: "http://127.0.0.1:1/append".to_string(),
            },
            filter: Filter::All,
            delivery: Delivery::Blocking,
            key: None,
            timeout_secs: 2,
        };
        let mut evidence = Evidence::open(tmp.path()).unwrap().with_sinks(vec![dead]);
        assert!(evidence.has_blocking_sinks());

        let err = evidence.record(&mint_event(), 1_000).unwrap_err();
        assert_eq!(err.code(), Code::BLOCKING_SINK_UNAVAILABLE);
        assert!(err.detail().contains("the operation is refused"));

        // Nothing was appended.
        assert_eq!(evidence.head(), (0, String::new()));
        let report = Evidence::verify(tmp.path(), None).unwrap();
        assert_eq!(report.entries, 0);
    }

    #[test]
    fn a_failed_fail_safe_sink_is_a_warning_not_an_error() {
        let tmp = TmpDir::new("failsafe");
        let dead = Sink {
            name: "lake".to_string(),
            format: Format::Ocsf,
            transport: crate::sink::Transport::Webhook {
                endpoint: "http://127.0.0.1:1/ocsf".to_string(),
            },
            filter: Filter::All,
            delivery: Delivery::FailSafe,
            key: None,
            timeout_secs: 2,
        };
        let mut evidence = Evidence::open(tmp.path()).unwrap().with_sinks(vec![dead]);

        let recorded = evidence.record(&mint_event(), 1_000).unwrap();
        assert_eq!(recorded.seq, 1, "the chain still holds the record");
        assert_eq!(recorded.warnings.len(), 1);
        assert!(recorded.warnings[0].contains("lake"));
        assert!(recorded.shipped.is_empty());
    }

    #[test]
    fn a_working_blocking_sink_ships_before_the_append() {
        let tmp = TmpDir::new("order");
        let sink_path = tmp.path().join("worm.jsonl");
        let mut sink = Sink::file("worm", &sink_path, Format::Ocsf);
        sink.delivery = Delivery::Blocking;

        let mut evidence = Evidence::open(tmp.path()).unwrap().with_sinks(vec![sink]);
        let recorded = evidence.record(&mint_event(), 1_000).unwrap();
        assert_eq!(recorded.shipped, vec!["worm".to_string()]);
        assert!(sink_path.exists());
        assert_eq!(recorded.seq, 1);
    }

    #[test]
    fn filters_are_honoured_per_sink() {
        let tmp = TmpDir::new("filters");
        let all_path = tmp.path().join("all.jsonl");
        let risk_path = tmp.path().join("risk.jsonl");
        let mut risky = Sink::file("risk", &risk_path, Format::Ocsf);
        risky.filter = Filter::HighRisk;

        let mut evidence = Evidence::open(tmp.path())
            .unwrap()
            .with_sinks(vec![Sink::file("all", &all_path, Format::Ocsf), risky]);

        // Informational: only the catch-all sink wants it.
        let low = evidence
            .record(&LifecycleEvent::new(EventKind::Discover, "a"), 1_000)
            .unwrap();
        assert_eq!(low.shipped, vec!["all".to_string()]);

        // Critical: both.
        let high = evidence
            .record(&LifecycleEvent::new(EventKind::Quarantine, "a"), 1_001)
            .unwrap();
        assert_eq!(high.shipped.len(), 2);

        assert_eq!(
            std::fs::read_to_string(&all_path).unwrap().lines().count(),
            2
        );
        assert_eq!(
            std::fs::read_to_string(&risk_path).unwrap().lines().count(),
            1
        );
    }

    // --- anchors ---

    #[test]
    fn evidence_anchors_and_verifies_end_to_end() {
        let tmp = TmpDir::new("anchor");
        {
            let mut evidence = Evidence::open(tmp.path())
                .unwrap()
                .with_anchor(PRIV, tmp.path().join(ANCHOR_FILE), 2)
                .unwrap();
            for i in 0..4 {
                evidence
                    .record(&LifecycleEvent::new(EventKind::Register, "ci"), 1_000 + i)
                    .unwrap();
            }
            assert!(evidence.checkpoint(2_000).unwrap().is_some());
        }
        let report = Evidence::verify(tmp.path(), Some(PUB)).unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.entries, 4);
        assert_eq!(report.anchors_verified, 3, "two on interval, one explicit");
    }

    // --- OCSF projection ---

    #[test]
    fn ocsf_classes_follow_the_lld_table() {
        for (kind, class) in [
            (EventKind::Register, 3004),
            (EventKind::Mint, 3004),
            (EventKind::AdmissionDenied, 2004),
            (EventKind::DriftMaterial, 2004),
            (EventKind::Quarantine, 2004),
            (EventKind::Approve, 3001),
            (EventKind::Discover, 6003),
            (EventKind::Export, 6003),
            (EventKind::MediatorAck, 6002),
        ] {
            assert_eq!(kind.ocsf_class(), class, "{}", kind.as_str());
        }
    }

    #[test]
    fn ocsf_severity_and_status_reflect_the_event() {
        let denied = LifecycleEvent::new(EventKind::AdmissionDenied, "ci")
            .with_reason("provenance unverifiable");
        let ocsf = denied.to_ocsf(1_000);
        assert_eq!(ocsf["status"], "Failure");
        assert_eq!(ocsf["severity_id"], 3);
        assert_eq!(ocsf["message"], "provenance unverifiable");
        assert_eq!(ocsf["metadata"]["event_code"], "entity.admission_denied");

        let quarantine = LifecycleEvent::new(EventKind::Quarantine, "secops");
        assert_eq!(quarantine.to_ocsf(1)["severity_id"], 5);
        // With no reason given, the message falls back to the kind rather than
        // being empty.
        assert_eq!(quarantine.to_ocsf(1)["message"], "quarantine.order");
    }

    #[test]
    fn ocsf_carries_the_connect_fields_in_unmapped() {
        let ocsf = mint_event().to_ocsf(1_000);
        assert_eq!(ocsf["unmapped"]["cid"], "conn_7f3a91c4");
        assert_eq!(ocsf["unmapped"]["policy_version"], "connect-policy@v37");
        assert_eq!(ocsf["unmapped"]["entities"].as_array().unwrap().len(), 2);
    }

    // --- CAEP projection ---

    #[test]
    fn caep_uses_the_right_event_uri_per_kind() {
        let quarantine = LifecycleEvent::new(EventKind::Quarantine, "secops")
            .with_entities(["spiffe://org/ns/agents/sa/rogue-9"]);
        let set = quarantine.to_caep(1_000);
        assert_eq!(set["sub_id"]["uri"], "spiffe://org/ns/agents/sa/rogue-9");
        assert!(set["events"]
            .as_object()
            .unwrap()
            .contains_key("https://schemas.openid.net/secevent/caep/event-type/session-revoked"));

        let drift = LifecycleEvent::new(EventKind::DriftMaterial, "sentinel");
        assert!(drift.to_caep(1)["events"]
            .as_object()
            .unwrap()
            .contains_key("https://schemas.openid.net/secevent/caep/event-type/credential-change"));

        // A kind with no standard URI still emits, under a vendor URI, rather than
        // being silently dropped.
        let mint = LifecycleEvent::new(EventKind::Mint, "cp");
        assert!(mint.to_caep(1)["events"]
            .as_object()
            .unwrap()
            .contains_key("https://warden.dev/secevent/connect/lifecycle"));
    }

    // --- kind classification ---

    #[test]
    fn denial_and_containment_classification_is_exhaustive() {
        assert!(EventKind::AdmissionDenied.is_denial());
        assert!(EventKind::ContractDenied.is_denial());
        assert!(!EventKind::Mint.is_denial());

        assert!(EventKind::Revoke.is_containment());
        assert!(EventKind::Quarantine.is_containment());
        assert!(EventKind::QuarantineCleared.is_containment());
        assert!(!EventKind::Suspend.is_containment());

        // A `record` event whose decision was overridden to deny still counts.
        let mut event = LifecycleEvent::new(EventKind::Mint, "a");
        event.decision = "deny".to_string();
        assert!(event.is_denial());
    }

    #[test]
    fn every_kind_has_a_distinct_name() {
        let kinds = [
            EventKind::Register,
            EventKind::Admit,
            EventKind::AdmissionDenied,
            EventKind::Discover,
            EventKind::Request,
            EventKind::Approve,
            EventKind::ContractDenied,
            EventKind::Mint,
            EventKind::Renew,
            EventKind::Revoke,
            EventKind::Suspend,
            EventKind::DriftBenign,
            EventKind::DriftMaterial,
            EventKind::Repin,
            EventKind::Reattest,
            EventKind::Quarantine,
            EventKind::QuarantineCleared,
            EventKind::MediatorAck,
            EventKind::MediatorUnconfirmed,
            EventKind::Export,
            EventKind::BreakGlass,
        ];
        let mut names: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "event kind names must be unique");
    }

    #[test]
    fn a_second_writer_cannot_open_the_chain() {
        let tmp = TmpDir::new("lock");
        let _held = Evidence::open(tmp.path()).unwrap();
        assert_eq!(
            Evidence::open(tmp.path()).unwrap_err().code(),
            Code::STORE_LOCKED
        );
    }

    #[test]
    fn the_chain_file_is_where_the_lld_says() {
        let tmp = TmpDir::new("layout");
        {
            let mut evidence = Evidence::open(tmp.path()).unwrap();
            evidence.record(&mint_event(), 1).unwrap();
        }
        assert!(tmp.path().join(CHAIN_FILE).exists());
    }
}
