//! The connection contract: the surface, the terms, and the registry record of
//! a minted contract (`docs/08-lld.md` §7.4, §8.8.2).
//!
//! This module holds the *data*. Minting and verification (§8.7.2, §8.6.3) build
//! on these types and land here too.
//!
//! A contract is a **ceiling, never a grant**: the effective authority for any
//! action is `contract.surface ∩ token.scope ∩ policy_decision`. Nothing in this
//! module may widen anything.

use serde::{Deserialize, Serialize};

use crate::error::{Code, Result, WcError};
use crate::model::{Cid, EntityId, HumanRef, Jti, Tier, ZoneId};

/// What may even be attempted over a connection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Surface {
    /// MCP tool names.
    #[serde(default)]
    pub tools: Vec<String>,
    /// A2A skill ids.
    #[serde(default)]
    pub skills: Vec<String>,
    /// Resource URI patterns.
    #[serde(default)]
    pub resources: Vec<String>,
}

impl Surface {
    /// Every contracted item name — tools and skills, the things that have a
    /// per-item pin. Sorted and deduplicated, so it can feed
    /// [`crate::model::Pin::surface_digest`] directly.
    #[must_use]
    pub fn items(&self) -> Vec<String> {
        let mut all: Vec<String> = self
            .tools
            .iter()
            .chain(self.skills.iter())
            .cloned()
            .collect();
        all.sort_unstable();
        all.dedup();
        all
    }

    /// Whether the surface grants nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty() && self.skills.is_empty() && self.resources.is_empty()
    }

    /// Whether `self` grants nothing that `other` does not also grant.
    #[must_use]
    pub fn is_subset_of(&self, other: &Surface) -> bool {
        self.tools.iter().all(|t| other.tools.contains(t))
            && self.skills.iter().all(|s| other.skills.contains(s))
            && self.resources.iter().all(|r| other.resources.contains(r))
    }
}

/// How much authority may cross a hop — the envelope `warden-delegate`
/// attenuates within, and can never raise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// Maximum delegation depth from the originating contract.
    pub max_depth: u8,
    /// Attenuation discipline. `"monotonic"` is the only value that means
    /// anything today: authority may only shrink.
    pub attenuation: String,
}

impl Default for Delegation {
    fn default() -> Self {
        Delegation {
            max_depth: 1,
            attenuation: "monotonic".to_string(),
        }
    }
}

/// The evidence obligation attached to a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceTerms {
    /// Sink identifier, e.g. `ocsf://siem`.
    pub sink: String,
    /// `"blocking"` — no connection without a recorded trail — or
    /// `"fail-safe"`.
    pub delivery: String,
}

impl Default for EvidenceTerms {
    fn default() -> Self {
        EvidenceTerms {
            sink: String::new(),
            delivery: "fail-safe".to_string(),
        }
    }
}

/// The terms of a connection: everything beyond *which* calls may be attempted.
///
/// Every ceiling is an `Option`, where `None` means "no ceiling from this
/// source". That matters for [`Terms::intersect`]: a source that says nothing
/// must not be read as a source that says "unlimited".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Terms {
    /// Data classes that may cross this connection.
    #[serde(default)]
    pub data_classes: Vec<String>,
    /// Jurisdictions this connection may operate across.
    #[serde(default)]
    pub jurisdictions: Vec<String>,
    /// Call-rate ceiling.
    #[serde(default)]
    pub max_calls_per_hour: Option<u32>,
    /// Concurrency ceiling.
    #[serde(default)]
    pub max_concurrent: Option<u32>,
    /// Daily spend ceiling, USD.
    #[serde(default)]
    pub max_spend_usd_per_day: Option<f64>,
    /// Human-oversight threshold, e.g. `required_above:10000_usd`.
    #[serde(default)]
    pub human_oversight: Option<String>,
    /// Delegation envelope.
    #[serde(default)]
    pub delegation: Delegation,
    /// Evidence obligation.
    #[serde(default)]
    pub evidence: EvidenceTerms,
}

impl Terms {
    /// Combine two sets of terms by taking the **more restrictive** of each.
    ///
    /// This is the narrowing algebra from §7.4 in code: a rule can never raise a
    /// ceiling a zone bar set, and a request can never raise either. Data classes
    /// and jurisdictions intersect; numeric ceilings take the minimum; delegation
    /// depth takes the minimum; a `blocking` evidence obligation wins over
    /// `fail-safe`.
    ///
    /// Monotonicity is asserted by `intersect_never_widens`.
    #[must_use]
    pub fn intersect(&self, other: &Terms) -> Terms {
        Terms {
            data_classes: intersect_or_union(&self.data_classes, &other.data_classes),
            jurisdictions: intersect_or_union(&self.jurisdictions, &other.jurisdictions),
            max_calls_per_hour: min_opt(self.max_calls_per_hour, other.max_calls_per_hour),
            max_concurrent: min_opt(self.max_concurrent, other.max_concurrent),
            max_spend_usd_per_day: match (self.max_spend_usd_per_day, other.max_spend_usd_per_day) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) | (None, Some(a)) => Some(a),
                (None, None) => None,
            },
            // Any oversight requirement from either side applies.
            human_oversight: self
                .human_oversight
                .clone()
                .or_else(|| other.human_oversight.clone()),
            delegation: Delegation {
                max_depth: self.delegation.max_depth.min(other.delegation.max_depth),
                attenuation: "monotonic".to_string(),
            },
            evidence: EvidenceTerms {
                sink: if self.evidence.sink.is_empty() {
                    other.evidence.sink.clone()
                } else {
                    self.evidence.sink.clone()
                },
                delivery: if self.evidence.delivery == "blocking"
                    || other.evidence.delivery == "blocking"
                {
                    "blocking".to_string()
                } else {
                    "fail-safe".to_string()
                },
            },
        }
    }
}

/// Intersect two allowlists. An empty list means "unconstrained by this source",
/// so it yields to the other rather than intersecting to nothing.
fn intersect_or_union(a: &[String], b: &[String]) -> Vec<String> {
    if a.is_empty() {
        return b.to_vec();
    }
    if b.is_empty() {
        return a.to_vec();
    }
    let mut out: Vec<String> = a.iter().filter(|x| b.contains(x)).cloned().collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn min_opt(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// How a contract came to be approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// A named human signed for it.
    Human,
    /// Issued under standing policy, no human in the loop (§8.17-Q4).
    StandingPolicy,
    /// Time-boxed emergency issuance, dual-controlled and maximally logged.
    BreakGlass,
}

/// The approval that authorised a contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRef {
    /// Who approved. Absent for standing policy.
    #[serde(default)]
    pub by: Option<HumanRef>,
    /// The approval artifact's id.
    #[serde(default)]
    pub jti: Option<Jti>,
    /// Change ticket.
    #[serde(default)]
    pub ticket: Option<String>,
    /// How it was approved.
    pub mode: ApprovalMode,
    /// Second approver, where dual control applied (tier 1).
    #[serde(default)]
    pub second: Option<HumanRef>,
}

impl ApprovalRef {
    /// Standing-policy issuance: no human, by design.
    #[must_use]
    pub fn standing() -> Self {
        ApprovalRef {
            by: None,
            jti: None,
            ticket: None,
            mode: ApprovalMode::StandingPolicy,
            second: None,
        }
    }

    /// Whether this approval satisfies the dual-control requirement: two
    /// *distinct* humans.
    #[must_use]
    pub fn satisfies_dual_control(&self) -> bool {
        match (&self.by, &self.second) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        }
    }
}

/// A contract's state in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    /// Live, subject to `exp`.
    Active,
    /// Barred pending re-approval — material drift, failed re-attestation.
    Suspended,
    /// Dead. Never returns.
    Revoked,
}

/// The registry's record of a minted contract.
///
/// Distinct from the signed JWS the mediator verifies: this is the control
/// plane's index over what it issued, carrying `jws_sha256` so the artifact in
/// `contracts/<cid>.jws` is provably the one this record describes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractRecord {
    /// Connection id — the correlation root.
    pub cid: Cid,
    /// The signed artifact's `jti`.
    pub jti: Jti,
    /// Calling party.
    pub caller: EntityId,
    /// Called party.
    pub callee: EntityId,
    /// Caller's zone at mint time.
    pub caller_zone: ZoneId,
    /// Callee's zone at mint time.
    pub callee_zone: ZoneId,
    /// Callee's tier at mint time.
    pub callee_tier: Tier,
    /// Callee's whole-surface manifest hash at mint time. Indexed, so material
    /// drift can find every affected contract in one lookup.
    pub callee_manifest: String,
    /// Digest over exactly the contracted items — what the mediator compares.
    pub surface_digest: String,
    /// The contracted surface.
    pub surface: Surface,
    /// The contracted terms.
    pub terms: Terms,
    /// Mediator ids this contract is addressed to. One contract per mediator, so
    /// replay against a different mediator fails on `aud`.
    #[serde(default)]
    pub aud: Vec<String>,
    /// `sha256:…` over the issued JWS.
    pub jws_sha256: String,
    /// Lifecycle state.
    pub status: ContractStatus,
    /// The approval that authorised issuance.
    pub approval: ApprovalRef,
    /// Policy version in force at mint time.
    pub policy_version: String,
    /// Issued at.
    pub iat: u64,
    /// Expires at. Hard: there is no grace period.
    pub exp: u64,
    /// Record schema version.
    #[serde(default = "default_schema")]
    pub schema: u16,
}

/// The contract record schema this build writes.
pub const CONTRACT_SCHEMA: u16 = 1;

fn default_schema() -> u16 {
    CONTRACT_SCHEMA
}

impl ContractRecord {
    /// Whether this contract authorises anything as of `now`.
    #[must_use]
    pub fn is_live(&self, now: u64) -> bool {
        self.status == ContractStatus::Active && now < self.exp
    }

    /// Time-to-live remaining, saturating at zero.
    #[must_use]
    pub fn remaining_secs(&self, now: u64) -> u64 {
        self.exp.saturating_sub(now)
    }

    /// Whether this party is either end of the contract.
    #[must_use]
    pub fn involves(&self, id: &EntityId) -> bool {
        &self.caller == id || &self.callee == id
    }

    /// Check the ceiling invariant: the contracted surface must be a subset of
    /// the callee's declared surface, and the recorded digest must be the one
    /// that subset actually hashes to.
    pub fn assert_digest_matches(&self, pin: &crate::model::Pin) -> Result<()> {
        let expected = pin.surface_digest(&self.surface.items())?;
        if expected != self.surface_digest {
            return Err(WcError::with_detail(
                Code::PIN_MISMATCH,
                format!(
                    "{}: contracted digest {} but declared surface hashes to {}",
                    self.cid, self.surface_digest, expected
                ),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::model::{Pin, PIN_ALG};
    use std::collections::BTreeMap;

    fn surface(tools: &[&str]) -> Surface {
        Surface {
            tools: tools.iter().map(|t| (*t).to_string()).collect(),
            skills: Vec::new(),
            resources: Vec::new(),
        }
    }

    #[test]
    fn items_are_sorted_and_deduplicated() {
        let s = Surface {
            tools: vec!["b".into(), "a".into(), "b".into()],
            skills: vec!["c".into()],
            resources: vec!["ledger://x".into()],
        };
        assert_eq!(s.items(), vec!["a".to_string(), "b".into(), "c".into()]);
    }

    #[test]
    fn subset_checks_every_dimension() {
        let declared = Surface {
            tools: vec!["a".into(), "b".into()],
            skills: vec!["s".into()],
            resources: vec!["ledger://*".into()],
        };
        assert!(surface(&["a"]).is_subset_of(&declared));
        assert!(!surface(&["a", "z"]).is_subset_of(&declared));

        let extra_skill = Surface {
            skills: vec!["other".into()],
            ..Default::default()
        };
        assert!(!extra_skill.is_subset_of(&declared));
    }

    // --- the narrowing algebra ---

    #[test]
    fn intersect_takes_the_tighter_ceiling() {
        let a = Terms {
            max_calls_per_hour: Some(500),
            max_concurrent: Some(8),
            max_spend_usd_per_day: Some(200.0),
            delegation: Delegation {
                max_depth: 2,
                attenuation: "monotonic".into(),
            },
            ..Default::default()
        };
        let b = Terms {
            max_calls_per_hour: Some(100),
            max_concurrent: Some(16),
            max_spend_usd_per_day: Some(50.0),
            delegation: Delegation {
                max_depth: 1,
                attenuation: "monotonic".into(),
            },
            ..Default::default()
        };
        let t = a.intersect(&b);
        assert_eq!(t.max_calls_per_hour, Some(100));
        assert_eq!(t.max_concurrent, Some(8));
        assert_eq!(t.max_spend_usd_per_day, Some(50.0));
        assert_eq!(t.delegation.max_depth, 1);
    }

    #[test]
    fn intersect_never_widens() {
        // The property §7.4 rests on: for every pair, the result is no more
        // permissive than either input.
        let samples = [
            Terms::default(),
            Terms {
                max_calls_per_hour: Some(10),
                ..Default::default()
            },
            Terms {
                max_calls_per_hour: Some(1_000),
                max_spend_usd_per_day: Some(5.0),
                delegation: Delegation {
                    max_depth: 4,
                    attenuation: "monotonic".into(),
                },
                ..Default::default()
            },
            Terms {
                data_classes: vec!["internal".into(), "confidential".into()],
                jurisdictions: vec!["SG".into(), "AU".into()],
                evidence: EvidenceTerms {
                    sink: "ocsf://siem".into(),
                    delivery: "blocking".into(),
                },
                ..Default::default()
            },
        ];

        for a in &samples {
            for b in &samples {
                let r = a.intersect(b);

                for (result, input) in [
                    (r.max_calls_per_hour, a.max_calls_per_hour),
                    (r.max_calls_per_hour, b.max_calls_per_hour),
                    (r.max_concurrent, a.max_concurrent),
                    (r.max_concurrent, b.max_concurrent),
                ] {
                    if let Some(limit) = input {
                        assert!(
                            result.is_some_and(|got| got <= limit),
                            "ceiling widened: {result:?} > {limit}"
                        );
                    }
                }

                assert!(r.delegation.max_depth <= a.delegation.max_depth);
                assert!(r.delegation.max_depth <= b.delegation.max_depth);

                // A blocking obligation on either side survives.
                if a.evidence.delivery == "blocking" || b.evidence.delivery == "blocking" {
                    assert_eq!(r.evidence.delivery, "blocking");
                }

                // Data classes never gain a class neither side allowed.
                for class in &r.data_classes {
                    assert!(
                        a.data_classes.contains(class) || b.data_classes.contains(class),
                        "invented data class {class}"
                    );
                }
            }
        }
    }

    #[test]
    fn an_empty_allowlist_yields_rather_than_zeroing() {
        // "This source says nothing" must not mean "this source forbids
        // everything", or a request with no declared jurisdictions would
        // silently produce a contract that permits none.
        let unconstrained = Terms::default();
        let constrained = Terms {
            jurisdictions: vec!["SG".into()],
            ..Default::default()
        };
        assert_eq!(
            unconstrained.intersect(&constrained).jurisdictions,
            vec!["SG".to_string()]
        );
    }

    #[test]
    fn intersect_is_commutative_on_ceilings() {
        let a = Terms {
            max_calls_per_hour: Some(7),
            ..Default::default()
        };
        let b = Terms {
            max_calls_per_hour: Some(9),
            max_concurrent: Some(3),
            ..Default::default()
        };
        assert_eq!(
            a.intersect(&b).max_calls_per_hour,
            b.intersect(&a).max_calls_per_hour
        );
        assert_eq!(
            a.intersect(&b).max_concurrent,
            b.intersect(&a).max_concurrent
        );
    }

    // --- approvals ---

    #[test]
    fn dual_control_needs_two_distinct_humans() {
        let cecil = HumanRef::new("human:cecil@org").unwrap();
        let priya = HumanRef::new("human:priya@org").unwrap();

        let single = ApprovalRef {
            by: Some(cecil.clone()),
            jti: None,
            ticket: None,
            mode: ApprovalMode::Human,
            second: None,
        };
        assert!(!single.satisfies_dual_control());

        let same_twice = ApprovalRef {
            second: Some(cecil.clone()),
            ..single.clone()
        };
        assert!(!same_twice.satisfies_dual_control());

        let two = ApprovalRef {
            second: Some(priya),
            ..single
        };
        assert!(two.satisfies_dual_control());

        assert!(!ApprovalRef::standing().satisfies_dual_control());
    }

    // --- records ---

    fn pin_with(items: &[(&str, &str)]) -> Pin {
        Pin {
            alg: PIN_ALG.to_string(),
            manifest: "sha256:whole".to_string(),
            items: items
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<BTreeMap<_, _>>(),
            pinned_at: 1,
        }
    }

    fn record(pin: &Pin, tools: &[&str], exp: u64) -> ContractRecord {
        let s = surface(tools);
        ContractRecord {
            cid: Cid::new("conn_7f3a91c4").unwrap(),
            jti: Jti::new("cx_84be0011").unwrap(),
            caller: EntityId::new("spiffe://org/ns/agents/sa/recon-bot-7").unwrap(),
            callee: EntityId::new("spiffe://org/ns/tools/sa/payments-mcp").unwrap(),
            caller_zone: ZoneId::new("internal.apac-ops").unwrap(),
            callee_zone: ZoneId::new("internal.payments").unwrap(),
            callee_tier: Tier::TWO,
            callee_manifest: pin.manifest.clone(),
            surface_digest: pin.surface_digest(&s.items()).unwrap(),
            surface: s,
            terms: Terms::default(),
            aud: vec!["warden:mediator:apac-ops".to_string()],
            jws_sha256: "sha256:deadbeef".to_string(),
            status: ContractStatus::Active,
            approval: ApprovalRef::standing(),
            policy_version: "connect-policy@v37".to_string(),
            iat: 1_000,
            exp,
            schema: CONTRACT_SCHEMA,
        }
    }

    #[test]
    fn liveness_respects_status_and_expiry() {
        let pin = pin_with(&[("get_balance", "sha256:aa")]);
        let mut r = record(&pin, &["get_balance"], 2_000);
        assert!(r.is_live(1_500));
        assert!(!r.is_live(2_000), "exp is exclusive; no grace period");
        assert_eq!(r.remaining_secs(1_500), 500);
        assert_eq!(r.remaining_secs(9_999), 0);

        r.status = ContractStatus::Suspended;
        assert!(!r.is_live(1_500));
        r.status = ContractStatus::Revoked;
        assert!(!r.is_live(1_500));
    }

    #[test]
    fn involves_matches_either_end() {
        let pin = pin_with(&[("get_balance", "sha256:aa")]);
        let r = record(&pin, &["get_balance"], 2_000);
        assert!(r.involves(&r.caller.clone()));
        assert!(r.involves(&r.callee.clone()));
        assert!(!r.involves(&EntityId::new("spiffe://org/ns/other/sa/x").unwrap()));
    }

    #[test]
    fn digest_check_survives_additive_drift_but_not_material_drift() {
        let pin = pin_with(&[("get_balance", "sha256:aa"), ("wire_funds", "sha256:bb")]);
        let r = record(&pin, &["get_balance"], 2_000);
        assert!(r.assert_digest_matches(&pin).is_ok());

        // Additive: a new uncontracted tool appears. The contract still verifies.
        let grown = pin_with(&[
            ("get_balance", "sha256:aa"),
            ("wire_funds", "sha256:bb"),
            ("new_tool", "sha256:cc"),
        ]);
        assert!(r.assert_digest_matches(&grown).is_ok());

        // Material: the contracted tool itself changed.
        let changed = pin_with(&[("get_balance", "sha256:ff"), ("wire_funds", "sha256:bb")]);
        assert_eq!(
            r.assert_digest_matches(&changed).unwrap_err().code(),
            Code::PIN_MISMATCH
        );

        // Removed: the contracted tool is gone.
        let removed = pin_with(&[("wire_funds", "sha256:bb")]);
        assert_eq!(
            r.assert_digest_matches(&removed).unwrap_err().code(),
            Code::SURFACE_NOT_SUBSET
        );
    }

    #[test]
    fn records_round_trip_through_json() {
        let pin = pin_with(&[("get_balance", "sha256:aa")]);
        let r = record(&pin, &["get_balance"], 2_000);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<ContractRecord>(&json).unwrap(), r);
    }
}
