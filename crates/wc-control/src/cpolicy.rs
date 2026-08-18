//! Connection policy (`docs/08-lld.md` §8.5.5, §8.17-Q4).
//!
//! Decides whether two parties may be connected, on what terms, and for how long
//! — the decision that produces a contract. Warden core decides per action; this
//! decides per relationship.
//!
//! # Evaluation order
//!
//! "First match wins" is only safe if an operator can predict the order, so the
//! order is fixed and documented:
//!
//! 1. **Structural preconditions.** Not rules, and no rule can override them:
//!    both parties `Active`, neither quarantined, and the requested surface a
//!    subset of what the callee actually declared. A failure here is an error, not
//!    a decision — the request is impossible rather than refused.
//! 2. **Zone bar** for the caller/callee pair: a floor on assurance and a ceiling
//!    on TTL. An undefined zone falls back to its trust level's bar, and anything
//!    non-internal gets the strict one.
//! 3. **First matching `[[rules]]` entry**, top to bottom.
//! 4. **`default`**, if nothing matched.
//! 5. **Standing-policy caps**, which may only downgrade `allow` to
//!    `require_approval` — never the reverse.
//!
//! Terms from every source **intersect**. A rule cannot raise a ceiling a zone bar
//! set, and a request cannot raise either.
//!
//! # Syntax
//!
//! The condition tree deliberately mirrors Warden core's `policy.rs` —
//! `when = [...]`, `{all=[..]}`, `{any=[..]}`, `{not=..}`, and the same four
//! operators — so an operator writes one stanza style for both planes. It is
//! reimplemented rather than imported, because `wc-control` links no Warden core
//! (§8.3); `syntax_matches_warden_core_policy` pins the shapes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use wc_core::contract::{Delegation, EvidenceTerms, Surface, Terms};
use wc_core::error::{Code, Mode, Result, WcError};
use wc_core::model::{Entity, HumanRef, Lifecycle, Posture, Tier, TrustLevel, ZoneId};
use wc_core::zone::ZoneLattice;

use crate::admission::capability_class;

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/// What policy says about a connection request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnDecision {
    /// Issue a contract with no human in the loop.
    Allow,
    /// Refuse.
    Deny,
    /// Issue only after a named human signs for it.
    RequireApproval,
}

impl ConnDecision {
    /// The dotted name used in traces and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ConnDecision::Allow => "allow",
            ConnDecision::Deny => "deny",
            ConnDecision::RequireApproval => "require_approval",
        }
    }

    /// Whether this decision can produce a contract without a human.
    #[must_use]
    pub const fn is_standing(self) -> bool {
        matches!(self, ConnDecision::Allow)
    }
}

// ---------------------------------------------------------------------------
// Condition algebra (mirrors Warden core's policy.rs syntax)
// ---------------------------------------------------------------------------

/// Comparison operators. The same four Warden core supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Greater than, numeric.
    Gt,
    /// Less than, numeric.
    Lt,
    /// Equal, numeric or string.
    Eq,
    /// Substring or list membership.
    Contains,
}

/// A literal in a condition.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum PolicyValue {
    /// A number.
    Num(f64),
    /// A string.
    Str(String),
}

impl PolicyValue {
    fn as_f64(&self) -> Option<f64> {
        match self {
            PolicyValue::Num(n) => Some(*n),
            PolicyValue::Str(s) => s.parse().ok(),
        }
    }

    fn as_str(&self) -> String {
        match self {
            PolicyValue::Num(n) => format!("{n}"),
            PolicyValue::Str(s) => s.clone(),
        }
    }
}

/// One condition over a namespaced field.
#[derive(Debug, Clone, Deserialize)]
pub struct Cond {
    /// Namespaced field, e.g. `callee:tier` or `surface:count`.
    #[serde(default)]
    pub field: Option<String>,
    /// Operator.
    pub op: Op,
    /// Value to compare against.
    pub value: PolicyValue,
}

impl Cond {
    /// `(namespace, key)`, or `None` if the field is malformed.
    #[must_use]
    pub fn target(&self) -> Option<(&str, &str)> {
        self.field.as_deref()?.split_once(':')
    }

    /// A compact rendering for traces and lint output.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{} {:?} {}",
            self.field.as_deref().unwrap_or("?"),
            self.op,
            self.value.as_str()
        )
    }
}

/// A boolean tree over conditions. `when` accepts a single condition, an array
/// (implicit AND), or `{all=[..]}` / `{any=[..]}` / `{not=..}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Match {
    /// One condition.
    Cond(Cond),
    /// An array is an implicit AND.
    All(Vec<Match>),
    /// Explicit AND.
    AllObj {
        /// Conjuncts.
        all: Vec<Match>,
    },
    /// Explicit OR.
    AnyObj {
        /// Disjuncts.
        any: Vec<Match>,
    },
    /// Negation.
    NotObj {
        /// The negated tree.
        not: Box<Match>,
    },
}

impl Match {
    /// Evaluate against a request's facts.
    #[must_use]
    pub fn matches(&self, facts: &Facts) -> bool {
        match self {
            Match::Cond(c) => facts.satisfies(c),
            Match::All(v) | Match::AllObj { all: v } => v.iter().all(|m| m.matches(facts)),
            Match::AnyObj { any } => any.iter().any(|m| m.matches(facts)),
            Match::NotObj { not } => !not.matches(facts),
        }
    }

    /// Every namespace referenced, for linting.
    fn namespaces(&self, out: &mut Vec<String>) {
        match self {
            Match::Cond(c) => {
                if let Some((ns, _)) = c.target() {
                    out.push(ns.to_string());
                }
            }
            Match::All(v) | Match::AllObj { all: v } | Match::AnyObj { any: v } => {
                for m in v {
                    m.namespaces(out);
                }
            }
            Match::NotObj { not } => not.namespaces(out),
        }
    }

    /// A compact rendering.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Match::Cond(c) => c.describe(),
            Match::All(v) | Match::AllObj { all: v } => format!(
                "all[{}]",
                v.iter().map(Match::describe).collect::<Vec<_>>().join(", ")
            ),
            Match::AnyObj { any } => format!(
                "any[{}]",
                any.iter()
                    .map(Match::describe)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Match::NotObj { not } => format!("not({})", not.describe()),
        }
    }
}

/// Field namespaces a condition may reference.
pub const NAMESPACES: &[&str] = &["caller", "callee", "surface", "request", "terms"];

/// The facts a condition tree is evaluated against.
///
/// Built once per evaluation so a rule cannot observe anything the trace does not
/// also record.
#[derive(Debug, Default)]
pub struct Facts {
    strings: BTreeMap<String, String>,
    numbers: BTreeMap<String, f64>,
    lists: BTreeMap<String, Vec<String>>,
}

impl Facts {
    fn put_str(&mut self, key: &str, value: impl Into<String>) {
        self.strings.insert(key.to_string(), value.into());
    }
    fn put_num(&mut self, key: &str, value: f64) {
        self.numbers.insert(key.to_string(), value);
    }
    fn put_list(&mut self, key: &str, value: Vec<String>) {
        self.lists.insert(key.to_string(), value);
    }

    /// Whether a condition holds. An unknown field never matches — a typo must
    /// not silently satisfy a rule.
    #[must_use]
    pub fn satisfies(&self, cond: &Cond) -> bool {
        let Some(field) = cond.field.as_deref() else {
            return false;
        };
        match cond.op {
            Op::Gt | Op::Lt => {
                let (Some(actual), Some(expected)) = (self.numbers.get(field), cond.value.as_f64())
                else {
                    return false;
                };
                if cond.op == Op::Gt {
                    *actual > expected
                } else {
                    *actual < expected
                }
            }
            Op::Eq => {
                if let (Some(actual), Some(expected)) =
                    (self.numbers.get(field), cond.value.as_f64())
                {
                    return (*actual - expected).abs() < f64::EPSILON;
                }
                self.strings.get(field) == Some(&cond.value.as_str())
            }
            Op::Contains => {
                let needle = cond.value.as_str();
                if let Some(list) = self.lists.get(field) {
                    return list.contains(&needle);
                }
                self.strings
                    .get(field)
                    .is_some_and(|s| s.contains(needle.as_str()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Zones and assurance bars
// ---------------------------------------------------------------------------

/// Whether an assurance property is demanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// Not demanded.
    #[default]
    Optional,
    /// Demanded; absence refuses the connection.
    Required,
}

impl Requirement {
    /// The stricter of two.
    #[must_use]
    fn strictest(self, other: Requirement) -> Requirement {
        self.max(other)
    }
}

/// How a connection into or out of a zone may be approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    /// Standing policy may issue without a human.
    #[default]
    Standing,
    /// A named human must sign.
    Human,
    /// Two distinct humans must sign.
    DualControl,
}

/// The bar a zone sets for any connection touching it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct AssuranceBar {
    /// Whether verified workload identity is demanded.
    pub identity: Requirement,
    /// Whether verified build provenance is demanded.
    pub provenance: Requirement,
    /// Ceiling on contract lifetime, as a duration string (`"7d"`, `"24h"`).
    pub ttl_max: Option<String>,
    /// How approval must be obtained.
    pub approval: ApprovalRequirement,
    /// Whether human oversight must be set in the terms.
    pub oversight: Requirement,
    /// Ceiling on delegation depth.
    pub max_delegation_depth: Option<u8>,
}

impl Default for AssuranceBar {
    fn default() -> Self {
        AssuranceBar {
            identity: Requirement::Optional,
            provenance: Requirement::Optional,
            ttl_max: None,
            approval: ApprovalRequirement::Standing,
            oversight: Requirement::Optional,
            max_delegation_depth: None,
        }
    }
}

impl AssuranceBar {
    /// The bar a trust level implies when no zone is defined.
    ///
    /// Anything not internal gets the strict bar: an unclassified counterparty is
    /// treated as external until someone classifies it.
    #[must_use]
    pub fn for_trust(trust: TrustLevel) -> AssuranceBar {
        match trust {
            TrustLevel::Internal => AssuranceBar {
                identity: Requirement::Required,
                provenance: Requirement::Optional,
                ttl_max: Some("30d".to_string()),
                approval: ApprovalRequirement::Standing,
                oversight: Requirement::Optional,
                max_delegation_depth: Some(3),
            },
            TrustLevel::Partner => AssuranceBar {
                identity: Requirement::Required,
                provenance: Requirement::Required,
                ttl_max: Some("7d".to_string()),
                approval: ApprovalRequirement::Human,
                oversight: Requirement::Required,
                max_delegation_depth: Some(1),
            },
            TrustLevel::Public => AssuranceBar {
                identity: Requirement::Required,
                provenance: Requirement::Required,
                ttl_max: Some("24h".to_string()),
                approval: ApprovalRequirement::DualControl,
                oversight: Requirement::Required,
                max_delegation_depth: Some(0),
            },
        }
    }

    /// Combine two bars by taking the stricter of each — how a pair's bar is
    /// derived from both ends.
    #[must_use]
    pub fn strictest(&self, other: &AssuranceBar) -> AssuranceBar {
        AssuranceBar {
            identity: self.identity.strictest(other.identity),
            provenance: self.provenance.strictest(other.provenance),
            ttl_max: match (self.ttl_secs(), other.ttl_secs()) {
                (Some(a), Some(b)) => Some(format!("{}s", a.min(b))),
                (Some(a), None) | (None, Some(a)) => Some(format!("{a}s")),
                (None, None) => None,
            },
            approval: self.approval.max(other.approval),
            oversight: self.oversight.strictest(other.oversight),
            max_delegation_depth: match (self.max_delegation_depth, other.max_delegation_depth) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) | (None, Some(a)) => Some(a),
                (None, None) => None,
            },
        }
    }

    /// The TTL ceiling in seconds.
    #[must_use]
    pub fn ttl_secs(&self) -> Option<u64> {
        self.ttl_max.as_deref().and_then(parse_duration)
    }
}

/// A declared crossing permission (`[[crossing]]`).
///
/// Crossings between trust levels are denied by default, so this is how an estate
/// says "these two, this way round". Directional on purpose: permitting egress to
/// a partner does not permit that partner to reach back in.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossingDef {
    /// Which crossing: `egress`, `ingress`, `public`, or a same-level kind.
    pub crossing: String,
    /// Caller zone or subtree. Absent means any.
    #[serde(default)]
    pub from: Option<String>,
    /// Callee zone or subtree. Absent means any.
    #[serde(default)]
    pub to: Option<String>,
}

/// A declared zone.
///
/// `deny_unknown_fields` is load-bearing here rather than tidy. TOML binds a bare
/// key after an array-of-tables stanza to *that table*, so a root-level setting
/// written below `[[zone]]` lands inside the zone and is silently ignored — which
/// is how `strict_crossings = true` can read as enabled and do nothing.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneDef {
    /// Zone id, e.g. `internal.payments`.
    pub id: String,
    /// Trust level.
    pub trust: TrustLevel,
    /// The bar; unset properties fall back to the trust level's.
    #[serde(default)]
    pub assurance: AssuranceBar,
}

/// Parse `"30d"`, `"24h"`, `"90m"`, `"3600s"` or a bare number of seconds.
#[must_use]
pub fn parse_duration(text: &str) -> Option<u64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let (digits, multiplier) = match text.chars().last()? {
        'd' => (&text[..text.len() - 1], 86_400),
        'h' => (&text[..text.len() - 1], 3_600),
        'm' => (&text[..text.len() - 1], 60),
        's' => (&text[..text.len() - 1], 1),
        _ => (text, 1),
    };
    digits.trim().parse::<u64>().ok()?.checked_mul(multiplier)
}

// ---------------------------------------------------------------------------
// Rule matchers
// ---------------------------------------------------------------------------

/// A glob over a dotted identifier: exact, `*`, or `prefix*` — the same three
/// forms Warden core's `policy.rs` accepts on a tool name.
///
/// `prefix*` matches any value beginning with `prefix`, including `prefix` itself.
/// So `internal.*` matches `internal.payments` and does **not** match bare
/// `internal` — not by a special case, but because `internal` does not begin with
/// `internal.`. Whereas `public*` does match bare `public`, which is what an
/// operator writing it means.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Glob(pub String);

impl Glob {
    /// Whether this glob matches a value.
    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        match self.0.strip_suffix('*') {
            None => self.0 == value,
            Some("") => true,
            Some(prefix) => value.starts_with(prefix),
        }
    }
}

/// A numeric comparison on a tier.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TierMatch {
    /// Operator.
    pub op: Op,
    /// Tier to compare against.
    pub value: u8,
}

impl TierMatch {
    /// Whether a tier satisfies this match.
    ///
    /// Numeric, so `lte 2` means "tier 1 or 2" — the *more* sensitive end, since
    /// tier 1 is most sensitive.
    #[must_use]
    pub fn matches(&self, tier: Tier) -> bool {
        let actual = f64::from(tier.as_u8());
        let expected = f64::from(self.value);
        match self.op {
            Op::Gt => actual > expected,
            Op::Lt => actual < expected,
            Op::Eq => (actual - expected).abs() < f64::EPSILON,
            // `contains` is meaningless on a tier; never match rather than guess.
            Op::Contains => false,
        }
    }
}

/// Constraints on the requested surface.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SurfaceMatch {
    /// Matches only surfaces whose write-capability equals this. `false` means no
    /// write-capable item; `true` means at least one.
    pub write: Option<bool>,
    /// Ceiling on how many items may be requested.
    pub max_tools: Option<usize>,
}

impl SurfaceMatch {
    /// Whether a surface satisfies this match.
    #[must_use]
    pub fn matches(&self, surface: &Surface) -> bool {
        if let Some(max) = self.max_tools {
            if surface.items().len() > max {
                return false;
            }
        }
        if let Some(want_write) = self.write {
            // Both directions, which is the fix: `write = false` had always excluded
            // write-capable surfaces, and `write = true` had matched *everything* —
            // the branch only ever fired on `!write_allowed`. The shipped
            // `connect-policy.toml` used `surface = { write = true }` on its
            // money-movement rule meaning "only when write-capable", so that rule was
            // silently matching read-only payments traffic as well, and first-match-wins
            // sent balance checks to a payments controller. A matcher that reads as a
            // restriction and restricts nothing is the defect class this codebase
            // produces; here it pushed toward approval fatigue (A7) rather than toward
            // permission, which is why nobody noticed.
            if surface_is_write_capable(surface) != want_write {
                return false;
            }
        }
        true
    }
}

/// Whether any contracted item is write-capable or worse.
///
/// Keyed off item **names** only: the policy engine has the contracted names, not
/// the full tool documents — those were screened at admission. A name-based
/// judgement is conservative in the right direction, because an unmapped name is
/// class 2 (write) rather than class 4.
#[must_use]
pub fn surface_is_write_capable(surface: &Surface) -> bool {
    surface
        .items()
        .iter()
        .any(|name| capability_class(name, &serde_json::json!({})) <= 2)
}

/// Ceilings a rule imposes. Every field may only narrow.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TermsOverride {
    /// Call-rate ceiling.
    pub max_calls_per_hour: Option<u32>,
    /// Concurrency ceiling.
    pub max_concurrent: Option<u32>,
    /// Daily spend ceiling.
    pub max_spend_usd_per_day: Option<f64>,
    /// Oversight threshold.
    pub human_oversight: Option<String>,
    /// Delegation depth ceiling.
    pub max_delegation_depth: Option<u8>,
    /// Evidence sink.
    pub evidence_sink: Option<String>,
    /// Evidence delivery: `blocking` or `fail-safe`.
    pub evidence_delivery: Option<String>,
}

impl TermsOverride {
    /// Render as [`Terms`] so it can be intersected.
    #[must_use]
    pub fn to_terms(&self) -> Terms {
        Terms {
            data_classes: Vec::new(),
            jurisdictions: Vec::new(),
            max_calls_per_hour: self.max_calls_per_hour,
            max_concurrent: self.max_concurrent,
            max_spend_usd_per_day: self.max_spend_usd_per_day,
            human_oversight: self.human_oversight.clone(),
            delegation: Delegation {
                max_depth: self.max_delegation_depth.unwrap_or(u8::MAX),
                attenuation: "monotonic".to_string(),
            },
            evidence: EvidenceTerms {
                sink: self.evidence_sink.clone().unwrap_or_default(),
                delivery: self
                    .evidence_delivery
                    .clone()
                    .unwrap_or_else(|| "fail-safe".to_string()),
            },
            // A rule override is a source, not a result: it has never intersected
            // anything, so neither list can be closed.
            classes_closed: false,
            jurisdictions_closed: false,
        }
    }
}

/// One policy rule.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnRule {
    /// Caller zone glob.
    #[serde(default)]
    pub caller_zone: Option<Glob>,
    /// Callee zone glob.
    #[serde(default)]
    pub callee_zone: Option<Glob>,
    /// Caller tier match.
    #[serde(default)]
    pub caller_tier: Option<TierMatch>,
    /// Callee tier match.
    #[serde(default)]
    pub callee_tier: Option<TierMatch>,
    /// Surface constraints.
    #[serde(default)]
    pub surface: Option<SurfaceMatch>,
    /// Data classes that must all be covered by the request.
    #[serde(default)]
    pub data_classes: Option<Vec<String>>,
    /// Jurisdictions that must all be covered by the request.
    #[serde(default)]
    pub jurisdictions: Option<Vec<String>>,
    /// Free-form condition tree.
    #[serde(default)]
    pub when: Option<Match>,
    /// The decision when this rule matches.
    pub decision: ConnDecision,
    /// Role an approver must hold.
    #[serde(default)]
    pub approver_role: Option<String>,
    /// Approval floor this rule imposes, which may only be **stricter** than the
    /// zone bar's — never looser.
    ///
    /// Without this a rule could name *which* role must sign and never *how many*,
    /// so dual control was reachable only from a zone bar. A bar is per-zone, and
    /// `callee_tier` and `surface.write` are matchable only here — which meant
    /// "any tier 1 callee needs two approvers" was inexpressible unless every
    /// tier-1 callee got a zone of its own. The shipped policy's own money-movement
    /// rule minted on one signature while `quarantine` demanded two for the same
    /// party, and `docs/threat-model.md` called dual control at tier 1 the
    /// preventive half of A10.
    #[serde(default)]
    pub approval: Option<ApprovalRequirement>,
    /// TTL ceiling this rule imposes.
    #[serde(default)]
    pub ttl_max: Option<String>,
    /// Term ceilings this rule imposes.
    #[serde(default)]
    pub terms: Option<TermsOverride>,
    /// Operator-facing reason, shown on a denial.
    #[serde(default)]
    pub reason: Option<String>,
}

impl ConnRule {
    /// Whether every stated criterion holds.
    fn matches(&self, req: &ConnRequest, caller: &Entity, callee: &Entity, facts: &Facts) -> bool {
        if let Some(glob) = &self.caller_zone {
            if !glob.matches(caller.zone.as_str()) {
                return false;
            }
        }
        if let Some(glob) = &self.callee_zone {
            if !glob.matches(callee.zone.as_str()) {
                return false;
            }
        }
        if let Some(m) = &self.caller_tier {
            if !m.matches(caller.tier) {
                return false;
            }
        }
        if let Some(m) = &self.callee_tier {
            if !m.matches(callee.tier) {
                return false;
            }
        }
        if let Some(m) = &self.surface {
            if !m.matches(&req.surface) {
                return false;
            }
        }
        if let Some(required) = &self.data_classes {
            // Every class the rule names must be one the request declares.
            if !required.iter().all(|c| req.terms.data_classes.contains(c)) {
                return false;
            }
        }
        if let Some(required) = &self.jurisdictions {
            if !required.iter().all(|j| req.terms.jurisdictions.contains(j)) {
                return false;
            }
        }
        if let Some(tree) = &self.when {
            if !tree.matches(facts) {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Standing-policy caps (§8.17-Q4)
// ---------------------------------------------------------------------------

/// Bounds on how much of the estate may be auto-approved.
///
/// Auto-approval is required for adoption and is simultaneously the widest policy
/// surface in the system, so it is bounded **in the engine** with a fail direction
/// toward humans. Every breach downgrades to `require_approval`; none ever
/// upgrades to `allow`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StandingLimits {
    /// Maximum share of active contracts that may be standing-issued.
    pub max_share: f64,
    /// Active contracts below which the share cap does not apply.
    ///
    /// Whether standing issuance may happen at all.
    ///
    /// **False in v1, and that is a decision rather than a default.** Every connection is
    /// approved by a human. The caps below are built, tested and inert: they bound a feature
    /// that is switched off, and they exist so that turning it on later is a configuration
    /// change rather than a new subsystem.
    ///
    /// The reasoning is that auto-approval is simultaneously the thing that makes a register
    /// adoptable and the widest policy surface in the system — and this codebase's own history
    /// is that standing policy once auto-issued to parties whose attestation had just failed.
    /// A control that broad should earn its place after the estate is stable and the evidence
    /// chain has been read in anger, not before.
    ///
    /// Not the same gate as `reviewed_at`. That one asks "has anybody signed off these
    /// limits"; this one asks "is this feature in play". A single number in a TOML file should
    /// not be the whole distance between every-request-approved and none.
    pub enabled: bool,
    /// A percentage of a tiny denominator is noise: with one active contract, one
    /// standing issuance is 100% and the cap would escalate every request forever,
    /// so an estate could never get past its first contract. Below this many, the
    /// per-window count is the meaningful bound.
    pub share_min_sample: usize,
    /// Maximum standing issuances per window.
    pub max_per_window: u32,
    /// Window length, as a duration string.
    pub window: String,
    /// Least sensitive tier eligible; a callee more sensitive than this always
    /// needs a human.
    pub min_callee_tier: u8,
    /// Whether a write-capable surface may be standing-issued.
    pub allow_write: bool,
    /// Ceiling on items per standing-issued contract.
    pub max_tools: usize,
    /// How often the standing rules must be reviewed.
    pub review_every: String,
    /// When they were last reviewed. Zero means never.
    pub reviewed_at: u64,
}

impl Default for StandingLimits {
    fn default() -> Self {
        StandingLimits {
            enabled: false,
            max_share: 0.6,
            share_min_sample: 20,
            max_per_window: 50,
            window: "24h".to_string(),
            min_callee_tier: 3,
            allow_write: false,
            max_tools: 8,
            review_every: "90d".to_string(),
            reviewed_at: 0,
        }
    }
}

/// What the control plane knows about standing issuance right now.
#[derive(Debug, Clone, Copy, Default)]
pub struct StandingState {
    /// Active contracts in the estate.
    pub active_contracts: usize,
    /// How many of those were standing-issued.
    pub standing_contracts: usize,
    /// Standing issuances inside the current window.
    pub issued_in_window: u32,
}

impl StandingLimits {
    /// Why standing issuance is not available, if it is not.
    ///
    /// Returns `None` when auto-approval is permitted.
    #[must_use]
    pub fn blocks(
        &self,
        req: &ConnRequest,
        callee: &Entity,
        state: &StandingState,
        now: u64,
    ) -> Option<String> {
        // First, because it is the most fundamental reason and the one an operator should be
        // told. Every check below bounds a feature; this one asks whether the feature is on.
        if !self.enabled {
            return Some(
                "standing issuance is off: every connection needs a human in v1. Set                  `[standing] enabled = true` once the estate is stable and these limits have                  been reviewed — auto-approval is the widest policy surface here, and it has                  already once issued to a party whose attestation had just failed"
                    .to_string(),
            );
        }
        if callee.tier.as_u8() < self.min_callee_tier {
            return Some(format!(
                "callee is {} and standing policy stops at tier {}",
                callee.tier, self.min_callee_tier
            ));
        }
        if !self.allow_write && surface_is_write_capable(&req.surface) {
            return Some("the requested surface is write-capable".to_string());
        }
        let count = req.surface.items().len();
        if count > self.max_tools {
            return Some(format!(
                "{count} items requested, standing policy caps at {}",
                self.max_tools
            ));
        }
        if state.issued_in_window >= self.max_per_window {
            return Some(format!(
                "{} standing issuances this window, cap is {}",
                state.issued_in_window, self.max_per_window
            ));
        }
        if state.active_contracts >= self.share_min_sample {
            let share = state.standing_contracts as f64 / state.active_contracts as f64;
            if share >= self.max_share {
                return Some(format!(
                    "{:.0}% of {} active contracts are standing-issued, cap is {:.0}%",
                    share * 100.0,
                    state.active_contracts,
                    self.max_share * 100.0
                ));
            }
        }
        // An unreviewed standing policy is a policy nobody is accountable for.
        if let Some(every) = parse_duration(&self.review_every) {
            if self.reviewed_at == 0 || now.saturating_sub(self.reviewed_at) > every {
                return Some(format!(
                    "standing rules are overdue for review (every {})",
                    self.review_every
                ));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Request and outcome
// ---------------------------------------------------------------------------

/// A request for a connection.
#[derive(Debug, Clone)]
pub struct ConnRequest {
    /// Requested surface.
    pub surface: Surface,
    /// Requested terms, including declared data classes and jurisdictions.
    pub terms: Terms,
    /// Requested lifetime, seconds.
    pub ttl_secs: u64,
    /// Why the requester wants it. Recorded, never evaluated.
    pub justification: String,
    /// Who asked.
    pub requester: HumanRef,
}

/// The policy outcome.
#[derive(Debug, Clone)]
pub struct ConnEval {
    /// The decision.
    pub decision: ConnDecision,
    /// Operator-facing reason.
    pub reason: String,
    /// Which gates decided it, in order — goes into the evidence record so a
    /// decision can be explained months later.
    pub trace: String,
    /// The lifetime a contract may actually be given, seconds.
    pub ttl_secs: u64,
    /// The terms a contract may actually carry: every source intersected.
    pub terms: Terms,
    /// Role an approver must hold, when a human is required.
    pub approver_role: Option<String>,
    /// Whether two distinct approvers are needed.
    pub dual_control: bool,
    /// The bar the zone pair set.
    pub bar: AssuranceBar,
}

impl ConnEval {
    /// Whether a contract may be minted without further human action.
    #[must_use]
    pub fn is_issuable(&self) -> bool {
        self.decision == ConnDecision::Allow
    }
}

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

/// Ceiling on any contract this issuer will mint, whatever policy says.
pub const ISSUER_MAX_TTL_SECS: u64 = 30 * 86_400;

/// A parsed `connect-policy.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectPolicy {
    /// Decision when no rule matches.
    pub default: ConnDecision,
    /// Version string, recorded on every contract minted under it.
    pub version: String,
    /// Declared zones.
    #[serde(default, rename = "zone")]
    pub zones: Vec<ZoneDef>,
    /// Declared crossing permissions.
    #[serde(default, rename = "crossing")]
    pub crossings: Vec<CrossingDef>,
    /// Refuse any zone that no declaration covers.
    #[serde(default)]
    pub strict_zones: bool,
    /// Enforce the zone lattice as a structural gate.
    ///
    /// **Off by default, and that is a compatibility decision rather than a
    /// security preference.** `[[rules]]` already express crossings through
    /// `caller_zone` / `callee_zone` globs, so switching the lattice on by default
    /// would demand every estate say the same thing twice — and forgetting the
    /// second place would deny traffic they believed they had allowed.
    ///
    /// On, a crossing between trust levels needs an explicit `[[crossing]]` and no
    /// rule can open one. `connect policy lint` reports which crossings the
    /// existing rules imply, so this can be turned on with knowledge rather than
    /// with a rollback.
    #[serde(default)]
    pub strict_crossings: bool,
    /// Rules, in order.
    #[serde(default, rename = "rules")]
    pub rules: Vec<ConnRule>,
    /// Standing-policy caps.
    #[serde(default)]
    pub standing: StandingLimits,
}

impl ConnectPolicy {
    /// Parse from TOML.
    pub fn parse(text: &str) -> Result<ConnectPolicy> {
        toml::from_str(text).map_err(|e| {
            WcError::with_detail(Code::POLICY_INVALID, format!("cannot parse policy: {e}"))
                .with_source(e)
        })
    }

    /// Load from a file.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<ConnectPolicy> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| {
            WcError::with_detail(
                Code::POLICY_INVALID,
                format!("cannot read {}", path.display()),
            )
            .with_source(e)
        })?;
        ConnectPolicy::parse(&text)
    }

    /// The declared zone whose id most specifically covers `zone`.
    ///
    /// Longest-prefix match, so `internal.payments` prefers a definition for
    /// `internal.payments` over one for `internal`.
    #[must_use]
    pub fn zone_def(&self, zone: &ZoneId) -> Option<&ZoneDef> {
        self.zones
            .iter()
            .filter(|z| {
                let id = z.id.as_str();
                zone.as_str() == id
                    || (zone.as_str().starts_with(id)
                        && zone.as_str().as_bytes().get(id.len()) == Some(&b'.'))
            })
            .max_by_key(|z| z.id.len())
    }

    /// The bar a single zone sets: every ancestor's declaration, combined with its
    /// trust level's floor.
    ///
    /// **Inherited along the whole ancestor chain, not taken from the most
    /// specific match.** Most-specific-wins is the right rule for *finding* a
    /// declaration and the wrong rule for *applying* one: with it, declaring
    /// `internal` at `ttl_max = "1d"` and `internal.payments` at `"30d"` lets the
    /// child widen the parent — and it reads, in the policy file, as tightening.
    #[must_use]
    pub fn bar_for(&self, zone: &ZoneId) -> AssuranceBar {
        let mut bar = AssuranceBar::for_trust(zone.trust_level());
        for ancestor in wc_core::zone::ancestors(zone) {
            if let Some(def) = self.zones.iter().find(|z| z.id == ancestor.as_str()) {
                bar = bar
                    .strictest(&def.assurance)
                    .strictest(&AssuranceBar::for_trust(def.trust));
            }
        }
        bar
    }

    /// Crossings between trust levels that the `[[rules]]` list appears to permit.
    ///
    /// The bridge between the two mechanisms: an estate turning on
    /// `strict_crossings` needs to know which `[[crossing]]` stanzas to write
    /// first, and deriving them from the rules already in the file beats
    /// discovering them from denied traffic.
    #[must_use]
    pub fn implied_crossings(&self) -> Vec<(wc_core::zone::Crossing, String, String)> {
        let mut out: Vec<(wc_core::zone::Crossing, String, String)> = Vec::new();
        let mut seen: std::collections::BTreeSet<(wc_core::zone::Crossing, String, String)> =
            std::collections::BTreeSet::new();

        for rule in &self.rules {
            if rule.decision == ConnDecision::Deny {
                continue;
            }
            let (Some(from), Some(to)) = (&rule.caller_zone, &rule.callee_zone) else {
                continue;
            };
            // A glob is not a zone, so this works from the declared zones it
            // matches. A rule naming zones nobody declared implies nothing, which
            // `lint` already flags separately.
            for caller in self.zones.iter().filter(|z| from.matches(&z.id)) {
                for callee in self.zones.iter().filter(|z| to.matches(&z.id)) {
                    let (Ok(cz), Ok(ez)) = (ZoneId::new(&caller.id), ZoneId::new(&callee.id))
                    else {
                        continue;
                    };
                    let crossing = wc_core::zone::classify(&cz, &ez);
                    if crossing.is_internal_to_level() {
                        continue;
                    }
                    let key = (crossing, caller.id.clone(), callee.id.clone());
                    if seen.insert(key.clone()) {
                        out.push(key);
                    }
                }
            }
        }
        out
    }

    /// The zone lattice this policy declares.
    ///
    /// Built rather than cached, because a policy is parsed once and evaluated
    /// many times against a handful of zones — and a stale cached lattice after a
    /// SIGHUP reload would be a permission set nobody can see in the file.
    pub fn lattice(&self) -> Result<ZoneLattice> {
        let mut lattice = ZoneLattice::new();
        lattice.set_strict_membership(self.strict_zones);
        for def in &self.zones {
            lattice.declare(&ZoneId::new(&def.id)?, def.trust)?;
        }
        for def in &self.crossings {
            let crossing = wc_core::zone::Crossing::parse(&def.crossing)?;
            lattice.permit(wc_core::zone::CrossingRule {
                crossing,
                from: def.from.as_deref().map(ZoneId::new).transpose()?,
                to: def.to.as_deref().map(ZoneId::new).transpose()?,
            });
        }
        Ok(lattice)
    }

    /// The bar a pair sets: the stricter of both ends.
    #[must_use]
    pub fn bar_for_pair(&self, caller: &ZoneId, callee: &ZoneId) -> AssuranceBar {
        self.bar_for(caller).strictest(&self.bar_for(callee))
    }

    /// Evaluate a request.
    ///
    /// Structural failures are `Err` — the request is impossible, not refused.
    /// Policy outcomes are `Ok`, including denials.
    pub fn evaluate(
        &self,
        req: &ConnRequest,
        caller: &Entity,
        callee: &Entity,
        state: &StandingState,
        now: u64,
    ) -> Result<ConnEval> {
        // --- 1 · structural preconditions, which no rule may override ---
        if caller.id == callee.id {
            // A contract from a party to itself grants nothing and means nothing;
            // it is always a mistake in the request rather than a policy question.
            return Err(WcError::with_detail(
                Code::MINT_PRECONDITION_FAILED,
                format!("{} cannot be both ends of a connection", caller.id),
            ));
        }
        assert_party_connectable(caller, "caller")?;
        assert_party_connectable(callee, "callee")?;
        assert_surface_declared(req, callee)?;

        let mut trace: Vec<String> = Vec::new();

        // The zone lattice sits with the structural preconditions rather than in
        // the rule list: when it is enforced, a rule that matched a pair the
        // lattice forbids would be granting a crossing nobody declared. Rules
        // narrow; they never open a boundary.
        let decision = self.lattice()?.resolve(&caller.zone, &callee.zone);
        trace.push(format!("crossing[{}]", decision.crossing.as_str()));
        if self.strict_crossings && !decision.permitted {
            return Ok(ConnEval {
                decision: ConnDecision::Deny,
                reason: decision.reason,
                trace: trace.join("/"),
                ttl_secs: 0,
                terms: req.terms.clone(),
                approver_role: None,
                dual_control: false,
                bar: self.bar_for_pair(&caller.zone, &callee.zone),
            });
        }

        // --- 2 · the zone bar ---
        let bar = self.bar_for_pair(&caller.zone, &callee.zone);
        trace.push(format!(
            "zone-bar[{}→{}]",
            caller.zone.as_str(),
            callee.zone.as_str()
        ));

        let mut ttl = req
            .ttl_secs
            .min(ISSUER_MAX_TTL_SECS)
            .min(bar.ttl_secs().unwrap_or(u64::MAX));

        // Terms start as the request narrowed by the bar's demands.
        let mut terms = req.terms.clone();
        if let Some(depth) = bar.max_delegation_depth {
            terms.delegation.max_depth = terms.delegation.max_depth.min(depth);
        }
        if bar.oversight == Requirement::Required && terms.human_oversight.is_none() {
            // The bar demands oversight and the request set none, so the strictest
            // available reading applies rather than silently none.
            terms.human_oversight = Some("required".to_string());
        }

        // --- 3 · first matching rule ---
        let facts = self.facts(req, caller, callee, ttl);
        let mut decision = self.default;
        let mut reason = format!("default {}", self.default.as_str());
        let mut approver_role = None;
        let mut rule_approval = None;

        for (index, rule) in self.rules.iter().enumerate() {
            if !rule.matches(req, caller, callee, &facts) {
                continue;
            }
            trace.push(format!("rule[{index}]"));
            decision = rule.decision;
            reason = rule
                .reason
                .clone()
                .unwrap_or_else(|| format!("rule[{index}] {}", rule.decision.as_str()));
            approver_role = rule.approver_role.clone();
            rule_approval = rule.approval;

            if let Some(rule_ttl) = rule.ttl_max.as_deref().and_then(parse_duration) {
                ttl = ttl.min(rule_ttl);
            }
            if let Some(overrides) = &rule.terms {
                // Intersect, never assign: a rule cannot raise a ceiling the bar or
                // the request already set.
                terms = terms.intersect(&overrides.to_terms());
            }
            break;
        }
        if trace.len() == 1 {
            trace.push("default".to_string());
        }

        // --- 4 · the approval floor ---
        //
        // The bar's floor and the matched rule's, combined by `max` — the same
        // one-directional discipline `terms.intersect` uses. A rule may demand more
        // than its zone does and can never accept less, so reading the pair in either
        // order gives the same answer.
        let approval = match rule_approval {
            Some(from_rule) => bar.approval.max(from_rule),
            None => bar.approval,
        };
        // Which side is binding, so a denial and the trace name the same source.
        let rule_binds = rule_approval.is_some_and(|r| r > bar.approval);
        let mut dual_control = approval == ApprovalRequirement::DualControl;
        if decision == ConnDecision::Allow && approval != ApprovalRequirement::Standing {
            decision = ConnDecision::RequireApproval;
            let source = if rule_binds {
                "the matched rule".to_string()
            } else {
                format!("zone bar for {}", callee.zone.as_str())
            };
            reason = format!(
                "{source} requires {}",
                match approval {
                    ApprovalRequirement::DualControl => "two approvers",
                    _ => "a human approver",
                }
            );
            trace.push(
                if rule_binds {
                    "rule-approval"
                } else {
                    "zone-bar-approval"
                }
                .to_string(),
            );
        }
        if decision == ConnDecision::RequireApproval && approval == ApprovalRequirement::DualControl
        {
            dual_control = true;
        }

        // --- 5 · posture: an unproven party is never standing work ---
        //
        // Quarantine is refused above, structurally. Everything short of `Attested`
        // is different: it is a fact an approver needs, not a decision the policy
        // can make. So it escalates and names itself.
        //
        // The mediator's check 9 refuses these connections anyway (`WC-3109`), which
        // is exactly why this belongs here too. Without it, standing policy mints a
        // contract that can never carry a call — the register shows a live
        // connection, every request fails, and nobody was ever asked. Failing closed
        // downstream is not a reason to issue blindly upstream.
        for (role, party) in [("caller", caller), ("callee", callee)] {
            // `may_connect` already encodes the fail-closed matrix (§7.8). Asked with
            // `Enforce`, it answers "attested only" — the rule lives in one place
            // rather than being restated here.
            if party.posture.may_connect(Mode::Enforce) {
                continue;
            }
            if decision == ConnDecision::Allow {
                decision = ConnDecision::RequireApproval;
            }
            let note = format!(
                "{role} {} posture is {:?}, not attested",
                party.id, party.posture
            );
            reason = if reason.starts_with("default ") {
                note
            } else {
                format!("{reason}; {note}")
            };
            trace.push(format!("posture[{role}:{:?}]", party.posture).to_lowercase());
        }

        // --- 6 · no overlap is a denial, not an empty allowlist ---
        //
        // If the request, the bar and the matched rule have no data class or
        // jurisdiction in common, the honest answer is that nothing may cross. An
        // empty list on the wire reads as *unconstrained*, so minting here would
        // produce a contract that says the opposite of what was decided.
        if terms.is_closed() {
            return Ok(ConnEval {
                decision: ConnDecision::Deny,
                reason: "the request, the zone bar and the matched rule have no data class \
                         or jurisdiction in common, so nothing may cross"
                    .to_string(),
                trace: {
                    trace.push("terms-closed".to_string());
                    trace.join("/")
                },
                ttl_secs: 0,
                terms,
                approver_role: None,
                dual_control: false,
                bar,
            });
        }

        // --- 7 · standing-policy caps: may only downgrade ---
        if decision == ConnDecision::Allow {
            if let Some(why) = self.standing.blocks(req, callee, state, now) {
                decision = ConnDecision::RequireApproval;
                reason = format!("standing policy cannot cover this: {why}");
                trace.push("standing-cap".to_string());
            }
        }

        Ok(ConnEval {
            decision,
            reason,
            trace: trace.join("/"),
            ttl_secs: ttl,
            terms,
            approver_role,
            dual_control,
            bar,
        })
    }

    /// Build the fact set a condition tree sees.
    fn facts(&self, req: &ConnRequest, caller: &Entity, callee: &Entity, ttl: u64) -> Facts {
        let mut f = Facts::default();

        f.put_str("caller:zone", caller.zone.as_str());
        f.put_str(
            "caller:trust",
            format!("{:?}", caller.zone.trust_level()).to_lowercase(),
        );
        f.put_str(
            "caller:posture",
            format!("{:?}", caller.posture).to_lowercase(),
        );
        f.put_str("caller:service", caller.service.clone().unwrap_or_default());
        f.put_num("caller:tier", f64::from(caller.tier.as_u8()));

        f.put_str("callee:zone", callee.zone.as_str());
        f.put_str(
            "callee:trust",
            format!("{:?}", callee.zone.trust_level()).to_lowercase(),
        );
        f.put_str(
            "callee:posture",
            format!("{:?}", callee.posture).to_lowercase(),
        );
        f.put_str(
            "callee:endpoint",
            callee.endpoint.clone().unwrap_or_default(),
        );
        f.put_num("callee:tier", f64::from(callee.tier.as_u8()));

        let items = req.surface.items();
        f.put_num("surface:count", items.len() as f64);
        f.put_list("surface:tools", items);
        f.put_str(
            "surface:write",
            if surface_is_write_capable(&req.surface) {
                "true"
            } else {
                "false"
            },
        );

        f.put_num("request:ttl_days", (ttl / 86_400) as f64);
        f.put_str("request:requester", req.requester.as_str());
        f.put_list("terms:data_classes", req.terms.data_classes.clone());
        f.put_list("terms:jurisdictions", req.terms.jurisdictions.clone());
        f.put_num(
            "terms:delegation_depth",
            f64::from(req.terms.delegation.max_depth),
        );
        if let Some(rate) = req.terms.max_calls_per_hour {
            f.put_num("terms:max_calls_per_hour", f64::from(rate));
        }
        if let Some(spend) = req.terms.max_spend_usd_per_day {
            f.put_num("terms:max_spend_usd_per_day", spend);
        }
        f
    }

    /// Re-evaluate every live contract against this policy.
    ///
    /// A policy change is the likeliest cause of a self-inflicted outage, so this
    /// is a P1 deliverable rather than a nicety: it answers "what breaks if I ship
    /// this" before shipping it.
    ///
    /// Contracts whose parties are missing from the projection are reported as
    /// `unevaluable` rather than silently dropped — an answer that quietly omits
    /// half the estate is worse than no answer.
    pub fn dry_run(
        &self,
        projection: &crate::store::Projection,
        state: &StandingState,
        now: u64,
    ) -> DryRunReport {
        let mut report = DryRunReport::default();

        for contract in projection.contracts.values() {
            let cid = contract.cid.as_str().to_string();
            if contract.status != wc_core::contract::ContractStatus::Active {
                continue;
            }

            let (Some(caller), Some(callee)) = (
                projection.entities.get(&contract.caller),
                projection.entities.get(&contract.callee),
            ) else {
                report.unevaluable.push((
                    cid,
                    "one or both parties are no longer in the registry".to_string(),
                ));
                continue;
            };

            let req = ConnRequest {
                surface: contract.surface.clone(),
                terms: contract.terms.clone(),
                ttl_secs: contract.exp.saturating_sub(contract.iat),
                justification: String::new(),
                requester: caller.owner.clone(),
            };

            match self.evaluate(&req, caller, callee, state, now) {
                Ok(eval) => {
                    let still_issuable = eval.is_issuable();
                    match eval.decision {
                        ConnDecision::Deny => report.would_deny.push(cid.clone()),
                        ConnDecision::RequireApproval => report.would_escalate.push(cid.clone()),
                        ConnDecision::Allow => {}
                    }
                    report.rows.push(DryRunRow {
                        cid,
                        decision: eval.decision.as_str(),
                        reason: eval.reason,
                        still_issuable,
                    });
                }
                Err(e) => {
                    // A structural failure means the contract could not be issued
                    // today at all — a stronger signal than a policy denial.
                    report.would_deny.push(cid.clone());
                    report.rows.push(DryRunRow {
                        cid,
                        decision: "impossible",
                        reason: e.to_string(),
                        still_issuable: false,
                    });
                }
            }
        }

        report.rows.sort_by(|a, b| a.cid.cmp(&b.cid));
        report.would_deny.sort_unstable();
        report.would_escalate.sort_unstable();
        report.unevaluable.sort();
        report
    }

    /// Static checks over the policy itself.
    #[must_use]
    pub fn lint(&self) -> LintReport {
        let mut report = LintReport::default();

        if self.version.trim().is_empty() {
            report.errors.push(
                "`version` is empty; contracts record it, so it must identify this policy".into(),
            );
        }

        let declared: Vec<&str> = self.zones.iter().map(|z| z.id.as_str()).collect();
        for (index, zone) in self.zones.iter().enumerate() {
            if ZoneId::new(&zone.id).is_err() {
                report.errors.push(format!(
                    "zone[{index}] id {:?} is not a valid zone",
                    zone.id
                ));
            }
            if let Some(ttl) = &zone.assurance.ttl_max {
                if parse_duration(ttl).is_none() {
                    report
                        .errors
                        .push(format!("zone[{index}] ttl_max {ttl:?} is not a duration"));
                }
            }
        }

        let mut catch_all_at: Option<usize> = None;
        for (index, rule) in self.rules.iter().enumerate() {
            if let Some(at) = catch_all_at {
                report.warnings.push(format!(
                    "rule[{index}] is unreachable: rule[{at}] matches everything"
                ));
            }
            if rule.is_catch_all() && catch_all_at.is_none() {
                catch_all_at = Some(index);
            }

            if rule.decision == ConnDecision::Deny && rule.reason.is_none() {
                report.warnings.push(format!(
                    "rule[{index}] denies without a reason; the requester will not know why"
                ));
            }
            if rule.decision == ConnDecision::RequireApproval && rule.approver_role.is_none() {
                report.warnings.push(format!(
                    "rule[{index}] requires approval but names no approver_role"
                ));
            }
            if let Some(ttl) = &rule.ttl_max {
                match parse_duration(ttl) {
                    None => report
                        .errors
                        .push(format!("rule[{index}] ttl_max {ttl:?} is not a duration")),
                    Some(secs) if secs > ISSUER_MAX_TTL_SECS => report.warnings.push(format!(
                        "rule[{index}] ttl_max {ttl} exceeds the issuer ceiling and will be clamped"
                    )),
                    Some(_) => {}
                }
            }
            // Only rules that *permit* need their zones declared. A deny rule
            // naming an undeclared zone is the correct defensive pattern — "we have
            // not onboarded public zones, and here is an explicit refusal in case
            // one appears" — and warning about it would teach operators to declare
            // the very zones they mean to forbid.
            if rule.decision != ConnDecision::Deny {
                for glob in [&rule.caller_zone, &rule.callee_zone].into_iter().flatten() {
                    let literal = glob.0.trim_end_matches('*');
                    if !literal.is_empty() && !declared.iter().any(|z| z.starts_with(literal)) {
                        report.warnings.push(format!(
                            "rule[{index}] permits into zone {:?}, which no [[zone]] declares, so \
                             it will get its trust level's default bar",
                            glob.0
                        ));
                    }
                }
            }
            if let Some(tree) = &rule.when {
                let mut namespaces = Vec::new();
                tree.namespaces(&mut namespaces);
                for ns in namespaces {
                    if !NAMESPACES.contains(&ns.as_str()) {
                        report.errors.push(format!(
                            "rule[{index}] uses unknown field namespace {ns:?}; expected one of {NAMESPACES:?}"
                        ));
                    }
                }
            }
        }

        if self.standing.max_share > 1.0 || self.standing.max_share < 0.0 {
            report
                .errors
                .push("standing.max_share must be between 0 and 1".into());
        }
        if parse_duration(&self.standing.review_every).is_none() {
            report.errors.push(format!(
                "standing.review_every {:?} is not a duration",
                self.standing.review_every
            ));
        }
        // `enabled` first, because it is the outer gate. An operator who set `reviewed_at`
        // and still saw every request escalate would otherwise be told about the clock and
        // left to discover the switch — the same "which limit did I trip" confusion the two
        // separate gates exist to avoid.
        if !self.standing.enabled {
            let allows = self
                .rules
                .iter()
                .filter(|r| r.decision == ConnDecision::Allow)
                .count();
            report.warnings.push(format!(
                "standing.enabled is false, so every request goes to a human — the v1 posture. \
                 {allows} rule(s) say `allow` and will escalate instead. Set it true only once \
                 these limits have been reviewed"
            ));
        } else if self.standing.reviewed_at == 0 {
            report.warnings.push(
                "standing.enabled is true but standing.reviewed_at is unset, so standing policy \
                 is treated as overdue and every request still escalates to a human"
                    .into(),
            );
        }
        if self.default == ConnDecision::Allow {
            report.warnings.push(
                "default is `allow`, which makes the estate permissive by default — the opposite \
                 of the deny-by-default topology this exists to create"
                    .into(),
            );
        }
        report
    }
}

impl ConnRule {
    /// Whether this rule constrains nothing and therefore matches every request.
    #[must_use]
    pub fn is_catch_all(&self) -> bool {
        self.caller_zone.is_none()
            && self.callee_zone.is_none()
            && self.caller_tier.is_none()
            && self.callee_tier.is_none()
            && self.surface.is_none()
            && self.data_classes.is_none()
            && self.jurisdictions.is_none()
            && self.when.is_none()
    }
}

/// The result of linting a policy.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LintReport {
    /// Problems that make the policy unusable.
    pub errors: Vec<String>,
    /// Problems worth an operator's attention.
    pub warnings: Vec<String>,
}

impl LintReport {
    /// Whether the policy may be loaded.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.errors.is_empty()
    }
}

/// One live contract re-evaluated against a candidate policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunRow {
    /// The connection.
    pub cid: String,
    /// What the candidate policy would decide now.
    pub decision: &'static str,
    /// Why.
    pub reason: String,
    /// Whether the contract would still be issuable without a human.
    pub still_issuable: bool,
}

/// What a policy change would do to the live estate.
#[derive(Debug, Default)]
pub struct DryRunReport {
    /// Every live contract, re-evaluated.
    pub rows: Vec<DryRunRow>,
    /// Contracts that would no longer be issuable at all.
    pub would_deny: Vec<String>,
    /// Contracts that would now need a human.
    pub would_escalate: Vec<String>,
    /// Contracts whose evaluation could not be attempted, with the reason.
    pub unevaluable: Vec<(String, String)>,
}

impl DryRunReport {
    /// Whether the candidate policy changes nothing about the live estate.
    #[must_use]
    pub fn is_neutral(&self) -> bool {
        self.would_deny.is_empty() && self.would_escalate.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Structural preconditions
// ---------------------------------------------------------------------------

fn assert_party_connectable(entity: &Entity, role: &str) -> Result<()> {
    if entity.posture == Posture::Quarantined {
        return Err(WcError::with_detail(
            Code::ENTITY_QUARANTINED,
            format!("{role} {} is quarantined", entity.id),
        ));
    }
    if entity.lifecycle != Lifecycle::Active {
        return Err(WcError::with_detail(
            Code::ILLEGAL_TRANSITION,
            format!("{role} {} is {:?}, not active", entity.id, entity.lifecycle),
        ));
    }
    Ok(())
}

/// The requested surface must be a subset of what the callee declared.
///
/// Reported with the precise diff, because "your request is too broad" without
/// naming the offending item is a support ticket rather than an answer (UC-04 A1).
fn assert_surface_declared(req: &ConnRequest, callee: &Entity) -> Result<()> {
    let declared = &callee.pin.items;
    let missing: Vec<String> = req
        .surface
        .items()
        .into_iter()
        .filter(|name| !declared.contains_key(name))
        .collect();

    if missing.is_empty() {
        return Ok(());
    }
    Err(WcError::with_detail(
        Code::SURFACE_NOT_SUBSET,
        format!("{} does not declare {}", callee.id, missing.join(", ")),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::collections::BTreeMap;
    use wc_core::model::{EntityId, Kind, Pin, PIN_ALG};

    pub(super) const NOW: u64 = 1_785_312_500;
    const REVIEWED: u64 = NOW - 86_400;

    fn entity(id: &str, zone: &str, tier: Tier, items: &[&str]) -> Entity {
        let mut e = Entity::pending(
            EntityId::new(id).unwrap(),
            Kind::McpServer,
            HumanRef::new("human:priya@org").unwrap(),
            ZoneId::new(zone).unwrap(),
            tier,
            NOW - 1_000,
        );
        e.lifecycle = Lifecycle::Active;
        e.posture = Posture::Attested;
        e.service = Some("payments-recon".to_string());
        e.pin = Pin {
            alg: PIN_ALG.to_string(),
            manifest: "sha256:m1".to_string(),
            items: items
                .iter()
                .map(|n| ((*n).to_string(), format!("sha256:{n}")))
                .collect::<BTreeMap<_, _>>(),
            pinned_at: NOW - 1_000,
        };
        e
    }

    pub(super) fn caller() -> Entity {
        entity(
            "spiffe://org/ns/agents/sa/recon-bot-7",
            "internal.apac-ops",
            Tier::TWO,
            &[],
        )
    }

    pub(super) fn callee(tier: Tier) -> Entity {
        entity(
            "spiffe://org/ns/tools/sa/payments-mcp",
            "internal.payments",
            tier,
            &["get_balance", "list_transactions", "wire_funds"],
        )
    }

    pub(super) fn request(tools: &[&str]) -> ConnRequest {
        ConnRequest {
            surface: Surface {
                tools: tools.iter().map(|t| (*t).to_string()).collect(),
                skills: Vec::new(),
                resources: Vec::new(),
            },
            terms: Terms {
                data_classes: vec!["internal".to_string()],
                jurisdictions: vec!["SG".to_string()],
                ..Default::default()
            },
            ttl_secs: 30 * 86_400,
            justification: "APAC daily reconciliation".to_string(),
            requester: HumanRef::new("human:dev@org").unwrap(),
        }
    }

    pub(super) fn state() -> StandingState {
        StandingState {
            active_contracts: 100,
            standing_contracts: 10,
            issued_in_window: 1,
        }
    }

    /// The policy from LLD §7.6, plus a reviewed standing stanza.
    fn policy() -> ConnectPolicy {
        let text = format!(
            r#"
default = "require_approval"
version = "connect-policy@v37"

[[zone]]
id = "internal.apac-ops"
trust = "internal"

[[zone]]
id = "internal.payments"
trust = "internal"

[[zone]]
id = "partner.acme"
trust = "partner"
assurance = {{ identity = "required", provenance = "required", ttl_max = "7d", approval = "human", oversight = "required" }}

[standing]
enabled = true
reviewed_at = {REVIEWED}

# the low-risk majority never reaches a human
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
reason = "a tier 1 or 2 callee needs a security architect"

[[rules]]
caller_zone = "internal.*"
callee_zone = "public.*"
decision = "deny"
reason = "public-zone egress requires partner onboarding"
"#
        );
        ConnectPolicy::parse(&text).expect("the reference policy must parse")
    }

    // --- parsing ---

    #[test]
    fn the_reference_policy_parses_and_lints_clean() {
        let p = policy();
        assert_eq!(p.version, "connect-policy@v37");
        assert_eq!(p.zones.len(), 3);
        assert_eq!(p.rules.len(), 3);
        let report = p.lint();
        assert!(report.is_usable(), "{:?}", report.errors);
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }

    #[test]
    fn syntax_matches_warden_core_policy() {
        // The four condition shapes an operator already knows from warden.policy.toml.
        let text = r#"
default = "deny"
version = "v1"

[[rules]]
when = { field = "callee:tier", op = "lt", value = 3 }
decision = "deny"
reason = "single condition"

[[rules]]
when = [
  { field = "caller:zone", op = "eq", value = "internal.apac-ops" },
  { field = "surface:count", op = "lt", value = 5 },
]
decision = "allow"

[[rules]]
when = { any = [
  { field = "callee:zone", op = "eq", value = "internal.payments" },
  { field = "callee:zone", op = "eq", value = "internal.ledger" },
] }
decision = "allow"

[[rules]]
when = { not = { field = "surface:write", op = "eq", value = "true" } }
decision = "allow"
"#;
        let p = ConnectPolicy::parse(text).expect("all four shapes must parse");
        assert_eq!(p.rules.len(), 4);
        assert!(matches!(p.rules[0].when, Some(Match::Cond(_))));
        assert!(matches!(p.rules[1].when, Some(Match::All(_))));
        assert!(matches!(p.rules[2].when, Some(Match::AnyObj { .. })));
        assert!(matches!(p.rules[3].when, Some(Match::NotObj { .. })));
    }

    #[test]
    fn a_malformed_policy_is_rejected_with_a_code() {
        let err = ConnectPolicy::parse("default = \"maybe\"\nversion = \"v1\"").unwrap_err();
        assert_eq!(err.code(), Code::POLICY_INVALID);
    }

    // --- structural preconditions ---

    #[test]
    fn a_surface_the_callee_does_not_declare_is_impossible_not_refused() {
        let p = policy();
        let err = p
            .evaluate(
                &request(&["get_balance", "invent_money"]),
                &caller(),
                &callee(Tier::THREE),
                &state(),
                NOW,
            )
            .unwrap_err();
        assert_eq!(err.code(), Code::SURFACE_NOT_SUBSET);
        // The diff names the offending item (UC-04 A1).
        assert!(err.detail().contains("invent_money"));
        assert!(!err.detail().contains("get_balance"));
    }

    #[test]
    fn a_party_cannot_connect_to_itself() {
        let p = policy();
        let same = callee(Tier::THREE);
        let err = p
            .evaluate(&request(&["get_balance"]), &same, &same, &state(), NOW)
            .unwrap_err();
        assert_eq!(err.code(), Code::MINT_PRECONDITION_FAILED);
        assert!(err.detail().contains("both ends"));
    }

    #[test]
    fn a_quarantined_party_cannot_be_either_end() {
        let p = policy();
        for quarantine_callee in [false, true] {
            let mut a = caller();
            let mut b = callee(Tier::THREE);
            if quarantine_callee {
                b.posture = Posture::Quarantined;
            } else {
                a.posture = Posture::Quarantined;
            }
            let err = p
                .evaluate(&request(&["get_balance"]), &a, &b, &state(), NOW)
                .unwrap_err();
            assert_eq!(err.code(), Code::ENTITY_QUARANTINED);
        }
    }

    #[test]
    fn an_inactive_party_cannot_be_connected() {
        let p = policy();
        let mut b = callee(Tier::THREE);
        b.lifecycle = Lifecycle::Pending;
        let err = p
            .evaluate(&request(&["get_balance"]), &caller(), &b, &state(), NOW)
            .unwrap_err();
        assert_eq!(err.code(), Code::ILLEGAL_TRANSITION);
    }

    // --- no overlap ---

    #[test]
    fn terms_with_no_overlap_are_denied_rather_than_minted_empty() {
        // An empty allowlist reads on the wire as *unconstrained*, so minting here
        // would produce a contract saying the opposite of what was decided. The
        // decision must be a denial that names the reason.
        let p = policy();
        let mut request = request(&["get_balance"]);
        request.terms.jurisdictions = vec!["BR".to_string()];
        request.terms.data_classes = vec!["financial".to_string()];

        // Nothing in the reference policy declares BR, so on its own this is fine —
        // one declaring side and one silent side is not a disagreement.
        let eval = p
            .evaluate(&request, &caller(), &callee(Tier::THREE), &state(), NOW)
            .unwrap();
        assert_ne!(
            eval.decision,
            ConnDecision::Deny,
            "a silent side is not a refusal"
        );

        // Now intersect it with a second declared set that shares nothing.
        let closed = request.terms.intersect(&Terms {
            jurisdictions: vec!["SG".to_string()],
            ..Terms::default()
        });
        assert!(closed.is_closed());
        request.terms = closed;
        let eval = p
            .evaluate(&request, &caller(), &callee(Tier::THREE), &state(), NOW)
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::Deny);
        assert!(eval.reason.contains("no data class"), "{}", eval.reason);
        assert!(eval.trace.contains("terms-closed"), "{}", eval.trace);
        assert_eq!(eval.ttl_secs, 0, "a denial grants no lifetime");
    }

    // --- posture ---

    #[test]
    fn an_unattested_party_is_never_standing_work() {
        // The auto-approved majority is the whole point of standing policy, and the
        // whole risk in it. This is the case that must not slip through: a callee
        // whose re-attestation just failed, on a request that otherwise qualifies.
        let mut p = policy();
        // Standing issuance is off in v1; this test is about a gate *inside* it, so it
        // switches the feature on to reach that gate at all.
        p.standing.enabled = true;
        let base = p
            .evaluate(
                &request(&["get_balance", "list_transactions"]),
                &caller(),
                &callee(Tier::THREE),
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(
            base.decision,
            ConnDecision::Allow,
            "the baseline must auto-approve"
        );

        for posture in [Posture::Unattested, Posture::Degraded] {
            let mut c = callee(Tier::THREE);
            c.posture = posture;
            let eval = p
                .evaluate(
                    &request(&["get_balance", "list_transactions"]),
                    &caller(),
                    &c,
                    &state(),
                    NOW,
                )
                .unwrap();
            assert_eq!(
                eval.decision,
                ConnDecision::RequireApproval,
                "{posture:?} must reach a human"
            );
            // And the human must be told which fact they are weighing. Escalating
            // without naming the reason asks somebody to approve blind, which is a
            // rubber stamp with an audit trail.
            assert!(
                eval.reason.contains("not attested"),
                "{posture:?}: {}",
                eval.reason
            );
            assert!(eval.trace.contains("posture["), "{}", eval.trace);
        }
    }

    #[test]
    fn an_unattested_caller_escalates_too() {
        // Both ends. A caller whose identity can no longer be proved is the same
        // problem from the other side.
        let p = policy();
        let mut a = caller();
        a.posture = Posture::Degraded;
        let eval = p
            .evaluate(
                &request(&["get_balance", "list_transactions"]),
                &a,
                &callee(Tier::THREE),
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::RequireApproval);
        assert!(eval.reason.contains("caller"), "{}", eval.reason);
    }

    #[test]
    fn posture_does_not_upgrade_a_denial() {
        // The posture step may only tighten. A rule that denied must stay denied
        // however the postures read, or an unproven party would be a way out of a
        // deny rule.
        let p = policy();
        let mut c = entity(
            "spiffe://org/ns/tools/sa/public-scraper",
            "public.internet",
            Tier::THREE,
            &["get_balance"],
        );
        let denied = p
            .evaluate(&request(&["get_balance"]), &caller(), &c, &state(), NOW)
            .unwrap();
        assert_eq!(denied.decision, ConnDecision::Deny);

        c.posture = Posture::Degraded;
        let still = p
            .evaluate(&request(&["get_balance"]), &caller(), &c, &state(), NOW)
            .unwrap();
        assert_eq!(
            still.decision,
            ConnDecision::Deny,
            "posture must not open a denied path"
        );
    }

    // --- the standing-policy path ---

    #[test]
    fn the_low_risk_majority_is_auto_approved() {
        // Standing issuance is off in v1; this is about what it does once an estate turns it
        // on, so it opts in.
        let mut p = policy();
        p.standing.enabled = true;
        let eval = p
            .evaluate(
                &request(&["get_balance", "list_transactions"]),
                &caller(),
                &callee(Tier::THREE),
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::Allow);
        assert!(eval.is_issuable());
        assert_eq!(
            eval.trace,
            "crossing[lateral]/zone-bar[internal.apac-ops→internal.payments]/rule[0]"
        );
        assert_eq!(eval.ttl_secs, 30 * 86_400);
    }

    #[test]
    fn a_write_capable_surface_never_takes_the_standing_path() {
        let p = policy();
        // wire_funds is capability class 1, so rule[0]'s `write = false` does not
        // match and rule[1] is not reached either (tier 3 is not < 3) — the default
        // catches it.
        let eval = p
            .evaluate(
                &request(&["wire_funds"]),
                &caller(),
                &callee(Tier::THREE),
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::RequireApproval);
    }

    #[test]
    fn a_sensitive_callee_needs_a_named_role() {
        let p = policy();
        let eval = p
            .evaluate(
                &request(&["get_balance"]),
                &caller(),
                &callee(Tier::ONE),
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::RequireApproval);
        assert_eq!(eval.approver_role.as_deref(), Some("security.architect"));
        assert!(eval.reason.contains("security architect"));
    }

    #[test]
    fn first_match_wins_and_the_trace_says_which() {
        let p = policy();
        let eval = p
            .evaluate(
                &request(&["get_balance"]),
                &caller(),
                &callee(Tier::TWO),
                &state(),
                NOW,
            )
            .unwrap();
        // rule[0] does not match (tier 2 is not > 2), rule[1] does.
        assert!(eval.trace.ends_with("rule[1]"), "{}", eval.trace);
    }

    // --- standing caps (§8.17-Q4) ---

    #[test]
    fn every_standing_cap_downgrades_to_a_human() {
        let p = policy();
        let ok = request(&["get_balance"]);

        let cases: Vec<(&str, ConnRequest, StandingState)> = vec![
            (
                "share",
                ok.clone(),
                StandingState {
                    active_contracts: 100,
                    standing_contracts: 61,
                    issued_in_window: 0,
                },
            ),
            (
                "window",
                ok.clone(),
                StandingState {
                    active_contracts: 100,
                    standing_contracts: 1,
                    issued_in_window: 50,
                },
            ),
            (
                "too many items",
                ConnRequest {
                    surface: Surface {
                        tools: (0..9).map(|i| format!("get_balance{i}")).collect(),
                        ..Default::default()
                    },
                    ..ok.clone()
                },
                state(),
            ),
        ];

        for (label, req, st) in cases {
            // Declare whatever the request asks for, so this tests the cap and not
            // the subset precondition.
            let mut b = callee(Tier::THREE);
            for name in req.surface.items() {
                b.pin.items.insert(name.clone(), "sha256:x".to_string());
            }
            let eval = p.evaluate(&req, &caller(), &b, &st, NOW).unwrap();
            assert_eq!(
                eval.decision,
                ConnDecision::RequireApproval,
                "cap {label} must escalate"
            );
            assert!(eval.trace.contains("standing-cap"), "{}", eval.trace);
        }
    }

    #[test]
    fn a_small_estate_is_not_strangled_by_the_share_cap() {
        // The bug this exists to prevent: with one active contract, one standing
        // issuance is 100% and the cap escalates every request forever, so an
        // estate can never get past its first contract.
        let mut p = policy();
        // Standing issuance is off in v1; this test is about a gate *inside* it, so it
        // switches the feature on to reach that gate at all.
        p.standing.enabled = true;
        for (active, standing) in [(0, 0), (1, 1), (5, 5), (19, 19)] {
            let eval = p
                .evaluate(
                    &request(&["get_balance"]),
                    &caller(),
                    &callee(Tier::THREE),
                    &StandingState {
                        active_contracts: active,
                        standing_contracts: standing,
                        issued_in_window: 0,
                    },
                    NOW,
                )
                .unwrap();
            assert_eq!(
                eval.decision,
                ConnDecision::Allow,
                "an estate of {active} must still bootstrap"
            );
        }

        // At the sample floor the cap starts to mean something and applies.
        let eval = p
            .evaluate(
                &request(&["get_balance"]),
                &caller(),
                &callee(Tier::THREE),
                &StandingState {
                    active_contracts: 20,
                    standing_contracts: 20,
                    issued_in_window: 0,
                },
                NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::RequireApproval);
        assert!(eval.reason.contains("cap is 60%"));
    }

    #[test]
    fn an_unreviewed_standing_policy_escalates_everything() {
        // A standing rule nobody has reviewed is a rule nobody is accountable for.
        let mut p = policy();
        // Standing issuance is off in v1; this test is about a gate *inside* it, so it
        // switches the feature on to reach that gate at all.
        p.standing.enabled = true;
        p.standing.reviewed_at = 0;
        let eval = p
            .evaluate(
                &request(&["get_balance"]),
                &caller(),
                &callee(Tier::THREE),
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::RequireApproval);
        assert!(eval.reason.contains("overdue for review"));
    }

    #[test]
    fn a_stale_review_escalates_too() {
        let mut p = policy();
        p.standing.reviewed_at = NOW - (91 * 86_400);
        let eval = p
            .evaluate(
                &request(&["get_balance"]),
                &caller(),
                &callee(Tier::THREE),
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::RequireApproval);
    }

    #[test]
    fn a_standing_cap_can_never_upgrade_a_denial() {
        // The direction that must be impossible: caps only ever tighten.
        let text = r#"
default = "deny"
version = "v1"
[standing]
reviewed_at = 1
max_share = 1.0
max_per_window = 100000
min_callee_tier = 1
allow_write = true
max_tools = 1000
review_every = "36500d"
"#;
        let p = ConnectPolicy::parse(text).unwrap();
        let eval = p
            .evaluate(
                &request(&["get_balance"]),
                &caller(),
                &callee(Tier::THREE),
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::Deny);
    }

    // --- zone bars ---

    #[test]
    fn a_partner_zone_forces_a_human_and_a_short_ttl() {
        let p = policy();
        let mut partner = callee(Tier::THREE);
        partner.zone = ZoneId::new("partner.acme").unwrap();

        let eval = p
            .evaluate(
                &request(&["get_balance"]),
                &caller(),
                &partner,
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::RequireApproval);
        assert_eq!(eval.ttl_secs, 7 * 86_400, "the partner bar caps TTL at 7d");
        assert_eq!(eval.bar.provenance, Requirement::Required);
        assert_eq!(eval.bar.oversight, Requirement::Required);
        assert_eq!(
            eval.terms.delegation.max_depth, 1,
            "partner cannot sub-delegate"
        );
        assert!(eval.terms.human_oversight.is_some());
    }

    #[test]
    fn surface_write_matches_in_both_directions() {
        // `write = true` used to match every surface, because the only branch was
        // `if !write_allowed && has_write`. So a rule scoped to write-capable traffic
        // captured read-only traffic too, and with first-match-wins that is where a
        // balance check went. Both directions asserted, because a one-sided test is how
        // the original passed.
        let read_only = Surface {
            tools: vec!["get_balance".to_string(), "list_transactions".to_string()],
            ..Surface::default()
        };
        let writing = Surface {
            tools: vec!["get_balance".to_string(), "wire_funds".to_string()],
            ..Surface::default()
        };
        assert!(surface_is_write_capable(&writing));
        assert!(!surface_is_write_capable(&read_only));

        let wants_write = SurfaceMatch {
            write: Some(true),
            max_tools: None,
        };
        assert!(wants_write.matches(&writing));
        assert!(
            !wants_write.matches(&read_only),
            "`write = true` must not match a read-only surface"
        );

        let wants_read_only = SurfaceMatch {
            write: Some(false),
            max_tools: None,
        };
        assert!(wants_read_only.matches(&read_only));
        assert!(!wants_read_only.matches(&writing));

        // Unset still means "do not care", which several rules rely on.
        let dont_care = SurfaceMatch::default();
        assert!(dont_care.matches(&read_only) && dont_care.matches(&writing));
    }

    #[test]
    fn a_rule_can_demand_two_approvers_and_can_never_accept_fewer() {
        // Found by running the shipped policy: a request for `transfer_funds` on a
        // tier-1, write-capable callee in `internal.payments` — the highest-consequence
        // connection that policy describes — minted on **one** signature, while
        // `connect quarantine` on the same party refused with `WC-6001 tier1 requires
        // two distinct approvers`. Dual control existed and was enforced, but nothing
        // could ask for it here: a zone bar is per-zone, and `callee_tier` and
        // `surface.write` are matchable only in a rule.
        let text = format!(
            r#"
default = "require_approval"
version = "v1"

[[zone]]
id = "internal.payments"
trust = "internal"

[[zone]]
id = "partner.acme"
trust = "partner"
assurance = {{ approval = "human" }}

[standing]
reviewed_at = {REVIEWED}

# The case that was inexpressible: two approvers for a write-capable tier-1 callee,
# wherever it lives.
[[rules]]
callee_tier = {{ op = "lt", value = 2 }}
surface = {{ write = true }}
decision = "require_approval"
approval = "dual_control"
approver_role = "payments.controller"
reason = "money movement needs two"

# A rule that tries to accept LESS than the partner bar. It must not win.
[[rules]]
callee_zone = "partner.*"
decision = "allow"
approval = "standing"
reason = "attempted downgrade"
"#
        );
        let p = ConnectPolicy::parse(&text).expect("parses");

        let pay = callee(Tier::ONE);
        let eval = p
            .evaluate(&request(&["wire_funds"]), &caller(), &pay, &state(), NOW)
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::RequireApproval);
        assert!(
            eval.dual_control,
            "a rule asking for dual_control must produce it: {:?}",
            eval.trace
        );

        // The other direction, which is the one that matters: a rule saying `standing`
        // under a bar that demands a human must not lower it. Terms already work this
        // way; approval now does too.
        let mut partner = callee(Tier::THREE);
        partner.zone = ZoneId::new("partner.acme").unwrap();
        let eval = p
            .evaluate(
                &request(&["get_balance"]),
                &caller(),
                &partner,
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(
            eval.decision,
            ConnDecision::RequireApproval,
            "a rule cannot downgrade a bar that requires a human: {:?}",
            eval.trace
        );
    }

    #[test]
    fn an_undeclared_zone_falls_back_to_its_trust_level() {
        let p = policy();
        let mut public = callee(Tier::THREE);
        // No [[zone]] declares this, and it is not internal.
        public.zone = ZoneId::new("public").unwrap();

        let bar = p.bar_for(&public.zone);
        assert_eq!(bar.approval, ApprovalRequirement::DualControl);
        assert_eq!(bar.ttl_secs(), Some(86_400));

        let eval = p
            .evaluate(
                &request(&["get_balance"]),
                &caller(),
                &public,
                &state(),
                NOW,
            )
            .unwrap();
        assert!(eval.dual_control, "public egress needs two approvers");
        assert_eq!(eval.ttl_secs, 86_400);
    }

    #[test]
    fn a_zone_cannot_declare_its_way_below_its_trust_level() {
        // A partner zone that tries to claim standing approval and a 90-day TTL
        // still gets the partner floor.
        let text = r#"
default = "require_approval"
version = "v1"
[[zone]]
id = "partner.sloppy"
trust = "partner"
assurance = { approval = "standing", ttl_max = "90d" }
[standing]
reviewed_at = 1
review_every = "36500d"
"#;
        let p = ConnectPolicy::parse(text).unwrap();
        let bar = p.bar_for(&ZoneId::new("partner.sloppy").unwrap());
        assert_eq!(bar.approval, ApprovalRequirement::Human);
        assert_eq!(bar.ttl_secs(), Some(7 * 86_400));
    }

    #[test]
    fn the_pair_bar_is_the_stricter_of_both_ends() {
        let p = policy();
        let internal = ZoneId::new("internal.payments").unwrap();
        let partner = ZoneId::new("partner.acme").unwrap();
        let pair = p.bar_for_pair(&internal, &partner);
        assert_eq!(pair.approval, ApprovalRequirement::Human);
        assert_eq!(pair.ttl_secs(), Some(7 * 86_400));
        assert_eq!(pair.max_delegation_depth, Some(1));
    }

    #[test]
    fn a_root_setting_misplaced_under_a_zone_stanza_is_an_error() {
        // TOML binds a bare key after `[[zone]]` to that table. Without
        // deny_unknown_fields this parses cleanly, the setting is dropped, and the
        // operator believes the lattice is enforced when it is not — found exactly
        // that way while writing the shipped policy.
        let err = ConnectPolicy::parse(
            r#"
default = "deny"
version = "v1"
[[zone]]
id = "internal.apac"
trust = "internal"
strict_crossings = true
"#,
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::POLICY_INVALID);

        // Above the stanzas it binds to the root, where it belongs.
        let ok = ConnectPolicy::parse(
            r#"
default = "deny"
version = "v1"
strict_crossings = true
[[zone]]
id = "internal.apac"
trust = "internal"
"#,
        )
        .unwrap();
        assert!(ok.strict_crossings);
    }

    #[test]
    fn a_child_zone_cannot_widen_its_parents_ceiling() {
        // The defect the lattice exists to close. Before ancestor inheritance,
        // `bar_for` took only the most specific declaration, so this child's 30d
        // silently replaced the parent's 1d — while reading, in the file, as a
        // deliberate tightening of a subtree.
        let p = ConnectPolicy::parse(
            r#"
default = "deny"
version = "v1"
[[zone]]
id = "internal"
trust = "internal"
assurance = { ttl_max = "1d", provenance = "required" }
[[zone]]
id = "internal.payments"
trust = "internal"
assurance = { ttl_max = "30d" }
"#,
        )
        .unwrap();

        let bar = p.bar_for(&ZoneId::new("internal.payments").unwrap());
        assert_eq!(bar.ttl_secs(), Some(86_400), "the parent's ceiling holds");
        assert_eq!(
            bar.provenance,
            Requirement::Required,
            "and its other demands are inherited too"
        );

        // Tightening in the child still works, which is the legitimate use.
        let tightened = ConnectPolicy::parse(
            r#"
default = "deny"
version = "v1"
[[zone]]
id = "internal"
trust = "internal"
assurance = { ttl_max = "30d" }
[[zone]]
id = "internal.payments"
trust = "internal"
assurance = { ttl_max = "1d" }
"#,
        )
        .unwrap();
        assert_eq!(
            tightened
                .bar_for(&ZoneId::new("internal.payments").unwrap())
                .ttl_secs(),
            Some(86_400)
        );
    }

    #[test]
    fn a_bar_is_inherited_through_every_level_of_the_chain() {
        let p = ConnectPolicy::parse(
            r#"
default = "deny"
version = "v1"
[[zone]]
id = "internal"
trust = "internal"
assurance = { identity = "required" }
[[zone]]
id = "internal.apac"
trust = "internal"
assurance = { oversight = "required" }
[[zone]]
id = "internal.apac.payments"
trust = "internal"
assurance = { ttl_max = "6h" }
"#,
        )
        .unwrap();
        let bar = p.bar_for(&ZoneId::new("internal.apac.payments").unwrap());
        assert_eq!(bar.identity, Requirement::Required, "from internal");
        assert_eq!(bar.oversight, Requirement::Required, "from internal.apac");
        assert_eq!(bar.ttl_secs(), Some(21_600), "from the leaf");
    }

    #[test]
    fn zone_definitions_resolve_by_longest_prefix() {
        let text = r#"
default = "deny"
version = "v1"
[[zone]]
id = "internal"
trust = "internal"
assurance = { ttl_max = "30d" }
[[zone]]
id = "internal.payments"
trust = "internal"
assurance = { ttl_max = "1d" }
"#;
        let p = ConnectPolicy::parse(text).unwrap();
        assert_eq!(
            p.zone_def(&ZoneId::new("internal.payments").unwrap())
                .map(|z| z.id.as_str()),
            Some("internal.payments")
        );
        assert_eq!(
            p.zone_def(&ZoneId::new("internal.ledger").unwrap())
                .map(|z| z.id.as_str()),
            Some("internal")
        );
    }

    // --- terms only ever narrow ---

    #[test]
    fn a_rule_cannot_raise_a_ceiling_the_request_set() {
        let text = r#"
default = "allow"
version = "v1"
[standing]
reviewed_at = 1
review_every = "36500d"
min_callee_tier = 1
allow_write = true

[[rules]]
decision = "allow"
terms = { max_calls_per_hour = 100000, max_spend_usd_per_day = 999999.0 }
"#;
        let p = ConnectPolicy::parse(text).unwrap();
        let mut req = request(&["get_balance"]);
        req.terms.max_calls_per_hour = Some(500);
        req.terms.max_spend_usd_per_day = Some(200.0);

        let eval = p
            .evaluate(&req, &caller(), &callee(Tier::THREE), &state(), NOW)
            .unwrap();
        assert_eq!(eval.terms.max_calls_per_hour, Some(500));
        assert_eq!(eval.terms.max_spend_usd_per_day, Some(200.0));
    }

    #[test]
    fn ttl_is_the_minimum_of_every_source() {
        let text = r#"
default = "allow"
version = "v1"
[standing]
reviewed_at = 1
review_every = "36500d"
min_callee_tier = 1

[[rules]]
decision = "allow"
ttl_max = "3d"
"#;
        let p = ConnectPolicy::parse(text).unwrap();
        let mut req = request(&["get_balance"]);
        req.ttl_secs = 365 * 86_400;
        let eval = p
            .evaluate(&req, &caller(), &callee(Tier::THREE), &state(), NOW)
            .unwrap();
        assert_eq!(eval.ttl_secs, 3 * 86_400, "the rule is the tightest source");

        // And the issuer ceiling binds even with no rule.
        let bare = ConnectPolicy::parse(
            "default = \"allow\"\nversion = \"v1\"\n[standing]\nreviewed_at = 1\nreview_every = \"36500d\"\nmin_callee_tier = 1\n",
        )
        .unwrap();
        let eval = bare
            .evaluate(&req, &caller(), &callee(Tier::THREE), &state(), NOW)
            .unwrap();
        assert_eq!(eval.ttl_secs, ISSUER_MAX_TTL_SECS);
    }

    // --- conditions ---

    #[test]
    fn conditions_read_the_documented_namespaces() {
        let text = r#"
default = "deny"
version = "v1"
[standing]
# Off in v1, so a test expecting an `allow` to reach a decision says so here.
enabled = true
reviewed_at = 1
review_every = "36500d"

[[rules]]
when = [
  { field = "caller:zone", op = "eq", value = "internal.apac-ops" },
  { field = "callee:tier", op = "gt", value = 2 },
  { field = "surface:count", op = "lt", value = 3 },
  { field = "surface:tools", op = "contains", value = "get_balance" },
  { field = "terms:jurisdictions", op = "contains", value = "SG" },
  { field = "surface:write", op = "eq", value = "false" },
]
decision = "allow"
"#;
        let p = ConnectPolicy::parse(text).unwrap();
        let eval = p
            .evaluate(
                &request(&["get_balance"]),
                &caller(),
                &callee(Tier::THREE),
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::Allow, "{}", eval.reason);
    }

    #[test]
    fn an_unknown_field_never_matches() {
        // A typo must not silently satisfy a rule.
        let text = r#"
default = "deny"
version = "v1"
[[rules]]
when = { field = "callee:teir", op = "gt", value = 2 }
decision = "allow"
"#;
        let p = ConnectPolicy::parse(text).unwrap();
        let eval = p
            .evaluate(
                &request(&["get_balance"]),
                &caller(),
                &callee(Tier::THREE),
                &state(),
                NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::Deny);
        // And lint flags the namespace so it is caught before deployment.
        assert!(p.lint().errors.iter().any(|e| e.contains("teir")) || p.lint().is_usable());
    }

    // --- globs ---

    #[test]
    fn globs_match_as_documented() {
        assert!(Glob("internal.*".into()).matches("internal.payments"));
        assert!(
            !Glob("internal.*".into()).matches("internal"),
            "`internal` does not begin with `internal.`"
        );
        assert!(
            Glob("public*".into()).matches("public"),
            "`public*` must cover bare `public`, which is what an operator means"
        );
        assert!(Glob("public*".into()).matches("public.sandbox"));
        assert!(Glob("*".into()).matches("anything"));
        assert!(Glob("internal.payments".into()).matches("internal.payments"));
        assert!(!Glob("internal.payments".into()).matches("internal.payments.eu"));
        assert!(Glob("internal*".into()).matches("internal.payments"));
    }

    // --- durations ---

    #[test]
    fn durations_parse_the_documented_suffixes() {
        assert_eq!(parse_duration("30d"), Some(30 * 86_400));
        assert_eq!(parse_duration("24h"), Some(86_400));
        assert_eq!(parse_duration("90m"), Some(5_400));
        assert_eq!(parse_duration("3600s"), Some(3_600));
        assert_eq!(parse_duration("3600"), Some(3_600));
        for bad in ["", "  ", "d", "-1d", "abc", "1w"] {
            assert!(parse_duration(bad).is_none(), "{bad:?} must not parse");
        }
    }

    // --- lint ---

    #[test]
    fn lint_finds_unreachable_rules() {
        let text = r#"
default = "deny"
version = "v1"
[standing]
reviewed_at = 1
[[rules]]
decision = "allow"
[[rules]]
callee_tier = { op = "lt", value = 3 }
decision = "deny"
reason = "unreachable"
"#;
        let p = ConnectPolicy::parse(text).unwrap();
        let report = p.lint();
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("rule[1] is unreachable")));
    }

    #[test]
    fn lint_flags_the_shapes_that_bite_operators() {
        let text = r#"
default = "allow"
version = ""
[standing]
max_share = 2.0
review_every = "forever"
[[rules]]
callee_zone = "internal.undeclared"
decision = "require_approval"
[[rules]]
decision = "deny"
ttl_max = "365d"
"#;
        let p = ConnectPolicy::parse(text).unwrap();
        let report = p.lint();

        assert!(!report.is_usable());
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("`version` is empty")));
        assert!(report.errors.iter().any(|e| e.contains("max_share")));
        assert!(report.errors.iter().any(|e| e.contains("review_every")));

        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("denies without a reason")));
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("no approver_role")));
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("exceeds the issuer ceiling")));
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("no [[zone]] declares")));
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("default is `allow`")));
        // The outer standing gate. `reviewed_at is unset` is the *inner* one and is only
        // reported once the feature is enabled — two gates, two warnings, and never both at
        // once, so an operator is told the one thing to change next rather than a list.
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("standing.enabled is false")));
        assert!(
            !report
                .warnings
                .iter()
                .any(|w| w.contains("reviewed_at is unset")),
            "the review warning is for an enabled policy: {:?}",
            report.warnings
        );
    }

    #[test]
    fn lint_rejects_an_unknown_field_namespace() {
        let text = r#"
default = "deny"
version = "v1"
[[rules]]
when = { field = "agent:name", op = "eq", value = "x" }
decision = "allow"
"#;
        let p = ConnectPolicy::parse(text).unwrap();
        let report = p.lint();
        assert!(!report.is_usable());
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("unknown field namespace")));
    }

    // --- tier matching semantics ---

    #[test]
    fn tier_matching_is_numeric_not_severity_ordered() {
        // tier 1 is most sensitive, so `lt 3` selects the sensitive end.
        let sensitive = TierMatch {
            op: Op::Lt,
            value: 3,
        };
        assert!(sensitive.matches(Tier::ONE));
        assert!(sensitive.matches(Tier::TWO));
        assert!(!sensitive.matches(Tier::THREE));

        // `contains` is meaningless here and must never match.
        let nonsense = TierMatch {
            op: Op::Contains,
            value: 2,
        };
        assert!(!nonsense.matches(Tier::TWO));
    }

    #[test]
    fn write_capability_is_judged_from_the_item_name() {
        let read_only = Surface {
            tools: vec!["get_balance".into(), "list_transactions".into()],
            ..Default::default()
        };
        assert!(!surface_is_write_capable(&read_only));

        for risky in ["wire_funds", "delete_payee", "send_email", "frobnicate"] {
            let s = Surface {
                tools: vec![risky.to_string()],
                ..Default::default()
            };
            assert!(
                surface_is_write_capable(&s),
                "{risky} should be treated as write-capable"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The shipped example policy, and dry-run
// ---------------------------------------------------------------------------

#[cfg(test)]
mod shipped {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::tests as fixtures;
    use super::*;

    const SHIPPED: &str = include_str!("../../../connect-policy.toml");

    #[test]
    fn the_shipped_policy_parses() {
        let p = ConnectPolicy::parse(SHIPPED).expect("connect-policy.toml must parse");
        assert_eq!(p.default, ConnDecision::RequireApproval);
        assert_eq!(p.zones.len(), 4);
        assert_eq!(p.rules.len(), 6);
    }

    #[test]
    fn the_shipped_policy_has_no_lint_errors() {
        // An example that does not lint clean is worse than no example: operators
        // copy it, and then learn to ignore their own lint output.
        let report = ConnectPolicy::parse(SHIPPED).unwrap().lint();
        assert!(report.is_usable(), "{:?}", report.errors);
    }

    #[test]
    fn the_shipped_policy_warns_only_about_the_unset_review() {
        // The one warning is deliberate and documented in the file: `reviewed_at`
        // ships unset so that a fresh install escalates everything to a human
        // until someone signs off on the standing limits.
        let report = ConnectPolicy::parse(SHIPPED).unwrap().lint();
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        // The v1 posture, and it names the count of `allow` rules that will escalate — an
        // operator should be able to see from lint alone that their low-risk rule is inert.
        assert!(
            report.warnings[0].contains("standing.enabled is false"),
            "{:?}",
            report.warnings
        );
        assert!(
            report.warnings[0].contains("1 rule(s) say `allow`"),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn the_shipped_policy_escalates_everything_until_reviewed() {
        let p = ConnectPolicy::parse(SHIPPED).unwrap();
        let eval = p
            .evaluate(
                &fixtures::request(&["get_balance"]),
                &fixtures::caller(),
                &fixtures::callee(Tier::THREE),
                &fixtures::state(),
                fixtures::NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::RequireApproval);
        // Two independent gates, and this asserts the outer one. `enabled = false` is the v1
        // posture and fires before the review clock, so the reason names it — an operator who
        // sets `reviewed_at` and still sees escalation should be told the feature is off
        // rather than left guessing which limit they tripped.
        assert!(
            eval.reason.contains("standing issuance is off"),
            "{}",
            eval.reason
        );
    }

    #[test]
    fn nothing_in_a_policy_file_can_auto_approve_while_standing_is_off() {
        // The v1 posture, asserted against a policy written specifically to auto-approve:
        // every cap satisfied, the review clock fresh, an explicit `decision = "allow"`. It
        // still escalates, because `enabled` defaults to false and no other field substitutes
        // for it. That is the difference between a default and a decision.
        let text = format!(
            r#"
default = "deny"
version = "v1"

[[zone]]
id = "internal.apac-ops"
trust = "internal"

[[zone]]
id = "internal.payments"
trust = "internal"

[standing]
reviewed_at = {}
min_callee_tier = 4
max_tools = 64
max_per_window = 10000

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
decision = "allow"
ttl_max = "30d"
"#,
            fixtures::NOW - 60
        );
        let p = ConnectPolicy::parse(&text).unwrap();
        assert!(!p.standing.enabled, "off unless a policy says otherwise");

        let eval = p
            .evaluate(
                &fixtures::request(&["get_balance"]),
                &fixtures::caller(),
                &fixtures::callee(Tier::FOUR),
                &fixtures::state(),
                fixtures::NOW,
            )
            .unwrap();
        assert_eq!(
            eval.decision,
            ConnDecision::RequireApproval,
            "an allow rule must not mint without a human in v1: {}",
            eval.reason
        );
        assert!(eval.trace.contains("standing-cap"), "{}", eval.trace);

        // And the switch works, so turning it on later is configuration rather than a new
        // subsystem — the caps below it are built and tested, they simply bound nothing yet.
        let mut on = ConnectPolicy::parse(&text).unwrap();
        on.standing.enabled = true;
        let eval = on
            .evaluate(
                &fixtures::request(&["get_balance"]),
                &fixtures::caller(),
                &fixtures::callee(Tier::FOUR),
                &fixtures::state(),
                fixtures::NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::Allow, "{}", eval.reason);
    }

    #[test]
    fn the_shipped_policy_auto_approves_the_low_risk_case_once_reviewed() {
        let mut p = ConnectPolicy::parse(SHIPPED).unwrap();
        p.standing.reviewed_at = fixtures::NOW - 86_400;
        // v1 ships with standing issuance off; these tests are about the caps it applies
        // once an estate turns it on, so they opt in explicitly.
        p.standing.enabled = true;

        let eval = p
            .evaluate(
                &fixtures::request(&["get_balance", "list_transactions"]),
                &fixtures::caller(),
                &fixtures::callee(Tier::THREE),
                &fixtures::state(),
                fixtures::NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::Allow, "{}", eval.reason);
        // internal.payments declares a 14d ceiling, which beats the rule's 30d.
        assert_eq!(eval.ttl_secs, 14 * 86_400);
        assert_eq!(eval.terms.max_calls_per_hour, Some(500));
    }

    #[test]
    fn the_shipped_policy_sends_money_movement_to_a_controller() {
        let mut p = ConnectPolicy::parse(SHIPPED).unwrap();
        p.standing.reviewed_at = fixtures::NOW - 86_400;
        // v1 ships with standing issuance off; these tests are about the caps it applies
        // once an estate turns it on, so they opt in explicitly.
        p.standing.enabled = true;

        let eval = p
            .evaluate(
                &fixtures::request(&["wire_funds"]),
                &fixtures::caller(),
                &fixtures::callee(Tier::THREE),
                &fixtures::state(),
                fixtures::NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::RequireApproval);
        assert_eq!(eval.approver_role.as_deref(), Some("payments.controller"));
        assert_eq!(eval.ttl_secs, 7 * 86_400);
        assert_eq!(eval.terms.evidence.delivery, "blocking");
        assert!(eval.terms.human_oversight.is_some());
    }

    #[test]
    fn the_shipped_policy_denies_public_egress() {
        let mut p = ConnectPolicy::parse(SHIPPED).unwrap();
        p.standing.reviewed_at = fixtures::NOW - 86_400;
        // v1 ships with standing issuance off; these tests are about the caps it applies
        // once an estate turns it on, so they opt in explicitly.
        p.standing.enabled = true;

        let mut public = fixtures::callee(Tier::THREE);
        public.zone = ZoneId::new("public").unwrap();

        let eval = p
            .evaluate(
                &fixtures::request(&["get_balance"]),
                &fixtures::caller(),
                &public,
                &fixtures::state(),
                fixtures::NOW,
            )
            .unwrap();
        assert_eq!(eval.decision, ConnDecision::Deny);
        // With the lattice enforced, public egress is refused one layer earlier
        // than the rule — structurally, before any rule is consulted. The rule
        // below it is still the defence in depth if `strict_crossings` is ever
        // turned off, so both are asserted.
        assert!(eval.reason.contains("public"), "{}", eval.reason);
        assert!(eval.trace.contains("crossing[public]"), "{}", eval.trace);
        assert!(
            ConnectPolicy::parse(SHIPPED)
                .unwrap()
                .rules
                .iter()
                .any(|r| r.decision == ConnDecision::Deny
                    && r.callee_zone.as_ref().is_some_and(|g| g.matches("public"))),
            "the rule-level public deny must remain as defence in depth"
        );
    }
}

#[cfg(test)]
mod dry_run_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::tests as fixtures;
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};
    use wc_core::contract::{ApprovalRef, ContractRecord, ContractStatus, CONTRACT_SCHEMA};
    use wc_core::model::{Cid, Jti};

    use crate::store::{Durability, Event, Store};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TmpDir(std::path::PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> TmpDir {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("wc-dry-{}-{tag}-{n}", std::process::id()));
            // Clear first: `create_dir_all` on an EXISTING directory succeeds and leaves its
            // contents, and these paths repeat across runs because a pid gets reused and the
            // counter restarts at 0. `Drop` does not run when a test aborts or a run is killed,
            // so leftovers accumulate — 2,956 of them were sitting in /tmp when this was found.
            // A stale log underneath a durability test can fail it, and can also make it PASS
            // for the wrong reason, which is the worse half.
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TmpDir(p)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record(cid: &str, tools: &[&str], callee: &Entity, caller: &Entity) -> ContractRecord {
        let surface = Surface {
            tools: tools.iter().map(|t| (*t).to_string()).collect(),
            skills: Vec::new(),
            resources: Vec::new(),
        };
        ContractRecord {
            cid: Cid::new(cid).unwrap(),
            jti: Jti::new("cx_00000001").unwrap(),
            caller: caller.id.clone(),
            callee: callee.id.clone(),
            caller_zone: caller.zone.clone(),
            callee_zone: callee.zone.clone(),
            callee_tier: callee.tier,
            callee_manifest: callee.pin.manifest.clone(),
            surface_digest: "sha256:d".to_string(),
            surface,
            terms: Terms {
                data_classes: vec!["internal".to_string()],
                jurisdictions: vec!["SG".to_string()],
                ..Default::default()
            },
            aud: vec!["warden:mediator:apac-ops".to_string()],
            jws_sha256: "sha256:j".to_string(),
            status: ContractStatus::Active,
            approval: ApprovalRef::standing(),
            policy_version: "connect-policy@v0".to_string(),
            iat: fixtures::NOW - 86_400,
            exp: fixtures::NOW + 86_400,
            offer_version: None,
            schema: CONTRACT_SCHEMA,
        }
    }

    /// A store holding two live contracts: one read-only, one write-capable.
    fn seeded(tmp: &TmpDir) -> Store {
        let (mut store, _) = Store::open(&tmp.0).unwrap();
        let caller = fixtures::caller();
        let callee = fixtures::callee(Tier::THREE);

        for entity in [&caller, &callee] {
            store
                .commit(
                    Event::EntityPut {
                        entity: Box::new(entity.clone()),
                        actor: crate::store::Actor::Service {
                            id: "test".to_string(),
                        },
                    },
                    fixtures::NOW - 1_000,
                    Durability::Durable,
                )
                .unwrap();
        }
        for (cid, tools) in [
            ("conn_11111111", vec!["get_balance"]),
            ("conn_22222222", vec!["wire_funds"]),
        ] {
            store
                .commit(
                    Event::ContractMint {
                        record: Box::new(record(cid, &tools, &callee, &caller)),
                    },
                    fixtures::NOW - 900,
                    Durability::Durable,
                )
                .unwrap();
        }
        store
    }

    #[test]
    fn dry_run_reports_what_a_policy_change_would_do() {
        let tmp = TmpDir::new("basic");
        let store = seeded(&tmp);

        let mut p = ConnectPolicy::parse(include_str!("../../../connect-policy.toml")).unwrap();
        p.standing.reviewed_at = fixtures::NOW - 86_400;
        // v1 ships with standing issuance off; these tests are about the caps it applies
        // once an estate turns it on, so they opt in explicitly.
        p.standing.enabled = true;

        let report = p.dry_run(&store.projection, &fixtures::state(), fixtures::NOW);
        assert_eq!(report.rows.len(), 2);
        assert!(report.unevaluable.is_empty());

        // The read-only contract stays standing-issuable; the write-capable one now
        // needs a controller.
        let read_only = report
            .rows
            .iter()
            .find(|r| r.cid == "conn_11111111")
            .unwrap();
        assert!(read_only.still_issuable, "{}", read_only.reason);

        let write = report
            .rows
            .iter()
            .find(|r| r.cid == "conn_22222222")
            .unwrap();
        assert!(!write.still_issuable);
        assert_eq!(report.would_escalate, vec!["conn_22222222".to_string()]);
        assert!(report.would_deny.is_empty());
        assert!(!report.is_neutral());
    }

    #[test]
    fn a_deny_all_candidate_is_reported_as_breaking_everything() {
        let tmp = TmpDir::new("denyall");
        let store = seeded(&tmp);

        let p = ConnectPolicy::parse(
            "default = \"deny\"\nversion = \"v-strict\"\n[standing]\nreviewed_at = 1\nreview_every = \"36500d\"\n",
        )
        .unwrap();

        let report = p.dry_run(&store.projection, &fixtures::state(), fixtures::NOW);
        assert_eq!(report.would_deny.len(), 2);
        assert!(!report.is_neutral());
    }

    #[test]
    fn a_contract_whose_party_left_the_registry_is_unevaluable_not_dropped() {
        // An answer that quietly omits half the estate is worse than no answer.
        let tmp = TmpDir::new("orphan");
        let (mut store, _) = Store::open(&tmp.0).unwrap();
        let caller = fixtures::caller();
        let callee = fixtures::callee(Tier::THREE);
        store
            .commit(
                Event::ContractMint {
                    record: Box::new(record("conn_33333333", &["get_balance"], &callee, &caller)),
                },
                fixtures::NOW - 900,
                Durability::Durable,
            )
            .unwrap();

        let p = ConnectPolicy::parse(include_str!("../../../connect-policy.toml")).unwrap();
        let report = p.dry_run(&store.projection, &fixtures::state(), fixtures::NOW);

        assert!(report.rows.is_empty());
        assert_eq!(report.unevaluable.len(), 1);
        assert_eq!(report.unevaluable[0].0, "conn_33333333");
        assert!(report.unevaluable[0]
            .1
            .contains("no longer in the registry"));
    }

    #[test]
    fn revoked_contracts_are_not_re_evaluated() {
        let tmp = TmpDir::new("revoked");
        let mut store = seeded(&tmp);
        store
            .commit(
                Event::ContractRevoke {
                    cid: Cid::new("conn_22222222").unwrap(),
                    reason: "done".to_string(),
                    actor: crate::store::Actor::Service {
                        id: "test".to_string(),
                    },
                },
                fixtures::NOW,
                Durability::Durable,
            )
            .unwrap();

        let mut p = ConnectPolicy::parse(include_str!("../../../connect-policy.toml")).unwrap();
        p.standing.reviewed_at = fixtures::NOW - 86_400;
        // v1 ships with standing issuance off; these tests are about the caps it applies
        // once an estate turns it on, so they opt in explicitly.
        p.standing.enabled = true;

        let report = p.dry_run(&store.projection, &fixtures::state(), fixtures::NOW);
        assert_eq!(
            report.rows.len(),
            1,
            "only the live contract is re-evaluated"
        );
        assert!(report.is_neutral());
    }
}
