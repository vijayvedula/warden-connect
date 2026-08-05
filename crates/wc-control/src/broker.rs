//! Mediated capability discovery (`docs/08-lld.md` §8.5.6, UC-03).
//!
//! "Which server can read a balance?" is the first question a developer asks, and
//! today the answer comes from Slack. Discovery has to be **the fastest way to
//! find a capability**, not merely the sanctioned one, or the whole adoption model
//! collapses at step one.
//!
//! It is also the estate's enumeration surface. A directory that answers freely
//! hands an attacker the map: every service, its owner, its tier, its jurisdiction
//! — which is exactly the reconnaissance that precedes a targeted request. So this
//! module is built around one question: *what can a caller learn from an answer
//! they were not entitled to?*
//!
//! # Four mechanics, and the order matters
//!
//! 1. **Eligibility filtering happens before shaping.** A candidate the asker
//!    could never connect to is dropped from the result set entirely, so a `Deny`
//!    is indistinguishable from a nonexistent entity. Filtering *after* shaping
//!    would leak existence through the count.
//! 2. **Results carry no reachability.** No endpoint, no tool schema, no full item
//!    list. Discovery tells you a capability exists and who owns it; reaching it
//!    still requires a contract.
//! 3. **Throttling truncates, it does not refuse.** Overflow returns
//!    `truncated: true` with an empty tail, never a `429` — a status code that
//!    changes when you cross a threshold is itself a signal, and a caller who can
//!    tell "throttled" from "no results" can binary-search the estate.
//! 4. **Latency is padded to a floor.** The empty-result path is faster than the
//!    non-empty one, and that difference is readable across a few hundred queries.
//!    Padding closes it — see [`Padding`] for the honest limits of that.
//!
//! # `CapKey` is a search key, never an authority key
//!
//! Capability keys are derived from names and declared tags by a deterministic
//! normalisation. They are lossy and approximate on purpose: they exist to make
//! things findable. Nothing in this system authorises against one, and a match
//! here grants exactly nothing — the contract still decides every tool.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use wc_core::error::{Code, Result, WcError};
use wc_core::model::{Entity, EntityId, Lifecycle, Posture};

use crate::cpolicy::{ConnDecision, ConnRequest, ConnectPolicy, StandingState};
use crate::store::Projection;

/// Tokens dropped when deriving capability keys.
///
/// Short and boring on purpose. An aggressive stop list makes two unrelated
/// capabilities collide, and a collision in a *search* key is a bad result rather
/// than a security failure — but it is still a bad result.
const STOP_WORDS: &[&str] = &[
    "a", "an", "and", "by", "for", "from", "in", "of", "on", "or", "the", "to", "with", "get",
    "set", "do", "make", "run", "mcp", "api", "v1", "v2", "tool", "tools", "service",
];

// ---------------------------------------------------------------------------
// Capability keys
// ---------------------------------------------------------------------------

/// A normalised, dotted capability key such as `payments.balance.read`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CapKey(String);

impl CapKey {
    /// Normalise free text into a capability key.
    ///
    /// Lowercase, split on anything that is not alphanumeric, drop stop words,
    /// dedupe, join with dots. Deterministic, so the same estate indexes the same
    /// way on every restart and a test can assert the result.
    #[must_use]
    pub fn normalise(text: &str) -> CapKey {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut parts: Vec<String> = Vec::new();
        for token in text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
        {
            let lower = token.to_lowercase();
            if STOP_WORDS.contains(&lower.as_str()) || lower.len() < 2 {
                continue;
            }
            if seen.insert(lower.clone()) {
                parts.push(lower);
            }
        }
        CapKey(parts.join("."))
    }

    /// The key as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the key is empty, which matches nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The individual tokens.
    #[must_use]
    pub fn tokens(&self) -> BTreeSet<&str> {
        self.0.split('.').filter(|t| !t.is_empty()).collect()
    }

    /// Whether this key satisfies a query.
    ///
    /// Every query token must be present. Substring matching would make
    /// `bal` match `balance` and also `imbalance`, and a search that returns
    /// surprising things is one people stop trusting.
    #[must_use]
    pub fn satisfies(&self, query: &CapKey) -> bool {
        if query.is_empty() {
            return false;
        }
        let mine = self.tokens();
        query.tokens().iter().all(|t| mine.contains(t))
    }
}

impl std::fmt::Display for CapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(&self.0)
    }
}

/// Every capability key an entity offers.
///
/// Derived from the pinned item names, the business service and the declared data
/// classes — all facts already on the record. Descriptions are deliberately **not**
/// indexed: they are attacker-controlled text (that is the whole premise of
/// `screen`), and letting them steer discovery would let a poisoned description
/// advertise itself into other teams' searches.
#[must_use]
pub fn capability_keys(entity: &Entity) -> BTreeSet<CapKey> {
    let mut keys: BTreeSet<CapKey> = BTreeSet::new();
    for name in entity.pin.items.keys() {
        let key = CapKey::normalise(name);
        if !key.is_empty() {
            keys.insert(key);
        }
    }
    if let Some(service) = &entity.service {
        let key = CapKey::normalise(service);
        if !key.is_empty() {
            keys.insert(key);
        }
    }
    for class in &entity.data_classes {
        let key = CapKey::normalise(class);
        if !key.is_empty() {
            keys.insert(key);
        }
    }
    keys
}

// ---------------------------------------------------------------------------
// Throttling
// ---------------------------------------------------------------------------

/// Per-asker query budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryLimits {
    /// Queries per minute.
    #[serde(default = "default_per_minute")]
    pub per_minute: u32,
    /// Queries per day.
    #[serde(default = "default_per_day")]
    pub per_day: u32,
    /// Matches returned in one answer.
    #[serde(default = "default_max_matches")]
    pub max_matches: usize,
    /// Latency floor in milliseconds, applied to every answer.
    #[serde(default = "default_latency_floor_ms")]
    pub latency_floor_ms: u64,
}

fn default_per_minute() -> u32 {
    30
}
fn default_per_day() -> u32 {
    300
}
fn default_max_matches() -> usize {
    20
}
fn default_latency_floor_ms() -> u64 {
    25
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        DiscoveryLimits {
            per_minute: default_per_minute(),
            per_day: default_per_day(),
            max_matches: default_max_matches(),
            latency_floor_ms: default_latency_floor_ms(),
        }
    }
}

impl DiscoveryLimits {
    /// Validate, refusing the shapes that quietly remove the bound.
    pub fn validate(&self) -> Result<()> {
        if self.per_minute == 0 || self.per_day == 0 {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "discovery limits of 0 would refuse every query rather than throttle it",
            ));
        }
        if self.per_day < self.per_minute {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "discovery per_day ({}) is below per_minute ({}), so the minute budget can never be spent",
                    self.per_day, self.per_minute
                ),
            ));
        }
        if self.max_matches == 0 {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "discovery max_matches = 0 would make every answer empty",
            ));
        }
        Ok(())
    }
}

/// One asker's spend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Spend {
    minute: u64,
    in_minute: u32,
    day: u64,
    in_day: u32,
}

/// Per-asker query budgets.
#[derive(Debug, Clone, Default)]
pub struct Throttle {
    spend: BTreeMap<String, Spend>,
}

impl Throttle {
    /// A fresh throttle.
    #[must_use]
    pub fn new() -> Throttle {
        Throttle::default()
    }

    /// Charge one query. `false` means the asker is over budget.
    pub fn charge(&mut self, asker: &EntityId, limits: &DiscoveryLimits, now: u64) -> bool {
        let (minute, day) = (now / 60, now / 86_400);
        let spend = self.spend.entry(asker.as_str().to_string()).or_default();
        if spend.minute != minute {
            spend.minute = minute;
            spend.in_minute = 0;
        }
        if spend.day != day {
            spend.day = day;
            spend.in_day = 0;
        }
        if spend.in_minute >= limits.per_minute || spend.in_day >= limits.per_day {
            return false;
        }
        spend.in_minute += 1;
        spend.in_day += 1;
        true
    }

    /// How many askers are being tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spend.len()
    }

    /// Whether nothing is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spend.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Latency padding
// ---------------------------------------------------------------------------

/// Pads every answer to a floor, so an empty result is not faster than a full one.
///
/// # What this does and does not achieve
///
/// It closes the *library-level* difference between "no candidates matched" and
/// "candidates matched and were filtered out", which is otherwise a few hundred
/// microseconds and readable across a few hundred queries.
///
/// It does **not** make discovery constant-time end to end. TLS record sizes,
/// response body length, HTTP/2 framing and the network itself all still vary with
/// the answer, and a floor cannot pad *down* a query that legitimately took
/// longer than it. [`Padded::exceeded`] reports when that happened, because a
/// padding that silently failed to mask is worse than none — it is the same
/// signal, plus a belief that it was covered.
#[derive(Debug, Clone, Copy)]
pub struct Padding {
    floor: Duration,
}

/// What padding did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Padded {
    /// How long the work actually took.
    pub elapsed: Duration,
    /// How long was added.
    pub added: Duration,
    /// Whether the work exceeded the floor, so the answer was not masked.
    pub exceeded: bool,
}

impl Padding {
    /// A floor in milliseconds.
    #[must_use]
    pub fn new(floor_ms: u64) -> Padding {
        Padding {
            floor: Duration::from_millis(floor_ms),
        }
    }

    /// Compute the pad for an elapsed duration, without sleeping.
    ///
    /// Separated from the sleep so the decision is testable and the caller chooses
    /// how to wait — a threaded server sleeps, an async one would not.
    #[must_use]
    pub fn plan(&self, elapsed: Duration) -> Padded {
        if elapsed >= self.floor {
            Padded {
                elapsed,
                added: Duration::ZERO,
                exceeded: true,
            }
        } else {
            Padded {
                elapsed,
                added: self.floor - elapsed,
                exceeded: false,
            }
        }
    }

    /// Plan and sleep.
    pub fn apply(&self, elapsed: Duration) -> Padded {
        let plan = self.plan(elapsed);
        if !plan.added.is_zero() {
            std::thread::sleep(plan.added);
        }
        plan
    }
}

// ---------------------------------------------------------------------------
// Query and result
// ---------------------------------------------------------------------------

/// A discovery query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// What the asker is looking for, e.g. `payments.balance.read`.
    pub capability: String,
    /// Restrict to entities operating in this jurisdiction.
    pub jurisdiction: Option<String>,
    /// Restrict to a data class.
    pub data_class: Option<String>,
}

impl Query {
    /// A capability query.
    #[must_use]
    pub fn new(capability: impl Into<String>) -> Query {
        Query {
            capability: capability.into(),
            jurisdiction: None,
            data_class: None,
        }
    }

    /// The normalised key.
    #[must_use]
    pub fn key(&self) -> CapKey {
        CapKey::normalise(&self.capability)
    }
}

/// One match, shaped.
///
/// Note what is absent: no endpoint, no tool schema, no item list, no pin. A match
/// tells the asker that a capability exists and who to ask for it. Reaching it
/// still requires a contract, so discovery hands out no reachability at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySummary {
    /// The entity, so a request can name it.
    pub entity: String,
    /// Which of its capability keys matched.
    pub capability: String,
    /// Risk tier, so the asker knows what approval to expect.
    pub tier: u8,
    /// Zone, so the asker knows whether this is a crossing.
    pub zone: String,
    /// The accountable human — the person to talk to.
    pub owner: String,
    /// Business service, where recorded.
    pub service: Option<String>,
    /// Whether a request would auto-approve or need a human. Saves a round trip,
    /// and reveals nothing the asker could not learn by requesting.
    pub likely_decision: String,
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverResult {
    /// Matches, shaped and sorted.
    pub matches: Vec<CapabilitySummary>,
    /// Whether the answer was cut short — by the match cap or by throttling.
    ///
    /// One flag for both on purpose. A caller who can tell "you are throttled"
    /// from "there are more results" can binary-search the estate by watching
    /// which one they get.
    pub truncated: bool,
    /// How many candidates were considered before eligibility filtering.
    ///
    /// **Never returned to the asker.** Present for the operator's metrics, and a
    /// test asserts it does not appear in the serialised summary.
    pub considered: usize,
}

/// Everything discovery needs.
#[derive(Debug)]
pub struct BrokerCtx<'a> {
    /// The estate.
    pub projection: &'a Projection,
    /// Connection policy, for the eligibility filter.
    pub policy: &'a ConnectPolicy,
    /// Standing-issuance state, so `likely_decision` is honest.
    pub standing: &'a StandingState,
    /// Query budgets.
    pub limits: &'a DiscoveryLimits,
    /// Wall clock.
    pub now: u64,
}

/// Answer a discovery query.
///
/// The asker must itself be registered and attested: an unattested party asking
/// what exists is reconnaissance, and answering it would make the register a
/// service for exactly the caller it was built to constrain.
pub fn discover(
    query: &Query,
    asker: &EntityId,
    throttle: &mut Throttle,
    ctx: &BrokerCtx<'_>,
) -> Result<DiscoverResult> {
    let asking = ctx.projection.entities.get(asker).ok_or_else(|| {
        WcError::with_detail(
            Code::ASKER_NOT_ATTESTED,
            format!("{asker} is not registered, so it cannot query the register"),
        )
    })?;
    if asking.lifecycle != Lifecycle::Active || asking.posture == Posture::Quarantined {
        return Err(WcError::with_detail(
            Code::ASKER_NOT_ATTESTED,
            format!("{asker} is {:?}/{:?}", asking.lifecycle, asking.posture),
        ));
    }

    // Over budget answers empty-and-truncated rather than erroring. A status code
    // that changes at a threshold is itself a signal.
    if !throttle.charge(asker, ctx.limits, ctx.now) {
        return Ok(DiscoverResult {
            matches: Vec::new(),
            truncated: true,
            considered: 0,
        });
    }

    let wanted = query.key();
    if wanted.is_empty() {
        return Ok(DiscoverResult {
            matches: Vec::new(),
            truncated: false,
            considered: 0,
        });
    }

    let mut candidates: Vec<(&Entity, CapKey)> = Vec::new();
    for entity in ctx.projection.entities.values() {
        if entity.id == *asker || entity.lifecycle != Lifecycle::Active {
            continue;
        }
        if let Some(j) = &query.jurisdiction {
            if !entity.jurisdictions.iter().any(|x| x.eq_ignore_ascii_case(j)) {
                continue;
            }
        }
        if let Some(c) = &query.data_class {
            if !entity.data_classes.iter().any(|x| x.eq_ignore_ascii_case(c)) {
                continue;
            }
        }
        if let Some(matched) = capability_keys(entity)
            .into_iter()
            .find(|k| k.satisfies(&wanted))
        {
            candidates.push((entity, matched));
        }
    }
    let considered = candidates.len();

    // Eligibility filtering, **before** shaping. A candidate the asker could never
    // connect to is dropped entirely, so a policy denial is indistinguishable from
    // a nonexistent entity.
    let mut matches: Vec<CapabilitySummary> = Vec::new();
    for (entity, capability) in candidates {
        let Some(decision) = eligibility(asking, entity, ctx) else {
            continue;
        };
        matches.push(CapabilitySummary {
            entity: entity.id.as_str().to_string(),
            capability: capability.as_str().to_string(),
            tier: entity.tier.as_u8(),
            zone: entity.zone.as_str().to_string(),
            owner: entity.owner.as_str().to_string(),
            service: entity.service.clone(),
            likely_decision: decision,
        });
    }

    // Sorted for reproducibility: an answer whose order shifts between identical
    // queries is another bit of signal.
    matches.sort_by(|a, b| (a.tier, &a.entity).cmp(&(b.tier, &b.entity)));
    let truncated = matches.len() > ctx.limits.max_matches;
    matches.truncate(ctx.limits.max_matches);

    Ok(DiscoverResult {
        matches,
        truncated,
        considered,
    })
}

/// Whether the asker could connect to this candidate at all, and how.
///
/// `None` means "never", which removes the candidate from the answer entirely.
fn eligibility(asker: &Entity, candidate: &Entity, ctx: &BrokerCtx<'_>) -> Option<String> {
    // The full surface the candidate declares — the most any request could ask
    // for. Evaluating against it means a candidate that would be denied for *any*
    // surface is denied here.
    let surface = wc_core::contract::Surface {
        tools: candidate.pin.items.keys().cloned().collect(),
        ..Default::default()
    };
    let request = ConnRequest {
        surface,
        terms: wc_core::contract::Terms {
            data_classes: candidate.data_classes.clone(),
            jurisdictions: candidate.jurisdictions.clone(),
            ..Default::default()
        },
        ttl_secs: 86_400,
        justification: String::new(),
        requester: asker.owner.clone(),
    };

    match ctx
        .policy
        .evaluate(&request, asker, candidate, ctx.standing, ctx.now)
    {
        Ok(eval) => match eval.decision {
            ConnDecision::Allow => Some("auto-approve".to_string()),
            ConnDecision::RequireApproval => Some(match &eval.approver_role {
                Some(role) => format!("needs {role}"),
                None => "needs approval".to_string(),
            }),
            ConnDecision::Deny => None,
        },
        // A structural refusal — quarantined, self-connection, surface mismatch —
        // is also "never", and is treated identically so the two are not
        // distinguishable from outside.
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::collections::BTreeMap as Map;
    use wc_core::model::{HumanRef, Kind, Pin, Tier, ZoneId, PIN_ALG};

    const NOW: u64 = 1_800_000_000;

    fn id(name: &str) -> EntityId {
        EntityId::new(format!("spiffe://org/ns/x/sa/{name}")).unwrap()
    }

    fn entity(name: &str, zone: &str, tier: u8, tools: &[&str]) -> Entity {
        let mut e = Entity::pending(
            id(name),
            Kind::McpServer,
            HumanRef::new("human:priya@org").unwrap(),
            ZoneId::new(zone).unwrap(),
            Tier::new(tier).unwrap(),
            NOW - 1_000,
        );
        e.lifecycle = Lifecycle::Active;
        e.posture = Posture::Attested;
        e.posture_score = 95;
        e.service = Some(format!("{name}-service"));
        e.jurisdictions = vec!["SG".to_string()];
        e.data_classes = vec!["financial".to_string()];
        e.pin = Pin {
            alg: PIN_ALG.to_string(),
            manifest: format!("sha256:{name}"),
            items: tools
                .iter()
                .map(|t| ((*t).to_string(), format!("sha256:{t}")))
                .collect::<Map<_, _>>(),
            pinned_at: NOW - 1_000,
        };
        e
    }

    fn policy(text: &str) -> ConnectPolicy {
        ConnectPolicy::parse(text).unwrap()
    }

    /// Internal-to-internal allowed; anything into `internal.vault` denied.
    fn default_policy() -> ConnectPolicy {
        policy(
            r#"
default = "require_approval"
version = "broker-test@v1"

[[zone]]
id = "internal.apac"
trust = "internal"
[[zone]]
id = "internal.payments"
trust = "internal"
[[zone]]
id = "internal.vault"
trust = "internal"

# Reviewed, or standing policy treats itself as overdue and escalates
# everything — which is the correct default and would make every
# `likely_decision` in these tests read "needs approval".
[standing]
reviewed_at = 1799000000
review_every = "90d"

[[rules]]
callee_zone = "internal.vault"
decision = "deny"
reason = "the vault is never discoverable"

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
callee_tier = { op = "gt", value = 2 }
decision = "allow"
"#,
        )
    }

    fn projection(entities: Vec<Entity>) -> Projection {
        let mut p = Projection::default();
        for e in entities {
            p.entities.insert(e.id.clone(), e);
        }
        p
    }

    fn ctx<'a>(
        projection: &'a Projection,
        pol: &'a ConnectPolicy,
        standing: &'a StandingState,
        limits: &'a DiscoveryLimits,
    ) -> BrokerCtx<'a> {
        BrokerCtx {
            projection,
            policy: pol,
            standing,
            limits,
            now: NOW,
        }
    }

    fn estate() -> Projection {
        projection(vec![
            entity("recon", "internal.apac", 3, &["reconcile"]),
            entity("payments", "internal.payments", 3, &["get_balance", "list_transactions"]),
            entity("vault", "internal.vault", 1, &["get_balance", "sign"]),
        ])
    }

    // --- capability keys ---------------------------------------------------

    #[test]
    fn keys_normalise_deterministically() {
        assert_eq!(CapKey::normalise("get_balance").as_str(), "balance");
        assert_eq!(
            CapKey::normalise("Payments.Balance.Read").as_str(),
            "payments.balance.read"
        );
        assert_eq!(CapKey::normalise("list_transactions").as_str(), "list.transactions");
        // Stop words and one-character tokens go.
        assert_eq!(CapKey::normalise("get the balance of a account").as_str(), "balance.account");
        // Duplicates collapse, and order is stable.
        assert_eq!(CapKey::normalise("balance balance read").as_str(), "balance.read");
        assert!(CapKey::normalise("the a of").is_empty());
        assert_eq!(CapKey::normalise("x"), CapKey::normalise(""));
    }

    #[test]
    fn a_query_matches_when_every_token_is_present() {
        let key = CapKey::normalise("payments.balance.read");
        assert!(key.satisfies(&CapKey::normalise("balance")));
        assert!(key.satisfies(&CapKey::normalise("balance.read")));
        assert!(key.satisfies(&CapKey::normalise("read payments")));
        // Not a substring match: `bal` must not find `balance`, or the search
        // returns surprising things and people stop trusting it.
        assert!(!key.satisfies(&CapKey::normalise("bal")));
        assert!(!key.satisfies(&CapKey::normalise("balance.write")));
        // An empty query matches nothing rather than everything.
        assert!(!key.satisfies(&CapKey::normalise("")));
    }

    #[test]
    fn descriptions_are_never_indexed() {
        // Descriptions are attacker-controlled text — that is the entire premise
        // of `screen`. Letting them steer discovery would let a poisoned
        // description advertise itself into other teams' searches.
        let mut e = entity("payments", "internal.payments", 3, &["get_balance"]);
        e.service = Some("payments-core".to_string());
        let keys = capability_keys(&e);
        assert!(keys.iter().any(|k| k.as_str() == "balance"));
        assert!(keys.iter().any(|k| k.as_str().contains("payments")));
        // Nothing derived from anything but names, service and data classes.
        assert_eq!(keys.len(), 3, "{keys:?}");
    }

    // --- the four mechanics ------------------------------------------------

    #[test]
    fn discovery_finds_an_eligible_capability() {
        let proj = estate();
        let pol = default_policy();
        let state = StandingState::default();
        let limits = DiscoveryLimits::default();
        let mut throttle = Throttle::new();

        let r = discover(
            &Query::new("balance"),
            &id("recon"),
            &mut throttle,
            &ctx(&proj, &pol, &state, &limits),
        )
        .unwrap();

        assert_eq!(r.matches.len(), 1, "{:?}", r.matches);
        assert!(r.matches[0].entity.contains("payments"));
        assert_eq!(r.matches[0].capability, "balance");
        assert_eq!(r.matches[0].likely_decision, "auto-approve");
        assert!(!r.truncated);
    }

    #[test]
    fn a_denied_candidate_is_indistinguishable_from_a_nonexistent_one() {
        // The vault offers `get_balance` too, and policy denies it. Filtering
        // after shaping would leak its existence through the count.
        let proj = estate();
        let pol = default_policy();
        let state = StandingState::default();
        let limits = DiscoveryLimits::default();
        let mut throttle = Throttle::new();

        let found = discover(
            &Query::new("balance"),
            &id("recon"),
            &mut throttle,
            &ctx(&proj, &pol, &state, &limits),
        )
        .unwrap();
        assert!(
            !found.matches.iter().any(|m| m.entity.contains("vault")),
            "the vault must not appear"
        );

        // And an estate where the vault simply does not exist gives the same
        // answer, byte for byte.
        let without = projection(vec![
            entity("recon", "internal.apac", 3, &["reconcile"]),
            entity("payments", "internal.payments", 3, &["get_balance", "list_transactions"]),
        ]);
        let mut t2 = Throttle::new();
        let absent = discover(
            &Query::new("balance"),
            &id("recon"),
            &mut t2,
            &ctx(&without, &pol, &state, &limits),
        )
        .unwrap();
        assert_eq!(found.matches, absent.matches);
        assert_eq!(found.truncated, absent.truncated);
    }

    #[test]
    fn a_match_carries_no_reachability() {
        let proj = estate();
        let pol = default_policy();
        let state = StandingState::default();
        let limits = DiscoveryLimits::default();
        let mut throttle = Throttle::new();
        let r = discover(
            &Query::new("balance"),
            &id("recon"),
            &mut throttle,
            &ctx(&proj, &pol, &state, &limits),
        )
        .unwrap();

        let json = serde_json::to_string(&r.matches[0]).unwrap();
        for leak in ["endpoint", "pin", "manifest", "sha256", "inputSchema", "items"] {
            assert!(!json.contains(leak), "summary leaked {leak}: {json}");
        }
        // And the candidate count is an operator metric, not part of the answer.
        assert!(!json.contains("considered"));
    }

    #[test]
    fn throttling_truncates_rather_than_refusing() {
        // A status code that changes at a threshold is itself a signal, and a
        // caller who can tell "throttled" from "no results" can binary-search the
        // estate.
        let proj = estate();
        let pol = default_policy();
        let state = StandingState::default();
        let limits = DiscoveryLimits {
            per_minute: 2,
            ..DiscoveryLimits::default()
        };
        let mut throttle = Throttle::new();
        let c = ctx(&proj, &pol, &state, &limits);

        for i in 0..2 {
            let r = discover(&Query::new("balance"), &id("recon"), &mut throttle, &c).unwrap();
            assert!(!r.truncated, "query {i} should be within budget");
        }
        let over = discover(&Query::new("balance"), &id("recon"), &mut throttle, &c).unwrap();
        assert!(over.matches.is_empty());
        assert!(over.truncated, "empty tail, not an error");

        // Which is the same shape as a genuine miss, deliberately.
        let miss = discover(&Query::new("nothing.here"), &id("recon"), &mut Throttle::new(), &c)
            .unwrap();
        assert_eq!(over.matches, miss.matches);
    }

    #[test]
    fn budgets_are_per_asker_and_reset() {
        let limits = DiscoveryLimits {
            per_minute: 1,
            ..DiscoveryLimits::default()
        };
        let mut t = Throttle::new();
        assert!(t.charge(&id("a"), &limits, NOW));
        assert!(!t.charge(&id("a"), &limits, NOW));
        // A second asker has its own budget.
        assert!(t.charge(&id("b"), &limits, NOW));
        // And the window rolls.
        assert!(t.charge(&id("a"), &limits, NOW + 60));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn the_daily_budget_binds_even_when_the_minute_one_does_not() {
        let limits = DiscoveryLimits {
            per_minute: 100,
            per_day: 3,
            ..DiscoveryLimits::default()
        };
        let mut t = Throttle::new();
        for i in 0..3u64 {
            assert!(t.charge(&id("a"), &limits, NOW + i * 60), "query {i}");
        }
        assert!(!t.charge(&id("a"), &limits, NOW + 600));
        // Next day.
        assert!(t.charge(&id("a"), &limits, NOW + 86_400));
    }

    // --- the asker ---------------------------------------------------------

    #[test]
    fn an_unregistered_or_inactive_asker_is_refused() {
        // Answering an unattested party would make the register a service for
        // exactly the caller it was built to constrain.
        let proj = estate();
        let pol = default_policy();
        let state = StandingState::default();
        let limits = DiscoveryLimits::default();
        let c = ctx(&proj, &pol, &state, &limits);

        assert_eq!(
            discover(&Query::new("balance"), &id("ghost"), &mut Throttle::new(), &c)
                .unwrap_err()
                .code(),
            Code::ASKER_NOT_ATTESTED
        );

        let mut suspended = estate();
        suspended.entities.get_mut(&id("recon")).unwrap().lifecycle = Lifecycle::Suspended;
        let c2 = ctx(&suspended, &pol, &state, &limits);
        assert_eq!(
            discover(&Query::new("balance"), &id("recon"), &mut Throttle::new(), &c2)
                .unwrap_err()
                .code(),
            Code::ASKER_NOT_ATTESTED
        );
    }

    #[test]
    fn an_asker_never_discovers_itself() {
        let proj = estate();
        let pol = default_policy();
        let state = StandingState::default();
        let limits = DiscoveryLimits::default();
        let r = discover(
            &Query::new("reconcile"),
            &id("recon"),
            &mut Throttle::new(),
            &ctx(&proj, &pol, &state, &limits),
        )
        .unwrap();
        assert!(r.matches.is_empty());
    }

    // --- filters and shaping ----------------------------------------------

    #[test]
    fn jurisdiction_and_data_class_narrow_the_answer() {
        let mut proj = estate();
        proj.entities.get_mut(&id("payments")).unwrap().jurisdictions = vec!["AU".to_string()];
        let pol = default_policy();
        let state = StandingState::default();
        let limits = DiscoveryLimits::default();
        let c = ctx(&proj, &pol, &state, &limits);

        let mut q = Query::new("balance");
        q.jurisdiction = Some("SG".to_string());
        assert!(discover(&q, &id("recon"), &mut Throttle::new(), &c).unwrap().matches.is_empty());

        q.jurisdiction = Some("au".to_string()); // case-insensitive
        assert_eq!(
            discover(&q, &id("recon"), &mut Throttle::new(), &c).unwrap().matches.len(),
            1
        );

        let mut q2 = Query::new("balance");
        q2.data_class = Some("health".to_string());
        assert!(discover(&q2, &id("recon"), &mut Throttle::new(), &c).unwrap().matches.is_empty());
    }

    #[test]
    fn the_match_cap_truncates_and_says_so() {
        let mut entities = vec![entity("recon", "internal.apac", 3, &["reconcile"])];
        for i in 0..5 {
            entities.push(entity(
                &format!("payments{i}"),
                "internal.payments",
                3,
                &["get_balance"],
            ));
        }
        let proj = projection(entities);
        let pol = default_policy();
        let state = StandingState::default();
        let limits = DiscoveryLimits {
            max_matches: 2,
            ..DiscoveryLimits::default()
        };
        let r = discover(
            &Query::new("balance"),
            &id("recon"),
            &mut Throttle::new(),
            &ctx(&proj, &pol, &state, &limits),
        )
        .unwrap();
        assert_eq!(r.matches.len(), 2);
        assert!(r.truncated);
        assert_eq!(r.considered, 5, "the operator metric sees them all");
    }

    #[test]
    fn results_are_ordered_reproducibly() {
        // An answer whose order shifts between identical queries is another bit of
        // signal.
        let mut entities = vec![entity("recon", "internal.apac", 3, &["reconcile"])];
        for (i, tier) in [(0, 4), (1, 3), (2, 4)] {
            entities.push(entity(
                &format!("p{i}"),
                "internal.payments",
                tier,
                &["get_balance"],
            ));
        }
        let proj = projection(entities);
        let pol = default_policy();
        let state = StandingState::default();
        let limits = DiscoveryLimits::default();
        let c = ctx(&proj, &pol, &state, &limits);

        let a = discover(&Query::new("balance"), &id("recon"), &mut Throttle::new(), &c).unwrap();
        let b = discover(&Query::new("balance"), &id("recon"), &mut Throttle::new(), &c).unwrap();
        assert_eq!(a.matches, b.matches);
        assert_eq!(a.matches[0].tier, 3, "most sensitive first");
    }

    #[test]
    fn likely_decision_saves_a_round_trip_without_revealing_anything_new() {
        // It reveals only what the asker would learn by requesting, which they may
        // do at any time.
        let proj = estate();
        let pol = policy(
            r#"
default = "require_approval"
version = "v1"
[[zone]]
id = "internal.apac"
trust = "internal"
[[zone]]
id = "internal.payments"
trust = "internal"
[[rules]]
callee_zone = "internal.payments"
decision = "require_approval"
approver_role = "payments.controller"
"#,
        );
        let state = StandingState::default();
        let limits = DiscoveryLimits::default();
        let r = discover(
            &Query::new("balance"),
            &id("recon"),
            &mut Throttle::new(),
            &ctx(&proj, &pol, &state, &limits),
        )
        .unwrap();
        assert_eq!(
            r.matches
                .iter()
                .find(|m| m.entity.contains("payments"))
                .map(|m| m.likely_decision.as_str()),
            Some("needs payments.controller")
        );
    }

    // --- padding -----------------------------------------------------------

    #[test]
    fn padding_lifts_a_fast_answer_to_the_floor() {
        let p = Padding::new(25);
        let fast = p.plan(Duration::from_millis(2));
        assert_eq!(fast.added, Duration::from_millis(23));
        assert!(!fast.exceeded);
    }

    #[test]
    fn padding_reports_when_it_failed_to_mask() {
        // A floor cannot pad *down*. Silently failing to mask is worse than not
        // padding: it is the same signal, plus a belief that it was covered.
        let p = Padding::new(25);
        let slow = p.plan(Duration::from_millis(90));
        assert_eq!(slow.added, Duration::ZERO);
        assert!(slow.exceeded);
    }

    #[test]
    fn padding_actually_waits() {
        let started = std::time::Instant::now();
        let plan = Padding::new(30).apply(Duration::from_millis(1));
        assert!(started.elapsed() >= Duration::from_millis(25), "did not wait");
        assert!(!plan.exceeded);
    }

    // --- limits ------------------------------------------------------------

    #[test]
    fn limits_that_would_disable_discovery_are_refused() {
        for bad in [
            DiscoveryLimits {
                per_minute: 0,
                ..Default::default()
            },
            DiscoveryLimits {
                per_day: 0,
                ..Default::default()
            },
            DiscoveryLimits {
                max_matches: 0,
                ..Default::default()
            },
            // A daily budget below the per-minute one means the minute budget can
            // never be spent, which reads as a working throttle.
            DiscoveryLimits {
                per_minute: 60,
                per_day: 10,
                ..Default::default()
            },
        ] {
            assert_eq!(bad.validate().unwrap_err().code(), Code::CONFIG_INVALID);
        }
        assert!(DiscoveryLimits::default().validate().is_ok());
    }
}
