//! The domain model: identifiers, entities, pins, and the lifecycle state
//! machine. See `docs/08-lld.md` §8.5.1.
//!
//! Two invariants are enforced structurally rather than by check, because a
//! check can be forgotten:
//!
//! - **An entity cannot exist without an owner** — [`Entity::owner`] is
//!   [`HumanRef`], not `Option<HumanRef>`.
//! - **Identifiers are validated once, at construction.** Every id is a newtype
//!   whose only constructors validate, including the `serde` path, so a
//!   malformed id cannot enter the process from a log record or an API body.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Code, Result, WcError};

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// Shared syntactic checks: non-empty, bounded, printable, no whitespace.
fn base_checks(what: &str, s: &str, max: usize) -> Result<()> {
    if s.is_empty() {
        return Err(WcError::with_detail(
            Code::MALFORMED_IDENTIFIER,
            format!("{what} must not be empty"),
        ));
    }
    if s.len() > max {
        return Err(WcError::with_detail(
            Code::MALFORMED_IDENTIFIER,
            format!("{what} exceeds {max} bytes: {} given", s.len()),
        ));
    }
    if let Some(bad) = s.chars().find(|c| c.is_control() || c.is_whitespace()) {
        return Err(WcError::with_detail(
            Code::MALFORMED_IDENTIFIER,
            format!("{what} contains an illegal character {bad:?}"),
        ));
    }
    Ok(())
}

/// Generates a validated string newtype: `new`, `as_str`, `Display`,
/// `AsRef<str>`, `TryFrom<String>`, `TryFrom<&str>`, `From<Self> for String`,
/// and `serde` that validates on the way in.
macro_rules! id_type {
    (
        $(#[$doc:meta])*
        $name:ident, validate = $validate:ident, max = $max:expr
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validate and wrap. The only way in.
            pub fn new(raw: impl Into<String>) -> Result<Self> {
                let raw = raw.into();
                $validate(&raw, $max)?;
                Ok($name(raw))
            }

            /// The underlying string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = WcError;
            fn try_from(v: String) -> Result<Self> {
                $name::new(v)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = WcError;
            fn try_from(v: &str) -> Result<Self> {
                $name::new(v)
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }
    };
}

fn validate_entity_id(s: &str, max: usize) -> Result<()> {
    base_checks("entity id", s, max)?;
    if s.starts_with("spiffe://") || s.starts_with("urn:") {
        return Ok(());
    }
    Err(WcError::with_detail(
        Code::MALFORMED_IDENTIFIER,
        format!("entity id must be a spiffe:// or urn: identifier: {s:?}"),
    ))
}

fn validate_cid(s: &str, max: usize) -> Result<()> {
    base_checks("cid", s, max)?;
    let Some(rest) = s.strip_prefix("conn_") else {
        return Err(WcError::with_detail(
            Code::MALFORMED_IDENTIFIER,
            format!("cid must start with `conn_`: {s:?}"),
        ));
    };
    if rest.len() < 8 || !rest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(WcError::with_detail(
            Code::MALFORMED_IDENTIFIER,
            format!("cid suffix must be at least 8 hex digits: {s:?}"),
        ));
    }
    Ok(())
}

fn validate_jti(s: &str, max: usize) -> Result<()> {
    base_checks("jti", s, max)?;
    if s.len() < 8 {
        return Err(WcError::with_detail(
            Code::MALFORMED_IDENTIFIER,
            format!("jti must be at least 8 characters: {s:?}"),
        ));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(WcError::with_detail(
            Code::MALFORMED_IDENTIFIER,
            format!("jti must be alphanumeric, `_` or `-`: {s:?}"),
        ));
    }
    Ok(())
}

fn validate_human_ref(s: &str, max: usize) -> Result<()> {
    base_checks("human ref", s, max)?;
    match s.strip_prefix("human:") {
        Some(rest) if !rest.is_empty() => Ok(()),
        _ => Err(WcError::with_detail(
            Code::MALFORMED_IDENTIFIER,
            format!("owner must be a `human:<id>` reference: {s:?}"),
        )),
    }
}

fn validate_zone_id(s: &str, max: usize) -> Result<()> {
    base_checks("zone id", s, max)?;
    let segments: Vec<&str> = s.split('.').collect();
    if segments.len() > 4 {
        return Err(WcError::with_detail(
            Code::MALFORMED_IDENTIFIER,
            format!("zone id may have at most 4 segments: {s:?}"),
        ));
    }
    for seg in &segments {
        if seg.is_empty()
            || !seg
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(WcError::with_detail(
                Code::MALFORMED_IDENTIFIER,
                format!("zone segment {seg:?} must be lowercase alphanumeric or `-`"),
            ));
        }
    }
    // §8.17-Q5: three trust levels over an extensible dotted namespace. The
    // first segment names the trust level, which is what makes prefix matching
    // a lattice later without a data migration.
    if TrustLevel::from_segment(segments[0]).is_none() {
        return Err(WcError::with_detail(
            Code::MALFORMED_IDENTIFIER,
            format!("zone must start with internal|partner|public: {s:?}"),
        ));
    }
    Ok(())
}

id_type! {
    /// The wire identity of an agent or tool server: a SPIFFE ID or a URN.
    EntityId, validate = validate_entity_id, max = 512
}

id_type! {
    /// A connection id — the correlation root stamped on every action,
    /// evidence row and delegation for the life of the relationship.
    Cid, validate = validate_cid, max = 64
}

id_type! {
    /// A JOSE `jti`: contracts, approvals, revocation subjects.
    Jti, validate = validate_jti, max = 128
}

id_type! {
    /// An accountable human, as `human:<directory-id>`.
    HumanRef, validate = validate_human_ref, max = 256
}

id_type! {
    /// A trust zone, as `<trust-level>[.<segment>]*` — e.g. `internal.payments`.
    ZoneId, validate = validate_zone_id, max = 128
}

impl ZoneId {
    /// The trust level named by the first segment.
    #[must_use]
    pub fn trust_level(&self) -> TrustLevel {
        let first = self.0.split('.').next().unwrap_or_default();
        // Validated at construction, so the fallback is unreachable for any
        // ZoneId that exists — but returning the most restrictive level is the
        // right direction to be wrong in.
        TrustLevel::from_segment(first).unwrap_or(TrustLevel::Public)
    }
}

/// Zone trust levels. Three of them, deliberately (§8.17-Q5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Inside the organisation's own trust boundary.
    Internal,
    /// A named counterparty organisation.
    Partner,
    /// Anything else. The most restrictive bar applies.
    Public,
}

impl TrustLevel {
    fn from_segment(seg: &str) -> Option<TrustLevel> {
        match seg {
            "internal" => Some(TrustLevel::Internal),
            "partner" => Some(TrustLevel::Partner),
            "public" => Some(TrustLevel::Public),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Kind, Tier, Posture, Lifecycle
// ---------------------------------------------------------------------------

/// What sort of party this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A calling agent.
    Agent,
    /// An MCP tool server.
    McpServer,
    /// An A2A agent acting as a callee.
    A2aAgent,
}

impl Kind {
    /// Whether a declared surface is fetched over MCP (`initialize` +
    /// `tools/list`) rather than from a signed agent card.
    #[must_use]
    pub fn speaks_mcp(self) -> bool {
        matches!(self, Kind::McpServer)
    }
}

/// Risk tier, 1 (most sensitive) to 4 (least). Derived at admission, never
/// self-asserted.
///
/// Note the inverted ordering: `Tier::ONE < Tier::THREE` numerically, and tier 1
/// is the *more* sensitive of the two. Policy reads as `callee_tier <= 2`, so
/// numeric ordering is what call sites want; [`Tier::is_at_least_as_sensitive_as`]
/// exists for the cases where the intent is easier to misread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct Tier(u8);

impl Tier {
    /// Tier 1 — most sensitive; dual control, hourly re-attestation.
    pub const ONE: Tier = Tier(1);
    /// Tier 2 — human approval required.
    pub const TWO: Tier = Tier(2);
    /// Tier 3 — standing policy eligible.
    pub const THREE: Tier = Tier(3);
    /// Tier 4 — least sensitive.
    pub const FOUR: Tier = Tier(4);

    /// Validate and wrap a tier number.
    pub fn new(raw: u8) -> Result<Tier> {
        if (1..=4).contains(&raw) {
            Ok(Tier(raw))
        } else {
            Err(WcError::with_detail(
                Code::TIER_EXCEEDS_CEILING,
                format!("tier must be 1..=4, got {raw}"),
            ))
        }
    }

    /// The numeric tier.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// True when `self` is at least as sensitive as `other` (i.e. numerically
    /// less than or equal).
    #[must_use]
    pub const fn is_at_least_as_sensitive_as(self, other: Tier) -> bool {
        self.0 <= other.0
    }

    /// Whether a connection to a callee at this tier needs a human approver
    /// (§8.7.3: tier ≤ 2).
    #[must_use]
    pub const fn requires_human_approval(self) -> bool {
        self.0 <= 2
    }

    /// Whether minting at this tier needs two distinct approvers.
    #[must_use]
    pub const fn requires_dual_control(self) -> bool {
        self.0 == 1
    }

    /// Default re-attestation interval in seconds (§8.5.7: tier 1 hourly,
    /// tier 4 weekly).
    #[must_use]
    pub const fn reattest_interval_secs(self) -> u32 {
        match self.0 {
            1 => 3_600,
            2 => 6 * 3_600,
            3 => 24 * 3_600,
            _ => 7 * 24 * 3_600,
        }
    }
}

impl TryFrom<u8> for Tier {
    type Error = WcError;
    fn try_from(v: u8) -> Result<Self> {
        Tier::new(v)
    }
}

impl From<Tier> for u8 {
    fn from(t: Tier) -> u8 {
        t.0
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tier{}", self.0)
    }
}

/// Continuous-assurance state. Distinct from [`Lifecycle`]: lifecycle is what
/// an operator did, posture is what the sentinel found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    /// Identity, provenance and surface all verified within their interval.
    Attested,
    /// Verified once, but something has slipped: drift, overdue re-attestation,
    /// orphaned owner. No renewal, no new contracts; existing ones run to `exp`.
    Degraded,
    /// Never successfully attested. Not connectable in enforce mode.
    Unattested,
    /// Contained. Terminal until a full re-admission (§8.5.1).
    Quarantined,
}

impl Posture {
    /// Whether a new connection may be minted for a party in this state.
    #[must_use]
    pub fn may_connect(self, mode: crate::error::Mode) -> bool {
        match self {
            Posture::Attested => true,
            Posture::Degraded | Posture::Unattested => {
                matches!(mode, crate::error::Mode::Observe)
            }
            // Never overridable, in any mode — §7.8 fail-closed matrix.
            Posture::Quarantined => false,
        }
    }
}

/// Operator-driven registry state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Registered, admission not yet complete. Holds zero connections.
    Pending,
    /// Admitted and connectable.
    Active,
    /// Admitted but currently barred — material drift, failed re-attestation,
    /// owner departure, quarantine.
    Suspended,
    /// Offboarded. Retained for the regulatory clock; never returns.
    Retired,
}

impl Lifecycle {
    /// Whether this transition is legal per the §8.5.1 table. Same-state
    /// transitions are rejected: a no-op that writes an event is a lie in the
    /// audit chain.
    #[must_use]
    pub fn can_transition_to(self, to: Lifecycle) -> bool {
        use Lifecycle::{Active, Pending, Retired, Suspended};
        matches!(
            (self, to),
            (Pending, Active)
                | (Pending, Retired)
                | (Active, Suspended)
                | (Active, Retired)
                | (Suspended, Active)
                | (Suspended, Retired)
        )
    }
}

// ---------------------------------------------------------------------------
// Pin and provenance
// ---------------------------------------------------------------------------

/// The pinned surface of a party.
///
/// `manifest` covers the whole declared surface; `items` carries a per-item hash
/// so drift can be localised and so a contract can pin only the subset it
/// actually contracted for (§8.7.1). That per-item split is what makes an
/// additive tool outside a contracted surface *structurally* unable to move the
/// contract's digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    /// Canonicalisation algorithm — `"wcs1"` today.
    pub alg: String,
    /// `sha256:…` over the whole canonical surface document.
    pub manifest: String,
    /// Item name → `sha256:…` over that item's canonical projection.
    pub items: BTreeMap<String, String>,
    /// When this pin was taken.
    pub pinned_at: u64,
}

/// The canonicalisation algorithm this build produces and understands.
pub const PIN_ALG: &str = "wcs1";

impl Pin {
    /// An empty pin, for an entity whose surface has not been captured yet.
    #[must_use]
    pub fn empty(now: u64) -> Pin {
        Pin {
            alg: PIN_ALG.to_string(),
            manifest: String::new(),
            items: BTreeMap::new(),
            pinned_at: now,
        }
    }

    /// Whether a surface has actually been captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.manifest.is_empty()
    }

    /// Digest over exactly the named subset — the value a contract carries and
    /// the mediator compares at check 8 (§8.6.3).
    ///
    /// Order-independent: names are sorted before hashing, so the caller's
    /// ordering cannot change the digest. Every name must be present, or the
    /// requested surface is not a subset of the declared one.
    pub fn surface_digest(&self, names: &[String]) -> Result<String> {
        let mut sorted: Vec<&String> = names.iter().collect();
        sorted.sort_unstable();
        sorted.dedup();

        let mut hasher = Sha256::new();
        hasher.update(self.alg.as_bytes());
        hasher.update([0x00]);
        for name in sorted {
            let item = self.items.get(name).ok_or_else(|| {
                WcError::with_detail(
                    Code::SURFACE_NOT_SUBSET,
                    format!("{name:?} is not in the declared surface"),
                )
            })?;
            hasher.update(name.as_bytes());
            hasher.update([0x00]);
            hasher.update(item.as_bytes());
            hasher.update([0x0a]);
        }
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    /// Item names present in this pin but not in `other` (added), and in `other`
    /// but not here (removed), plus names whose hash moved (changed).
    #[must_use]
    pub fn diff(&self, other: &Pin) -> PinDiff {
        let added = other
            .items
            .keys()
            .filter(|k| !self.items.contains_key(*k))
            .cloned()
            .collect();
        let removed = self
            .items
            .keys()
            .filter(|k| !other.items.contains_key(*k))
            .cloned()
            .collect();
        let changed = self
            .items
            .iter()
            .filter(|(k, v)| other.items.get(*k).is_some_and(|o| o != *v))
            .map(|(k, _)| k.clone())
            .collect();
        PinDiff {
            added,
            removed,
            changed,
        }
    }
}

/// The structural difference between two pins, as consumed by drift
/// classification (§8.7.5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinDiff {
    /// Items present in the new pin only.
    pub added: Vec<String>,
    /// Items present in the old pin only.
    pub removed: Vec<String>,
    /// Items present in both, with a different hash.
    pub changed: Vec<String>,
}

impl PinDiff {
    /// Whether the two pins were identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// A build-provenance reference captured at admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvRef {
    /// `slsa-provenance` | `sigstore-bundle` | `rekor-entry` | `in-toto`.
    pub kind: String,
    /// The reference itself — a digest, bundle id or log index.
    pub reference: String,
}

// ---------------------------------------------------------------------------
// Entity
// ---------------------------------------------------------------------------

/// A registry entity: an agent, an MCP tool server, or an A2A agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    /// Wire identity.
    pub id: EntityId,
    /// What sort of party this is.
    pub kind: Kind,
    /// The accountable human. Required — invariant 1 is enforced by this type
    /// not being an `Option`.
    pub owner: HumanRef,
    /// Business service reference.
    #[serde(default)]
    pub service: Option<String>,
    /// Derived risk tier.
    pub tier: Tier,
    /// Trust zone.
    pub zone: ZoneId,
    /// Pinned surface.
    pub pin: Pin,
    /// Provenance references.
    #[serde(default)]
    pub provenance: Vec<ProvRef>,
    /// Continuous-assurance state.
    pub posture: Posture,
    /// Posture score, 0..=100 (§8.7.6).
    #[serde(default)]
    pub posture_score: u8,
    /// Operator-driven state.
    pub lifecycle: Lifecycle,
    /// Declared data classes.
    #[serde(default)]
    pub data_classes: Vec<String>,
    /// Declared jurisdictions.
    #[serde(default)]
    pub jurisdictions: Vec<String>,
    /// Endpoint, for servers. Never returned by discovery — reachability is
    /// granted by a contract, not by a lookup.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Re-attestation interval, seconds.
    pub reattest_every: u32,
    /// When the party last re-attested successfully.
    #[serde(default)]
    pub reattested_at: u64,
    /// Creation timestamp.
    pub created_at: u64,
    /// Last-update timestamp.
    pub updated_at: u64,
    /// Record schema version.
    #[serde(default = "default_schema")]
    pub schema: u16,
}

/// The entity record schema this build writes.
pub const ENTITY_SCHEMA: u16 = 1;

fn default_schema() -> u16 {
    ENTITY_SCHEMA
}

impl Entity {
    /// A freshly registered entity: `Pending` and `Unattested` until admission
    /// says otherwise. Registration is not connectivity (UC-01 postcondition).
    #[must_use]
    pub fn pending(
        id: EntityId,
        kind: Kind,
        owner: HumanRef,
        zone: ZoneId,
        tier: Tier,
        now: u64,
    ) -> Entity {
        Entity {
            id,
            kind,
            owner,
            service: None,
            tier,
            zone,
            pin: Pin::empty(now),
            provenance: Vec::new(),
            posture: Posture::Unattested,
            posture_score: 0,
            lifecycle: Lifecycle::Pending,
            data_classes: Vec::new(),
            jurisdictions: Vec::new(),
            endpoint: None,
            reattest_every: tier.reattest_interval_secs(),
            reattested_at: 0,
            created_at: now,
            updated_at: now,
            schema: ENTITY_SCHEMA,
        }
    }

    /// Whether this party may be one end of a new connection.
    ///
    /// Invariant 2: a contract can never reference a quarantined entity.
    pub fn assert_connectable(&self, mode: crate::error::Mode) -> Result<()> {
        if self.posture == Posture::Quarantined {
            return Err(WcError::with_detail(
                Code::ENTITY_QUARANTINED,
                format!("{} is quarantined", self.id),
            ));
        }
        if self.lifecycle != Lifecycle::Active {
            return Err(WcError::with_detail(
                Code::ILLEGAL_TRANSITION,
                format!("{} is {:?}, not active", self.id, self.lifecycle),
            ));
        }
        if !self.posture.may_connect(mode) {
            return Err(WcError::with_detail(
                Code::POSTURE_NOT_ATTESTED,
                format!("{} posture is {:?}", self.id, self.posture),
            ));
        }
        Ok(())
    }

    /// Apply a lifecycle transition, enforcing the §8.5.1 table.
    ///
    /// A quarantined entity cannot be transitioned at all: clearing quarantine
    /// is [`Entity::clear_quarantine`], which forces a full re-admission rather
    /// than a state flip.
    pub fn transition_to(&mut self, to: Lifecycle, now: u64) -> Result<()> {
        if self.posture == Posture::Quarantined {
            return Err(WcError::with_detail(
                Code::ENTITY_QUARANTINED,
                format!("{} is quarantined; re-admission is required", self.id),
            ));
        }
        if !self.lifecycle.can_transition_to(to) {
            return Err(WcError::with_detail(
                Code::ILLEGAL_TRANSITION,
                format!("{:?} -> {:?} is not a legal transition", self.lifecycle, to),
            ));
        }
        self.lifecycle = to;
        self.updated_at = now;
        Ok(())
    }

    /// Contain this party: posture becomes terminal and it is barred from every
    /// connection. Infallible on purpose — containment must never be refused
    /// because of the state the entity happened to be in.
    pub fn quarantine(&mut self, now: u64) {
        self.posture = Posture::Quarantined;
        self.posture_score = 0;
        self.lifecycle = Lifecycle::Suspended;
        self.updated_at = now;
    }

    /// Lift quarantine by returning the entity to `Pending`, which forces the
    /// full admission pipeline to run again (UC-07 A3).
    pub fn clear_quarantine(&mut self, now: u64) -> Result<()> {
        if self.posture != Posture::Quarantined {
            return Err(WcError::with_detail(
                Code::ILLEGAL_TRANSITION,
                format!("{} is not quarantined", self.id),
            ));
        }
        self.posture = Posture::Unattested;
        self.posture_score = 0;
        self.lifecycle = Lifecycle::Pending;
        self.updated_at = now;
        Ok(())
    }

    /// Record a new pin, returning the structural diff against the old one.
    pub fn repin(&mut self, pin: Pin, now: u64) -> Result<PinDiff> {
        if pin.alg != PIN_ALG {
            return Err(WcError::with_detail(
                Code::PIN_WRITE_FAILED,
                format!("unknown canonicalisation algorithm {:?}", pin.alg),
            ));
        }
        let diff = self.pin.diff(&pin);
        self.pin = pin;
        self.updated_at = now;
        Ok(diff)
    }

    /// Whether re-attestation is overdue as of `now`.
    #[must_use]
    pub fn reattest_overdue(&self, now: u64) -> bool {
        now.saturating_sub(self.reattested_at) > u64::from(self.reattest_every)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::error::Mode;

    fn zone(s: &str) -> ZoneId {
        ZoneId::new(s).unwrap()
    }

    fn entity() -> Entity {
        Entity::pending(
            EntityId::new("spiffe://org/ns/agents/sa/recon-bot-7").unwrap(),
            Kind::Agent,
            HumanRef::new("human:priya@org").unwrap(),
            zone("internal.apac-ops"),
            Tier::TWO,
            1_785_312_000,
        )
    }

    // --- identifiers ---

    #[test]
    fn entity_ids_require_a_known_scheme() {
        assert!(EntityId::new("spiffe://org/ns/tools/sa/payments-mcp").is_ok());
        assert!(EntityId::new("urn:wc:agent:recon-bot-7").is_ok());
        for bad in [
            "",
            "recon-bot-7",
            "https://example.com/agent",
            "spiffe://org/ns/a b",
        ] {
            assert!(EntityId::new(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn malformed_ids_carry_the_right_code() {
        let err = EntityId::new("nope").unwrap_err();
        assert_eq!(err.code(), Code::MALFORMED_IDENTIFIER);
    }

    #[test]
    fn cids_are_prefixed_hex() {
        assert!(Cid::new("conn_7f3a91c4").is_ok());
        for bad in ["conn_", "conn_7f3a", "7f3a91c4", "conn_zzzzzzzz"] {
            assert!(Cid::new(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn owners_must_be_human_refs() {
        assert!(HumanRef::new("human:cecil@org").is_ok());
        for bad in ["cecil@org", "human:", "service:ci"] {
            assert!(HumanRef::new(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn zones_name_a_trust_level_first() {
        assert_eq!(
            zone("internal.payments").trust_level(),
            TrustLevel::Internal
        );
        assert_eq!(zone("partner.acme").trust_level(), TrustLevel::Partner);
        assert_eq!(zone("public").trust_level(), TrustLevel::Public);
        for bad in [
            "",
            "prod.payments",
            "Internal.payments",
            "internal..x",
            "a.b.c.d.e",
        ] {
            assert!(ZoneId::new(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn ids_validate_on_deserialize() {
        // The serde path must not be a way around the constructor.
        let ok: std::result::Result<EntityId, _> =
            serde_json::from_str("\"spiffe://org/ns/agents/sa/a\"");
        assert!(ok.is_ok());

        let bad: std::result::Result<EntityId, _> = serde_json::from_str("\"not-an-id\"");
        assert!(bad.is_err());

        let bad_zone: std::result::Result<ZoneId, _> = serde_json::from_str("\"prod.payments\"");
        assert!(bad_zone.is_err());
    }

    #[test]
    fn ids_round_trip_through_json() {
        let id = EntityId::new("spiffe://org/ns/tools/sa/payments-mcp").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"spiffe://org/ns/tools/sa/payments-mcp\"");
        assert_eq!(serde_json::from_str::<EntityId>(&json).unwrap(), id);
    }

    // --- tier ---

    #[test]
    fn tiers_are_bounded_and_ordered() {
        assert!(Tier::new(0).is_err());
        assert!(Tier::new(5).is_err());
        assert!(Tier::ONE < Tier::THREE);
        assert!(Tier::ONE.is_at_least_as_sensitive_as(Tier::THREE));
        assert!(!Tier::THREE.is_at_least_as_sensitive_as(Tier::ONE));
    }

    #[test]
    fn tier_drives_approval_and_reattestation() {
        assert!(Tier::ONE.requires_dual_control());
        assert!(!Tier::TWO.requires_dual_control());
        assert!(Tier::TWO.requires_human_approval());
        assert!(!Tier::THREE.requires_human_approval());
        assert_eq!(Tier::ONE.reattest_interval_secs(), 3_600);
        assert_eq!(Tier::FOUR.reattest_interval_secs(), 604_800);
    }

    #[test]
    fn tier_rejects_out_of_range_on_deserialize() {
        assert!(serde_json::from_str::<Tier>("2").is_ok());
        assert!(serde_json::from_str::<Tier>("7").is_err());
    }

    // --- lifecycle ---

    #[test]
    fn lifecycle_table_matches_the_lld() {
        use Lifecycle::{Active, Pending, Retired, Suspended};
        let legal = [
            (Pending, Active),
            (Pending, Retired),
            (Active, Suspended),
            (Active, Retired),
            (Suspended, Active),
            (Suspended, Retired),
        ];
        for (from, to) in legal {
            assert!(
                from.can_transition_to(to),
                "{from:?} -> {to:?} must be legal"
            );
        }
        let illegal = [
            (Active, Pending),
            (Suspended, Pending),
            (Retired, Active),
            (Retired, Pending),
            (Retired, Suspended),
            (Active, Active),
            (Pending, Pending),
        ];
        for (from, to) in illegal {
            assert!(
                !from.can_transition_to(to),
                "{from:?} -> {to:?} must be illegal"
            );
        }
    }

    #[test]
    fn registration_grants_no_connectivity() {
        let e = entity();
        assert_eq!(e.lifecycle, Lifecycle::Pending);
        assert_eq!(e.posture, Posture::Unattested);
        assert!(e.assert_connectable(Mode::Enforce).is_err());
    }

    #[test]
    fn active_and_attested_is_connectable() {
        let mut e = entity();
        e.transition_to(Lifecycle::Active, 1).unwrap();
        e.posture = Posture::Attested;
        assert!(e.assert_connectable(Mode::Enforce).is_ok());
    }

    #[test]
    fn observe_mode_admits_unattested_but_never_quarantined() {
        let mut e = entity();
        e.transition_to(Lifecycle::Active, 1).unwrap();
        assert!(e.assert_connectable(Mode::Enforce).is_err());
        assert!(e.assert_connectable(Mode::Observe).is_ok());

        e.quarantine(2);
        assert!(e.assert_connectable(Mode::Observe).is_err());
        assert_eq!(
            e.assert_connectable(Mode::Observe).unwrap_err().code(),
            Code::ENTITY_QUARANTINED
        );
    }

    #[test]
    fn quarantine_is_terminal_until_re_admission() {
        let mut e = entity();
        e.transition_to(Lifecycle::Active, 1).unwrap();
        e.quarantine(2);

        // No state flip out of quarantine, in any direction.
        for to in [Lifecycle::Active, Lifecycle::Suspended, Lifecycle::Retired] {
            let err = e.transition_to(to, 3).unwrap_err();
            assert_eq!(err.code(), Code::ENTITY_QUARANTINED);
        }

        // Clearing it forces the full admission pipeline to run again.
        e.clear_quarantine(4).unwrap();
        assert_eq!(e.lifecycle, Lifecycle::Pending);
        assert_eq!(e.posture, Posture::Unattested);
        assert!(e.clear_quarantine(5).is_err());
    }

    #[test]
    fn entity_round_trips_through_json() {
        let mut e = entity();
        e.transition_to(Lifecycle::Active, 2).unwrap();
        e.posture = Posture::Attested;
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<Entity>(&json).unwrap(), e);
    }

    // --- pins ---

    fn pin_with(items: &[(&str, &str)]) -> Pin {
        Pin {
            alg: PIN_ALG.to_string(),
            manifest: "sha256:whole".to_string(),
            items: items
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            pinned_at: 1,
        }
    }

    #[test]
    fn surface_digest_is_order_independent() {
        let pin = pin_with(&[
            ("get_balance", "sha256:aa"),
            ("list_transactions", "sha256:bb"),
            ("wire_funds", "sha256:cc"),
        ]);
        let a = pin
            .surface_digest(&["get_balance".into(), "list_transactions".into()])
            .unwrap();
        let b = pin
            .surface_digest(&["list_transactions".into(), "get_balance".into()])
            .unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn surface_digest_ignores_uncontracted_items() {
        // The property the whole per-item pin design exists for: adding a tool
        // outside the contracted surface cannot move a contract's digest.
        let before = pin_with(&[("get_balance", "sha256:aa")]);
        let after = pin_with(&[("get_balance", "sha256:aa"), ("new_tool", "sha256:dd")]);
        let names = vec!["get_balance".to_string()];
        assert_eq!(
            before.surface_digest(&names).unwrap(),
            after.surface_digest(&names).unwrap()
        );
    }

    #[test]
    fn surface_digest_moves_when_a_contracted_item_changes() {
        let before = pin_with(&[("get_balance", "sha256:aa")]);
        let after = pin_with(&[("get_balance", "sha256:ff")]);
        let names = vec!["get_balance".to_string()];
        assert_ne!(
            before.surface_digest(&names).unwrap(),
            after.surface_digest(&names).unwrap()
        );
    }

    #[test]
    fn surface_digest_rejects_a_non_subset() {
        let pin = pin_with(&[("get_balance", "sha256:aa")]);
        let err = pin
            .surface_digest(&["get_balance".into(), "wire_funds".into()])
            .unwrap_err();
        assert_eq!(err.code(), Code::SURFACE_NOT_SUBSET);
    }

    #[test]
    fn duplicate_names_do_not_change_the_digest() {
        let pin = pin_with(&[("get_balance", "sha256:aa")]);
        let once = pin.surface_digest(&["get_balance".into()]).unwrap();
        let twice = pin
            .surface_digest(&["get_balance".into(), "get_balance".into()])
            .unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn pin_diff_classifies_structurally() {
        let old = pin_with(&[("a", "sha256:1"), ("b", "sha256:2"), ("c", "sha256:3")]);
        let new = pin_with(&[("b", "sha256:2"), ("c", "sha256:9"), ("d", "sha256:4")]);
        let diff = old.diff(&new);
        assert_eq!(diff.added, vec!["d".to_string()]);
        assert_eq!(diff.removed, vec!["a".to_string()]);
        assert_eq!(diff.changed, vec!["c".to_string()]);
        assert!(!diff.is_empty());
        assert!(old.diff(&old).is_empty());
    }

    #[test]
    fn repin_rejects_an_unknown_algorithm() {
        let mut e = entity();
        let mut pin = pin_with(&[("a", "sha256:1")]);
        pin.alg = "wcs2".to_string();
        assert_eq!(e.repin(pin, 5).unwrap_err().code(), Code::PIN_WRITE_FAILED);
    }

    #[test]
    fn reattest_overdue_uses_the_tier_interval() {
        let mut e = entity();
        e.reattested_at = 1_000;
        e.reattest_every = 3_600;
        assert!(!e.reattest_overdue(4_000));
        assert!(e.reattest_overdue(5_000));
    }
}
