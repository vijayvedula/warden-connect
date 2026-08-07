//! Cross-organisation federation: trust chains and partner resolution
//! (`docs/08-lld.md` §8.5, HLD §7.5 F5, UC-05).
//!
//! Two organisations each run a control plane. Neither exposes a catalogue,
//! neither holds the other's keys directly, and both need to end up believing the
//! same thing about one specific partner agent. The mechanism is an
//! OpenID-Federation-shaped trust chain: a sequence of signed **entity
//! statements** running from the leaf up to an anchor whose key was exchanged out
//! of band.
//!
//! # The property everything rests on
//!
//! **A leaf's self-signed statement is not evidence of its keys.** Anyone can
//! mint a self-signed statement claiming any subject and any key set — that is
//! what self-signed means. What makes the leaf's keys trustworthy is the
//! *superior's* subordinate statement about the leaf, signed with the superior's
//! key, which is in turn attested one level up, terminating at an anchor we
//! configured.
//!
//! So [`resolve`] verifies each statement with **the keys the next statement up
//! asserts**, never with the keys the statement asserts about itself. The leaf's
//! self-signature is checked too, but only as a proof-of-possession: it shows the
//! leaf holds the key its superior vouched for. Getting this backwards produces an
//! implementation that verifies every signature and trusts anything.
//!
//! # Three more rules that are easy to omit
//!
//! * **The chain must terminate at a configured anchor.** Verifying every link and
//!   never checking the root accepts any self-consistent chain an attacker builds.
//! * **`authority_hints` are never followed.** They name who *claims* to vouch for
//!   an entity; following them is a fetch-a-URL-of-the-attacker's-choosing
//!   primitive. Only configured anchors terminate a chain.
//! * **Superiors narrow, never widen.** A subordinate statement may restrict what
//!   its subject may do; it may not grant more than its own superior permitted.
//!   Same ceiling algebra as contracts and zone bars.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use wc_core::contract::{IssuerKeys, ACCEPTED_ALG_NAMES};
use wc_core::error::{Code, Result, WcError};
use wc_core::model::{TrustLevel, ZoneId};

/// The most statements a chain may contain, leaf to anchor.
///
/// Bounded because a chain arrives from a counterparty: an unbounded one is a
/// cheap way to make this control plane do unbounded signature verification.
pub const MAX_CHAIN_LEN: usize = 6;

/// Longest an entity statement may be trusted without re-verification.
pub const DEFAULT_ANCHOR_REVERIFY_SECS: u64 = 86_400;

// ---------------------------------------------------------------------------
// Entity statements
// ---------------------------------------------------------------------------

/// A federation entity statement, as carried in a signed JWT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityStatement {
    /// Who issued the statement. Equal to `sub` for a self-signed leaf.
    pub iss: String,
    /// Who the statement is about.
    pub sub: String,
    /// Issued at.
    #[serde(default)]
    pub iat: u64,
    /// Expiry. Required — a statement with no expiry never stops applying.
    pub exp: u64,
    /// The subject's key set, as `kid -> PEM`.
    ///
    /// PEM rather than JWK because the rest of this codebase speaks PEM and
    /// converting in one place beats converting in five.
    #[serde(default)]
    pub jwks: BTreeMap<String, String>,
    /// What the subject is permitted to be.
    #[serde(default)]
    pub metadata: FederationMetadata,
    /// Who the issuer claims vouches for it. **Recorded, never followed.**
    #[serde(default)]
    pub authority_hints: Vec<String>,
}

impl EntityStatement {
    /// Whether this is a self-signed leaf statement.
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.iss == self.sub
    }

    /// Whether the statement is valid at `now`.
    #[must_use]
    pub fn is_current(&self, now: u64, leeway: u64) -> bool {
        now.saturating_sub(leeway) < self.exp && self.iat.saturating_sub(leeway) <= now
    }

    /// The subject's keys as a verifier.
    pub fn keys(&self) -> Result<IssuerKeys> {
        let mut keys = IssuerKeys::new();
        for (kid, pem) in &self.jwks {
            let bytes = pem.as_bytes();
            // EC first, then Ed25519 — the two families this system mints with.
            if keys
                .add_ec_pem(kid, bytes, wc_core::contract::Algorithm::ES256)
                .is_err()
                && keys.add_ed_pem(kid, bytes).is_err()
            {
                return Err(WcError::with_detail(
                    Code::FEDERATION_CHAIN_INVALID,
                    format!("{}: key {kid:?} is not a usable public PEM", self.sub),
                ));
            }
        }
        Ok(keys)
    }
}

/// What a federated entity is permitted to be.
///
/// Deliberately small. Federation decides *whether these two organisations may be
/// introduced and on what terms*; the connection contract still decides every
/// tool, and local policy still applies its own bar on top.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationMetadata {
    /// Zone the subject's parties are placed in locally.
    #[serde(default)]
    pub zone: Option<String>,
    /// Capability tags the subject may advertise.
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    /// Jurisdictions the subject operates in.
    #[serde(default)]
    pub jurisdictions: BTreeSet<String>,
    /// Data classes the subject may receive.
    #[serde(default)]
    pub data_classes: BTreeSet<String>,
    /// Ceiling on contract lifetime, seconds.
    #[serde(default)]
    pub max_ttl_secs: Option<u64>,
    /// Ceiling on delegation depth. UC-05 pins this at 1 for partners.
    #[serde(default)]
    pub max_delegation_depth: Option<u8>,
}

impl FederationMetadata {
    /// Narrow this metadata by a superior's.
    ///
    /// Sets intersect, ceilings take the minimum, and a zone the superior did not
    /// name cannot be claimed. This is the ceiling algebra the whole system runs
    /// on, applied one level up: a subordinate may restrict itself further and may
    /// never grant itself more.
    #[must_use]
    pub fn narrowed_by(&self, superior: &FederationMetadata) -> FederationMetadata {
        FederationMetadata {
            zone: match (&self.zone, &superior.zone) {
                // The superior placed the subtree; a subordinate may only place
                // itself *inside* that placement.
                (Some(mine), Some(theirs)) => {
                    let (Ok(m), Ok(t)) = (ZoneId::new(mine), ZoneId::new(theirs)) else {
                        return FederationMetadata {
                            zone: Some(theirs.clone()),
                            ..self.intersect_rest(superior)
                        };
                    };
                    if wc_core::zone::contains(&t, &m) {
                        Some(mine.clone())
                    } else {
                        Some(theirs.clone())
                    }
                }
                (None, Some(theirs)) => Some(theirs.clone()),
                (Some(mine), None) => Some(mine.clone()),
                (None, None) => None,
            },
            ..self.intersect_rest(superior)
        }
    }

    fn intersect_rest(&self, superior: &FederationMetadata) -> FederationMetadata {
        fn narrow(mine: &BTreeSet<String>, theirs: &BTreeSet<String>) -> BTreeSet<String> {
            if theirs.is_empty() {
                // An unconstrained superior does not narrow. Treating "unset" as
                // "empty set" would make every chain resolve to nothing.
                mine.clone()
            } else {
                mine.intersection(theirs).cloned().collect()
            }
        }
        FederationMetadata {
            zone: None,
            capabilities: narrow(&self.capabilities, &superior.capabilities),
            jurisdictions: narrow(&self.jurisdictions, &superior.jurisdictions),
            data_classes: narrow(&self.data_classes, &superior.data_classes),
            max_ttl_secs: min_opt(self.max_ttl_secs, superior.max_ttl_secs),
            max_delegation_depth: min_opt(self.max_delegation_depth, superior.max_delegation_depth),
        }
    }

    /// Whether this metadata claims anything the superior did not permit.
    #[must_use]
    pub fn widens(&self, superior: &FederationMetadata) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for (name, mine, theirs) in [
            ("capabilities", &self.capabilities, &superior.capabilities),
            (
                "jurisdictions",
                &self.jurisdictions,
                &superior.jurisdictions,
            ),
            ("data_classes", &self.data_classes, &superior.data_classes),
        ] {
            if theirs.is_empty() {
                continue;
            }
            let extra: Vec<&String> = mine.difference(theirs).collect();
            if !extra.is_empty() {
                out.push(format!(
                    "{name}: {} not permitted by the superior",
                    extra
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        if let (Some(mine), Some(theirs)) = (self.max_ttl_secs, superior.max_ttl_secs) {
            if mine > theirs {
                out.push(format!(
                    "max_ttl_secs: {mine} exceeds the superior's {theirs}"
                ));
            }
        }
        if let (Some(mine), Some(theirs)) =
            (self.max_delegation_depth, superior.max_delegation_depth)
        {
            if mine > theirs {
                out.push(format!(
                    "max_delegation_depth: {mine} exceeds the superior's {theirs}"
                ));
            }
        }
        if let (Some(mine), Some(theirs)) = (&self.zone, &superior.zone) {
            if let (Ok(m), Ok(t)) = (ZoneId::new(mine), ZoneId::new(theirs)) {
                if !wc_core::zone::contains(&t, &m) {
                    out.push(format!("zone: {mine} is outside the superior's {theirs}"));
                }
            }
        }
        out
    }
}

fn min_opt<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

// ---------------------------------------------------------------------------
// Anchors
// ---------------------------------------------------------------------------

/// A trust anchor: an entity whose keys were exchanged out of band.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchor {
    /// The anchor's entity identifier.
    pub entity: String,
    /// Its keys, `kid -> PEM`.
    pub jwks: BTreeMap<String, String>,
    /// The ceiling this anchor imposes on everything beneath it.
    #[serde(default)]
    pub metadata: FederationMetadata,
    /// When the anchor was last confirmed out of band.
    #[serde(default)]
    pub verified_at: u64,
    /// How often it must be re-confirmed.
    #[serde(default = "default_reverify")]
    pub reverify_every: u64,
}

fn default_reverify() -> u64 {
    DEFAULT_ANCHOR_REVERIFY_SECS
}

impl TrustAnchor {
    /// Whether this anchor is overdue for re-verification (UC-05 A2).
    #[must_use]
    pub fn is_stale(&self, now: u64) -> bool {
        self.reverify_every > 0 && now.saturating_sub(self.verified_at) > self.reverify_every
    }

    /// The anchor's keys as a verifier.
    pub fn keys(&self) -> Result<IssuerKeys> {
        EntityStatement {
            iss: self.entity.clone(),
            sub: self.entity.clone(),
            iat: 0,
            exp: u64::MAX,
            jwks: self.jwks.clone(),
            metadata: FederationMetadata::default(),
            authority_hints: Vec::new(),
        }
        .keys()
    }
}

/// The anchors this control plane trusts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorSet {
    /// Configured anchors.
    #[serde(default, rename = "anchor")]
    pub anchors: Vec<TrustAnchor>,
}

impl AnchorSet {
    /// Parse from TOML.
    pub fn parse(text: &str) -> Result<AnchorSet> {
        let set: AnchorSet = toml::from_str(text).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, "anchor set is not valid TOML")
                .with_source(e)
        })?;
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for a in &set.anchors {
            if !seen.insert(a.entity.as_str()) {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("anchor {:?} is listed twice", a.entity),
                ));
            }
            if a.jwks.is_empty() {
                // An anchor with no keys cannot terminate anything, and silently
                // holding one means every chain through it fails for a reason
                // nobody can find.
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("anchor {:?} has no keys", a.entity),
                ));
            }
            a.keys()?;
        }
        Ok(set)
    }

    /// Read from disk.
    pub fn load(path: &std::path::Path) -> Result<AnchorSet> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("cannot read anchor set {}", path.display()),
            )
            .with_source(e)
        })?;
        AnchorSet::parse(&text)
    }

    /// Look one up.
    #[must_use]
    pub fn get(&self, entity: &str) -> Option<&TrustAnchor> {
        self.anchors.iter().find(|a| a.entity == entity)
    }

    /// Anchors overdue for re-verification.
    #[must_use]
    pub fn stale(&self, now: u64) -> Vec<&TrustAnchor> {
        self.anchors.iter().filter(|a| a.is_stale(now)).collect()
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// A verified federated entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The subject.
    pub subject: String,
    /// Its verified keys.
    pub jwks: BTreeMap<String, String>,
    /// Metadata after every superior narrowed it.
    pub metadata: FederationMetadata,
    /// The anchor the chain terminated at.
    pub anchor: String,
    /// Earliest expiry in the chain — the resolution is no fresher than its
    /// shortest-lived link.
    pub expires_at: u64,
    /// Statements traversed, leaf to anchor.
    pub chain_len: usize,
    /// Whether the anchor is overdue for out-of-band re-verification.
    ///
    /// Reported rather than fatal: UC-05 A2 says existing contracts run to `exp`
    /// while issuance stops, and that is the caller's decision to make.
    pub anchor_stale: bool,
}

impl Resolved {
    /// The zone this partner's parties belong in, defaulting to the partner
    /// trust level when the chain named none.
    #[must_use]
    pub fn zone(&self) -> ZoneId {
        self.metadata
            .zone
            .as_deref()
            .and_then(|z| ZoneId::new(z).ok())
            // An unplaced partner is still a partner. Falling back to something
            // internal would be the one mistake that matters here.
            .unwrap_or_else(|| {
                ZoneId::new("partner.unclassified").unwrap_or_else(|_| unreachable!())
            })
    }

    /// Whether a new contract may be issued against this resolution.
    #[must_use]
    pub fn may_issue(&self, now: u64) -> bool {
        !self.anchor_stale && now < self.expires_at
    }
}

/// Read a JOSE header without letting a library choose the algorithm.
fn header_of(jws: &str) -> Result<Map<String, Value>> {
    use base64::Engine as _;
    let segment = jws.split('.').next().unwrap_or_default();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| {
            WcError::with_detail(
                Code::FEDERATION_CHAIN_INVALID,
                "entity statement header is not base64url",
            )
            .with_source(e)
        })?;
    serde_json::from_slice(&bytes).map_err(|e| {
        WcError::with_detail(
            Code::FEDERATION_CHAIN_INVALID,
            "entity statement header is not JSON",
        )
        .with_source(e)
    })
}

/// Verify one statement against a key set, returning its claims.
fn verify_statement(jws: &str, keys: &IssuerKeys) -> Result<EntityStatement> {
    let header = header_of(jws)?;
    let alg = header.get("alg").and_then(Value::as_str).ok_or_else(|| {
        WcError::with_detail(
            Code::FEDERATION_CHAIN_INVALID,
            "entity statement header has no `alg`",
        )
    })?;
    if !ACCEPTED_ALG_NAMES.contains(&alg) {
        return Err(WcError::with_detail(
            Code::ALG_NOT_ASYMMETRIC,
            format!("entity statement uses {alg:?}"),
        ));
    }
    let kid = header.get("kid").and_then(Value::as_str).ok_or_else(|| {
        WcError::with_detail(
            Code::FEDERATION_CHAIN_INVALID,
            "entity statement has no `kid`; there is no way to choose a key",
        )
    })?;

    wc_core::contract::verify_detached::<EntityStatement>(jws, kid, keys).map_err(|e| {
        WcError::with_detail(
            Code::FEDERATION_CHAIN_INVALID,
            format!("entity statement does not verify under kid {kid:?}"),
        )
        .with_source(e)
    })
}

/// Resolve a trust chain to a verified entity.
///
/// `chain` runs **leaf first**: `[leaf self-signed, superior-about-leaf, …,
/// anchor-about-its-subordinate]`.
///
/// The leaf's self-signature proves possession of a key; it does not establish
/// which keys to trust. That comes from the next statement up, and so on, until a
/// statement is verified with an anchor's configured keys.
pub fn resolve(chain: &[String], anchors: &AnchorSet, now: u64, leeway: u64) -> Result<Resolved> {
    if chain.is_empty() {
        return Err(WcError::with_detail(
            Code::FEDERATION_CHAIN_INVALID,
            "an empty chain establishes nothing",
        ));
    }
    if chain.len() > MAX_CHAIN_LEN {
        return Err(WcError::with_detail(
            Code::FEDERATION_CHAIN_INVALID,
            format!(
                "chain is {} statements, limit is {MAX_CHAIN_LEN}",
                chain.len()
            ),
        ));
    }

    // --- 1 · the anchor end ------------------------------------------------
    //
    // Verified first, and from the configured side. Walking down from a trusted
    // root is the only order in which "does this terminate somewhere I trust" is
    // answered before any of the counterparty's claims are believed.
    let top = chain.last().unwrap_or_else(|| unreachable!());
    let top_header_iss = peek_iss(top)?;
    let anchor = anchors.get(&top_header_iss).ok_or_else(|| {
        WcError::with_detail(
            Code::FEDERATION_ANCHOR_UNKNOWN,
            format!(
                "chain terminates at {top_header_iss:?}, which is not a configured trust anchor"
            ),
        )
    })?;

    let mut verifier = anchor.keys()?;
    let mut ceiling = anchor.metadata.clone();
    let mut expires_at = u64::MAX;
    let mut expected_sub: Option<String> = None;

    // --- 2 · walk down from the anchor to the leaf -------------------------
    for (depth, jws) in chain.iter().enumerate().rev() {
        let statement = verify_statement(jws, &verifier)?;

        if !statement.is_current(now, leeway) {
            return Err(WcError::with_detail(
                Code::FEDERATION_STATEMENT_EXPIRED,
                format!(
                    "statement about {} expired at {} (now {now})",
                    statement.sub, statement.exp
                ),
            ));
        }
        // Each statement must be about the entity the one above it named, or the
        // chain is a set of unrelated valid statements stapled together.
        if let Some(expected) = &expected_sub {
            if &statement.iss != expected && &statement.sub != expected {
                return Err(WcError::with_detail(
                    Code::FEDERATION_CHAIN_INVALID,
                    format!(
                        "statement {depth} is about {} / issued by {}, but the level above named {expected}",
                        statement.sub, statement.iss
                    ),
                ));
            }
        }

        let widened = statement.metadata.widens(&ceiling);
        if !widened.is_empty() {
            return Err(WcError::with_detail(
                Code::FEDERATION_METADATA_WIDENED,
                format!("{}: {}", statement.sub, widened.join("; ")),
            ));
        }
        ceiling = statement.metadata.narrowed_by(&ceiling);
        expires_at = expires_at.min(statement.exp);

        if depth == 0 {
            // The leaf. Its self-signature was just verified with the keys its
            // superior asserted, which is the proof-of-possession that closes the
            // chain.
            if !statement.is_self_signed() {
                return Err(WcError::with_detail(
                    Code::FEDERATION_CHAIN_INVALID,
                    format!(
                        "leaf statement is issued by {} about {}; a leaf must be self-signed",
                        statement.iss, statement.sub
                    ),
                ));
            }
            return Ok(Resolved {
                subject: statement.sub.clone(),
                jwks: statement.jwks.clone(),
                metadata: ceiling,
                anchor: anchor.entity.clone(),
                expires_at,
                chain_len: chain.len(),
                anchor_stale: anchor.is_stale(now),
            });
        }

        // The next statement down must verify with the keys this one asserts.
        verifier = statement.keys()?;
        expected_sub = Some(statement.sub.clone());
    }

    Err(WcError::with_detail(
        Code::FEDERATION_CHAIN_INVALID,
        "chain did not reach a leaf",
    ))
}

/// The `iss` of a statement, read without verifying it.
///
/// Used only to *select* which configured anchor to verify against — never to
/// decide anything. Picking a key by an unverified claim is safe; believing the
/// claim is not.
fn peek_iss(jws: &str) -> Result<String> {
    use base64::Engine as _;
    let segment = jws.split('.').nth(1).unwrap_or_default();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| {
            WcError::with_detail(
                Code::FEDERATION_CHAIN_INVALID,
                "entity statement payload is not base64url",
            )
            .with_source(e)
        })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        WcError::with_detail(
            Code::FEDERATION_CHAIN_INVALID,
            "entity statement payload is not JSON",
        )
        .with_source(e)
    })?;
    value
        .get("iss")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            WcError::with_detail(Code::FEDERATION_CHAIN_INVALID, "statement has no `iss`")
        })
}

/// Terms a resolved partner implies, for the admission and policy layers.
///
/// Federation says *whether* and *on what ceiling*; it never says which tools.
/// That stays with the contract, and local policy still applies its own bar on
/// top — this is a third ceiling, not a replacement for either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartnerTerms {
    /// Zone to place the partner's parties in.
    pub zone: ZoneId,
    /// Ceiling on contract lifetime.
    pub max_ttl_secs: Option<u64>,
    /// Ceiling on delegation depth.
    pub max_delegation_depth: Option<u8>,
    /// Jurisdictions the partner declared.
    pub jurisdictions: Vec<String>,
    /// Data classes the partner may receive.
    pub data_classes: Vec<String>,
}

impl Resolved {
    /// The terms this resolution implies.
    #[must_use]
    pub fn partner_terms(&self) -> PartnerTerms {
        let zone = self.zone();
        PartnerTerms {
            // UC-05 pins partner delegation at 1. A chain may narrow further; it
            // may never raise it, whatever the metadata says.
            max_delegation_depth: Some(
                self.metadata
                    .max_delegation_depth
                    .map_or(1, |d| d.min(1))
                    .min(if zone.trust_level() == TrustLevel::Internal {
                        u8::MAX
                    } else {
                        1
                    }),
            ),
            zone,
            max_ttl_secs: self.metadata.max_ttl_secs,
            jurisdictions: self.metadata.jurisdictions.iter().cloned().collect(),
            data_classes: self.metadata.data_classes.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use wc_core::contract::{Algorithm, IssuerKey};

    const NOW: u64 = 1_800_000_000;

    fn keys_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/keys")
    }

    fn priv_pem() -> Vec<u8> {
        std::fs::read(keys_dir().join("test_issuer_es256_priv.pem")).unwrap()
    }

    fn pub_pem() -> String {
        std::fs::read_to_string(keys_dir().join("test_issuer_es256_pub.pem")).unwrap()
    }

    fn other_priv_pem() -> Vec<u8> {
        std::fs::read(keys_dir().join("test_anchor_priv.pem")).unwrap()
    }

    fn other_pub_pem() -> String {
        std::fs::read_to_string(keys_dir().join("test_anchor_pub.pem")).unwrap()
    }

    fn jwks(kid: &str, pem: &str) -> BTreeMap<String, String> {
        [(kid.to_string(), pem.to_string())].into_iter().collect()
    }

    fn sign(statement: &EntityStatement, kid: &str, pem: &[u8]) -> String {
        let key = IssuerKey::ec_pem(kid, pem, Algorithm::ES256).unwrap();
        wc_core::contract::sign_detached(statement, &key).unwrap()
    }

    fn meta(caps: &[&str], ttl: Option<u64>, depth: Option<u8>) -> FederationMetadata {
        FederationMetadata {
            zone: Some("partner.acme".to_string()),
            capabilities: caps.iter().map(|c| (*c).to_string()).collect(),
            jurisdictions: ["SG".to_string(), "AU".to_string()].into_iter().collect(),
            data_classes: ["financial".to_string()].into_iter().collect(),
            max_ttl_secs: ttl,
            max_delegation_depth: depth,
        }
    }

    fn anchors() -> AnchorSet {
        AnchorSet {
            anchors: vec![TrustAnchor {
                entity: "https://acme.example/federation".to_string(),
                jwks: jwks("acme-root", &other_pub_pem()),
                metadata: meta(&["settlement", "fx"], Some(7 * 86_400), Some(2)),
                verified_at: NOW - 100,
                reverify_every: DEFAULT_ANCHOR_REVERIFY_SECS,
            }],
        }
    }

    /// A two-link chain: anchor vouches for the leaf, leaf self-signs.
    fn chain(leaf_meta: FederationMetadata, leaf_exp: u64) -> Vec<String> {
        let leaf_sub = "https://acme.example/agents/settlement";

        // The anchor's subordinate statement about the leaf, carrying the leaf's
        // *real* keys. This is what makes the leaf's keys trustworthy.
        let subordinate = EntityStatement {
            iss: "https://acme.example/federation".to_string(),
            sub: leaf_sub.to_string(),
            iat: NOW - 1_000,
            exp: NOW + 86_400,
            jwks: jwks("acme-leaf", &pub_pem()),
            metadata: meta(&["settlement"], Some(3 * 86_400), Some(1)),
            authority_hints: vec![],
        };
        // The leaf's self-signed statement, signed with the key above.
        let leaf = EntityStatement {
            iss: leaf_sub.to_string(),
            sub: leaf_sub.to_string(),
            iat: NOW - 1_000,
            exp: leaf_exp,
            jwks: jwks("acme-leaf", &pub_pem()),
            metadata: leaf_meta,
            authority_hints: vec!["https://acme.example/federation".to_string()],
        };
        vec![
            sign(&leaf, "acme-leaf", &priv_pem()),
            sign(&subordinate, "acme-root", &other_priv_pem()),
        ]
    }

    // --- the happy path ----------------------------------------------------

    #[test]
    fn a_well_formed_chain_resolves_to_the_leaf() {
        let r = resolve(
            &chain(meta(&["settlement"], Some(86_400), Some(1)), NOW + 3_600),
            &anchors(),
            NOW,
            60,
        )
        .expect("resolves");

        assert_eq!(r.subject, "https://acme.example/agents/settlement");
        assert_eq!(r.anchor, "https://acme.example/federation");
        assert_eq!(r.chain_len, 2);
        assert!(!r.anchor_stale);
        assert!(r.may_issue(NOW));
        // No fresher than its shortest-lived link.
        assert_eq!(r.expires_at, NOW + 3_600);
        assert_eq!(r.jwks.len(), 1);
    }

    #[test]
    fn ceilings_narrow_down_the_chain() {
        // Anchor 7d/depth2, subordinate 3d/depth1, leaf 1d — the leaf wins because
        // it is the narrowest, and could not have widened past its superiors.
        let r = resolve(
            &chain(meta(&["settlement"], Some(86_400), Some(1)), NOW + 86_400),
            &anchors(),
            NOW,
            60,
        )
        .unwrap();
        assert_eq!(r.metadata.max_ttl_secs, Some(86_400));
        assert_eq!(r.metadata.max_delegation_depth, Some(1));
        // `fx` was permitted by the anchor but not by the subordinate.
        assert_eq!(
            r.metadata.capabilities.iter().cloned().collect::<Vec<_>>(),
            vec!["settlement"]
        );
    }

    // --- the property everything rests on ----------------------------------

    #[test]
    fn a_self_signed_leaf_alone_establishes_nothing() {
        // The whole point. Anyone can mint a self-signed statement claiming any
        // subject and any keys — that is what self-signed means.
        let leaf = EntityStatement {
            iss: "https://evil.example/agent".to_string(),
            sub: "https://evil.example/agent".to_string(),
            iat: NOW - 10,
            exp: NOW + 86_400,
            jwks: jwks("evil-1", &pub_pem()),
            metadata: meta(&["settlement"], None, None),
            authority_hints: vec!["https://acme.example/federation".to_string()],
        };
        let err = resolve(&[sign(&leaf, "evil-1", &priv_pem())], &anchors(), NOW, 60).unwrap_err();
        assert_eq!(err.code(), Code::FEDERATION_ANCHOR_UNKNOWN);
        assert!(err.to_string().contains("not a configured trust anchor"));
    }

    #[test]
    fn authority_hints_are_recorded_and_never_followed() {
        // Following them is a fetch-a-URL-of-the-attacker's-choosing primitive.
        // The hint above names a real anchor and still does not help.
        let leaf = EntityStatement {
            iss: "https://evil.example/agent".to_string(),
            sub: "https://evil.example/agent".to_string(),
            iat: NOW - 10,
            exp: NOW + 86_400,
            jwks: jwks("evil-1", &pub_pem()),
            metadata: FederationMetadata::default(),
            authority_hints: vec!["https://acme.example/federation".to_string()],
        };
        assert!(resolve(&[sign(&leaf, "evil-1", &priv_pem())], &anchors(), NOW, 60).is_err());
    }

    #[test]
    fn a_chain_signed_entirely_by_the_attacker_does_not_terminate() {
        // Self-consistent and internally valid at every link. It fails because it
        // ends nowhere we configured — verifying links without checking the root
        // is the classic hole.
        let root = EntityStatement {
            iss: "https://evil.example/federation".to_string(),
            sub: "https://evil.example/agent".to_string(),
            iat: NOW - 10,
            exp: NOW + 86_400,
            jwks: jwks("evil-1", &pub_pem()),
            metadata: FederationMetadata::default(),
            authority_hints: vec![],
        };
        let leaf = EntityStatement {
            iss: "https://evil.example/agent".to_string(),
            sub: "https://evil.example/agent".to_string(),
            iat: NOW - 10,
            exp: NOW + 86_400,
            jwks: jwks("evil-1", &pub_pem()),
            metadata: FederationMetadata::default(),
            authority_hints: vec![],
        };
        let err = resolve(
            &[
                sign(&leaf, "evil-1", &priv_pem()),
                sign(&root, "evil-1", &priv_pem()),
            ],
            &anchors(),
            NOW,
            60,
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::FEDERATION_ANCHOR_UNKNOWN);
    }

    #[test]
    fn a_leaf_whose_keys_the_superior_did_not_vouch_for_is_refused() {
        // The subordinate statement says the leaf's key is `acme-leaf`, so a leaf
        // self-signed with anything else cannot verify.
        let leaf_sub = "https://acme.example/agents/settlement";
        let subordinate = EntityStatement {
            iss: "https://acme.example/federation".to_string(),
            sub: leaf_sub.to_string(),
            iat: NOW - 1_000,
            exp: NOW + 86_400,
            jwks: jwks("acme-leaf", &pub_pem()),
            metadata: meta(&["settlement"], None, Some(1)),
            authority_hints: vec![],
        };
        let leaf = EntityStatement {
            iss: leaf_sub.to_string(),
            sub: leaf_sub.to_string(),
            iat: NOW - 1_000,
            exp: NOW + 86_400,
            // The leaf claims a different key and signs with it.
            jwks: jwks("acme-leaf", &other_pub_pem()),
            metadata: meta(&["settlement"], None, Some(1)),
            authority_hints: vec![],
        };
        let err = resolve(
            &[
                sign(&leaf, "acme-leaf", &other_priv_pem()),
                sign(&subordinate, "acme-root", &other_priv_pem()),
            ],
            &anchors(),
            NOW,
            60,
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::FEDERATION_CHAIN_INVALID);
        assert!(err.to_string().contains("does not verify"));
    }

    #[test]
    fn a_non_self_signed_leaf_is_refused() {
        let leaf_sub = "https://acme.example/agents/settlement";
        let subordinate = EntityStatement {
            iss: "https://acme.example/federation".to_string(),
            sub: leaf_sub.to_string(),
            iat: NOW - 1_000,
            exp: NOW + 86_400,
            jwks: jwks("acme-leaf", &pub_pem()),
            metadata: meta(&["settlement"], None, Some(1)),
            authority_hints: vec![],
        };
        let not_a_leaf = EntityStatement {
            iss: leaf_sub.to_string(),
            sub: "https://acme.example/agents/someone-else".to_string(),
            iat: NOW - 1_000,
            exp: NOW + 86_400,
            jwks: jwks("acme-leaf", &pub_pem()),
            metadata: meta(&["settlement"], None, Some(1)),
            authority_hints: vec![],
        };
        let err = resolve(
            &[
                sign(&not_a_leaf, "acme-leaf", &priv_pem()),
                sign(&subordinate, "acme-root", &other_priv_pem()),
            ],
            &anchors(),
            NOW,
            60,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be self-signed"), "{err}");
    }

    // --- narrowing ---------------------------------------------------------

    #[test]
    fn a_subordinate_that_widens_its_superior_is_refused() {
        // The ceiling algebra, one level up. A leaf claiming a longer TTL than its
        // superior permitted is not narrowed silently — it is refused, because
        // silently narrowing would hide a counterparty trying it on.
        let err = resolve(
            &chain(
                meta(&["settlement"], Some(30 * 86_400), Some(1)),
                NOW + 86_400,
            ),
            &anchors(),
            NOW,
            60,
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::FEDERATION_METADATA_WIDENED);
        assert!(err.to_string().contains("max_ttl_secs"), "{err}");
    }

    #[test]
    fn a_leaf_claiming_an_unvouched_capability_is_refused() {
        let err = resolve(
            &chain(
                meta(&["settlement", "wire_transfer"], Some(86_400), Some(1)),
                NOW + 86_400,
            ),
            &anchors(),
            NOW,
            60,
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::FEDERATION_METADATA_WIDENED);
        assert!(err.to_string().contains("wire_transfer"), "{err}");
    }

    #[test]
    fn a_leaf_claiming_a_zone_outside_its_superiors_is_refused() {
        let mut m = meta(&["settlement"], Some(86_400), Some(1));
        m.zone = Some("internal.payments".to_string());
        let err = resolve(&chain(m, NOW + 86_400), &anchors(), NOW, 60).unwrap_err();
        assert_eq!(err.code(), Code::FEDERATION_METADATA_WIDENED);
        assert!(err.to_string().contains("outside the superior"), "{err}");
    }

    #[test]
    fn an_unconstrained_superior_does_not_narrow_to_nothing() {
        // Treating "unset" as "the empty set" would make every chain resolve to a
        // partner permitted to do nothing, which reads as a working federation.
        let open = FederationMetadata::default();
        let mine = meta(&["settlement"], Some(3_600), Some(1));
        let narrowed = mine.narrowed_by(&open);
        assert_eq!(narrowed.capabilities.len(), 1);
        assert_eq!(narrowed.jurisdictions.len(), 2);
        assert!(mine.widens(&open).is_empty());
    }

    // --- expiry and staleness ---------------------------------------------

    #[test]
    fn an_expired_statement_anywhere_in_the_chain_refuses_it() {
        let err = resolve(
            &chain(meta(&["settlement"], Some(86_400), Some(1)), NOW - 1),
            &anchors(),
            NOW,
            0,
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::FEDERATION_STATEMENT_EXPIRED);
    }

    #[test]
    fn a_stale_anchor_still_resolves_but_stops_issuance() {
        // UC-05 A2: existing contracts run to exp, no new ones are issued. That is
        // a degrade, not a refusal, and the distinction is the caller's to act on.
        let mut set = anchors();
        set.anchors[0].verified_at = NOW - 10 * 86_400;
        let r = resolve(
            &chain(meta(&["settlement"], Some(86_400), Some(1)), NOW + 86_400),
            &set,
            NOW,
            60,
        )
        .expect("still resolves");
        assert!(r.anchor_stale);
        assert!(!r.may_issue(NOW), "issuance stops");
        assert_eq!(set.stale(NOW).len(), 1);
    }

    #[test]
    fn a_chain_longer_than_the_bound_is_refused_before_any_verification() {
        // An unbounded chain from a counterparty is cheap unbounded work for us.
        let long: Vec<String> = (0..MAX_CHAIN_LEN + 1)
            .map(|_| "a.b.c".to_string())
            .collect();
        let err = resolve(&long, &anchors(), NOW, 60).unwrap_err();
        assert_eq!(err.code(), Code::FEDERATION_CHAIN_INVALID);
        assert!(err.to_string().contains("limit is"));
    }

    #[test]
    fn an_empty_chain_establishes_nothing() {
        assert_eq!(
            resolve(&[], &anchors(), NOW, 60).unwrap_err().code(),
            Code::FEDERATION_CHAIN_INVALID
        );
    }

    // --- anchors -----------------------------------------------------------

    #[test]
    fn an_anchor_set_parses_and_rejects_the_useless_shapes() {
        let text = format!(
            r#"
            [[anchor]]
            entity = "https://acme.example/federation"
            verified_at = 1000
            jwks = {{ "acme-root" = """{}""" }}
            "#,
            other_pub_pem()
        );
        let set = AnchorSet::parse(&text).unwrap();
        assert_eq!(set.anchors.len(), 1);
        assert_eq!(set.anchors[0].reverify_every, DEFAULT_ANCHOR_REVERIFY_SECS);

        // An anchor with no keys terminates nothing, and holding one silently
        // means every chain through it fails for a reason nobody can find.
        let err = AnchorSet::parse(
            r#"
            [[anchor]]
            entity = "https://acme.example/federation"
            jwks = {}
            "#,
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(err.to_string().contains("no keys"));
    }

    #[test]
    fn a_duplicate_anchor_is_refused() {
        let text = format!(
            r#"
            [[anchor]]
            entity = "https://acme.example/federation"
            jwks = {{ "a" = """{pem}""" }}
            [[anchor]]
            entity = "https://acme.example/federation"
            jwks = {{ "b" = """{pem}""" }}
            "#,
            pem = other_pub_pem()
        );
        assert_eq!(
            AnchorSet::parse(&text).unwrap_err().code(),
            Code::CONFIG_INVALID
        );
    }

    #[test]
    fn an_anchor_with_an_unusable_key_is_refused_at_load() {
        let err = AnchorSet::parse(
            r#"
            [[anchor]]
            entity = "https://acme.example/federation"
            jwks = { "a" = "not a pem" }
            "#,
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::FEDERATION_CHAIN_INVALID);
    }

    // --- partner terms -----------------------------------------------------

    #[test]
    fn partner_terms_pin_delegation_at_one_whatever_the_metadata_says() {
        // UC-05 step 5: a partner agent may not sub-delegate onward. A chain may
        // narrow further; it may never raise this.
        // Every level of the chain permits 5, so nothing is being narrowed by the
        // federation algebra — the pin has to come from `partner_terms` itself.
        let mut set = anchors();
        set.anchors[0].metadata.max_delegation_depth = Some(5);

        let leaf_sub = "https://acme.example/agents/settlement";
        let permissive = meta(&["settlement"], Some(86_400), Some(5));
        let subordinate = EntityStatement {
            iss: "https://acme.example/federation".to_string(),
            sub: leaf_sub.to_string(),
            iat: NOW - 1_000,
            exp: NOW + 86_400,
            jwks: jwks("acme-leaf", &pub_pem()),
            metadata: permissive.clone(),
            authority_hints: vec![],
        };
        let leaf = EntityStatement {
            iss: leaf_sub.to_string(),
            sub: leaf_sub.to_string(),
            iat: NOW - 1_000,
            exp: NOW + 86_400,
            jwks: jwks("acme-leaf", &pub_pem()),
            metadata: permissive,
            authority_hints: vec![],
        };
        let chain = vec![
            sign(&leaf, "acme-leaf", &priv_pem()),
            sign(&subordinate, "acme-root", &other_priv_pem()),
        ];

        let r = resolve(&chain, &set, NOW, 60).unwrap();
        assert_eq!(
            r.metadata.max_delegation_depth,
            Some(5),
            "the chain itself permits 5"
        );
        let terms = r.partner_terms();
        assert_eq!(terms.max_delegation_depth, Some(1));
        assert_eq!(terms.zone.as_str(), "partner.acme");
        assert_eq!(terms.zone.trust_level(), TrustLevel::Partner);
    }

    #[test]
    fn an_unplaced_partner_lands_in_a_partner_zone_not_an_internal_one() {
        // The one mistake that would matter here.
        let r = Resolved {
            subject: "x".to_string(),
            jwks: BTreeMap::new(),
            metadata: FederationMetadata::default(),
            anchor: "a".to_string(),
            expires_at: NOW + 1,
            chain_len: 2,
            anchor_stale: false,
        };
        assert_eq!(r.zone().trust_level(), TrustLevel::Partner);
        assert_eq!(r.zone().as_str(), "partner.unclassified");
    }
}
