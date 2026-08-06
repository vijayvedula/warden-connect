//! CAEP ingest: acting on signals from other people's systems
//! (`docs/08-lld.md` §8.9.4, UC-05 A1, RFC 8417).
//!
//! Emission is easy — `to_caep` projects a lifecycle event onto a shared-signals
//! stream and something downstream decides what to do. **Ingest is the dangerous
//! direction**, because it is a remote-triggered containment path: a receiver that
//! acts on a Security Event Token it did not verify has published an
//! unauthenticated API for degrading its own estate.
//!
//! # The property that bounds the damage
//!
//! **What a transmitter may cause is bounded by what it has authority over.**
//!
//! A verified signature says *who sent this*, not *that they were entitled to say
//! it*. An identity provider may revoke sessions for the humans in its own
//! directory; it may not revoke a partner's connection. A federated partner may
//! cut a connection they are a party to; they may not degrade a party they have
//! never met. So every accepted token is matched against a [`Transmitter`] whose
//! authority is declared locally, and an event outside that authority is refused
//! even though the signature is perfect.
//!
//! # Ingest degrades; it does not quarantine
//!
//! Nothing arriving over this path can quarantine the estate. That is the same
//! rule the posture score follows and for the same reason: an external input that
//! can cut connections is a denial-of-service primitive handed to whoever can
//! reach the endpoint. The strongest outcome an ingested signal produces is
//! [`Effect::RevokeConnection`] for a connection the transmitter is a party to,
//! and otherwise a degradation a human can see and reverse.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use wc_core::contract::IssuerKeys;
use wc_core::error::{Code, Result, WcError};

/// CAEP `session-revoked`.
pub const SESSION_REVOKED: &str =
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
/// CAEP `credential-change`.
pub const CREDENTIAL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/credential-change";
/// CAEP `assurance-level-change`.
pub const ASSURANCE_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
/// warden-connect's own subject type, for a partner cutting a shared connection.
pub const CONNECTION_REVOKED: &str = "https://warden.dev/secevent/connect/connection-revoked";

/// Every event type this receiver acts on.
///
/// Kept beside the `match` in [`ingest`] so an event cannot be understood by one
/// and not the other — a URI in this list with no arm produces no effect and no
/// diagnostic, which is the worst of both.
pub const UNDERSTOOD: &[&str] = &[
    SESSION_REVOKED,
    CREDENTIAL_CHANGE,
    ASSURANCE_CHANGE,
    CONNECTION_REVOKED,
];

/// How stale a token may be and still be acted on.
///
/// A containment signal that arrives an hour late is still worth acting on; one
/// that arrives a week late is replay or a broken pipeline, and acting on it
/// re-degrades a party somebody has since remediated.
pub const DEFAULT_MAX_AGE_SECS: u64 = 3_600;

// ---------------------------------------------------------------------------
// Transmitters
// ---------------------------------------------------------------------------

/// What a transmitter is permitted to say something about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    /// May speak about the humans in its directory: owners and approvers.
    ///
    /// An identity provider. It can tell us an owner left; it cannot tell us
    /// anything about a tool server.
    Directory,
    /// May speak about connections it is itself a party to.
    ///
    /// A federated partner. Scoped further by [`Transmitter::parties`], because a
    /// partner may cut *their* connections and not somebody else's.
    Partner,
    /// May speak about parties in this estate.
    ///
    /// A sibling control plane in the same organisation — a different tenant's, or
    /// a different region's.
    Estate,
}

impl Authority {
    /// Event types this authority may assert.
    #[must_use]
    pub fn permits(self, event_uri: &str) -> bool {
        match self {
            // A directory knows about credentials and sessions, not connections.
            Authority::Directory => {
                matches!(event_uri, SESSION_REVOKED | CREDENTIAL_CHANGE | ASSURANCE_CHANGE)
            }
            // A partner may cut a shared connection, and nothing else. In
            // particular not `credential-change`, which would let a counterparty
            // degrade our attestation posture.
            Authority::Partner => event_uri == CONNECTION_REVOKED,
            Authority::Estate => matches!(
                event_uri,
                SESSION_REVOKED | CREDENTIAL_CHANGE | ASSURANCE_CHANGE | CONNECTION_REVOKED
            ),
        }
    }
}

/// A stream this control plane accepts signals from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transmitter {
    /// The `iss` its tokens carry.
    pub issuer: String,
    /// Verification keys, `kid -> PEM`.
    pub jwks: BTreeMap<String, String>,
    /// What it may speak about.
    pub authority: Authority,
    /// The `aud` its tokens must carry — this receiver's own identifier.
    ///
    /// Required, because a token minted for somebody else's stream must not be
    /// replayable into ours.
    pub audience: String,
    /// Subjects this transmitter may name. Empty means any subject its authority
    /// covers.
    ///
    /// For a partner this is the list of parties they are; without it, `Partner`
    /// authority would let any onboarded partner cut any connection.
    #[serde(default)]
    pub parties: BTreeSet<String>,
    /// How stale a token from this stream may be.
    #[serde(default = "default_max_age")]
    pub max_age_secs: u64,
}

fn default_max_age() -> u64 {
    DEFAULT_MAX_AGE_SECS
}

impl Transmitter {
    /// The verifier for this stream.
    pub fn keys(&self) -> Result<IssuerKeys> {
        let mut keys = IssuerKeys::new();
        for (kid, pem) in &self.jwks {
            let bytes = pem.as_bytes();
            if keys
                .add_ec_pem(kid, bytes, wc_core::contract::Algorithm::ES256)
                .is_err()
                && keys.add_ed_pem(kid, bytes).is_err()
            {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("transmitter {}: key {kid:?} is not a usable public PEM", self.issuer),
                ));
            }
        }
        Ok(keys)
    }

    /// Whether this transmitter may name a subject.
    #[must_use]
    pub fn may_name(&self, subject: &str) -> bool {
        // An empty list means "anything its authority covers"; for a partner that
        // is deliberately checked at load, because an unscoped Partner would be
        // able to cut any connection in the estate.
        self.parties.is_empty() || self.parties.iter().any(|p| p == subject)
    }
}

/// The streams this control plane accepts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransmitterSet {
    /// Configured streams.
    #[serde(default, rename = "transmitter")]
    pub transmitters: Vec<Transmitter>,
}

impl TransmitterSet {
    /// Parse from TOML.
    pub fn parse(text: &str) -> Result<TransmitterSet> {
        let set: TransmitterSet = toml::from_str(text).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, "transmitter set is not valid TOML")
                .with_source(e)
        })?;
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for t in &set.transmitters {
            if !seen.insert(t.issuer.as_str()) {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("transmitter {:?} is listed twice", t.issuer),
                ));
            }
            if t.jwks.is_empty() {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("transmitter {:?} has no keys, so nothing from it could verify", t.issuer),
                ));
            }
            if t.audience.trim().is_empty() {
                // Without an audience, a token minted for somebody else's stream
                // replays into ours.
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("transmitter {:?} must declare the audience its tokens carry", t.issuer),
                ));
            }
            if t.authority == Authority::Partner && t.parties.is_empty() {
                // The check that keeps `Partner` from meaning "any connection".
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!(
                        "transmitter {:?} has partner authority and names no parties; it could \
                         then cut any connection in the estate",
                        t.issuer
                    ),
                ));
            }
            t.keys()?;
        }
        Ok(set)
    }

    /// Read from disk.
    pub fn load(path: &std::path::Path) -> Result<TransmitterSet> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("cannot read transmitter set {}", path.display()),
            )
            .with_source(e)
        })?;
        TransmitterSet::parse(&text)
    }

    /// Look one up by issuer.
    #[must_use]
    pub fn get(&self, issuer: &str) -> Option<&Transmitter> {
        self.transmitters.iter().find(|t| t.issuer == issuer)
    }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// A Security Event Token's claims, as far as this receiver reads them.
#[derive(Debug, Clone, Deserialize)]
pub struct SetClaims {
    /// Transmitter.
    pub iss: String,
    /// Unique token id, for replay rejection.
    pub jti: String,
    /// Issued at.
    pub iat: u64,
    /// Audience.
    #[serde(default)]
    pub aud: Value,
    /// The subject.
    #[serde(default)]
    pub sub_id: Value,
    /// Event map: URI to payload.
    #[serde(default)]
    pub events: BTreeMap<String, Value>,
}

impl SetClaims {
    /// The subject URI, from `sub_id`.
    #[must_use]
    pub fn subject(&self) -> Option<String> {
        self.sub_id
            .get("uri")
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

/// Seen token ids, for replay rejection.
///
/// Bounded and FIFO: an unbounded set is a memory-growth primitive for anyone who
/// can send us tokens. Eviction is by insertion order rather than by time, because
/// the freshness window already bounds how old an acceptable token is — a `jti`
/// older than that window is refused on age whether or not it is still remembered.
#[derive(Debug, Clone)]
pub struct SeenTokens {
    order: VecDeque<String>,
    set: BTreeSet<String>,
    capacity: usize,
}

impl Default for SeenTokens {
    fn default() -> Self {
        SeenTokens::new(10_000)
    }
}

impl SeenTokens {
    /// A store holding at most `capacity` ids.
    #[must_use]
    pub fn new(capacity: usize) -> SeenTokens {
        SeenTokens {
            order: VecDeque::new(),
            set: BTreeSet::new(),
            capacity: capacity.max(1),
        }
    }

    /// Record a token id. `false` means it was seen before.
    pub fn accept(&mut self, jti: &str) -> bool {
        if self.set.contains(jti) {
            return false;
        }
        if self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.order.push_back(jti.to_string());
        self.set.insert(jti.to_string());
        true
    }

    /// How many ids are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether nothing is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Effects
// ---------------------------------------------------------------------------

/// What an accepted signal asks this control plane to do.
///
/// Note what is absent: nothing here quarantines. An external input that can cut
/// the estate is a denial-of-service primitive handed to whoever can reach the
/// endpoint, so the strongest outcome is revoking one connection the transmitter
/// is itself a party to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// A human's sessions were revoked; parties they own lose their owner.
    ///
    /// Degrades posture and blocks renewal. Existing contracts run to `exp`,
    /// because an IdP telling us somebody left is not a reason to cut production.
    OwnerOrphaned {
        /// The human.
        owner: String,
    },
    /// A credential changed; the party must re-attest before its next renewal.
    ReattestRequired {
        /// The party.
        party: String,
        /// Why, from the event payload.
        reason: String,
    },
    /// An assurance level moved; rescore posture.
    RescorePosture {
        /// The party.
        party: String,
        /// The level the transmitter asserted.
        level: String,
    },
    /// A partner cut a connection they are a party to.
    RevokeConnection {
        /// The connection.
        cid: String,
        /// Who asked.
        by: String,
    },
}

impl Effect {
    /// A label for the evidence record.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Effect::OwnerOrphaned { .. } => "owner-orphaned",
            Effect::ReattestRequired { .. } => "reattest-required",
            Effect::RescorePosture { .. } => "rescore-posture",
            Effect::RevokeConnection { .. } => "revoke-connection",
        }
    }
}

/// The outcome of ingesting one token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingested {
    /// Which transmitter.
    pub issuer: String,
    /// Token id.
    pub jti: String,
    /// The subject named.
    pub subject: String,
    /// What to do.
    pub effects: Vec<Effect>,
    /// Event URIs present but not acted on, with the reason.
    ///
    /// Reported rather than ignored: a stream sending events we silently drop is a
    /// partner who believes they have told us something.
    pub unhandled: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

/// Verify a Security Event Token and translate it into effects.
///
/// Order matters and is the point:
///
/// 1. the issuer must be a configured transmitter — an unknown `iss` never reaches
///    a signature check, so an attacker cannot make us verify against a key of
///    their choosing;
/// 2. the signature must verify against **that** transmitter's keys;
/// 3. the audience must be ours, so a token minted for another receiver's stream
///    does not replay into this one;
/// 4. the token must be fresh and unseen;
/// 5. and only then is each event matched against the transmitter's authority.
pub fn ingest(
    token: &str,
    transmitters: &TransmitterSet,
    seen: &mut SeenTokens,
    now: u64,
) -> Result<Ingested> {
    // 1 · the issuer, read unverified only to select a key set. Selecting a key by
    // an unverified claim is safe; believing the claim is not.
    let issuer = peek_claim(token, "iss")?;
    let transmitter = transmitters.get(&issuer).ok_or_else(|| {
        WcError::with_detail(
            Code::SIGNATURE_INVALID,
            format!("no configured transmitter for issuer {issuer:?}"),
        )
    })?;

    // 2 · the signature.
    let kid = peek_header(token, "kid")?;
    let alg = peek_header(token, "alg")?;
    if !wc_core::contract::ACCEPTED_ALG_NAMES.contains(&alg.as_str()) {
        return Err(WcError::with_detail(
            Code::ALG_NOT_ASYMMETRIC,
            format!("SET uses {alg:?}"),
        ));
    }
    let claims: SetClaims =
        wc_core::contract::verify_detached(token, &kid, &transmitter.keys()?).map_err(|e| {
            WcError::with_detail(
                Code::SIGNATURE_INVALID,
                format!("SET from {issuer:?} does not verify under kid {kid:?}"),
            )
            .with_source(e)
        })?;
    if claims.iss != transmitter.issuer {
        return Err(WcError::with_detail(
            Code::SIGNATURE_INVALID,
            "SET issuer changed between the unverified header and the signed claims",
        ));
    }

    // 3 · the audience.
    if !audience_matches(&claims.aud, &transmitter.audience) {
        return Err(WcError::with_detail(
            Code::AUDIENCE_MISMATCH,
            format!(
                "SET audience does not include {:?}; a token minted for another receiver's stream \
                 does not replay into this one",
                transmitter.audience
            ),
        ));
    }

    // 4 · freshness, then replay.
    let age = now.saturating_sub(claims.iat);
    if claims.iat > now.saturating_add(300) {
        return Err(WcError::with_detail(
            Code::APPROVAL_STALE,
            format!("SET is issued at {} , which is in the future", claims.iat),
        ));
    }
    if age > transmitter.max_age_secs {
        // Acting on a week-old containment signal re-degrades a party somebody has
        // since remediated.
        return Err(WcError::with_detail(
            Code::APPROVAL_STALE,
            format!(
                "SET is {age}s old, limit for this stream is {}s",
                transmitter.max_age_secs
            ),
        ));
    }
    if !seen.accept(&claims.jti) {
        return Err(WcError::with_detail(
            Code::APPROVAL_STALE,
            format!("SET {} has already been processed", claims.jti),
        ));
    }

    let subject = claims.subject().ok_or_else(|| {
        WcError::with_detail(
            Code::MALFORMED_IDENTIFIER,
            "SET has no sub_id.uri; there is nothing to act on",
        )
    })?;
    if !transmitter.may_name(&subject) {
        return Err(WcError::with_detail(
            Code::SIGNAL_NOT_AUTHORISED,
            format!(
                "transmitter {issuer:?} is not authorised to name {subject:?}",
            ),
        ));
    }
    if claims.events.is_empty() {
        return Err(WcError::with_detail(
            Code::FRAME_MALFORMED,
            "SET carries no events",
        ));
    }

    // 5 · authority, per event.
    let mut effects: Vec<Effect> = Vec::new();
    let mut unhandled: Vec<(String, String)> = Vec::new();

    for (uri, payload) in &claims.events {
        // "We do not understand this" and "you are not allowed to say this" are
        // different problems for whoever is debugging the integration, so the
        // unknown case is named first. Neither produces an effect.
        if !UNDERSTOOD.contains(&uri.as_str()) {
            unhandled.push((uri.clone(), "event type not understood".to_string()));
            continue;
        }
        if !transmitter.authority.permits(uri) {
            // A perfect signature from a stream with no authority over this event
            // type. Refused, and named — this is the case a receiver that only
            // checks signatures gets wrong.
            unhandled.push((
                uri.clone(),
                format!(
                    "{:?} authority does not permit this event type",
                    transmitter.authority
                ),
            ));
            continue;
        }
        match uri.as_str() {
            SESSION_REVOKED => effects.push(Effect::OwnerOrphaned {
                owner: subject.clone(),
            }),
            CREDENTIAL_CHANGE => effects.push(Effect::ReattestRequired {
                party: subject.clone(),
                reason: payload
                    .get("change_type")
                    .and_then(Value::as_str)
                    .unwrap_or("credential changed")
                    .to_string(),
            }),
            ASSURANCE_CHANGE => effects.push(Effect::RescorePosture {
                party: subject.clone(),
                level: payload
                    .get("current_level")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
            }),
            CONNECTION_REVOKED => match payload.get("cid").and_then(Value::as_str) {
                Some(cid) => effects.push(Effect::RevokeConnection {
                    cid: cid.to_string(),
                    by: issuer.clone(),
                }),
                None => unhandled.push((uri.clone(), "no cid in the event payload".to_string())),
            },
            // Unreachable: `UNDERSTOOD` above is the same list.
            other => unhandled.push((other.to_string(), "event type not understood".to_string())),
        }
    }

    Ok(Ingested {
        issuer,
        jti: claims.jti,
        subject,
        effects,
        unhandled,
    })
}

fn audience_matches(aud: &Value, expected: &str) -> bool {
    match aud {
        Value::String(s) => s == expected,
        Value::Array(items) => items.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

/// Read one claim from an unverified payload, to select a key set.
fn peek_claim(token: &str, name: &str) -> Result<String> {
    let value = decode_segment(token, 1)?;
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            WcError::with_detail(
                Code::FRAME_MALFORMED,
                format!("SET has no `{name}` claim"),
            )
        })
}

/// Read one header field, before any JOSE library chooses an algorithm.
fn peek_header(token: &str, name: &str) -> Result<String> {
    let value = decode_segment(token, 0)?;
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            WcError::with_detail(
                Code::FRAME_MALFORMED,
                format!("SET header has no `{name}`"),
            )
        })
}

fn decode_segment(token: &str, index: usize) -> Result<Value> {
    use base64::Engine as _;
    let segment = token.split('.').nth(index).unwrap_or_default();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| {
            WcError::with_detail(Code::FRAME_MALFORMED, "SET segment is not base64url")
                .with_source(e)
        })?;
    serde_json::from_slice(&bytes).map_err(|e| {
        WcError::with_detail(Code::FRAME_MALFORMED, "SET segment is not JSON").with_source(e)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use wc_core::contract::{Algorithm, IssuerKey};

    const NOW: u64 = 1_800_000_000;
    const RECEIVER: &str = "https://connect.internal/caep";

    fn keys_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/keys")
    }

    fn signer(kid: &str) -> IssuerKey {
        let pem = std::fs::read(keys_dir().join("test_issuer_es256_priv.pem")).unwrap();
        IssuerKey::ec_pem(kid, &pem, Algorithm::ES256).unwrap()
    }

    fn other_signer(kid: &str) -> IssuerKey {
        let pem = std::fs::read(keys_dir().join("test_anchor_priv.pem")).unwrap();
        IssuerKey::ec_pem(kid, &pem, Algorithm::ES256).unwrap()
    }

    fn pub_pem() -> String {
        std::fs::read_to_string(keys_dir().join("test_issuer_es256_pub.pem")).unwrap()
    }

    fn transmitter(issuer: &str, authority: Authority, parties: &[&str]) -> Transmitter {
        Transmitter {
            issuer: issuer.to_string(),
            jwks: [("idp-1".to_string(), pub_pem())].into_iter().collect(),
            authority,
            audience: RECEIVER.to_string(),
            parties: parties.iter().map(|p| (*p).to_string()).collect(),
            max_age_secs: DEFAULT_MAX_AGE_SECS,
        }
    }

    fn streams() -> TransmitterSet {
        TransmitterSet {
            transmitters: vec![
                transmitter("https://idp.example", Authority::Directory, &[]),
                transmitter(
                    "https://acme.example",
                    Authority::Partner,
                    &["conn_0000dead"],
                ),
            ],
        }
    }

    fn set(
        issuer: &str,
        subject: &str,
        events: serde_json::Value,
        iat: u64,
        jti: &str,
    ) -> String {
        let claims = serde_json::json!({
            "iss": issuer,
            "jti": jti,
            "iat": iat,
            "aud": RECEIVER,
            "sub_id": { "format": "uri", "uri": subject },
            "events": events,
        });
        wc_core::contract::sign_detached(&claims, &signer("idp-1")).unwrap()
    }

    fn session_revoked() -> serde_json::Value {
        serde_json::json!({ SESSION_REVOKED: { "reason": "leaver" } })
    }

    // --- the happy paths ---------------------------------------------------

    #[test]
    fn a_directory_can_report_a_leaver() {
        let token = set(
            "https://idp.example",
            "human:priya@org",
            session_revoked(),
            NOW - 10,
            "set_1",
        );
        let out = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap();
        assert_eq!(
            out.effects,
            vec![Effect::OwnerOrphaned {
                owner: "human:priya@org".to_string()
            }]
        );
        assert!(out.unhandled.is_empty());
    }

    #[test]
    fn a_partner_can_cut_a_connection_it_is_a_party_to() {
        let token = set(
            "https://acme.example",
            "conn_0000dead",
            serde_json::json!({ CONNECTION_REVOKED: { "cid": "conn_0000dead" } }),
            NOW - 10,
            "set_2",
        );
        let out = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap();
        assert_eq!(
            out.effects,
            vec![Effect::RevokeConnection {
                cid: "conn_0000dead".to_string(),
                by: "https://acme.example".to_string()
            }]
        );
    }

    #[test]
    fn a_credential_change_asks_for_re_attestation() {
        let token = set(
            "https://idp.example",
            "spiffe://org/ns/agents/sa/recon",
            serde_json::json!({ CREDENTIAL_CHANGE: { "change_type": "revoke" } }),
            NOW - 10,
            "set_3",
        );
        let out = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap();
        assert_eq!(
            out.effects,
            vec![Effect::ReattestRequired {
                party: "spiffe://org/ns/agents/sa/recon".to_string(),
                reason: "revoke".to_string()
            }]
        );
    }

    // --- authority: the property that bounds the damage --------------------

    #[test]
    fn a_perfect_signature_from_the_wrong_authority_is_refused() {
        // The case a receiver that only checks signatures gets wrong. A partner
        // asserting `credential-change` would degrade our attestation posture on
        // their word.
        let token = set(
            "https://acme.example",
            "conn_0000dead",
            serde_json::json!({ CREDENTIAL_CHANGE: { "change_type": "revoke" } }),
            NOW - 10,
            "set_4",
        );
        let out = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap();
        assert!(out.effects.is_empty(), "nothing acted on");
        assert_eq!(out.unhandled.len(), 1);
        assert!(out.unhandled[0].1.contains("does not permit"));
    }

    #[test]
    fn a_directory_cannot_cut_a_connection() {
        let token = set(
            "https://idp.example",
            "conn_0000dead",
            serde_json::json!({ CONNECTION_REVOKED: { "cid": "conn_0000dead" } }),
            NOW - 10,
            "set_5",
        );
        let out = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap();
        assert!(out.effects.is_empty());
        assert!(out.unhandled[0].1.contains("Directory"));
    }

    #[test]
    fn a_partner_cannot_name_a_connection_it_is_not_a_party_to() {
        // Without the party list, `Partner` authority would let any onboarded
        // partner cut any connection in the estate.
        let token = set(
            "https://acme.example",
            "conn_0000beef",
            serde_json::json!({ CONNECTION_REVOKED: { "cid": "conn_0000beef" } }),
            NOW - 10,
            "set_6",
        );
        let err = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap_err();
        assert!(err.to_string().contains("not authorised to name"), "{err}");
    }

    #[test]
    fn nothing_ingested_can_quarantine() {
        // An external input that can cut the estate is a denial-of-service
        // primitive handed to whoever can reach the endpoint. Asserted over every
        // event type this receiver understands.
        for (issuer, events) in [
            ("https://idp.example", session_revoked()),
            (
                "https://idp.example",
                serde_json::json!({ CREDENTIAL_CHANGE: {} }),
            ),
            (
                "https://idp.example",
                serde_json::json!({ ASSURANCE_CHANGE: { "current_level": "low" } }),
            ),
            (
                "https://acme.example",
                serde_json::json!({ CONNECTION_REVOKED: { "cid": "conn_0000dead" } }),
            ),
        ] {
            let subject = if issuer.contains("acme") {
                "conn_0000dead"
            } else {
                "human:priya@org"
            };
            let token = set(issuer, subject, events, NOW - 10, &format!("j{issuer}{subject}"));
            let out = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap();
            for effect in &out.effects {
                assert_ne!(
                    effect.kind(),
                    "quarantine",
                    "ingest produced a quarantine effect"
                );
            }
        }
    }

    // --- verification order ------------------------------------------------

    #[test]
    fn an_unknown_issuer_never_reaches_a_signature_check() {
        // An attacker must not be able to make us verify against a key of their
        // choosing by naming one.
        let claims = serde_json::json!({
            "iss": "https://evil.example",
            "jti": "set_x",
            "iat": NOW,
            "aud": RECEIVER,
            "sub_id": { "format": "uri", "uri": "human:priya@org" },
            "events": session_revoked(),
        });
        let token = wc_core::contract::sign_detached(&claims, &signer("idp-1")).unwrap();
        let err = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap_err();
        assert_eq!(err.code(), Code::SIGNATURE_INVALID);
        assert!(err.to_string().contains("no configured transmitter"));
    }

    #[test]
    fn a_token_signed_by_the_wrong_key_is_refused() {
        let claims = serde_json::json!({
            "iss": "https://idp.example",
            "jti": "set_y",
            "iat": NOW,
            "aud": RECEIVER,
            "sub_id": { "format": "uri", "uri": "human:priya@org" },
            "events": session_revoked(),
        });
        let token = wc_core::contract::sign_detached(&claims, &other_signer("idp-1")).unwrap();
        assert_eq!(
            ingest(&token, &streams(), &mut SeenTokens::default(), NOW)
                .unwrap_err()
                .code(),
            Code::SIGNATURE_INVALID
        );
    }

    #[test]
    fn a_token_for_another_receivers_stream_does_not_replay_into_ours() {
        let claims = serde_json::json!({
            "iss": "https://idp.example",
            "jti": "set_z",
            "iat": NOW,
            "aud": "https://someone-else.example/caep",
            "sub_id": { "format": "uri", "uri": "human:priya@org" },
            "events": session_revoked(),
        });
        let token = wc_core::contract::sign_detached(&claims, &signer("idp-1")).unwrap();
        let err = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap_err();
        assert_eq!(err.code(), Code::AUDIENCE_MISMATCH);
    }

    #[test]
    fn an_audience_array_containing_us_is_accepted() {
        let claims = serde_json::json!({
            "iss": "https://idp.example",
            "jti": "set_arr",
            "iat": NOW,
            "aud": ["https://other.example", RECEIVER],
            "sub_id": { "format": "uri", "uri": "human:priya@org" },
            "events": session_revoked(),
        });
        let token = wc_core::contract::sign_detached(&claims, &signer("idp-1")).unwrap();
        assert!(ingest(&token, &streams(), &mut SeenTokens::default(), NOW).is_ok());
    }

    #[test]
    fn alg_none_is_reported_as_not_asymmetric() {
        use base64::Engine as _;
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let payload = serde_json::json!({
            "iss": "https://idp.example",
            "jti": "n",
            "iat": NOW,
            "aud": RECEIVER,
            "sub_id": { "format": "uri", "uri": "x" },
            "events": session_revoked(),
        });
        let token = format!(
            "{}.{}.",
            b64(br#"{"alg":"none","kid":"idp-1"}"#),
            b64(serde_json::to_string(&payload).unwrap().as_bytes())
        );
        assert_eq!(
            ingest(&token, &streams(), &mut SeenTokens::default(), NOW)
                .unwrap_err()
                .code(),
            Code::ALG_NOT_ASYMMETRIC
        );
    }

    // --- freshness and replay ---------------------------------------------

    #[test]
    fn a_stale_token_is_refused() {
        // Acting on a week-old containment signal re-degrades a party somebody has
        // since remediated.
        let token = set(
            "https://idp.example",
            "human:priya@org",
            session_revoked(),
            NOW - 7 * 86_400,
            "set_old",
        );
        let err = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap_err();
        assert_eq!(err.code(), Code::APPROVAL_STALE);
        assert!(err.to_string().contains("old"));
    }

    #[test]
    fn a_token_from_the_future_is_refused() {
        let token = set(
            "https://idp.example",
            "human:priya@org",
            session_revoked(),
            NOW + 3_600,
            "set_future",
        );
        assert!(ingest(&token, &streams(), &mut SeenTokens::default(), NOW).is_err());
    }

    #[test]
    fn a_replayed_token_is_refused_once_seen() {
        let token = set(
            "https://idp.example",
            "human:priya@org",
            session_revoked(),
            NOW - 10,
            "set_once",
        );
        let mut seen = SeenTokens::default();
        assert!(ingest(&token, &streams(), &mut seen, NOW).is_ok());
        let err = ingest(&token, &streams(), &mut seen, NOW).unwrap_err();
        assert!(err.to_string().contains("already been processed"));
    }

    #[test]
    fn the_replay_store_is_bounded() {
        // An unbounded set is a memory-growth primitive for anyone who can send us
        // tokens.
        let mut seen = SeenTokens::new(3);
        for i in 0..5 {
            assert!(seen.accept(&format!("j{i}")));
        }
        assert_eq!(seen.len(), 3);
        // The oldest were evicted, so they would be accepted again — which the
        // freshness window makes safe, because a token that old is refused on age.
        assert!(seen.accept("j0"));
        assert!(!seen.accept("j4"));
    }

    // --- shape -------------------------------------------------------------

    #[test]
    fn an_unhandled_event_type_is_reported_not_dropped() {
        // A stream sending events we silently drop is a partner who believes they
        // have told us something.
        let token = set(
            "https://idp.example",
            "human:priya@org",
            serde_json::json!({
                SESSION_REVOKED: {},
                "https://example.com/some-other-event": {}
            }),
            NOW - 10,
            "set_mixed",
        );
        let out = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap();
        assert_eq!(out.effects.len(), 1, "the understood one still applies");
        assert_eq!(out.unhandled.len(), 1);
        assert!(out.unhandled[0].1.contains("not understood"));
    }

    #[test]
    fn a_token_with_no_events_or_no_subject_is_refused() {
        let no_events = set(
            "https://idp.example",
            "human:priya@org",
            serde_json::json!({}),
            NOW - 10,
            "set_empty",
        );
        assert_eq!(
            ingest(&no_events, &streams(), &mut SeenTokens::default(), NOW)
                .unwrap_err()
                .code(),
            Code::FRAME_MALFORMED
        );

        let claims = serde_json::json!({
            "iss": "https://idp.example",
            "jti": "set_nosub",
            "iat": NOW,
            "aud": RECEIVER,
            "events": session_revoked(),
        });
        let token = wc_core::contract::sign_detached(&claims, &signer("idp-1")).unwrap();
        assert_eq!(
            ingest(&token, &streams(), &mut SeenTokens::default(), NOW)
                .unwrap_err()
                .code(),
            Code::MALFORMED_IDENTIFIER
        );
    }

    #[test]
    fn a_connection_revoked_without_a_cid_is_reported() {
        let token = set(
            "https://acme.example",
            "conn_0000dead",
            serde_json::json!({ CONNECTION_REVOKED: {} }),
            NOW - 10,
            "set_nocid",
        );
        let out = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap();
        assert!(out.effects.is_empty());
        assert!(out.unhandled[0].1.contains("no cid"));
    }

    // --- configuration -----------------------------------------------------

    #[test]
    fn a_transmitter_set_refuses_the_dangerous_shapes() {
        let ok = format!(
            r#"
            [[transmitter]]
            issuer = "https://idp.example"
            authority = "directory"
            audience = "{RECEIVER}"
            jwks = {{ "idp-1" = """{}""" }}
            "#,
            pub_pem()
        );
        assert_eq!(TransmitterSet::parse(&ok).unwrap().transmitters.len(), 1);

        // Partner authority with no party list could cut any connection.
        let unscoped = format!(
            r#"
            [[transmitter]]
            issuer = "https://acme.example"
            authority = "partner"
            audience = "{RECEIVER}"
            jwks = {{ "a" = """{}""" }}
            "#,
            pub_pem()
        );
        let err = TransmitterSet::parse(&unscoped).unwrap_err();
        assert!(err.to_string().contains("could \n                         then cut any connection")
            || err.to_string().contains("cut any connection"), "{err}");

        // No audience means a token for someone else's stream replays into ours.
        let no_aud = format!(
            r#"
            [[transmitter]]
            issuer = "https://idp.example"
            authority = "directory"
            audience = ""
            jwks = {{ "a" = """{}""" }}
            "#,
            pub_pem()
        );
        assert!(TransmitterSet::parse(&no_aud).is_err());

        // No keys means nothing from it could ever verify.
        let no_keys = format!(
            r#"
            [[transmitter]]
            issuer = "https://idp.example"
            authority = "directory"
            audience = "{RECEIVER}"
            jwks = {{}}
            "#
        );
        assert!(TransmitterSet::parse(&no_keys).is_err());
    }

    #[test]
    fn every_understood_event_produces_an_effect_for_some_authority() {
        // A URI in UNDERSTOOD with no match arm produces no effect and no
        // diagnostic, which is the worst of both.
        for uri in UNDERSTOOD {
            let authority = if *uri == CONNECTION_REVOKED {
                Authority::Partner
            } else {
                Authority::Directory
            };
            assert!(authority.permits(uri), "{uri} is understood by nobody");

            let subject = if *uri == CONNECTION_REVOKED {
                "conn_0000dead"
            } else {
                "human:priya@org"
            };
            let issuer = if *uri == CONNECTION_REVOKED {
                "https://acme.example"
            } else {
                "https://idp.example"
            };
            let token = set(
                issuer,
                subject,
                serde_json::json!({ *uri: { "cid": "conn_0000dead" } }),
                NOW - 10,
                &format!("eff{uri}"),
            );
            let out = ingest(&token, &streams(), &mut SeenTokens::default(), NOW).unwrap();
            assert_eq!(out.effects.len(), 1, "{uri} produced no effect");
            assert!(out.unhandled.is_empty(), "{uri}: {:?}", out.unhandled);
        }
    }

    #[test]
    fn authority_permits_only_its_own_event_types() {
        assert!(Authority::Directory.permits(SESSION_REVOKED));
        assert!(Authority::Directory.permits(CREDENTIAL_CHANGE));
        assert!(!Authority::Directory.permits(CONNECTION_REVOKED));

        assert!(Authority::Partner.permits(CONNECTION_REVOKED));
        assert!(!Authority::Partner.permits(CREDENTIAL_CHANGE));
        assert!(!Authority::Partner.permits(SESSION_REVOKED));

        // A sibling control plane in the same organisation may say all of it.
        for uri in [
            SESSION_REVOKED,
            CREDENTIAL_CHANGE,
            ASSURANCE_CHANGE,
            CONNECTION_REVOKED,
        ] {
            assert!(Authority::Estate.permits(uri));
        }
    }
}
