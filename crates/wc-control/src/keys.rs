//! The issuer keyring and its rotation lifecycle (`docs/08-lld.md` §8.12.1).
//!
//! Verification is `kid`-directed: a mediator reads the `kid` from a contract's
//! header and looks it up in the JWKS it holds. That is what makes rotation
//! possible at all — and what makes retiring a key the single most dangerous
//! routine operation in this system.
//!
//! # The one property this module exists for
//!
//! **A key may not be retired while a contract signed with it is still live.**
//!
//! Retiring early does not fail loudly. It fails at the mediator, on the next
//! `tools/call`, for every agent holding a contract signed by that `kid` — as
//! `WC-3102 signature or issuer chain invalid`, which reads like an attack rather
//! than an operations mistake. So [`Keyring::retire`] refuses unless the caller
//! passes the latest expiry among contracts signed by that key, and refuses again
//! if that moment has not arrived.
//!
//! The overlap is therefore not a fixed 7 days: it is *the longest-lived contract
//! that key signed, plus a margin*. A 30-day contract minted an hour before
//! rotation keeps its key alive for 30 days, and no amount of policy shortens
//! that after the fact.
//!
//! # Generation is not this module's job
//!
//! `keys new` prints the exact `openssl` invocation, or runs it if openssl is on
//! the path. Rolling a keygen into a control plane means owning an entropy and
//! PKCS#8 bug surface for no gain — every host that runs this already has a tool
//! that does it correctly, and a PKCS#11 or KMS URI is the production answer
//! anyway.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use wc_core::contract::{Algorithm, IssuerKeys};
use wc_core::error::{Code, Result, WcError};

/// Margin added on top of the last contract expiry before a key may be retired.
///
/// Clock skew between the control plane and a mediator, plus the mediator's own
/// contract-set poll interval, means "expired" is not simultaneous everywhere.
pub const RETIREMENT_MARGIN_SECS: u64 = 7 * 86_400;

/// Default rotation interval.
pub const DEFAULT_ROTATE_EVERY_SECS: u64 = 90 * 86_400;

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// Where a key sits in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// Signs new contracts. Exactly one key is active.
    Active,
    /// No longer signs, still verifies. Contracts it signed are still live.
    Retiring,
    /// Removed from the JWKS. Any contract it signed no longer verifies.
    Retired,
}

impl KeyState {
    /// Whether a mediator should still hold this key.
    #[must_use]
    pub const fn verifies(self) -> bool {
        matches!(self, KeyState::Active | KeyState::Retiring)
    }

    /// Label for operator output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyState::Active => "active",
            KeyState::Retiring => "retiring",
            KeyState::Retired => "retired",
        }
    }
}

/// One key in the ring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    /// The `kid` stamped into every contract this key signs.
    pub kid: String,
    /// Signing algorithm.
    #[serde(default = "default_alg")]
    pub alg: String,
    /// Public key, PEM (SPKI).
    pub public_pem: String,
    /// Where the private key lives. A path, a `pkcs11:` URI, or a KMS reference —
    /// recorded so an operator knows what to rotate, never read by this module.
    #[serde(default)]
    pub private_ref: Option<String>,
    /// Lifecycle state.
    pub state: KeyState,
    /// When it became active.
    #[serde(default)]
    pub activated_at: u64,
    /// When it stopped signing.
    #[serde(default)]
    pub retiring_at: Option<u64>,
    /// The latest `exp` among contracts this key signed, as last recorded.
    ///
    /// The whole safety property hangs on this number. `None` means nobody has
    /// told the ring, which is treated as "unknown", not as "none".
    #[serde(default)]
    pub last_contract_exp: Option<u64>,
    /// When it was removed from the JWKS.
    #[serde(default)]
    pub retired_at: Option<u64>,
}

fn default_alg() -> String {
    "ES256".to_string()
}

impl KeyEntry {
    /// The earliest moment this key may safely leave the JWKS.
    ///
    /// `None` means "not yet knowable" — nobody has recorded what this key signed,
    /// and guessing would be guessing about other people's live traffic.
    #[must_use]
    pub fn safe_to_retire_at(&self) -> Option<u64> {
        self.last_contract_exp
            .map(|exp| exp.saturating_add(RETIREMENT_MARGIN_SECS))
    }

    /// The algorithm, parsed.
    pub fn algorithm(&self) -> Result<Algorithm> {
        match self.alg.as_str() {
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            "EdDSA" | "Ed25519" => Ok(Algorithm::EdDSA),
            other => Err(WcError::with_detail(
                Code::ALG_NOT_ASYMMETRIC,
                format!("key {:?} declares algorithm {other:?}", self.kid),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// The ring
// ---------------------------------------------------------------------------

/// The issuer keyring.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keyring {
    /// How often the active key should be rotated.
    #[serde(default = "default_rotate_every")]
    pub rotate_every: u64,
    /// The keys.
    #[serde(default, rename = "key")]
    pub keys: Vec<KeyEntry>,
}

fn default_rotate_every() -> u64 {
    DEFAULT_ROTATE_EVERY_SECS
}

impl Default for Keyring {
    /// Hand-written rather than derived: a derived `Default` gives
    /// `rotate_every: 0`, which `rotation_due` reads as "never due" — so a ring
    /// created by `keys add` would silently never report rotation overdue.
    fn default() -> Self {
        Keyring {
            rotate_every: default_rotate_every(),
            keys: Vec::new(),
        }
    }
}

impl Keyring {
    /// Parse from TOML.
    pub fn parse(text: &str) -> Result<Keyring> {
        let ring: Keyring = toml::from_str(text).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, "keyring is not valid TOML").with_source(e)
        })?;
        ring.validate()?;
        Ok(ring)
    }

    /// Read from disk.
    pub fn load(path: &Path) -> Result<Keyring> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("cannot read keyring {}", path.display()),
            )
            .with_source(e)
        })?;
        Keyring::parse(&text)
    }

    /// Persist.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let text = toml::to_string_pretty(self).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, "cannot serialise the keyring")
                .with_source(e)
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, text).map_err(|e| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("cannot write keyring {}", path.display()),
            )
            .with_source(e)
        })
    }

    fn validate(&self) -> Result<()> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for k in &self.keys {
            if k.kid.trim().is_empty() {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    "a key has an empty kid; verification is kid-directed, so it could never be found",
                ));
            }
            if !seen.insert(k.kid.as_str()) {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("kid {:?} appears twice; a kid must name exactly one key", k.kid),
                ));
            }
            k.algorithm()?;
        }
        let active = self.keys.iter().filter(|k| k.state == KeyState::Active).count();
        if active > 1 {
            // Two active keys means two signers and no way to say which one a
            // given contract should have come from.
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("{active} keys are active; exactly one may sign"),
            ));
        }
        Ok(())
    }

    /// The key that signs new contracts.
    pub fn active(&self) -> Result<&KeyEntry> {
        self.keys
            .iter()
            .find(|k| k.state == KeyState::Active)
            .ok_or_else(|| {
                WcError::with_detail(
                    Code::CONFIG_INVALID,
                    "no active key; nothing can be minted until one is activated",
                )
            })
    }

    /// A key by `kid`.
    #[must_use]
    pub fn get(&self, kid: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// Every key a mediator should still hold.
    #[must_use]
    pub fn verifying(&self) -> Vec<&KeyEntry> {
        self.keys.iter().filter(|k| k.state.verifies()).collect()
    }

    /// The verifier a mediator would build from this ring.
    pub fn verifiers(&self) -> Result<IssuerKeys> {
        let mut keys = IssuerKeys::new();
        for entry in self.verifying() {
            let alg = entry.algorithm()?;
            let pem = entry.public_pem.as_bytes();
            match alg {
                Algorithm::EdDSA => keys.add_ed_pem(&entry.kid, pem)?,
                other => keys.add_ec_pem(&entry.kid, pem, other)?,
            }
        }
        Ok(keys)
    }

    /// Add a key, inactive.
    pub fn add(&mut self, entry: KeyEntry) -> Result<()> {
        if self.get(&entry.kid).is_some() {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("kid {:?} is already in the ring", entry.kid),
            ));
        }
        self.keys.push(entry);
        self.validate()
    }

    /// Promote a key to active, moving the previous one to retiring.
    ///
    /// The old key keeps verifying. Nothing it signed stops working, which is the
    /// entire point of a `kid`-directed scheme — and `retire` is a separate,
    /// guarded step precisely so that rotation and removal cannot be confused.
    pub fn rotate_to(&mut self, kid: &str, now: u64) -> Result<Rotation> {
        if self.get(kid).is_none() {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("kid {kid:?} is not in the ring; add it before rotating to it"),
            ));
        }
        if self.get(kid).is_some_and(|k| k.state == KeyState::Retired) {
            // A retired key has been removed from mediators' JWKS. Bringing it
            // back would mint contracts nobody can verify.
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("kid {kid:?} is retired; a retired key must never sign again"),
            ));
        }

        let previous = self
            .keys
            .iter()
            .find(|k| k.state == KeyState::Active && k.kid != kid)
            .map(|k| k.kid.clone());

        for key in &mut self.keys {
            if key.kid == kid {
                key.state = KeyState::Active;
                key.activated_at = now;
                key.retiring_at = None;
            } else if key.state == KeyState::Active {
                key.state = KeyState::Retiring;
                key.retiring_at = Some(now);
            }
        }
        self.validate()?;
        Ok(Rotation {
            now_active: kid.to_string(),
            now_retiring: previous,
        })
    }

    /// Record the latest contract expiry a key signed.
    ///
    /// Called by the issuer on every mint. Monotonic: a later mint can only push
    /// the date out, never pull it in, because pulling it in would let a
    /// short-lived contract minted after a long-lived one shorten the key's
    /// required life.
    pub fn note_signed(&mut self, kid: &str, exp: u64) {
        if let Some(key) = self.keys.iter_mut().find(|k| k.kid == kid) {
            key.last_contract_exp = Some(key.last_contract_exp.map_or(exp, |e| e.max(exp)));
        }
    }

    /// Remove a key from the JWKS.
    ///
    /// Refuses while any contract it signed is still live. This is the guard the
    /// module exists for: retiring early fails at the mediator, on the next call,
    /// for every agent holding a contract signed by that `kid` — reported as
    /// `WC-3102`, which reads like an attack rather than an operations mistake.
    pub fn retire(&mut self, kid: &str, now: u64) -> Result<()> {
        let key = self.get(kid).ok_or_else(|| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("kid {kid:?} is not in the ring"))
        })?;
        if key.state == KeyState::Active {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("kid {kid:?} is the active key; rotate to another key first"),
            ));
        }
        if key.state == KeyState::Retired {
            return Ok(());
        }

        match key.safe_to_retire_at() {
            None => Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "kid {kid:?} has no recorded contract expiry, so it is not known whether any \
                     contract it signed is still live; record one with `keys note` or pass the \
                     latest expiry explicitly"
                ),
            )),
            Some(safe_at) if now < safe_at => Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "kid {kid:?} signed a contract expiring at {}; it may be retired at {safe_at} \
                     (in {}s), and retiring now would break verification for every holder",
                    key.last_contract_exp.unwrap_or_default(),
                    safe_at - now
                ),
            )),
            Some(_) => {
                if let Some(key) = self.keys.iter_mut().find(|k| k.kid == kid) {
                    key.state = KeyState::Retired;
                    key.retired_at = Some(now);
                }
                Ok(())
            }
        }
    }

    /// Whether the active key is overdue for rotation.
    #[must_use]
    pub fn rotation_due(&self, now: u64) -> bool {
        self.active().is_ok_and(|k| {
            self.rotate_every > 0 && now.saturating_sub(k.activated_at) > self.rotate_every
        })
    }

    /// Keys that may now be retired.
    #[must_use]
    pub fn retirable(&self, now: u64) -> Vec<&KeyEntry> {
        self.keys
            .iter()
            .filter(|k| {
                k.state == KeyState::Retiring && k.safe_to_retire_at().is_some_and(|at| now >= at)
            })
            .collect()
    }

    /// Render the public JWKS a mediator verifies against.
    ///
    /// Contains every verifying key, so a contract signed before a rotation still
    /// resolves. A retired key is absent, which is what makes retirement a real
    /// revocation of that key's signing authority.
    pub fn jwks(&self) -> Result<String> {
        let mut entries: Vec<serde_json::Value> = Vec::new();
        for key in self.verifying() {
            entries.push(jwk_from_pem(&key.kid, &key.alg, &key.public_pem)?);
        }
        serde_json::to_string_pretty(&serde_json::json!({ "keys": entries })).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, "cannot render the JWKS").with_source(e)
        })
    }
}

/// What a rotation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    /// The key now signing.
    pub now_active: String,
    /// The key that stopped signing, if there was one.
    pub now_retiring: Option<String>,
}

// ---------------------------------------------------------------------------
// JWK rendering
// ---------------------------------------------------------------------------

/// Build a JWK from a public PEM.
///
/// P-256 and P-384 SPKI end with an uncompressed point — `0x04 ‖ X ‖ Y` — of a
/// fixed length for the curve, so the coordinates are the tail of the DER. Parsed
/// as a suffix rather than with a full ASN.1 reader: this is a *rendering* path
/// with a known input shape, and a DER parser here would be a new attack surface
/// for a format we ourselves wrote.
pub fn jwk_from_pem(kid: &str, alg: &str, pem: &str) -> Result<serde_json::Value> {
    use base64::Engine as _;

    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("key {kid:?} is not a base64 PEM body"),
            )
            .with_source(e)
        })?;

    let (crv, coord_len) = match alg {
        "ES256" => ("P-256", 32usize),
        "ES384" => ("P-384", 48usize),
        "EdDSA" | "Ed25519" => {
            // Ed25519 SPKI is a fixed 44 bytes with the 32-byte key as the tail.
            let x = der.len().checked_sub(32).map(|i| &der[i..]).ok_or_else(|| {
                WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("key {kid:?} is too short to be an Ed25519 SPKI"),
                )
            })?;
            return Ok(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "alg": "EdDSA",
                "use": "sig",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
            }));
        }
        other => {
            return Err(WcError::with_detail(
                Code::ALG_NOT_ASYMMETRIC,
                format!("key {kid:?} declares algorithm {other:?}"),
            ))
        }
    };

    let point_len = 1 + 2 * coord_len;
    let point = der
        .len()
        .checked_sub(point_len)
        .map(|i| &der[i..])
        .ok_or_else(|| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("key {kid:?} is too short to be a {crv} SPKI"),
            )
        })?;
    if point[0] != 0x04 {
        // A compressed point, or not a public key at all. Refusing beats emitting
        // a JWK with coordinates read from the wrong offset, which would verify
        // nothing and look like a valid key.
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!(
                "key {kid:?} does not end in an uncompressed {crv} point (found 0x{:02x}); \
                 compressed points are not supported",
                point[0]
            ),
        ));
    }

    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    Ok(serde_json::json!({
        "kty": "EC",
        "crv": crv,
        "kid": kid,
        "alg": alg,
        "use": "sig",
        "x": b64(&point[1..=coord_len]),
        "y": b64(&point[1 + coord_len..]),
    }))
}

/// The `openssl` invocation that produces a key this ring accepts.
///
/// Printed rather than embedded: rolling a keygen into a control plane means
/// owning an entropy and PKCS#8 bug surface for no gain, and a PKCS#11 or KMS URI
/// is the production answer anyway.
#[must_use]
pub fn generation_command(alg: &str, private_path: &str, public_path: &str) -> Vec<String> {
    let curve = match alg {
        "ES384" => "P-384",
        _ => "P-256",
    };
    vec![
        format!(
            "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:{curve} \
             -pkeyopt ec_param_enc:named_curve -out {private_path}"
        ),
        format!("chmod 600 {private_path}"),
        format!("openssl pkey -in {private_path} -pubout -out {public_path}"),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;

    fn pub_pem() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/keys/test_issuer_es256_pub.pem"),
        )
        .unwrap()
    }

    fn entry(kid: &str, state: KeyState) -> KeyEntry {
        KeyEntry {
            kid: kid.to_string(),
            alg: "ES256".to_string(),
            public_pem: pub_pem(),
            private_ref: Some(format!("/keys/{kid}.pem")),
            state,
            activated_at: NOW - DAY,
            retiring_at: None,
            last_contract_exp: None,
            retired_at: None,
        }
    }

    fn ring() -> Keyring {
        Keyring {
            rotate_every: DEFAULT_ROTATE_EVERY_SECS,
            keys: vec![entry("k-2026-01", KeyState::Active)],
        }
    }

    // --- the property this module exists for -------------------------------

    #[test]
    fn a_key_cannot_be_retired_while_a_contract_it_signed_is_live() {
        // Retiring early does not fail loudly. It fails at the mediator, on the
        // next call, for every agent holding a contract signed by that kid — as
        // WC-3102, which reads like an attack rather than an ops mistake.
        let mut r = ring();
        r.add(entry("k-2026-04", KeyState::Retiring)).unwrap();
        r.note_signed("k-2026-04", NOW + 30 * DAY);

        let err = r.retire("k-2026-04", NOW).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(err.to_string().contains("would break verification"), "{err}");

        // Still live at the raw expiry, because of the margin.
        assert!(r.retire("k-2026-04", NOW + 30 * DAY).is_err());
        // And retirable once the margin has passed.
        assert!(r
            .retire("k-2026-04", NOW + 30 * DAY + RETIREMENT_MARGIN_SECS)
            .is_ok());
        assert_eq!(r.get("k-2026-04").unwrap().state, KeyState::Retired);
    }

    #[test]
    fn an_unknown_contract_expiry_blocks_retirement_rather_than_assuming_none() {
        // "Nobody told us" and "nothing was signed" are different, and guessing
        // would be guessing about other people's live traffic.
        let mut r = ring();
        r.add(entry("k-old", KeyState::Retiring)).unwrap();
        assert!(r.get("k-old").unwrap().last_contract_exp.is_none());

        let err = r.retire("k-old", NOW + 365 * DAY).unwrap_err();
        assert!(err.to_string().contains("not known whether"), "{err}");
    }

    #[test]
    fn the_recorded_expiry_only_moves_outward() {
        // A short-lived contract minted after a long-lived one must not shorten
        // the key's required life.
        let mut r = ring();
        r.note_signed("k-2026-01", NOW + 30 * DAY);
        r.note_signed("k-2026-01", NOW + DAY);
        assert_eq!(
            r.get("k-2026-01").unwrap().last_contract_exp,
            Some(NOW + 30 * DAY)
        );
    }

    #[test]
    fn the_active_key_cannot_be_retired() {
        let mut r = ring();
        r.note_signed("k-2026-01", NOW - DAY);
        let err = r.retire("k-2026-01", NOW + 365 * DAY).unwrap_err();
        assert!(err.to_string().contains("rotate to another key first"));
    }

    #[test]
    fn retiring_twice_is_a_no_op_rather_than_an_error() {
        let mut r = ring();
        r.add(entry("k-old", KeyState::Retiring)).unwrap();
        r.note_signed("k-old", NOW - 365 * DAY);
        assert!(r.retire("k-old", NOW).is_ok());
        assert!(r.retire("k-old", NOW).is_ok());
    }

    // --- rotation ----------------------------------------------------------

    #[test]
    fn rotation_keeps_the_old_key_verifying() {
        // The entire point of a kid-directed scheme: nothing the old key signed
        // stops working.
        let mut r = ring();
        r.add(entry("k-2026-04", KeyState::Retiring)).unwrap();
        // Make the new key inactive first, as `add` leaves it.
        r.keys.last_mut().unwrap().state = KeyState::Retiring;

        let rotation = r.rotate_to("k-2026-04", NOW).unwrap();
        assert_eq!(rotation.now_active, "k-2026-04");
        assert_eq!(rotation.now_retiring.as_deref(), Some("k-2026-01"));

        assert_eq!(r.active().unwrap().kid, "k-2026-04");
        assert_eq!(r.get("k-2026-01").unwrap().state, KeyState::Retiring);
        assert_eq!(r.get("k-2026-01").unwrap().retiring_at, Some(NOW));
        // Both still verify.
        assert_eq!(r.verifying().len(), 2);
        assert_eq!(r.verifiers().unwrap().len(), 2);
    }

    #[test]
    fn a_retired_key_may_never_sign_again() {
        // It has been removed from mediators' JWKS, so anything it signed now
        // would be unverifiable everywhere.
        let mut r = ring();
        r.add(KeyEntry {
            state: KeyState::Retired,
            retired_at: Some(NOW - DAY),
            ..entry("k-old", KeyState::Retired)
        })
        .unwrap();
        let err = r.rotate_to("k-old", NOW).unwrap_err();
        assert!(err.to_string().contains("must never sign again"));
    }

    #[test]
    fn rotating_to_an_unknown_kid_is_refused() {
        let mut r = ring();
        assert!(r.rotate_to("k-nope", NOW).is_err());
    }

    #[test]
    fn exactly_one_key_may_be_active() {
        let mut r = ring();
        let err = r.add(entry("k-two", KeyState::Active)).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(err.to_string().contains("exactly one may sign"));
    }

    #[test]
    fn a_ring_with_no_active_key_cannot_mint() {
        let mut r = ring();
        r.keys[0].state = KeyState::Retiring;
        let err = r.active().unwrap_err();
        assert!(err.to_string().contains("nothing can be minted"));
    }

    #[test]
    fn a_fresh_ring_has_a_real_rotation_interval() {
        // A derived Default gives 0, which `rotation_due` reads as "never due" —
        // so a ring created by `keys add` would silently never report rotation
        // overdue. Found by running `connect keys list` on a new ring.
        let fresh = Keyring::default();
        assert_eq!(fresh.rotate_every, DEFAULT_ROTATE_EVERY_SECS);
        assert_ne!(fresh.rotate_every, 0);
    }

    #[test]
    fn rotation_becomes_due_after_the_interval() {
        let r = ring();
        assert!(!r.rotation_due(NOW));
        assert!(r.rotation_due(NOW + DEFAULT_ROTATE_EVERY_SECS + DAY));
    }

    #[test]
    fn retirable_lists_only_keys_that_are_actually_safe() {
        let mut r = ring();
        r.add(entry("k-ready", KeyState::Retiring)).unwrap();
        r.add(entry("k-waiting", KeyState::Retiring)).unwrap();
        r.add(entry("k-unknown", KeyState::Retiring)).unwrap();
        r.note_signed("k-ready", NOW - 365 * DAY);
        r.note_signed("k-waiting", NOW + 30 * DAY);

        let ready: Vec<&str> = r.retirable(NOW).iter().map(|k| k.kid.as_str()).collect();
        assert_eq!(ready, vec!["k-ready"]);
    }

    // --- the ring ----------------------------------------------------------

    #[test]
    fn a_duplicate_or_empty_kid_is_refused() {
        // Verification is kid-directed, so a duplicate names two keys and an empty
        // one could never be found.
        let mut r = ring();
        assert!(r.add(entry("k-2026-01", KeyState::Retiring)).is_err());

        assert!(Keyring::parse(&format!(
            "[[key]]\nkid = \"\"\nstate = \"active\"\npublic_pem = \"\"\"{}\"\"\"\n",
            pub_pem()
        ))
        .is_err());
    }

    #[test]
    fn a_ring_round_trips_through_toml() {
        let mut r = ring();
        r.add(entry("k-next", KeyState::Retiring)).unwrap();
        r.note_signed("k-next", NOW + DAY);

        let text = toml::to_string_pretty(&r).unwrap();
        let back = Keyring::parse(&text).unwrap();
        assert_eq!(back.keys.len(), 2);
        assert_eq!(back.get("k-next").unwrap().last_contract_exp, Some(NOW + DAY));
        assert_eq!(back.active().unwrap().kid, "k-2026-01");
    }

    // --- JWKS --------------------------------------------------------------

    #[test]
    fn the_jwks_carries_every_verifying_key_and_no_retired_one() {
        let mut r = ring();
        r.add(entry("k-retiring", KeyState::Retiring)).unwrap();
        r.add(KeyEntry {
            state: KeyState::Retired,
            ..entry("k-gone", KeyState::Retired)
        })
        .unwrap();

        let jwks: serde_json::Value = serde_json::from_str(&r.jwks().unwrap()).unwrap();
        let kids: Vec<&str> = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap())
            .collect();
        assert_eq!(kids, vec!["k-2026-01", "k-retiring"]);
        // A retired key's absence is what makes retirement a real revocation of
        // that key's signing authority.
        assert!(!kids.contains(&"k-gone"));
    }

    #[test]
    fn a_jwk_carries_real_p256_coordinates() {
        let jwk = jwk_from_pem("k1", "ES256", &pub_pem()).unwrap();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["use"], "sig");

        use base64::Engine as _;
        for coord in ["x", "y"] {
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwk[coord].as_str().unwrap())
                .unwrap();
            assert_eq!(raw.len(), 32, "{coord} must be a 32-byte P-256 coordinate");
        }
        // And the two coordinates differ, which a wrong offset would not give.
        assert_ne!(jwk["x"], jwk["y"]);
    }

    #[test]
    fn a_key_that_is_not_an_uncompressed_point_is_refused() {
        // Refusing beats emitting a JWK with coordinates read from the wrong
        // offset, which would verify nothing and look like a valid key.
        let err = jwk_from_pem("k1", "ES256", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")
            .unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);

        let bogus = {
            use base64::Engine as _;
            let der = vec![0u8; 91]; // right length, wrong first byte
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                base64::engine::general_purpose::STANDARD.encode(&der)
            )
        };
        let err = jwk_from_pem("k1", "ES256", &bogus).unwrap_err();
        assert!(err.to_string().contains("uncompressed"), "{err}");
    }

    #[test]
    fn an_unsupported_algorithm_is_refused() {
        assert_eq!(
            jwk_from_pem("k1", "HS256", &pub_pem()).unwrap_err().code(),
            Code::ALG_NOT_ASYMMETRIC
        );
    }

    #[test]
    fn the_generation_command_is_printable_and_names_the_right_curve() {
        let cmds = generation_command("ES384", "/keys/a.pem", "/keys/a.pub");
        assert!(cmds[0].contains("P-384"));
        assert!(cmds[1].contains("chmod 600"), "a private key must not be world-readable");
        assert!(cmds[2].contains("-pubout"));
        assert!(generation_command("ES256", "a", "b")[0].contains("P-256"));
    }
}
