//! Air-gapped contract bundles (`docs/08-lld.md` §8.9.4, §7.9).
//!
//! An estate with no route to the control plane still needs contracts. A bundle
//! is one signed envelope carrying everything a mediator would otherwise pull:
//! the contracts, the JWKS that verifies them, and the revocations in force when
//! it was cut.
//!
//! # Expiry is the whole design
//!
//! A mediator that pulls learns about a revocation within its poll interval. A
//! mediator fed by bundles learns about one when somebody carries the next bundle
//! in — so the bundle's own `exp` is the **forcing function** that bounds how
//! stale an air-gapped estate can get.
//!
//! That makes one rule non-negotiable: **past `exp`, the entire bundle is refused,
//! even though the contracts inside are still within their own `exp`.** It is the
//! surprising behaviour and the correct one. A bundle whose contracts outlive it
//! would be an air-gapped estate running on a revocation list from an unknown
//! date, which is exactly the state this format exists to bound.
//!
//! # What the signature covers
//!
//! Everything, by digest: the contracts, the JWKS, the revocations and the
//! expiry. Signing only a manifest of contract ids would let a courier strip the
//! revocations and leave a bundle that still verifies — the removal being
//! invisible is the point of putting them under the signature.
//!
//! # Verified by the same code path
//!
//! The contracts inside are verified by `contract::verify_artifact`, exactly as a
//! pulled one is. A bundle is a *transport*, not a second trust model, and an
//! import path with its own verification is an import path with its own bugs.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use wc_core::contract::{IssuerKey, IssuerKeys};
use wc_core::error::{Code, Result, WcError};
use wc_core::util::{canonical_json, sha256_hex};

/// Bundle format version. A mediator refuses a version it does not know rather
/// than guessing at the fields.
pub const BUNDLE_SCHEMA: u16 = 1;

/// Longest a bundle may be valid for.
///
/// Two weeks, because the bundle's expiry is the only bound on how stale an
/// air-gapped estate's revocation list can be. A year-long bundle is a
/// permanently unrevocable estate with a reassuring file extension.
pub const MAX_BUNDLE_TTL_SECS: u64 = 14 * 86_400;

// ---------------------------------------------------------------------------
// The envelope
// ---------------------------------------------------------------------------

/// What a bundle carries, before signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleBody {
    /// Format version.
    pub schema: u16,
    /// Which mediator this bundle is for. One bundle, one mediator, for the same
    /// reason one contract has one audience: a bundle usable anywhere is a bundle
    /// replayable anywhere.
    pub mediator_id: String,
    /// When it was cut.
    pub issued_at: u64,
    /// When it stops being usable, whatever the contracts inside say.
    pub exp: u64,
    /// Contract artifacts, compact JWS.
    #[serde(default)]
    pub contracts: Vec<String>,
    /// The JWKS a mediator verifies those contracts against.
    pub jwks: String,
    /// Signed revocation entries in force at issue time.
    #[serde(default)]
    pub revocations: Vec<serde_json::Value>,
    /// Digest over the revocation feed head, so a mediator can tell two bundles
    /// apart even when both carry an empty list.
    #[serde(default)]
    pub revocation_head: String,
}

impl BundleBody {
    /// The digest the signature covers.
    ///
    /// Over the canonical form of the whole body, so contracts, JWKS,
    /// revocations and expiry are all sealed together. Signing a manifest of
    /// contract ids instead would let a courier strip the revocations and leave a
    /// bundle that still verifies.
    #[must_use]
    pub fn digest(&self) -> String {
        format!(
            "sha256:{}",
            sha256_hex(&canonical_json(
                &serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
            ))
        )
    }
}

/// Claims in the bundle's detached signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BundleClaims {
    /// Digest of the body.
    digest: String,
    /// Repeated in the claims so a signature cannot be lifted onto a body with a
    /// different audience or lifetime even if a digest ever collided.
    mediator_id: String,
    exp: u64,
    iat: u64,
}

/// A signed bundle, as written to a `.wcb` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    /// The payload.
    pub body: BundleBody,
    /// Detached JWS over [`BundleBody::digest`].
    pub bundle_jws: String,
    /// Key that signed the envelope.
    pub kid: String,
}

/// What a bundle contained, after verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    /// The mediator it was cut for.
    pub mediator_id: String,
    /// Contracts that verified.
    pub contracts: Vec<String>,
    /// Contracts that did not, with the code.
    pub rejected: Vec<(usize, Code)>,
    /// Revocation entries carried.
    pub revocations: usize,
    /// Feed head the revocations were taken from.
    pub revocation_head: String,
    /// When the bundle stops being usable.
    pub exp: u64,
    /// Seconds of usable life left.
    pub remaining: u64,
}

impl Imported {
    /// Whether every contract in the bundle verified.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.rejected.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// What goes into a bundle.
#[derive(Debug, Clone)]
pub struct ExportRequest {
    /// The mediator this bundle is for.
    pub mediator_id: String,
    /// Contract artifacts.
    pub contracts: Vec<String>,
    /// The JWKS to ship alongside them.
    pub jwks: String,
    /// Signed revocation entries in force.
    pub revocations: Vec<serde_json::Value>,
    /// Digest of the revocation feed head.
    pub revocation_head: String,
    /// How long the bundle is usable for.
    pub ttl_secs: u64,
}

/// Cut and sign a bundle.
pub fn export(request: &ExportRequest, now: u64, key: &IssuerKey) -> Result<Bundle> {
    if request.mediator_id.trim().is_empty() {
        return Err(WcError::with_detail(
            Code::EXPORT_FAILED,
            "a bundle must name one mediator; a bundle usable anywhere is replayable anywhere",
        ));
    }
    if request.ttl_secs == 0 || request.ttl_secs > MAX_BUNDLE_TTL_SECS {
        return Err(WcError::with_detail(
            Code::EXPORT_FAILED,
            format!(
                "bundle ttl must be 1..={MAX_BUNDLE_TTL_SECS}s, got {}s; the expiry is the only \
                 bound on how stale an air-gapped estate's revocation list can be",
                request.ttl_secs
            ),
        ));
    }
    if request.jwks.trim().is_empty() {
        // A bundle whose contracts cannot be verified is a file, not a bundle.
        return Err(WcError::with_detail(
            Code::EXPORT_FAILED,
            "a bundle must carry the JWKS its contracts verify against",
        ));
    }

    let body = BundleBody {
        schema: BUNDLE_SCHEMA,
        mediator_id: request.mediator_id.clone(),
        issued_at: now,
        exp: now.saturating_add(request.ttl_secs),
        contracts: request.contracts.clone(),
        jwks: request.jwks.clone(),
        revocations: request.revocations.clone(),
        revocation_head: request.revocation_head.clone(),
    };

    let claims = BundleClaims {
        digest: body.digest(),
        mediator_id: body.mediator_id.clone(),
        exp: body.exp,
        iat: body.issued_at,
    };
    let bundle_jws = wc_core::contract::sign_detached(&claims, key).map_err(|e| {
        WcError::with_detail(Code::EXPORT_FAILED, "cannot sign the bundle").with_source(e)
    })?;

    Ok(Bundle {
        body,
        bundle_jws,
        kid: key.kid().to_string(),
    })
}

/// Serialise a bundle to the bytes written to a `.wcb` file.
pub fn to_bytes(bundle: &Bundle) -> Result<String> {
    serde_json::to_string_pretty(bundle).map_err(|e| {
        WcError::with_detail(Code::EXPORT_FAILED, "cannot serialise the bundle").with_source(e)
    })
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Verify a bundle and return what it carried.
///
/// `envelope_keys` verifies the bundle's own signature; `contract_keys` verifies
/// the contracts inside. They are separate arguments because they are separate
/// trust decisions: an operator may accept a courier's envelope key without
/// accepting whatever JWKS the envelope happens to contain.
pub fn import(
    text: &str,
    envelope_keys: &IssuerKeys,
    trust: &wc_core::contract::Trust<'_>,
    now: u64,
) -> Result<Imported> {
    let bundle: Bundle = serde_json::from_str(text).map_err(|e| {
        WcError::with_detail(Code::EXPORT_FAILED, "not a warden-connect bundle").with_source(e)
    })?;

    if bundle.body.schema != BUNDLE_SCHEMA {
        // Refuse rather than guess at the fields of a version we do not know.
        return Err(WcError::with_detail(
            Code::SCHEMA_UNKNOWN,
            format!(
                "bundle schema {} is not {BUNDLE_SCHEMA}",
                bundle.body.schema
            ),
        ));
    }

    // The signature first. Nothing in the body is believed until it verifies —
    // including the expiry, which an unverified body could otherwise extend.
    let claims: BundleClaims =
        wc_core::contract::verify_detached(&bundle.bundle_jws, &bundle.kid, envelope_keys)
            .map_err(|e| {
                WcError::with_detail(
                    Code::SIGNATURE_INVALID,
                    format!(
                        "bundle signature does not verify under kid {:?}",
                        bundle.kid
                    ),
                )
                .with_source(e)
            })?;

    let actual = bundle.body.digest();
    if claims.digest != actual {
        // The body was edited after signing. This is the check that makes
        // stripping the revocations impossible rather than merely rude.
        return Err(WcError::with_detail(
            Code::SIGNATURE_INVALID,
            "bundle contents do not match the signed digest",
        ));
    }
    if claims.mediator_id != bundle.body.mediator_id || claims.exp != bundle.body.exp {
        return Err(WcError::with_detail(
            Code::SIGNATURE_INVALID,
            "bundle claims disagree with its body",
        ));
    }

    if bundle.body.mediator_id != trust.mediator_id {
        return Err(WcError::with_detail(
            Code::AUDIENCE_MISMATCH,
            format!(
                "bundle is for {:?}, this mediator is {:?}",
                bundle.body.mediator_id, trust.mediator_id
            ),
        ));
    }

    // Hard expiry. The surprising rule and the correct one: past this moment the
    // whole bundle is refused, even though the contracts inside may still be
    // within their own `exp`. A bundle whose contracts outlive it is an
    // air-gapped estate running on a revocation list from an unknown date.
    if now >= bundle.body.exp {
        return Err(WcError::with_detail(
            Code::CONTRACT_EXPIRED,
            format!(
                "bundle expired at {} ({}s ago); its contracts are not usable regardless of their \
                 own expiry — carry in a fresh bundle",
                bundle.body.exp,
                now - bundle.body.exp
            ),
        ));
    }
    if now < bundle.body.issued_at.saturating_sub(300) {
        return Err(WcError::with_detail(
            Code::CONTRACT_EXPIRED,
            format!(
                "bundle is issued at {} , which is in the future",
                bundle.body.issued_at
            ),
        ));
    }

    // Each contract through the same verification a pulled one gets — including the
    // issuer check. A bundle is the one path where a contract *arrives as a file carried
    // between planes*, so it is the last place `iss` should be taken on trust.
    let opts = wc_core::contract::VerifyOpts::trusting(trust, now);
    let mut verified: Vec<String> = Vec::new();
    let mut rejected: Vec<(usize, Code)> = Vec::new();
    for (i, jws) in bundle.body.contracts.iter().enumerate() {
        match wc_core::contract::verify_artifact(jws, &opts) {
            Ok(_) => verified.push(jws.clone()),
            // One bad artifact does not cost the courier the whole trip, but it is
            // reported rather than dropped.
            Err(e) => rejected.push((i, e.code())),
        }
    }

    Ok(Imported {
        mediator_id: bundle.body.mediator_id.clone(),
        contracts: verified,
        rejected,
        revocations: bundle.body.revocations.len(),
        revocation_head: bundle.body.revocation_head.clone(),
        exp: bundle.body.exp,
        remaining: bundle.body.exp.saturating_sub(now),
    })
}

/// Read a bundle from disk and verify it.
pub fn import_file(
    path: &Path,
    envelope_keys: &IssuerKeys,
    trust: &wc_core::contract::Trust<'_>,
    now: u64,
) -> Result<Imported> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        WcError::with_detail(
            Code::EXPORT_FAILED,
            format!("cannot read bundle {}", path.display()),
        )
        .with_source(e)
    })?;
    import(&text, envelope_keys, trust, now)
}

/// Contract audiences present in a bundle, for a pre-flight check.
#[must_use]
pub fn audiences(bundle: &Bundle) -> BTreeSet<String> {
    std::iter::once(bundle.body.mediator_id.clone()).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use wc_core::contract::Algorithm;

    const NOW: u64 = 1_800_000_000;
    const MEDIATOR: &str = "warden:mediator:apac-ops";
    const ISS: &str = "https://connect.internal/t/apac";

    /// The trust an importing mediator verifies under. Named once, so a test cannot
    /// quietly stop checking `iss`.
    fn trusting(keys: &IssuerKeys) -> wc_core::contract::Trust<'_> {
        wc_core::contract::Trust {
            keys,
            mediator_id: MEDIATOR,
            issuer: ISS,
        }
    }

    fn keys_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/keys")
    }

    fn signer() -> IssuerKey {
        let pem = std::fs::read(keys_dir().join("test_issuer_es256_priv.pem")).unwrap();
        IssuerKey::ec_pem("bundle-1", &pem, Algorithm::ES256).unwrap()
    }

    fn envelope_keys() -> IssuerKeys {
        let pem = std::fs::read(keys_dir().join("test_issuer_es256_pub.pem")).unwrap();
        let mut keys = IssuerKeys::new();
        keys.add_ec_pem("bundle-1", &pem, Algorithm::ES256).unwrap();
        keys
    }

    fn request() -> ExportRequest {
        ExportRequest {
            mediator_id: MEDIATOR.to_string(),
            // Contract verification is exercised elsewhere; these stand in for
            // artifacts and are expected to be rejected by `verify_artifact`.
            contracts: vec!["a.b.c".to_string()],
            jwks: r#"{"keys":[]}"#.to_string(),
            revocations: vec![serde_json::json!({ "seq": 1, "kind": "party" })],
            revocation_head: "sha256:feed".to_string(),
            ttl_secs: 7 * 86_400,
        }
    }

    fn cut() -> Bundle {
        export(&request(), NOW, &signer()).unwrap()
    }

    // --- expiry: the whole design ------------------------------------------

    #[test]
    fn a_bundle_is_refused_past_its_own_expiry() {
        // The surprising rule and the correct one. The bundle's exp is the only
        // bound on how stale an air-gapped estate's revocation list can be.
        let text = to_bytes(&cut()).unwrap();
        let keys = envelope_keys();

        let fresh = import(&text, &keys, &trusting(&keys), NOW + 86_400).unwrap();
        assert_eq!(fresh.remaining, 6 * 86_400);

        let err = import(&text, &keys, &trusting(&keys), NOW + 7 * 86_400).unwrap_err();
        assert_eq!(err.code(), Code::CONTRACT_EXPIRED);
        assert!(
            err.to_string().contains("regardless of their own expiry"),
            "{err}"
        );
    }

    #[test]
    fn a_bundle_ttl_beyond_the_ceiling_is_refused_at_export() {
        // A year-long bundle is a permanently unrevocable estate with a reassuring
        // file extension.
        let long = ExportRequest {
            ttl_secs: 365 * 86_400,
            ..request()
        };
        let err = export(&long, NOW, &signer()).unwrap_err();
        assert_eq!(err.code(), Code::EXPORT_FAILED);
        assert!(err.to_string().contains("how stale"), "{err}");

        assert!(export(
            &ExportRequest {
                ttl_secs: 0,
                ..request()
            },
            NOW,
            &signer()
        )
        .is_err());
    }

    #[test]
    fn a_bundle_from_the_future_is_refused() {
        let text = to_bytes(&cut()).unwrap();
        let keys = envelope_keys();
        assert!(import(&text, &keys, &trusting(&keys), NOW - 3_600).is_err());
        // Small skew is tolerated.
        assert!(import(&text, &keys, &trusting(&keys), NOW - 60).is_ok());
    }

    // --- the signature covers everything -----------------------------------

    #[test]
    fn stripping_the_revocations_breaks_the_signature() {
        // The reason revocations are under the signature rather than beside it: a
        // courier who can remove them silently is a courier who can un-revoke.
        let mut bundle = cut();
        assert_eq!(bundle.body.revocations.len(), 1);
        bundle.body.revocations.clear();

        let keys = envelope_keys();
        let err = import(&to_bytes(&bundle).unwrap(), &keys, &trusting(&keys), NOW).unwrap_err();
        assert_eq!(err.code(), Code::SIGNATURE_INVALID);
        assert!(err.to_string().contains("do not match the signed digest"));
    }

    #[test]
    fn extending_the_expiry_breaks_the_signature() {
        let mut bundle = cut();
        bundle.body.exp += 365 * 86_400;
        let keys = envelope_keys();
        assert_eq!(
            import(&to_bytes(&bundle).unwrap(), &keys, &trusting(&keys), NOW)
                .unwrap_err()
                .code(),
            Code::SIGNATURE_INVALID
        );
    }

    #[test]
    fn adding_a_contract_breaks_the_signature() {
        let mut bundle = cut();
        bundle.body.contracts.push("x.y.z".to_string());
        let keys = envelope_keys();
        assert!(import(&to_bytes(&bundle).unwrap(), &keys, &trusting(&keys), NOW).is_err());
    }

    #[test]
    fn swapping_the_jwks_breaks_the_signature() {
        // Otherwise a courier substitutes their own verification keys and every
        // contract they mint verifies.
        let mut bundle = cut();
        bundle.body.jwks = r#"{"keys":[{"kid":"attacker"}]}"#.to_string();
        let keys = envelope_keys();
        assert!(import(&to_bytes(&bundle).unwrap(), &keys, &trusting(&keys), NOW).is_err());
    }

    #[test]
    fn an_envelope_signed_by_an_untrusted_key_is_refused() {
        let text = to_bytes(&cut()).unwrap();
        let empty = IssuerKeys::new();
        let err = import(&text, &empty, &trusting(&empty), NOW).unwrap_err();
        assert_eq!(err.code(), Code::SIGNATURE_INVALID);
    }

    // --- audience ----------------------------------------------------------

    #[test]
    fn a_bundle_cut_for_another_mediator_is_refused() {
        // One bundle, one mediator, for the same reason one contract has one
        // audience: a bundle usable anywhere is replayable anywhere.
        let text = to_bytes(&cut()).unwrap();
        let keys = envelope_keys();
        let err = import(
            &text,
            &keys,
            &wc_core::contract::Trust {
                keys: &keys,
                mediator_id: "warden:mediator:emea",
                issuer: ISS,
            },
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::AUDIENCE_MISMATCH);
        assert_eq!(audiences(&cut()).len(), 1);
    }

    #[test]
    fn a_bundle_naming_no_mediator_cannot_be_cut() {
        let err = export(
            &ExportRequest {
                mediator_id: "  ".to_string(),
                ..request()
            },
            NOW,
            &signer(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("replayable anywhere"));
    }

    #[test]
    fn a_bundle_without_a_jwks_cannot_be_cut() {
        // A bundle whose contracts cannot be verified is a file, not a bundle.
        assert!(export(
            &ExportRequest {
                jwks: String::new(),
                ..request()
            },
            NOW,
            &signer()
        )
        .is_err());
    }

    // --- contracts ---------------------------------------------------------

    #[test]
    fn contracts_go_through_the_same_verification_as_a_pulled_one() {
        // A bundle is a transport, not a second trust model. These stand-ins are
        // not real artifacts, so they are rejected — and reported rather than
        // dropped.
        let text = to_bytes(&cut()).unwrap();
        let keys = envelope_keys();
        let imported = import(&text, &keys, &trusting(&keys), NOW).unwrap();
        assert!(imported.contracts.is_empty());
        assert_eq!(imported.rejected.len(), 1);
        assert!(!imported.is_clean());
        // The rest of the bundle still arrives.
        assert_eq!(imported.revocations, 1);
        assert_eq!(imported.revocation_head, "sha256:feed");
    }

    #[test]
    fn an_unknown_schema_is_refused_rather_than_guessed_at() {
        let mut bundle = cut();
        bundle.body.schema = 99;
        let keys = envelope_keys();
        assert_eq!(
            import(&to_bytes(&bundle).unwrap(), &keys, &trusting(&keys), NOW)
                .unwrap_err()
                .code(),
            Code::SCHEMA_UNKNOWN
        );
    }

    #[test]
    fn a_bundle_round_trips_through_its_file_form() {
        let bundle = cut();
        let text = to_bytes(&bundle).unwrap();
        let back: Bundle = serde_json::from_str(&text).unwrap();
        assert_eq!(back.body, bundle.body);
        assert_eq!(back.kid, "bundle-1");
        assert_eq!(back.body.digest(), bundle.body.digest());
    }

    #[test]
    fn garbage_is_refused_cleanly() {
        let keys = envelope_keys();
        assert_eq!(
            import("{not json}", &keys, &trusting(&keys), NOW)
                .unwrap_err()
                .code(),
            Code::EXPORT_FAILED
        );
    }
}
