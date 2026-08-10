//! Small shared primitives: canonical JSON, hashing.
//!
//! # Why these live here rather than being imported
//!
//! Every member of the Warden family needs them, and every member must be
//! **independently adoptable** — a team may run `warden-connect` with no Warden
//! core, or substitute its own registry and only mint contracts this
//! implementation must verify. The family's interface is deliberately two signed
//! artifacts and one identifier (§7.7), not a shared crate.
//!
//! That matters most for the contract verifier: §7.4 makes
//! `connect verify <contract>` the conformance ground truth, and a reference
//! verifier that requires linking the vendor's product is not a reference
//! verifier.
//!
//! These functions are **behaviourally identical** to Warden core's
//! `warden::util` equivalents, deliberately and permanently: a chain or digest
//! produced by one must verify with the other. Compatibility is held by the
//! golden vectors in `fixtures/` rather than by a code dependency — checked,
//! rather than assumed.
//!
//! When a third family member needs these same primitives, extract them into a
//! neutral crate then. Not before: duplicating thirty lines twice is cheaper
//! than getting a crate boundary wrong across four repositories.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// SHA-256 of a string, lowercase hex.
#[must_use]
pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Raw SHA-256 digest bytes, for JWK thumbprints and the like.
#[must_use]
pub fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// Lowercase hex. Re-exported from here so callers need not add `hex` as a dependency —
/// §8.3 caps the count, and every crate that needs hex already needs `wc-core`.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode lowercase or uppercase hex. `None` rather than an error type, so a caller can
/// attach its own code and detail — a hex failure means different things in a Merkle path and
/// in a config file.
#[must_use]
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.trim()).ok()
}

/// Decode standard (padded) base64 — what DSSE payloads and Rekor bodies use, as distinct
/// from the base64url a JWS segment uses. `None` so the caller attaches its own code.
#[must_use]
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
}

/// `sha256:` hex over bytes — what an artifact digest looks like on the wire.
///
/// Named separately from [`sha256_hex`], which takes a `&str`: a caller hashing a *file*
/// would otherwise have to go through `String::from_utf8`, and a release binary is not UTF-8.
#[must_use]
pub fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Deterministic JSON serialisation with object keys sorted, so hashes are
/// stable regardless of map ordering.
///
/// Keys are sorted explicitly rather than relying on `serde_json::Map` being a
/// `BTreeMap`: if any crate in the dependency graph enabled
/// `serde_json/preserve_order`, feature unification would make maps
/// insertion-ordered and silently change every digest this produces.
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    let encoded_key = serde_json::to_string(k).unwrap_or_default();
                    let encoded_value = map
                        .get(*k)
                        .map_or_else(|| "null".to_string(), canonical_json);
                    format!("{encoded_key}:{encoded_value}")
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use serde_json::json;

    #[test]
    fn hashing_matches_the_published_vector() {
        // The canonical SHA-256 of the empty string; pins the encoding as much as
        // the algorithm.
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_bytes(b"abc")[0], 0xba);
    }

    #[test]
    fn object_keys_are_sorted() {
        assert_eq!(canonical_json(&json!({"b": 1, "a": 2})), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn key_order_cannot_change_the_digest() {
        let a = json!({"z": {"y": 1, "x": 2}, "a": [3, 4]});
        let b = json!({"a": [3, 4], "z": {"x": 2, "y": 1}});
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(
            sha256_hex(&canonical_json(&a)),
            sha256_hex(&canonical_json(&b))
        );
    }

    #[test]
    fn array_order_is_preserved() {
        // Arrays carry meaning; only `wcs1` decides which ones may be sorted.
        assert_ne!(
            canonical_json(&json!([1, 2])),
            canonical_json(&json!([2, 1]))
        );
    }

    #[test]
    fn scalars_round_trip_as_json() {
        assert_eq!(canonical_json(&json!(null)), "null");
        assert_eq!(canonical_json(&json!(true)), "true");
        assert_eq!(canonical_json(&json!(1.5)), "1.5");
        assert_eq!(canonical_json(&json!("a\"b")), r#""a\"b""#);
    }

    #[test]
    fn nesting_is_canonical_all_the_way_down() {
        assert_eq!(
            canonical_json(&json!({"outer": {"b": [{"d": 1, "c": 2}], "a": null}})),
            r#"{"outer":{"a":null,"b":[{"c":2,"d":1}]}}"#
        );
    }
}
