#![no_main]
//! Fuzz the revocation feed as it arrives from the control plane.
//!
//! The feed is the containment path, so the properties are about what an
//! attacker-shaped delta can and cannot achieve: it may never *un*-revoke, and it
//! may never leave the mediator believing it is current when it has missed a cut.
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use wc_core::contract::{Algorithm, IssuerKeys};
use wc_mediator::cache::Revocations;
use wc_mediator::client::{self, RevocationDelta};

const PUB: &[u8] = include_bytes!("../../fixtures/keys/test_issuer_es256_pub.pem");
const ALREADY: &str = "spiffe://org/ns/agents/sa/already-revoked";

static KEYS: OnceLock<IssuerKeys> = OnceLock::new();

fn keys() -> &'static IssuerKeys {
    KEYS.get_or_init(|| {
        let mut k = IssuerKeys::new();
        let _ = k.add_ec_pem("revoke-1", PUB, Algorithm::ES256);
        k
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(delta) = serde_json::from_str::<RevocationDelta>(text) else {
        return;
    };

    let mut previous = Revocations::new();
    previous.revoke_party(ALREADY);
    let report = client::apply_revocations(&delta, keys(), &previous, 0);
    let set = report.set.clone().expect("apply_revocations always returns a set");

    // Deny-only: no delta, however shaped, may lift an existing revocation.
    assert!(
        wc_core::contract::RevocationView::party_revoked(&set, ALREADY),
        "a delta un-revoked a party"
    );
    // Nothing unverifiable is ever applied, and a bad pull poisons the set rather
    // than installing a partial one.
    assert!(report.applied <= delta.events.len());
    if !report.is_clean() {
        assert!(set.distrusted().is_some(), "a bad pull produced a trusted set");
    }
    // The applied sequence never runs ahead of what was verified contiguously.
    if !report.contiguous {
        assert!(report.applied_seq < delta.head_seq.max(report.applied_seq));
    }
});
