#![no_main]
//! Fuzz contract artifact verification — the one entry point that turns bytes
//! somebody else controls into authority.
//!
//! Two properties, not one. No panic is the floor; the ceiling is that **no
//! malformed input is ever accepted**, so a success is re-checked and its claims
//! are asserted to be internally consistent. A fuzzer that only looked for crashes
//! would be satisfied by a verifier that accepted everything.
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use wc_core::contract::{self, Algorithm, IssuerKeys, VerifyOpts};

const PUB: &[u8] = include_bytes!("../../fixtures/keys/test_issuer_es256_pub.pem");
const MEDIATOR: &str = "warden:mediator:apac-ops";
const NOW: u64 = 1_785_312_500;

static KEYS: OnceLock<IssuerKeys> = OnceLock::new();

fn keys() -> &'static IssuerKeys {
    KEYS.get_or_init(|| {
        let mut k = IssuerKeys::new();
        let _ = k.add_ec_pem("wc-e2e-es256", PUB, Algorithm::ES256);
        k
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let opts = VerifyOpts::new(keys(), MEDIATOR, NOW);
    let Ok(verified) = contract::verify_artifact(text, &opts) else {
        return;
    };

    // Anything that verified must be self-consistent, or "verified" means nothing.
    let p = &verified.payload;
    assert!(p.nbf <= p.exp, "accepted a contract whose window is inverted");
    assert!(NOW >= p.nbf && NOW < p.exp, "accepted a contract outside its window");
    assert_eq!(p.aud, MEDIATOR, "accepted another mediator's contract");
    assert!(!p.cid.as_str().is_empty() && !p.jti.as_str().is_empty());
    assert_ne!(p.caller.id, p.callee.id, "accepted a contract from a party to itself");

    // And verification is deterministic: the same bytes verify the same way twice.
    assert!(contract::verify_artifact(text, &opts).is_ok());
});
