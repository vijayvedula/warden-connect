#![no_main]
//! Fuzz the connect-policy (TOML) parser.
//!
//! Policy is operator input, so this is less about a hostile author than about
//! never being unbootable: a malformed file must be a refusal with a code, never a
//! panic that takes the control plane down. And a policy that parses must be one
//! the linter can also reason about.
use libfuzzer_sys::fuzz_target;
use wc_control::cpolicy::ConnectPolicy;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(policy) = ConnectPolicy::parse(text) else {
        return;
    };

    // A parsed policy must survive every read-only path an operator can reach,
    // because those run before anyone has looked at the file.
    let _ = policy.lint();
    let _ = policy.lattice();
    for rule in &policy.rules {
        assert!(rule.decision.as_str().len() > 1);
    }
});
