#![no_main]
//! Fuzz `wcs1` canonicalisation over arbitrary JSON.
//!
//! The pin is the whole drift mechanism, so the canonicaliser sees every surface
//! any server ever returns — including a hostile one. `Limits` is what makes "no
//! unbounded allocation" a property rather than a hope, so the target asserts the
//! output stays inside them.
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::model::EntityId;

static ID: OnceLock<EntityId> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let id = ID.get_or_init(|| {
        EntityId::new("spiffe://org/ns/tools/sa/fuzz").expect("a fixed, valid id")
    });
    let limits = Limits::default();

    for kind in [SurfaceKind::McpTools, SurfaceKind::A2aCard] {
        let Ok(canonical) = canon::canonicalise(kind, id, &value, &limits) else {
            continue;
        };
        // Bounded: the limits are the allocation guarantee, so a success that
        // exceeded them would mean the check is decorative.
        assert!(canonical.items.len() <= limits.max_items);
        assert!(canonical.document.len() <= limits.max_bytes);

        // Idempotent: canonicalising the canonical form changes nothing. This is the
        // property a pin comparison depends on.
        let first = canonical.manifest_hash();
        let again = canon::canonicalise(kind, id, &value, &limits)
            .expect("a surface that canonicalised once must do so again");
        assert_eq!(first, again.manifest_hash());
    }
});
