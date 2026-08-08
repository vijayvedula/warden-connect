#![no_main]
//! Fuzz the injection-screening detectors over arbitrary description text.
//!
//! Descriptions are attacker-controlled by definition — that is the premise the
//! whole detector set exists for. Two properties beyond no-panic: the report must
//! always say which detectors ran, and **no ruleset or input may promote a
//! flag-class finding into a blocking one** (§8.9). The blocking set is fixed in
//! code precisely so a configuration mistake cannot widen it.
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use wc_control::screen::{self, Acceptances, NameIndex, ScreenCtx, ScreenMode, ScreenRules};
use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::model::{EntityId, Tier};

static ID: OnceLock<EntityId> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let id = ID
        .get_or_init(|| EntityId::new("spiffe://org/ns/tools/sa/fuzz").expect("a fixed, valid id"));
    let surface = serde_json::json!({
        "tools": [{
            "name": "fuzzed_tool",
            "description": text,
            "inputSchema": {"type": "object", "properties": {"arg": {"description": text}}},
        }],
    });
    let Ok(canonical) =
        canon::canonicalise(SurfaceKind::McpTools, id, &surface, &Limits::default())
    else {
        return;
    };

    let rules = ScreenRules::default();
    let acceptances = Acceptances::default();
    let names = NameIndex::empty();
    for mode in [ScreenMode::Observe, ScreenMode::Flag, ScreenMode::Enforce] {
        for tier in [Tier::ONE, Tier::THREE] {
            let report = screen::screen(
                &canonical,
                tier,
                &ScreenCtx {
                    rules: &rules,
                    acceptances: &acceptances,
                    names: &names,
                    entity: id,
                    mode,
                },
            );
            // A detector that did not run is a gap, and a report that does not say so
            // is a lie. Every detector must be accounted for, either way.
            //
            // Membership, not a count. This asserted
            // `ran.len() + skipped.len() == ALL.len()` and was **wrong by design**: `S2`
            // lands in *both* lists when the name index is empty, which is the honest
            // answer — its script half ran and its collision half could not, so reporting
            // it as run would claim coverage that does not exist and reporting it as
            // skipped would discard the findings it did produce.
            //
            // The stable mirror in `crates/wc-e2e/tests/fuzz.rs` already asserted it this
            // way, so the two tiers had drifted — which is exactly what the mirror exists
            // to prevent, and exactly what only a real campaign could reveal: the mirror
            // cannot fail its own invariant, and this target had never been run.
            for d in screen::Detector::ALL {
                assert!(
                    report.ran.contains(&d) || report.skipped.iter().any(|(s, _)| *s == d),
                    "{d:?} was neither run nor reported skipped"
                );
            }
            // Blocking is earned in code, never granted by input: a verdict that
            // blocks must be backed by a detector whose blocking status is fixed in
            // `is_blocking`, which no ruleset can reach.
            if report.verdict == screen::Verdict::Block {
                assert!(
                    report.live_hits().iter().any(|h| h.detector.is_blocking()),
                    "a blocking verdict with no blocking-class hit behind it"
                );
            }
        }
    }
});
