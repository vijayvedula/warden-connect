//! Two regions, two tenants, and what residency actually guarantees
//! (production-readiness P2 #19).
//!
//! #19's finding was precise: `tenant.rs` and `federate.rs` are unit-tested, including the
//! path-traversal fix and cross-tenant `WC-8002`, but **no two-region deployment has been
//! stood up** — and residency is the constraint the one-pager leads with.
//!
//! So this stands one up. Two tenants under one root, each with its **own issuer key**,
//! standing in for two regional control planes; then the questions an auditor asks:
//!
//! * can a contract minted in one region be used in the other?
//! * does one region's state leak into the other's?
//! * does a connection whose data would span residency boundaries get treated differently?
//!
//! # What residency is, in this system
//!
//! Narrow and worth stating, because "data residency" invites people to assume more than is
//! there. §8.7.3 specifies exactly one residency rule: **jurisdictions spanning more than one
//! residency group escalate the tier one step toward 1**, which pulls the connection into
//! human approval and then dual control.
//!
//! That is a *governance* control, not a network control. warden-connect does not route
//! traffic, cannot see where bytes go, and does not stop a callee in Frankfurt answering a
//! caller in Singapore. What it does is make the crossing **declared, tiered and approved by
//! a human**, and refuse to issue a contract whose terms exceed what the zone bar allows.
//! Anything stronger is a network and storage property, and claiming it here would be
//! exactly the kind of control that reads as configured and does nothing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod harness;

use harness::*;
use wc_control::admission::{self, Declared, FetchedSurface, TierRules, DEFAULT_RESIDENCY_GROUPS};
use wc_control::store::Store;
use wc_control::tenant::{TenantId, TenantPaths};
use wc_core::canon::SurfaceKind;
use wc_core::error::Code;
use wc_core::model::{Tier, ZoneId};

/// Two regions, named as an estate would name them.
const EU: &str = "eu-frankfurt";
const APAC: &str = "apac-singapore";

// ===========================================================================
// 1 · Two regions are two estates
// ===========================================================================

#[test]
fn each_region_has_its_own_state_and_neither_can_see_the_other() {
    // The isolation is by construction: a tenant id is a path component, and `TenantPaths`
    // derives a separate state and evidence root per tenant. Asserted here across two
    // *regional* names rather than two arbitrary strings, because that is the deployment
    // shape #19 asked for.
    let root = Root::new("res-two-regions");
    let eu = TenantPaths::new(&root.dir, &TenantId::new(EU).unwrap());
    let apac = TenantPaths::new(&root.dir, &TenantId::new(APAC).unwrap());

    assert_ne!(eu.state, apac.state);
    assert_ne!(eu.evidence, apac.evidence);
    assert!(
        !eu.state.starts_with(&apac.state) && !apac.state.starts_with(&eu.state),
        "neither region's state may be nested inside the other's: {} vs {}",
        eu.state.display(),
        apac.state.display()
    );

    // Each takes its own writer lock, so one region's control plane cannot block the other's
    // — which is the whole point of running two rather than one with a wide policy.
    let (_eu_store, _) = Store::open(&eu.state).unwrap();
    let (_apac_store, _) = Store::open(&apac.state).unwrap();

    // And a second writer *within* one region is still refused.
    assert_eq!(
        Store::open(&eu.state).unwrap_err().code(),
        Code::STORE_LOCKED
    );
}

#[test]
fn a_region_name_cannot_escape_its_root() {
    // The path-traversal fix, asserted at the deployment shape rather than only as a unit
    // test: a region is operator-supplied configuration, and `--tenant ../../../../tmp` once
    // wrote an estate's state outside its root.
    for hostile in [
        "../../../../tmp/elsewhere",
        "eu/../apac",
        "..",
        "/absolute",
        "eu\0frankfurt",
    ] {
        assert!(
            TenantId::new(hostile).is_err(),
            "{hostile:?} must not be a usable region id"
        );
    }
}

// ===========================================================================
// 2 · A contract does not cross regions
// ===========================================================================

#[test]
fn a_contract_minted_in_one_region_does_not_verify_in_the_other() {
    // §8.5.9's reason for a per-tenant issuer key, stated as a cross-region property: with
    // one key across regions, a contract minted for Frankfurt would be cryptographically
    // indistinguishable from one minted for Singapore, and the isolation would be a
    // filesystem convention rather than something a mediator can check.
    //
    // Here `signer()`/`verifier()` stand in for one region's key and the anchor keypair for
    // the other's.
    let eu_signer = signer();
    let contract = wc_core::contract::sign_detached(
        &serde_json::json!({"region": EU, "sub": "conn_1"}),
        &eu_signer,
    )
    .unwrap();

    // The other region trusts only its own key, registered under the same `kid` — the worst
    // case, because a differing kid would fail for the uninteresting reason.
    let mut apac_keys = wc_core::contract::IssuerKeys::new();
    let apac_pub = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/keys/test_anchor_pub.pem"),
    )
    .unwrap();
    apac_keys
        .add_ec_pem(KID, &apac_pub, wc_core::contract::Algorithm::ES256)
        .unwrap();

    let seen: Result<serde_json::Value, _> =
        wc_core::contract::verify_detached(&contract, KID, &apac_keys);
    assert!(
        seen.is_err(),
        "a contract from {EU} must not verify against {APAC}'s key set"
    );

    // And it does verify at home, so the test is about the key and not about a broken
    // artifact.
    let home = verifier();
    let mine: serde_json::Value =
        wc_core::contract::verify_detached(&contract, KID, &home).unwrap();
    assert_eq!(mine["region"], EU);
}

#[test]
fn an_unknown_region_is_refused_rather_than_defaulted() {
    // Falling back to `default` would silently operate on the wrong estate, which for a
    // residency control is the one failure that matters: an operator believing they were
    // acting in Frankfurt while writing to Singapore.
    let registry = wc_control::tenant::TenantRegistry::parse(&format!(
        "[[tenant]]\nid = \"{EU}\"\nname = \"EU\"\n\
         [[tenant]]\nid = \"{APAC}\"\nname = \"APAC\"\n"
    ))
    .unwrap();

    assert_eq!(registry.len(), 2);
    assert!(registry.resolve(&TenantId::new(EU).unwrap()).is_ok());

    let err = registry
        .resolve(&TenantId::new("us-east").unwrap())
        .unwrap_err();
    assert_eq!(err.code(), Code::TENANT_UNKNOWN);
}

// ===========================================================================
// 3 · What residency actually does: it escalates
// ===========================================================================

#[test]
fn a_connection_that_stays_in_region_is_not_escalated_for_residency() {
    // The baseline. Without it, the escalation below could pass on a rule that escalates
    // everything.
    let rules = TierRules::default();
    let (stayed, _) = tier_for(&["SG", "MY"], &rules);
    let (crossed, why) = tier_for(&["SG", "DE"], &rules);

    assert!(
        crossed < stayed,
        "SG+DE spans two residency groups and must escalate one step toward 1: {crossed} vs {stayed}"
    );
    assert!(
        why.contains("residency"),
        "and it must say why, or an operator cannot tell this escalation from any other: {why}"
    );
}

#[test]
fn a_cross_region_connection_reaches_a_human() {
    // The governance claim made concrete. §8.7.3: tier <= 2 needs human approval, tier == 1
    // needs dual control. So the point of the rule is that no cross-region connection is
    // issued by standing policy alone.
    let rules = TierRules::default();
    let (crossed, _) = tier_for(&["SG", "DE", "US"], &rules);
    assert!(
        crossed <= 2,
        "a connection spanning three residency groups must reach a human, got tier {crossed}"
    );
}

#[test]
fn the_residency_groups_are_configurable_because_they_are_a_legal_question() {
    // The default is coarse on purpose: an estate's real boundaries are counsel's answer, not
    // a library constant. A hard-coded list would be a residency control that is wrong for
    // every estate that is not the author's.
    assert!(
        DEFAULT_RESIDENCY_GROUPS.len() > 1,
        "one group would escalate nothing"
    );

    // An estate treating a whole region as one boundary escalates nothing for residency,
    // which is a legitimate configuration and must not be an error.
    static ONE_WORLD: &[&[&str]] = &[&["SG", "DE", "US", "GB", "AU", "MY"]];
    // `residency_groups` is `TierRules`'s only field today, so no struct-update is needed —
    // which is itself the point: residency is the one tunable in tier derivation.
    let permissive = TierRules {
        residency_groups: ONE_WORLD,
    };

    let (strictly, _) = tier_for(&["SG", "DE"], &TierRules::default());
    let (permissively, _) = tier_for(&["SG", "DE"], &permissive);
    assert!(
        permissively > strictly,
        "widening the groups must remove the escalation, or the rule is not configurable: \
         {permissively} vs {strictly}"
    );
}

#[test]
fn a_single_jurisdiction_and_none_at_all_are_both_in_region() {
    // A contract declaring no jurisdiction is not "spanning" anything. Treating an empty list
    // as a crossing would escalate every contract in an estate that has not adopted
    // jurisdictions yet, and an escalation that fires on everything is one nobody can act on.
    let rules = TierRules::default();
    let (one, _) = tier_for(&["SG"], &rules);
    let (none, _) = tier_for(&[], &rules);
    assert_eq!(none, one, "no declared jurisdiction is not a crossing");
}

// ===========================================================================
// 4 · The honest limit
// ===========================================================================

#[test]
fn residency_is_a_governance_control_and_says_so() {
    // Recorded as a test so the claim cannot quietly grow. warden-connect does not route
    // traffic and cannot see where bytes go: a contract crossing a residency boundary is
    // *declared, tiered and approved*, not prevented. If somebody later adds a
    // "residency denied" outcome, this is where they will have to argue for it.
    let rules = TierRules::default();
    let (crossed, why) = tier_for(&["SG", "DE"], &rules);

    assert!(crossed < Tier::THREE.as_u8(), "it escalates");
    assert!(
        why.contains("escalated"),
        "the mechanism is escalation, not refusal: {why}"
    );
}

/// Derive a tier from a declaration that differs **only** in its jurisdictions, so any
/// difference is attributable to residency and nothing else.
fn tier_for(jurisdictions: &[&str], rules: &TierRules) -> (u8, String) {
    let declared = Declared {
        data_classes: vec!["internal".to_string()],
        jurisdictions: jurisdictions.iter().map(|j| (*j).to_string()).collect(),
        ..Default::default()
    };
    let fetched = FetchedSurface {
        kind: SurfaceKind::McpTools,
        raw: serde_json::json!({"tools": [{"name": "get_balance", "description": "Read a balance."}]}),
        source: "residency-test".to_string(),
    };
    // A fixed internal zone, so the zone escalation is constant across every call and the
    // only thing varying is the jurisdiction span.
    let zone = ZoneId::new("internal.payments").unwrap();
    let (tier, why) = admission::derive_tier(&declared, &fetched, &zone, rules);
    (tier.as_u8(), why)
}
