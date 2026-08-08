//! Federation against a **second** control plane (§8.16 P4, production-readiness P1 #9).
//!
//! Of the four §8.16 acceptance criteria that were never measured, this one mattered most:
//!
//! > *"federation is the claim that two organisations interoperate on two signed artifacts,
//! > and it has only ever been tested against itself."*
//!
//! That was accurate. `uc05_federation` in `e2e.rs` exercises the **partner-zone policy** —
//! the bar, the TTL ceiling, delegation depth — inside one estate holding one issuer key. It
//! never resolves a trust chain that another organisation actually signed, so a
//! `resolve` that quietly verified against the *local* issuer keys would have passed it.
//!
//! So these tests stand up two independent control planes:
//!
//! | | Org A (us) | Org B (the partner) |
//! |---|---|---|
//! | issuer key | `test_issuer_es256` | `test_anchor` — **a different keypair** |
//! | state root | its own | its own |
//! | role | holds B as a trust anchor, issues the contract | signs statements about its own parties |
//!
//! `a_statement_signed_by_our_own_key_is_not_a_partner` is the test that makes the rest
//! meaningful: it is the assertion that would fail if this were self-federation wearing two
//! names.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod harness;

use std::collections::BTreeMap;

use harness::*;
use wc_control::federate::{self, AnchorSet, EntityStatement, FederationMetadata, TrustAnchor};
use wc_core::canon::SurfaceKind;
use wc_core::contract::{Algorithm, IssuerKey};
use wc_core::error::Code;
use wc_core::model::Kind;

/// Org B's issuer key. **Not** the harness key — that is the whole point.
const B_PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_anchor_priv.pem");
const B_PUB: &str = include_str!("../../../fixtures/keys/test_anchor_pub.pem");

/// Org A's public key, so a test can try to pass our own signature off as a partner's.
const A_PUB: &str = include_str!("../../../fixtures/keys/test_issuer_es256_pub.pem");

const B_ENTITY: &str = "https://connect.acme.example/t/settlement";
const B_KID: &str = "acme-fed-1";
const PARTNER_AGENT: &str = "spiffe://acme.example/ns/agents/sa/fx-settlement";

/// Our own agent. Local to this file rather than shared, because these two identifiers are
/// the two sides of the boundary being tested and reading them together is the point.
const OUR_AGENT: &str = "spiffe://org/ns/agents/sa/recon";

fn jwks(kid: &str, pem: &str) -> BTreeMap<String, String> {
    [(kid.to_string(), pem.to_string())].into_iter().collect()
}

/// Sign a statement as some organisation.
fn sign_as(statement: &EntityStatement, kid: &str, priv_pem: &[u8]) -> String {
    let key = IssuerKey::ec_pem(kid, priv_pem, Algorithm::ES256).unwrap();
    wc_core::contract::sign_detached(statement, &key).unwrap()
}

/// What org B publishes about itself: a self-signed statement naming its keys and the
/// terms it claims for its parties.
fn b_statement(now: u64, metadata: FederationMetadata) -> EntityStatement {
    EntityStatement {
        iss: B_ENTITY.to_string(),
        sub: B_ENTITY.to_string(),
        iat: now - 60,
        exp: now + 30 * DAY,
        jwks: jwks(B_KID, B_PUB),
        metadata,
        authority_hints: Vec::new(),
    }
}

/// The ceiling org A configured for org B, out of band.
fn a_anchor_for_b(now: u64, metadata: FederationMetadata) -> AnchorSet {
    AnchorSet {
        anchors: vec![TrustAnchor {
            entity: B_ENTITY.to_string(),
            jwks: jwks(B_KID, B_PUB),
            metadata,
            verified_at: now - DAY,
            reverify_every: 90 * DAY,
        }],
    }
}

fn partner_meta(ttl: Option<u64>, depth: Option<u8>) -> FederationMetadata {
    FederationMetadata {
        zone: Some("partner.acme".to_string()),
        capabilities: ["fx.settlement.read".to_string()].into_iter().collect(),
        jurisdictions: ["SG".to_string()].into_iter().collect(),
        data_classes: ["financial".to_string()].into_iter().collect(),
        max_ttl_secs: ttl,
        max_delegation_depth: depth,
    }
}

// ===========================================================================
// 1 · The two control planes are genuinely two
// ===========================================================================

#[test]
fn the_two_organisations_hold_different_keys() {
    // Guards every other test in this file. If these keys were the same, everything below
    // would pass while testing nothing — which is exactly the state P1 #9 described.
    assert_ne!(
        A_PUB.trim(),
        B_PUB.trim(),
        "org A and org B must be two organisations, not one estate named twice"
    );

    // And a signature from one does not verify under the other's key set.
    let now = 1_785_312_500;
    let statement = b_statement(now, partner_meta(None, None));
    let signed_by_b = sign_as(&statement, B_KID, B_PRIV);

    let mut a_keys = wc_core::contract::IssuerKeys::new();
    a_keys
        .add_ec_pem(B_KID, A_PUB.as_bytes(), Algorithm::ES256)
        .unwrap();
    let as_json: Result<serde_json::Value, _> =
        wc_core::contract::verify_detached(&signed_by_b, B_KID, &a_keys);
    assert!(
        as_json.is_err(),
        "B's statement must not verify under A's key"
    );
}

// ===========================================================================
// 2 · A resolves a chain the partner actually signed
// ===========================================================================

#[test]
fn a_resolves_a_partner_chain_signed_by_the_partners_own_key() {
    let now = 1_785_312_500;
    let anchors = a_anchor_for_b(now, partner_meta(Some(7 * DAY), Some(1)));
    // The partner claims *less* than our anchor allows, which is the ordinary case.
    let chain = vec![sign_as(
        &b_statement(now, partner_meta(Some(DAY), Some(1))),
        B_KID,
        B_PRIV,
    )];

    let resolved = federate::resolve(&chain, &anchors, now, 0).expect("the chain must resolve");

    assert_eq!(resolved.anchor, B_ENTITY);
    assert_eq!(resolved.subject, B_ENTITY);
    assert!(!resolved.anchor_stale);
    assert!(resolved.may_issue(now));

    // Narrowing downward is honoured: the resolution is the tighter of the two.
    assert_eq!(resolved.metadata.max_ttl_secs, Some(DAY));
    assert_eq!(resolved.metadata.max_delegation_depth, Some(1));
    assert_eq!(resolved.zone().as_str(), "partner.acme");
    assert_eq!(resolved.chain_len, 1);
}

#[test]
fn a_partner_asking_for_more_than_its_anchor_allows_is_refused_not_quietly_narrowed() {
    // I expected this to narrow, the way `Terms::intersect` does on a contract. It refuses,
    // and refusing is the stronger choice: a statement asking for thirty days when the
    // anchor says seven is not a partner being generous with itself, it is a partner whose
    // published terms and our agreement **disagree** — and silently proceeding on our
    // reading of a disagreement is how two organisations end up with different beliefs
    // about the same relationship. Recorded here because the test asserted the weaker
    // behaviour first.
    let now = 1_785_312_500;
    let anchors = a_anchor_for_b(now, partner_meta(Some(7 * DAY), Some(1)));
    let chain = vec![sign_as(
        &b_statement(now, partner_meta(Some(30 * DAY), Some(5))),
        B_KID,
        B_PRIV,
    )];

    let err = federate::resolve(&chain, &anchors, now, 0).unwrap_err();
    assert_eq!(err.code(), Code::FEDERATION_METADATA_WIDENED);
    let text = format!("{err}");
    // Both violations named, not just the first: an operator fixing one and rediscovering
    // the other is two round trips with a partner.
    assert!(text.contains("max_ttl_secs"), "{text}");
    assert!(text.contains("max_delegation_depth"), "{text}");
}

#[test]
fn a_statement_signed_by_our_own_key_is_not_a_partner() {
    // **The test that makes this file worth having.** Federation had only ever been
    // exercised against one estate holding one key, so an implementation that verified a
    // partner's statement against the *local* issuer keys would have passed every existing
    // test. Here org B's identifier is claimed by a statement signed with org A's key.
    let now = 1_785_312_500;
    let anchors = a_anchor_for_b(now, partner_meta(Some(7 * DAY), Some(1)));

    // Signed by A's key, claiming to be B, and even naming B's real kid.
    let forged = sign_as(
        &b_statement(now, partner_meta(None, None)),
        B_KID,
        PRIV, // org A's private key — the harness one
    );

    let err = federate::resolve(&[forged], &anchors, now, 0)
        .expect_err("a statement we signed ourselves is not a partner's");
    assert_eq!(err.code(), Code::FEDERATION_CHAIN_INVALID);
}

#[test]
fn an_unanchored_organisation_is_refused_even_with_a_perfect_signature() {
    // B signs correctly for an identifier A has never exchanged keys with. The signature is
    // valid; the trust is absent. Those are different questions and the second one is the
    // one federation exists to answer.
    let now = 1_785_312_500;
    let anchors = a_anchor_for_b(now, partner_meta(None, None));

    let stranger = EntityStatement {
        iss: "https://connect.stranger.example/t/x".to_string(),
        sub: "https://connect.stranger.example/t/x".to_string(),
        ..b_statement(now, partner_meta(None, None))
    };
    let chain = vec![sign_as(&stranger, B_KID, B_PRIV)];

    let err = federate::resolve(&chain, &anchors, now, 0).unwrap_err();
    assert_eq!(err.code(), Code::FEDERATION_ANCHOR_UNKNOWN);
}

#[test]
fn a_stale_anchor_stops_new_issuance_and_says_so_rather_than_failing() {
    // UC-05 A2: the anchor was last confirmed out of band longer ago than its policy
    // allows. Existing contracts run to `exp`; new ones stop. Reported rather than fatal,
    // because which of those a caller does is the caller's decision.
    let now = 1_785_312_500;
    let mut anchors = a_anchor_for_b(now, partner_meta(None, None));
    anchors.anchors[0].verified_at = now - 200 * DAY;
    anchors.anchors[0].reverify_every = 90 * DAY;

    let chain = vec![sign_as(
        &b_statement(now, partner_meta(None, None)),
        B_KID,
        B_PRIV,
    )];
    let resolved = federate::resolve(&chain, &anchors, now, 0).expect("resolution still works");

    assert!(resolved.anchor_stale, "the staleness has to be visible");
    assert!(
        !resolved.may_issue(now),
        "and it has to stop issuance, or reporting it achieves nothing"
    );
}

#[test]
fn an_expired_statement_is_refused_because_a_resolution_is_no_fresher_than_its_links() {
    let now = 1_785_312_500;
    let anchors = a_anchor_for_b(now, partner_meta(None, None));
    let mut statement = b_statement(now, partner_meta(None, None));
    statement.exp = now - 1;

    let err =
        federate::resolve(&[sign_as(&statement, B_KID, B_PRIV)], &anchors, now, 0).unwrap_err();
    assert_eq!(err.code(), Code::FEDERATION_STATEMENT_EXPIRED);
}

// ===========================================================================
// 3 · End to end: A issues a contract to a party in B's estate
// ===========================================================================

#[test]
fn a_contract_to_a_resolved_partner_is_issued_under_our_key_and_bounded_by_our_bar() {
    // The full criterion: two organisations, two key sets, one signed artifact crossing
    // between them. B's statement establishes *who they are and on what terms*; A's
    // contract establishes *what may be reached*, and it is signed by A because A's
    // mediators are the ones that will verify it.
    let now = 1_785_312_500;
    let anchors = a_anchor_for_b(now, partner_meta(Some(7 * DAY), Some(1)));
    let chain = vec![sign_as(
        &b_statement(now, partner_meta(Some(7 * DAY), Some(1))),
        B_KID,
        B_PRIV,
    )];
    let resolved = federate::resolve(&chain, &anchors, now, 0).unwrap();
    assert!(resolved.may_issue(now));

    // Org A's own estate. The partner's agent is placed in the zone the *resolution*
    // named, not the zone the partner asked for.
    let mut a = Estate::new("fed-cross");
    let ours = a.register(
        OUR_AGENT,
        Kind::Agent,
        "internal.apac-ops",
        &agent_card(),
        SurfaceKind::A2aCard,
        Some("payments-recon"),
    );
    let theirs = a.register(
        PARTNER_AGENT,
        Kind::A2aAgent,
        resolved.zone().as_str(),
        &agent_card(),
        SurfaceKind::A2aCard,
        Some("fx-settlement"),
    );
    a.activate(&ours.id);
    a.activate(&theirs.id);

    // A partner connection reaches a human, whatever the resolution said.
    let outcome = a.request(&ours.id, &theirs.id, &["reconcile"], 30 * DAY);
    let pending = match outcome {
        wc_control::issuance::Outcome::AwaitingApproval(p) => p,
        other => panic!("a partner connection must reach a human: {other:?}"),
    };
    let issued = a.approve(&pending.id, &[cecil(), dana()]);

    // Signed by A, verifiable by A's mediators — and **not** by B's key. A contract a
    // partner could forge would make the whole federation pointless.
    let mut b_keys = wc_core::contract::IssuerKeys::new();
    b_keys
        .add_ec_pem(KID, B_PUB.as_bytes(), Algorithm::ES256)
        .unwrap();
    let opts = wc_core::contract::VerifyOpts::new(&b_keys, MEDIATOR, now);
    assert!(
        wc_core::contract::verify_artifact(&issued.artifacts[0].1, &opts).is_err(),
        "the partner's key must not verify our contract"
    );

    let ours_keys = verifier();
    let opts = wc_core::contract::VerifyOpts::new(&ours_keys, MEDIATOR, a.now);
    wc_core::contract::verify_artifact(&issued.artifacts[0].1, &opts)
        .expect("our own mediator must accept it");

    // The bar applied on top of the federation ceiling, which is the layering the design
    // claims: federation says whether they may be introduced, local policy says on what
    // terms, the contract says what may be reached.
    assert!(
        issued.record.terms.delegation.max_depth <= 1,
        "the partner-zone bar pins depth at 1: {}",
        issued.record.terms.delegation.max_depth
    );
    assert!(issued.record.exp - issued.record.iat <= 7 * DAY);
}

#[test]
fn a_partner_cannot_place_itself_in_one_of_our_internal_zones() {
    // The escalation that would matter most: a partner naming `internal.payments` as its
    // own zone and being treated as an internal party, which would put it inside every
    // same-trust-level rule instead of across a boundary.
    //
    // Refused rather than re-placed, and for once the stricter answer is also the simpler
    // one: a statement whose zone is outside its superior's is a disagreement about the
    // relationship, and there is no reading of it that is safe to act on.
    let now = 1_785_312_500;
    let anchors = a_anchor_for_b(now, partner_meta(None, None));
    let mut greedy = partner_meta(None, None);
    greedy.zone = Some("internal.payments".to_string());

    let err = federate::resolve(
        &[sign_as(&b_statement(now, greedy), B_KID, B_PRIV)],
        &anchors,
        now,
        0,
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::FEDERATION_METADATA_WIDENED);
    assert!(format!("{err}").contains("outside the superior"), "{err}");

    // And a partner that names no zone at all lands somewhere unmistakably external
    // rather than defaulting inwards.
    let mut silent = partner_meta(None, None);
    silent.zone = None;
    let resolved = federate::resolve(
        &[sign_as(&b_statement(now, silent), B_KID, B_PRIV)],
        &anchors,
        now,
        0,
    )
    .unwrap();
    assert!(
        resolved.zone().as_str().starts_with("partner."),
        "an unplaced partner is still a partner: {}",
        resolved.zone().as_str()
    );
}
