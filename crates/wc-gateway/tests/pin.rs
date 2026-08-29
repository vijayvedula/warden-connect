//! Gate 8 through the gateway filter, against a real minted contract.
//!
//! These are integration tests rather than unit tests because the check they cover is
//! `VerifiedContract::check_pin`, and a stub contract would be testing a stub. The first
//! version of this code compared the presented *manifest* digest to the contract's, which
//! passed every unit test written against a fixture that pinned the whole catalogue and would
//! have refused every real contract — the digest is over exactly the contracted items, so it
//! mismatches the moment a callee serves more tools than are contracted. That is the normal
//! case, and it is why this test mints a contract for a SUBSET.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use serde_json::{json, Value};
use warden_connect_gateway::{BodyAction, Filter, FilterCfg, PinLedger, Verdict};
use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::contract::{
    mint, verify_artifact, Algorithm, Assurance, ContractPayload, IssuerKey, IssuerKeys, Party,
    Surface, Terms, VerifiedContract, VerifyOpts,
};
use wc_core::error::{Code, Mode};
use wc_core::model::{Cid, EntityId, Jti, Tier, ZoneId};

const PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");
const PUB: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_pub.pem");
const KID: &str = "wc-test-es256";
const MEDIATOR: &str = "warden:mediator:gateway-test";
const ISS: &str = "https://connect.internal";
const NOW: u64 = 1_800_000_000;

fn callee() -> EntityId {
    EntityId::new("spiffe://org/ns/tools/sa/payments-mcp").unwrap()
}

/// The three tools the server actually serves.
fn served() -> Value {
    json!({"tools":[
        {"name":"get_balance","description":"Read an account balance."},
        {"name":"list_transactions","description":"List recent transactions."},
        {"name":"wire_funds","description":"Move money between accounts."}
    ]})
}

fn pin_of(catalogue: &Value) -> wc_core::model::Pin {
    canon::pin(
        SurfaceKind::McpTools,
        &callee(),
        catalogue,
        &Limits::default(),
        NOW,
    )
    .unwrap()
}

/// A contract over `tools`, pinned against the surface the server presents in `catalogue`.
fn contract(tools: &[&str], catalogue: &Value) -> Arc<VerifiedContract> {
    let pin = pin_of(catalogue);
    let surface = Surface {
        tools: tools.iter().map(|t| (*t).to_string()).collect(),
        skills: Vec::new(),
        resources: Vec::new(),
    };
    // Over the contracted subset only — the whole point.
    let digest = pin.surface_digest(&surface.items()).unwrap();

    let mut payload = ContractPayload::new(
        Cid::new("conn_7f3a91c4").unwrap(),
        Jti::new("cx_84be0011").unwrap(),
        ISS,
        MEDIATOR,
        Party {
            id: EntityId::new("spiffe://org/ns/agents/sa/recon-bot-7").unwrap(),
            zone: ZoneId::new("internal.apac-ops").unwrap(),
            tier: Tier::TWO,
            card: None,
            manifest: None,
            surface_digest: None,
        },
        Party {
            id: callee(),
            zone: ZoneId::new("internal.payments").unwrap(),
            tier: Tier::TWO,
            card: None,
            manifest: Some(pin.manifest.clone()),
            surface_digest: Some(digest),
        },
    );
    payload.iat = NOW - 100;
    payload.nbf = NOW - 100;
    payload.exp = NOW + 3_600;
    payload.surface = surface;
    payload.terms = Terms::default();
    payload.assurance = Assurance::default();

    let jws = mint(
        &payload,
        &IssuerKey::ec_pem(KID, PRIV, Algorithm::ES256).unwrap(),
    )
    .unwrap();
    let mut keys = IssuerKeys::new();
    keys.add_ec_pem(KID, PUB, Algorithm::ES256).unwrap();
    Arc::new(
        verify_artifact(
            &jws,
            &VerifyOpts {
                keys: &keys,
                mediator_id: MEDIATOR,
                expected_iss: Some(ISS),
                now: NOW,
                leeway: 0,
                revoked: &wc_core::contract::NoRevocations,
            },
        )
        .unwrap(),
    )
}

fn admitted(items: &[&str]) -> wc_core::contract::Admitted {
    wc_core::contract::Admitted {
        cid: Cid::new("conn_7f3a91c4").unwrap(),
        jti: Jti::new("cx_84be0011").unwrap(),
        items: items.iter().map(|s| (*s).to_string()).collect(),
        resources: Vec::new(),
        terms: Terms::default(),
        exp: u64::MAX,
        findings: Vec::new(),
    }
}

fn cfg(pins: Option<Arc<PinLedger>>, pin_max_age: u64) -> FilterCfg {
    FilterCfg {
        mode: Mode::Enforce,
        callee: callee(),
        pins,
        pin_max_age,
    }
}

fn filter_for(tools: &[&str], catalogue: &Value) -> Filter {
    Filter::new(
        vec![(admitted(tools), Some(contract(tools, catalogue)))],
        NOW,
        &cfg(None, 0),
    )
}

fn run(f: &mut Filter, catalogue: &Value) -> BodyAction {
    f.on_request("tools/list", &json!({}));
    let body = json!({"jsonrpc":"2.0","id":1,"result": catalogue});
    f.on_response_body(body.to_string().as_bytes())
}

#[test]
fn a_contract_over_a_subset_verifies_against_the_full_surface() {
    // The case the earlier implementation got wrong: the server serves three tools, the
    // contract covers one, and the pin must still verify.
    let mut f = filter_for(&["get_balance"], &served());
    let BodyAction::Rewrite(frame) = run(&mut f, &served()) else {
        panic!("a valid subset contract was refused — the pin is being compared wrongly");
    };
    let names: Vec<&str> = frame["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["get_balance"], "the catalogue was not filtered");
}

#[test]
fn a_contracted_tool_that_the_callee_dropped_is_refused_with_3108() {
    // Drift: the contract covers `get_balance` and the callee stopped serving it.
    let mut f = filter_for(&["get_balance"], &served());
    let shrunk = json!({"tools":[
        {"name":"list_transactions","description":"List recent transactions."},
        {"name":"wire_funds","description":"Move money between accounts."}
    ]});
    match run(&mut f, &shrunk) {
        BodyAction::Refuse { code, .. } => assert_eq!(code, Code::PIN_MISMATCH),
        other => panic!("a dropped contracted tool was served: {other:?}"),
    }
}

#[test]
fn a_reworded_description_moves_the_pin() {
    // The digest covers descriptions. A provider editing wording without regenerating the
    // surface breaks the pin, and that is intended.
    let mut f = filter_for(&["get_balance"], &served());
    let reworded = json!({"tools":[
        {"name":"get_balance","description":"Read an account balance TODAY."},
        {"name":"list_transactions","description":"List recent transactions."},
        {"name":"wire_funds","description":"Move money between accounts."}
    ]});
    assert!(
        matches!(
            run(&mut f, &reworded),
            BodyAction::Refuse {
                code: Code::PIN_MISMATCH,
                ..
            }
        ),
        "a reworded contracted tool passed the pin"
    );
}

#[test]
fn a_stream_with_no_contract_does_not_silently_pass_a_catalogue() {
    // No contract means no admitted connection, so there is nothing to filter against and the
    // request never reaches the catalogue phase in the first place.
    let mut f = Filter::new(Vec::new(), NOW, &cfg(None, 0));
    assert_eq!(
        f.on_request("tools/list", &json!({})),
        warden_connect_gateway::Verdict::Refuse {
            code: Code::NO_CONTRACT,
            detail: "no contract for this caller and callee".to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// The ledger: gate 8 for streams that carry no catalogue of their own
// ---------------------------------------------------------------------------

fn filter_with_ledger(
    tools: &[&str],
    catalogue: &Value,
    ledger: &Arc<PinLedger>,
    max_age: u64,
    now: u64,
) -> Filter {
    let mut a = admitted(tools);
    a.jti = Jti::new("cx_84be0011").unwrap();
    Filter::new(
        vec![(a, Some(contract(tools, catalogue)))],
        now,
        &cfg(Some(Arc::clone(ledger)), max_age),
    )
}

fn a_call() -> (String, Value) {
    (
        "tools/call".to_string(),
        json!({"name": "get_balance", "arguments": {}}),
    )
}

#[test]
fn a_tool_call_is_refused_until_a_catalogue_has_pinned_the_contract() {
    // The gap this closes: a client that never calls tools/list was never checked against the
    // pin at all, so the callee could have changed its surface and nothing would notice.
    let ledger = Arc::new(PinLedger::new());
    let mut f = filter_with_ledger(&["get_balance"], &served(), &ledger, 0, NOW);
    let (m, p) = a_call();
    match f.on_request(&m, &p) {
        Verdict::Refuse { code, .. } => assert_eq!(code, Code::SURFACE_UNOBTAINABLE),
        Verdict::Forward => panic!("an unpinned contract admitted a tool call"),
    }

    // A catalogue passes on another stream, on the same contract.
    let mut lister = filter_with_ledger(&["get_balance"], &served(), &ledger, 0, NOW);
    assert!(matches!(
        run(&mut lister, &served()),
        BodyAction::Rewrite(_)
    ));

    // Now the tool call is admitted — the evidence reaches every stream on that contract.
    let mut after = filter_with_ledger(&["get_balance"], &served(), &ledger, 0, NOW);
    assert_eq!(after.on_request(&m, &p), Verdict::Forward);
}

#[test]
fn a_mismatched_catalogue_does_not_mark_the_contract_pinned() {
    // Otherwise one bad catalogue would unlock every later tool call on that contract.
    let ledger = Arc::new(PinLedger::new());
    let mut lister = filter_with_ledger(&["get_balance"], &served(), &ledger, 0, NOW);
    let moved = json!({"tools":[
        {"name":"get_balance","description":"Read an account balance CHANGED."},
        {"name":"list_transactions","description":"List recent transactions."},
        {"name":"wire_funds","description":"Move money between accounts."}
    ]});
    assert!(matches!(
        run(&mut lister, &moved),
        BodyAction::Refuse { .. }
    ));
    assert!(
        ledger.verified_at("cx_84be0011").is_none(),
        "a mismatched catalogue marked the contract pinned"
    );
}

#[test]
fn a_pin_verified_too_long_ago_stops_counting() {
    let ledger = Arc::new(PinLedger::new());
    let mut lister = filter_with_ledger(&["get_balance"], &served(), &ledger, 60, NOW);
    assert!(matches!(
        run(&mut lister, &served()),
        BodyAction::Rewrite(_)
    ));

    // Inside the window.
    let mut fresh = filter_with_ledger(&["get_balance"], &served(), &ledger, 60, NOW + 59);
    assert_eq!(fresh.on_request(&a_call().0, &a_call().1), Verdict::Forward);

    // Past it.
    let mut stale = filter_with_ledger(&["get_balance"], &served(), &ledger, 60, NOW + 61);
    assert!(matches!(
        stale.on_request(&a_call().0, &a_call().1),
        Verdict::Refuse {
            code: Code::SURFACE_UNOBTAINABLE,
            ..
        }
    ));
}

#[test]
fn a_max_age_of_zero_means_a_pin_never_expires() {
    let ledger = Arc::new(PinLedger::new());
    let mut lister = filter_with_ledger(&["get_balance"], &served(), &ledger, 0, NOW);
    assert!(matches!(
        run(&mut lister, &served()),
        BodyAction::Rewrite(_)
    ));
    let mut much_later =
        filter_with_ledger(&["get_balance"], &served(), &ledger, 0, NOW + 10_000_000);
    assert_eq!(
        much_later.on_request(&a_call().0, &a_call().1),
        Verdict::Forward
    );
}

#[test]
fn no_ledger_means_the_requirement_is_off_entirely() {
    // The documented escape for an estate whose clients never list tools. Everything else is
    // still enforced; only gate 8 on catalogue-less streams is given up.
    let mut f = Filter::new(
        vec![(
            admitted(&["get_balance"]),
            Some(contract(&["get_balance"], &served())),
        )],
        NOW,
        &cfg(None, 0),
    );
    assert_eq!(f.on_request(&a_call().0, &a_call().1), Verdict::Forward);
}

#[test]
fn the_ledger_does_not_let_one_contract_vouch_for_another() {
    // Keyed by jti, not by callee. Two contracts over different subsets of the same callee
    // carry different digests, and verifying one says nothing about the other.
    let ledger = Arc::new(PinLedger::new());
    ledger.record("cx_a_different_contract", NOW);
    let mut f = filter_with_ledger(&["get_balance"], &served(), &ledger, 0, NOW);
    assert!(matches!(
        f.on_request(&a_call().0, &a_call().1),
        Verdict::Refuse {
            code: Code::SURFACE_UNOBTAINABLE,
            ..
        }
    ));
}

#[test]
fn a_detected_mismatch_revokes_an_earlier_verification() {
    // The order that matters: verified, then the callee drifts, then a client lists and gets
    // WC-3108. If the earlier record survived, tool calls would keep flowing on a contract
    // whose callee has demonstrably moved — drift detected and then ignored.
    let ledger = Arc::new(PinLedger::new());
    let mut lister = filter_with_ledger(&["get_balance"], &served(), &ledger, 0, NOW);
    assert!(matches!(
        run(&mut lister, &served()),
        BodyAction::Rewrite(_)
    ));
    assert!(ledger.verified_at("cx_84be0011").is_some());

    let moved = json!({"tools":[
        {"name":"get_balance","description":"Read an account balance CHANGED."},
        {"name":"list_transactions","description":"List recent transactions."},
        {"name":"wire_funds","description":"Move money between accounts."}
    ]});
    let mut again = filter_with_ledger(&["get_balance"], &served(), &ledger, 0, NOW + 1);
    assert!(matches!(run(&mut again, &moved), BodyAction::Refuse { .. }));
    assert!(
        ledger.verified_at("cx_84be0011").is_none(),
        "a detected mismatch left the earlier verification standing"
    );

    // And a tool call is refused from now on.
    let mut after = filter_with_ledger(&["get_balance"], &served(), &ledger, 0, NOW + 2);
    assert!(matches!(
        after.on_request(&a_call().0, &a_call().1),
        Verdict::Refuse {
            code: Code::SURFACE_UNOBTAINABLE,
            ..
        }
    ));
}
