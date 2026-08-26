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
use warden_connect_gateway::{BodyAction, Filter};
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

fn filter_for(tools: &[&str], catalogue: &Value) -> Filter {
    Filter::new(
        Some(admitted(tools)),
        Mode::Enforce,
        Some(contract(tools, catalogue)),
        callee(),
        NOW,
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
    let mut f = Filter::new(None, Mode::Enforce, None, callee(), NOW);
    assert_eq!(
        f.on_request("tools/list", &json!({})),
        warden_connect_gateway::Verdict::Refuse {
            code: Code::NO_CONTRACT,
            detail: "no contract for this caller and callee".to_string()
        }
    );
}
