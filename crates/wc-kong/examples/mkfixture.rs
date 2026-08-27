//! Write a contract, a route table and a config into a directory, for the Lua spec to load.
//!
//! The Lua suite needs a real signed contract, and minting one is Rust's job. Rather than teach
//! the spec to sign, or commit an artifact that expires, this mints a fresh one at run time —
//! the same way the ABI tests do, through the same public API.
//!
//! Usage: `cargo run -q --example mkfixture -- <dir>`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::contract::{
    mint, Algorithm, Assurance, ContractPayload, IssuerKey, Party, Surface, Terms,
};
use wc_core::model::{Cid, EntityId, Jti, Tier, ZoneId};

const PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");
const KID: &str = "wc-test-es256";
const MEDIATOR: &str = "warden:mediator:kong-test";
const ISS: &str = "https://connect.internal";
const CALLER: &str = "spiffe://org/ns/agents/sa/recon-bot-7";
const CALLEE: &str = "spiffe://org/ns/tools/sa/payments-mcp";

fn main() {
    let dir = std::env::args().nth(1).expect("usage: mkfixture <dir>");
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();

    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let callee = EntityId::new(CALLEE).unwrap();
    let served = json!({"tools":[
        {"name":"get_balance","description":"Read an account balance."},
        {"name":"list_transactions","description":"List recent transactions."},
        {"name":"transfer_funds","description":"Move money between accounts."}
    ]});
    let pin = canon::pin(
        SurfaceKind::McpTools,
        &callee,
        &served,
        &Limits::default(),
        at,
    )
    .unwrap();
    let surface = Surface {
        tools: vec!["get_balance".into(), "list_transactions".into()],
        skills: Vec::new(),
        resources: Vec::new(),
    };
    let digest = pin.surface_digest(&surface.items()).unwrap();
    let mut payload = ContractPayload::new(
        Cid::new("conn_7f3a91c4").unwrap(),
        Jti::new("cx_84be0011").unwrap(),
        ISS,
        MEDIATOR,
        Party {
            id: EntityId::new(CALLER).unwrap(),
            zone: ZoneId::new("internal.apac-ops").unwrap(),
            tier: Tier::TWO,
            card: None,
            manifest: None,
            surface_digest: None,
        },
        Party {
            id: callee,
            zone: ZoneId::new("internal.payments").unwrap(),
            tier: Tier::TWO,
            card: None,
            manifest: Some(pin.manifest.clone()),
            surface_digest: Some(digest),
        },
    );
    payload.iat = at - 100;
    payload.nbf = at - 100;
    payload.exp = at + 3_600;
    payload.surface = surface;
    // Bounded on purpose: the Lua suite has to exercise the acknowledgement, and a fixture
    // with no ceiling would leave that path untested in the binding that has the problem.
    payload.terms = Terms {
        max_calls_per_hour: Some(10),
        max_concurrent: Some(3),
        ..Terms::default()
    };
    payload.assurance = Assurance::default();

    let jws = mint(
        &payload,
        &IssuerKey::ec_pem(KID, PRIV, Algorithm::ES256).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("c.jws"), jws).unwrap();
    std::fs::write(
        dir.join("routes.toml"),
        format!("[[route]]\ncluster = \"payments\"\ncallee = \"{CALLEE}\"\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("served.json"),
        serde_json::to_string(&served).unwrap(),
    )
    .unwrap();
    println!("{}", dir.display());
}
