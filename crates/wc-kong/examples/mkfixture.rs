//! Write a contract, a route table and a config into a directory, for the Lua spec to load.
//!
//! The Lua suite needs a real signed contract, and minting one is Rust's job. Rather than teach
//! the spec to sign, or commit an artifact that expires, this mints a fresh one at run time —
//! the same way the ABI tests do, through the same public API.
//!
//! Usage: `cargo run -q --example mkfixture -- <dir> [k=v ...]`
//!
//! Keys: `caller`, `callee`, `tools` (comma separated), `served` (comma separated),
//! `served_file` (a JSON surface as the callee emits it, which overrides `served`),
//! `mediator`, `issuer`, `revoke_party` (writes a signed revocation delta for that party).
//! Everything has a default, so the Lua spec
//! passes only a directory and the drill overrides the identities it generated certificates
//! for.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::contract::{
    mint, Algorithm, Assurance, ContractPayload, IssuerKey, Party, Surface, Terms,
};
use wc_core::model::{Cid, EntityId, Jti, Tier, ZoneId};

const PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");
const KID: &str = "wc-test-es256";

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = std::path::PathBuf::from(args.next().expect("usage: mkfixture <dir> [k=v ...]"));
    let mut kv = std::collections::HashMap::new();
    for a in args {
        let (k, v) = a.split_once('=').expect("arguments are k=v");
        kv.insert(k.to_string(), v.to_string());
    }
    let get = |k: &str, d: &str| kv.get(k).cloned().unwrap_or_else(|| d.to_string());
    let list = |k: &str, d: &str| {
        get(k, d)
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    };

    let caller_id = get("caller", "spiffe://org/ns/agents/sa/recon-bot-7");
    let callee_id = get("callee", "spiffe://org/ns/tools/sa/payments-mcp");
    let mediator = get("mediator", "warden:mediator:kong-test");
    let issuer = get("issuer", "https://connect.internal");
    let tools = list("tools", "get_balance,list_transactions");
    let served_names = list("served", "get_balance,list_transactions,transfer_funds");

    std::fs::create_dir_all(&dir).unwrap();
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let callee = EntityId::new(&callee_id).unwrap();
    // The pin is over the surface the callee actually serves, schemas and all. A surface
    // invented here from names alone would mismatch the real server on the first catalogue and
    // read as drift — so a drill against a real upstream passes its emitted surface in.
    let served = match kv.get("served_file") {
        Some(p) => serde_json::from_str::<serde_json::Value>(
            &std::fs::read_to_string(p).expect("read served_file"),
        )
        .expect("served_file is JSON"),
        None => json!({
            "tools": served_names
                .iter()
                .map(|n| json!({"name": n, "description": format!("The {n} tool.")}))
                .collect::<Vec<_>>()
        }),
    };
    let pin = canon::pin(
        SurfaceKind::McpTools,
        &callee,
        &served,
        &Limits::default(),
        at,
    )
    .unwrap();
    let surface = Surface {
        tools: tools.clone(),
        skills: Vec::new(),
        resources: Vec::new(),
    };
    let digest = pin.surface_digest(&surface.items()).unwrap();
    let mut payload = ContractPayload::new(
        Cid::new("conn_7f3a91c4").unwrap(),
        Jti::new("cx_84be0011").unwrap(),
        &issuer,
        &mediator,
        Party {
            id: EntityId::new(&caller_id).unwrap(),
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
    payload.terms = Terms::default();
    payload.assurance = Assurance::default();

    let jws = mint(
        &payload,
        &IssuerKey::ec_pem(KID, PRIV, Algorithm::ES256).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("c.jws"), jws).unwrap();

    // A signed revocation delta, for a drill that needs to serve one without standing up a
    // whole control plane. The Envoy drill proves the plane end of containment; what this lets
    // a Kong drill prove is the BINDING end — that a worker's background refresher pulls the
    // feed, applies it, and that the request path sees the result.
    if let Some(party) = kv.get("revoke_party") {
        let feed_path = dir.join("feed.jsonl");
        let _ = std::fs::remove_file(&feed_path);
        let mut feed = wc_control::contain::RevocationFeed::open(&feed_path).unwrap();
        let signed = feed
            .append(
                wc_control::contain::Revoked::Party {
                    id: EntityId::new(party).unwrap(),
                },
                "drill: revocation reach",
                "human:drill@org",
                at,
                &IssuerKey::ec_pem(KID, PRIV, Algorithm::ES256).unwrap(),
            )
            .unwrap();
        let delta = json!({
            "since": 0,
            "head_seq": signed.event.seq,
            "head_digest": "sha256:drill",
            "events": [{ "event": signed.event, "jws": signed.jws, "kid": signed.kid }],
        });
        std::fs::write(
            dir.join("revocations.json"),
            serde_json::to_string(&delta).unwrap(),
        )
        .unwrap();
    }
    std::fs::write(
        dir.join("routes.toml"),
        format!("[[route]]\ncluster = \"payments\"\ncallee = \"{callee_id}\"\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("served.json"),
        serde_json::to_string(&served).unwrap(),
    )
    .unwrap();
    println!("{}", dir.display());
}
