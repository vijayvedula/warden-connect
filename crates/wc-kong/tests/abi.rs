//! The ABI as Lua will call it.
//!
//! These go through the `extern "C"` symbols rather than the Rust types behind them, because
//! the thing under test is the boundary: null handling, ownership, and that a verdict survives
//! the trip out. A test written against `Filter` directly would pass whatever the ABI did.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use serde_json::{json, Value};
use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::contract::{
    mint, Algorithm, Assurance, ContractPayload, IssuerKey, Party, Surface, Terms,
};
use wc_core::model::{Cid, EntityId, Jti, Tier, ZoneId};
use wc_kong::{
    wc_contract_count, wc_free, wc_init, wc_on_request, wc_on_response_body,
    wc_on_response_headers, wc_out_free, wc_stream_free, wc_stream_new, WcOut, WC_BUFFER,
    WC_ERR_BADARG, WC_FORWARD, WC_REFUSE, WC_REWRITE,
};

const PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");
const PUB_PATH: &str = "../../fixtures/keys/test_issuer_es256_pub.pem";
const KID: &str = "wc-test-es256";
const MEDIATOR: &str = "warden:mediator:kong-test";
const ISS: &str = "https://connect.internal";
const CALLER: &str = "spiffe://org/ns/agents/sa/recon-bot-7";
const CALLEE: &str = "spiffe://org/ns/tools/sa/payments-mcp";
const TOOL_CALL: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance"}}"#;

/// A verified peer certificate whose single URI SAN is `CALLER`.
const CERT: &str = include_str!("../../../fixtures/keys/test_peer_spiffe.pem");
/// Two spiffe URI SANs — not a valid SVID.
const CERT_TWO: &str = include_str!("../../../fixtures/keys/test_peer_two_uris.pem");
/// A URI SAN that is not a spiffe id.
const CERT_HTTPS: &str = include_str!("../../../fixtures/keys/test_peer_not_spiffe.pem");

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// What the server actually serves. Three tools; the contract will cover two.
fn served() -> Value {
    json!({"tools":[
        {"name":"get_balance","description":"Read an account balance."},
        {"name":"list_transactions","description":"List recent transactions."},
        {"name":"transfer_funds","description":"Move money between accounts."}
    ]})
}

/// A signed contract over `tools` with `terms`, valid now.
fn jws_with(tools: &[&str], terms: Terms) -> String {
    let at = now();
    let callee = EntityId::new(CALLEE).unwrap();
    let pin = canon::pin(
        SurfaceKind::McpTools,
        &callee,
        &served(),
        &Limits::default(),
        at,
    )
    .unwrap();
    let surface = Surface {
        tools: tools.iter().map(|t| (*t).to_string()).collect(),
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
    payload.terms = terms;
    payload.assurance = Assurance::default();
    mint(
        &payload,
        &IssuerKey::ec_pem(KID, PRIV, Algorithm::ES256).unwrap(),
    )
    .unwrap()
}

/// A contract that expired an hour ago. Structurally valid, refused on its dates.
fn expired_jws() -> String {
    let at = now() - 7_200;
    let callee = EntityId::new(CALLEE).unwrap();
    let served = json!({"tools":[{"name":"get_balance","description":"Read an account balance."}]});
    let pin = canon::pin(
        SurfaceKind::McpTools,
        &callee,
        &served,
        &Limits::default(),
        at,
    )
    .unwrap();
    let surface = Surface {
        tools: vec!["get_balance".to_string()],
        skills: Vec::new(),
        resources: Vec::new(),
    };
    let digest = pin.surface_digest(&surface.items()).unwrap();
    let mut payload = ContractPayload::new(
        Cid::new("conn_deadbeef").unwrap(),
        Jti::new("cx_deadbeef01").unwrap(),
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
    payload.iat = at;
    payload.nbf = at;
    payload.exp = at + 3_600; // an hour after it was issued, which was two hours ago
    payload.surface = surface;
    payload.terms = Terms::default();
    payload.assurance = Assurance::default();
    mint(
        &payload,
        &IssuerKey::ec_pem(KID, PRIV, Algorithm::ES256).unwrap(),
    )
    .unwrap()
}

/// A private directory per test — shared paths across tests are a flake this repo has already
/// paid for once.
fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wc-kong-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Config JSON for a handle whose contract covers `tools` and whose route table maps `service`.
fn setup(name: &str, tools: &[&str], service: &str) -> String {
    setup_terms(name, tools, service, Terms::default())
}

fn setup_terms(name: &str, tools: &[&str], service: &str, terms: Terms) -> String {
    let d = dir(name);
    let cpath = d.join("c.jws");
    std::fs::write(&cpath, jws_with(tools, terms)).unwrap();
    let rpath = d.join("routes.toml");
    std::fs::write(
        &rpath,
        format!("[[route]]\ncluster = \"{service}\"\ncallee = \"{CALLEE}\"\n"),
    )
    .unwrap();
    json!({
        "contracts": [cpath.to_str().unwrap()],
        "routes": rpath.to_str().unwrap(),
        "issuer_pub": PUB_PATH,
        "kid": KID,
        "mediator_id": MEDIATOR,
        "issuer_id": ISS,
        "identity": "tls",
        "mode": "enforce"
    })
    .to_string()
}

/// Open a handle, or explain why not.
fn init(cfg: &str) -> Result<*mut wc_kong::config::Handle, String> {
    let mut err = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    // SAFETY: cfg lives for the call; err is a live WcOut.
    let h = unsafe { wc_init(cfg.as_ptr(), cfg.len(), &raw mut err) };
    if h.is_null() {
        // SAFETY: wc_init filled err on failure.
        let msg = unsafe {
            String::from_utf8_lossy(std::slice::from_raw_parts(err.ptr, err.len)).into_owned()
        };
        unsafe { wc_out_free(&raw mut err) };
        return Err(msg);
    }
    unsafe { wc_out_free(&raw mut err) };
    Ok(h)
}

/// A peer as Lua would report it: nginx verified the chain, and here is the chain.
fn peer(service: &str, cert: Option<&str>) -> String {
    json!({
        "tls_verify": cert.map(|_| "SUCCESS"),
        "cert_pem": cert,
        "remote": "10.0.0.7",
        "service": service
    })
    .to_string()
}

/// Drive one request frame through a fresh stream and return (verdict, body, code).
fn request(h: *mut wc_kong::config::Handle, p: &str, frame: &str) -> (i32, String, i32) {
    let mut err = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    // SAFETY: h is live; p lives for the call.
    let s = unsafe { wc_stream_new(h, p.as_ptr(), p.len(), &raw mut err) };
    unsafe { wc_out_free(&raw mut err) };
    assert!(!s.is_null(), "no contract is a verdict, not a null stream");
    let mut out = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    // SAFETY: s is live; frame lives for the call.
    let v = unsafe { wc_on_request(s, frame.as_ptr(), frame.len(), &raw mut out) };
    let body = if out.ptr.is_null() {
        String::new()
    } else {
        // SAFETY: filled by the call above.
        unsafe {
            String::from_utf8_lossy(std::slice::from_raw_parts(out.ptr, out.len)).into_owned()
        }
    };
    let code = out.code;
    unsafe {
        wc_out_free(&raw mut out);
        wc_stream_free(s);
    }
    (v, body, code)
}

// --- startup --------------------------------------------------------------

#[test]
fn a_handle_opens_and_counts_what_it_verified() {
    let h = init(&setup(
        "open",
        &["get_balance", "list_transactions"],
        "payments",
    ))
    .unwrap();
    // SAFETY: h is live.
    assert_eq!(unsafe { wc_contract_count(h) }, 1);
    unsafe { wc_free(h) };
}

#[test]
fn unparseable_config_refuses_to_start_and_says_so() {
    let e = init("{not json").unwrap_err();
    assert!(e.contains("config:"), "got {e}");
}

#[test]
fn no_contracts_refuses_to_start_rather_than_denying_everything_quietly() {
    let d = dir("nocontract");
    let rpath = d.join("routes.toml");
    std::fs::write(
        &rpath,
        format!("[[route]]\ncluster = \"payments\"\ncallee = \"{CALLEE}\"\n"),
    )
    .unwrap();
    let cfg = json!({
        "contracts": [], "routes": rpath.to_str().unwrap(),
        "issuer_pub": PUB_PATH, "kid": KID,
        "mediator_id": MEDIATOR, "issuer_id": ISS, "identity": "tls"
    })
    .to_string();
    let e = init(&cfg).unwrap_err();
    assert!(
        e.contains("denies every call"),
        "starting with no contracts must name the consequence, got: {e}"
    );
}

#[test]
fn a_missing_contract_file_names_the_path() {
    let d = dir("missingfile");
    let rpath = d.join("routes.toml");
    std::fs::write(
        &rpath,
        format!("[[route]]\ncluster = \"payments\"\ncallee = \"{CALLEE}\"\n"),
    )
    .unwrap();
    let cfg = json!({
        "contracts": ["/nonexistent/nope.jws"], "routes": rpath.to_str().unwrap(),
        "issuer_pub": PUB_PATH, "kid": KID,
        "mediator_id": MEDIATOR, "issuer_id": ISS, "identity": "tls"
    })
    .to_string();
    let e = init(&cfg).unwrap_err();
    assert!(e.contains("nope.jws"), "got {e}");
}

// --- the verdicts ---------------------------------------------------------

/// Verify the pin for this contract by passing a catalogue through one stream, the way any
/// real client does when it connects.
fn verify_pin(h: *mut wc_kong::config::Handle, p: &str) {
    let mut err = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    // SAFETY: h is live.
    let s = unsafe { wc_stream_new(h, p.as_ptr(), p.len(), &raw mut err) };
    unsafe { wc_out_free(&raw mut err) };
    let frame = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let mut out = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    let ct = "application/json";
    let body = json!({"jsonrpc":"2.0","id":1,"result": served()}).to_string();
    // SAFETY: s is live for all three phases.
    unsafe {
        assert_eq!(
            wc_on_request(s, frame.as_ptr(), frame.len(), &raw mut out),
            WC_BUFFER
        );
        wc_out_free(&raw mut out);
        assert_eq!(
            wc_on_response_headers(s, ct.as_ptr(), ct.len(), &raw mut out),
            WC_BUFFER
        );
        wc_out_free(&raw mut out);
        assert_eq!(
            wc_on_response_body(s, body.as_ptr(), body.len(), &raw mut out),
            WC_REWRITE
        );
        wc_out_free(&raw mut out);
        wc_stream_free(s);
    }
}

/// Gate 8 has not run yet on a stream that has seen no catalogue, and the pin is what bounds
/// surface drift. Forwarding here would admit a call against a surface nothing has checked.
#[test]
fn a_tool_call_before_any_catalogue_is_refused_because_the_pin_is_unverified() {
    let h = init(&setup("prepin", &["get_balance"], "payments")).unwrap();
    let (v, body, code) = request(
        h,
        &peer("payments", Some(CERT)),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance"}}"#,
    );
    assert_eq!(v, WC_REFUSE);
    assert_eq!(code, 1002, "WC-1002, the pin has not been verified");
    assert!(body.contains("WC-1002"), "got {body}");
    unsafe { wc_free(h) };
}

/// And once a catalogue has verified the pin for that contract, it forwards — including on a
/// different stream, because the ledger is keyed by contract and not by session.
#[test]
fn a_contracted_tool_is_forwarded_once_the_pin_is_verified() {
    let h = init(&setup(
        "forward",
        &["get_balance", "list_transactions"],
        "payments",
    ))
    .unwrap();
    let p = peer("payments", Some(CERT));
    verify_pin(h, &p);
    let (v, body, _) = request(
        h,
        &p,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance"}}"#,
    );
    assert_eq!(v, WC_FORWARD, "got {body}");
    assert!(body.is_empty(), "a forward carries no body");
    unsafe { wc_free(h) };
}

#[test]
fn an_uncontracted_tool_is_refused_with_the_code_lua_can_label() {
    let h = init(&setup("uncontracted", &["get_balance"], "payments")).unwrap();
    let p = peer("payments", Some(CERT));
    verify_pin(h, &p);
    let (v, body, code) = request(
        h,
        &p,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer_funds"}}"#,
    );
    assert_eq!(v, WC_REFUSE);
    assert_eq!(
        code, 4002,
        "the taxonomy code has to cross the ABI as a number"
    );
    let v: Value = serde_json::from_str(&body).expect("the refusal is a JSON-RPC frame");
    assert_eq!(v["error"]["data"]["code"], "WC-4002");
    unsafe { wc_free(h) };
}

#[test]
fn an_unmapped_route_refuses_and_does_not_fall_through() {
    let h = init(&setup("unmapped", &["get_balance"], "payments")).unwrap();
    let (v, _, code) = request(
        h,
        &peer("some-other-service", Some(CERT)),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance"}}"#,
    );
    assert_eq!(v, WC_REFUSE);
    assert_eq!(code, 4001);
    unsafe { wc_free(h) };
}

#[test]
fn an_absent_caller_identity_is_refused_not_treated_as_anonymous_but_allowed() {
    let h = init(&setup("nocaller", &["get_balance"], "payments")).unwrap();
    let (v, _, code) = request(
        h,
        &peer("payments", None),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance"}}"#,
    );
    assert_eq!(v, WC_REFUSE);
    assert_eq!(code, 4001);
    unsafe { wc_free(h) };
}

#[test]
fn a_batch_is_refused_through_the_abi_too() {
    let h = init(&setup("batch", &["get_balance"], "payments")).unwrap();
    let (v, body, _) = request(
        h,
        &peer("payments", Some(CERT)),
        r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance"}}]"#,
    );
    assert_eq!(v, WC_REFUSE);
    assert!(body.contains("batch"), "got {body}");
    unsafe { wc_free(h) };
}

/// nginx hands back nil once a body exceeds `client_body_buffer_size`. Treating that as an
/// empty body would forward exactly the largest requests unchecked.
#[test]
fn an_unreadable_body_is_refused_rather_than_read_as_no_tool_call() {
    let h = init(&setup("nobody", &["get_balance"], "payments")).unwrap();
    let p = peer("payments", Some(CERT));
    let mut err = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    // SAFETY: h is live.
    let s = unsafe { wc_stream_new(h, p.as_ptr(), p.len(), &raw mut err) };
    unsafe { wc_out_free(&raw mut err) };
    let mut out = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    // SAFETY: s is live; a null body is the case under test.
    let v = unsafe { wc_on_request(s, std::ptr::null(), 0, &raw mut out) };
    assert_eq!(
        v, WC_REFUSE,
        "a body nginx could not give us is not an empty one"
    );
    // SAFETY: filled above.
    let body = unsafe {
        String::from_utf8_lossy(std::slice::from_raw_parts(out.ptr, out.len)).into_owned()
    };
    assert!(body.contains("client_body_buffer_size"), "got {body}");
    unsafe {
        wc_out_free(&raw mut out);
        wc_stream_free(s);
        wc_free(h);
    }
}

// --- the catalogue path ---------------------------------------------------

#[test]
fn a_catalogue_request_buffers_and_its_response_is_filtered_to_the_contract() {
    let h = init(&setup(
        "catalogue",
        &["get_balance", "list_transactions"],
        "payments",
    ))
    .unwrap();
    let p = peer("payments", Some(CERT));
    let mut err = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    // SAFETY: h is live.
    let s = unsafe { wc_stream_new(h, p.as_ptr(), p.len(), &raw mut err) };
    unsafe { wc_out_free(&raw mut err) };

    let frame = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let mut out = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    // SAFETY: s is live.
    let v = unsafe { wc_on_request(s, frame.as_ptr(), frame.len(), &raw mut out) };
    assert_eq!(
        v, WC_BUFFER,
        "a catalogue must be buffered at the request phase — Kong decides buffering before it \
         proxies, so learning at the response phase would be too late"
    );
    unsafe { wc_out_free(&raw mut out) };

    let ct = "application/json";
    // SAFETY: s is live.
    let v = unsafe { wc_on_response_headers(s, ct.as_ptr(), ct.len(), &raw mut out) };
    assert_eq!(v, WC_BUFFER);
    unsafe { wc_out_free(&raw mut out) };

    let body = json!({"jsonrpc":"2.0","id":1,"result": served()}).to_string();
    // SAFETY: s is live.
    let v = unsafe { wc_on_response_body(s, body.as_ptr(), body.len(), &raw mut out) };
    assert_eq!(v, WC_REWRITE, "three tools served, two contracted");
    // SAFETY: filled above.
    let rewritten = unsafe {
        String::from_utf8_lossy(std::slice::from_raw_parts(out.ptr, out.len)).into_owned()
    };
    let parsed: Value = serde_json::from_str(&rewritten).expect("valid json");
    let names: Vec<&str> = parsed["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, vec!["get_balance", "list_transactions"]);
    assert!(
        !rewritten.contains("transfer_funds"),
        "the uncontracted tool must not survive the filter"
    );
    unsafe {
        wc_out_free(&raw mut out);
        wc_stream_free(s);
        wc_free(h);
    }
}

// --- the boundary itself --------------------------------------------------

#[test]
fn a_null_stream_is_a_bad_argument_not_a_crash() {
    let mut out = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    // SAFETY: passing null is the case under test.
    let v = unsafe { wc_on_request(std::ptr::null_mut(), b"{}".as_ptr(), 2, &raw mut out) };
    assert_eq!(v, WC_ERR_BADARG);
    assert!(v < 0, "the plugin refuses on any negative return");
    unsafe { wc_out_free(&raw mut out) };
}

// --- the header is part of the ABI ----------------------------------------

/// `include/wc_kong.h` is hand-written, which means it can drift from the Rust it describes —
/// and a drifted constant is not a compile error on either side, it is Lua acting on a verdict
/// that means something else. So the header is parsed and compared here.
#[test]
fn the_c_header_agrees_with_the_rust_it_describes() {
    let h = include_str!("../include/wc_kong.h");

    let define = |name: &str| -> i32 {
        let line = h
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("#define {name} ")))
            .unwrap_or_else(|| panic!("{name} is not defined in wc_kong.h"));
        let rest = line.split_whitespace().nth(2).expect("a value");
        rest.trim_matches(|c| c == '(' || c == ')')
            .parse()
            .unwrap_or_else(|e| panic!("{name} = {rest:?}: {e}"))
    };

    for (name, rust) in [
        ("WC_FORWARD", wc_kong::WC_FORWARD),
        ("WC_REFUSE", wc_kong::WC_REFUSE),
        ("WC_BUFFER", wc_kong::WC_BUFFER),
        ("WC_SKIP", wc_kong::WC_SKIP),
        ("WC_PASS", wc_kong::WC_PASS),
        ("WC_REWRITE", wc_kong::WC_REWRITE),
        ("WC_ERR_PANIC", wc_kong::WC_ERR_PANIC),
        ("WC_ERR_BADARG", wc_kong::WC_ERR_BADARG),
        ("WC_ERR_CONFIG", wc_kong::WC_ERR_CONFIG),
    ] {
        assert_eq!(
            define(name),
            rust,
            "{name} differs between wc_kong.h and Rust"
        );
    }

    for sym in [
        "wc_init",
        "wc_free",
        "wc_contract_count",
        "wc_version",
        "wc_stream_new",
        "wc_stream_free",
        "wc_on_request",
        "wc_on_response_headers",
        "wc_on_response_body",
        "wc_out_free",
        "wc_refusal",
    ] {
        assert!(
            h.contains(&format!("{sym}(")),
            "{sym} is exported but not declared in wc_kong.h"
        );
    }

    // The struct Lua reads field-by-field. A field added or reordered here silently changes
    // what `out.code` means on the Lua side.
    assert!(h.contains("uint8_t *ptr;"), "wc_out.ptr");
    assert!(h.contains("size_t   len;"), "wc_out.len");
    assert!(h.contains("int      code;"), "wc_out.code");
    assert_eq!(
        std::mem::size_of::<WcOut>(),
        std::mem::size_of::<*mut u8>() + std::mem::size_of::<usize>() + 8,
        "wc_out layout changed; wc_kong.h and the Lua ffi.cdef must change with it"
    );
}

// --- identity ------------------------------------------------------------
//
// Increment 2's `Peer` had a `caller` field, which meant anything able to reach the Lua plugin
// could state an identity. These are the tests that field could not have had.

/// A verified certificate for a different workload.
const CERT_OTHER: &str = include_str!("../../../fixtures/keys/test_peer_other_spiffe.pem");

fn cfg_with(name: &str, extra: Value) -> String {
    let mut v: Value = serde_json::from_str(&setup(name, &["get_balance"], "payments")).unwrap();
    let obj = v.as_object_mut().unwrap();
    for (k, val) in extra.as_object().unwrap() {
        if val.is_null() {
            obj.remove(k);
        } else {
            obj.insert(k.clone(), val.clone());
        }
    }
    v.to_string()
}

#[test]
fn config_without_an_identity_source_refuses_to_start() {
    let e = init(&cfg_with("noident", json!({ "identity": null }))).unwrap_err();
    assert!(e.contains("identity"), "got {e}");
}

#[test]
fn xfcc_without_a_mesh_origin_refuses_to_start() {
    let e = init(&cfg_with("xfccnoorigin", json!({ "identity": "xfcc" }))).unwrap_err();
    assert!(e.contains("mesh_origin"), "got {e}");
}

/// Two configured sources would mean an attacker who can suppress one selects the other.
#[test]
fn tls_with_a_mesh_origin_refuses_to_start_rather_than_ignoring_one() {
    let e = init(&cfg_with(
        "bothsources",
        json!({ "identity": "tls", "mesh_origin": "/tmp/mesh.sock" }),
    ))
    .unwrap_err();
    assert!(e.contains("Pick one source"), "got {e}");
}

#[test]
fn an_unverified_chain_is_not_an_identity_however_good_the_certificate_looks() {
    let h = init(&setup("unverified", &["get_balance"], "payments")).unwrap();
    for verdict in ["NONE", "FAILED:self signed certificate", ""] {
        let p = json!({
            "tls_verify": verdict, "cert_pem": CERT,
            "remote": "10.0.0.7", "service": "payments"
        })
        .to_string();
        let (v, _, code) = request(h, &p, TOOL_CALL);
        assert_eq!(v, WC_REFUSE, "ssl_client_verify={verdict:?} must not admit");
        assert_eq!(code, 4001);
    }
    unsafe { wc_free(h) };
}

#[test]
fn a_verified_certificate_carrying_two_spiffe_ids_is_refused() {
    let h = init(&setup("twoids", &["get_balance"], "payments")).unwrap();
    let (v, _, code) = request(h, &peer("payments", Some(CERT_TWO)), TOOL_CALL);
    assert_eq!(v, WC_REFUSE);
    assert_eq!(code, 4001);
    unsafe { wc_free(h) };
}

#[test]
fn a_verified_certificate_whose_uri_is_not_a_spiffe_id_is_refused() {
    let h = init(&setup("httpsid", &["get_balance"], "payments")).unwrap();
    let (v, _, code) = request(h, &peer("payments", Some(CERT_HTTPS)), TOOL_CALL);
    assert_eq!(v, WC_REFUSE);
    assert_eq!(code, 4001);
    unsafe { wc_free(h) };
}

/// The point of the whole increment: a certificate that is valid, verified and *someone else's*
/// resolves to no contract.
#[test]
fn a_different_verified_identity_gets_no_contract() {
    let h = init(&setup("otherid", &["get_balance"], "payments")).unwrap();
    let p = peer("payments", Some(CERT_OTHER));
    // Not even the catalogue, which is the frame a client sends first.
    let (v, _, code) = request(h, &p, r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
    assert_eq!(v, WC_REFUSE);
    assert_eq!(code, 4001);
    unsafe { wc_free(h) };
}

/// An earlier draft built the XFCC origin out of the configured `mesh_origin`, so the origin was
/// always the trusted one and the mesh check never failed — any client able to set the header
/// could assert any identity. This is the test that fails if that comes back.
#[test]
fn an_xfcc_header_from_an_untrusted_origin_is_refused() {
    let cfg = cfg_with(
        "xfccorigin",
        json!({ "identity": "xfcc", "mesh_origin": "/run/mesh/sidecar.sock" }),
    );
    let h = init(&cfg).unwrap();
    let xfcc = format!("URI={CALLER}");
    for remote in [
        "10.0.0.7",                // some TCP peer
        "unix:/tmp/attacker.sock", // a different socket
        "unix:",                   // no path at all
    ] {
        let p = json!({ "xfcc": xfcc, "remote": remote, "service": "payments" }).to_string();
        let (v, _, code) = request(h, &p, TOOL_CALL);
        assert_eq!(v, WC_REFUSE, "an XFCC from {remote} must not be believed");
        assert_eq!(code, 4001);
    }
    unsafe { wc_free(h) };
}

#[test]
fn an_xfcc_header_from_the_trusted_socket_is_believed() {
    let cfg = cfg_with(
        "xfccgood",
        json!({ "identity": "xfcc", "mesh_origin": "/run/mesh/sidecar.sock" }),
    );
    let h = init(&cfg).unwrap();
    let p = json!({
        "xfcc": format!("URI={CALLER}"),
        "remote": "unix:/run/mesh/sidecar.sock",
        "service": "payments"
    })
    .to_string();
    // Reaches the pin gate rather than the contract gate, which is how we know identity
    // resolved: WC-1002 is only reachable once a contract has been found.
    let (v, body, code) = request(h, &p, TOOL_CALL);
    assert_eq!(v, WC_REFUSE);
    assert_eq!(code, 1002, "expected the pin gate, not WC-4001. got {body}");
    unsafe { wc_free(h) };
}

/// And with `identity = "tls"` the header is not read at all, so setting it changes nothing.
#[test]
fn under_tls_identity_an_xfcc_header_is_ignored_not_used_as_a_fallback() {
    let h = init(&setup("nofallback", &["get_balance"], "payments")).unwrap();
    let p = json!({
        "tls_verify": "NONE",
        "xfcc": format!("URI={CALLER}"),
        "remote": "unix:/run/mesh/sidecar.sock",
        "service": "payments"
    })
    .to_string();
    let (v, _, code) = request(h, &p, TOOL_CALL);
    assert_eq!(
        v, WC_REFUSE,
        "a suppressed certificate must not promote the header"
    );
    assert_eq!(code, 4001);
    unsafe { wc_free(h) };
}

#[test]
fn wc_refusal_builds_the_same_frame_shape_as_a_real_verdict() {
    let mut out = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    let d = "a panic was caught at the FFI boundary";
    // SAFETY: d lives for the call; out is writable.
    let v = unsafe { wc_kong::wc_refusal(8004, d.as_ptr(), d.len(), &raw mut out) };
    assert_eq!(v, WC_REFUSE);
    assert_eq!(out.code, 8004);
    // SAFETY: filled above.
    let body = unsafe {
        String::from_utf8_lossy(std::slice::from_raw_parts(out.ptr, out.len)).into_owned()
    };
    let parsed: Value = serde_json::from_str(&body).expect("the fallback is a JSON-RPC frame");
    assert_eq!(parsed["error"]["data"]["code"], "WC-8004");
    assert_eq!(parsed["error"]["code"], -32001);
    assert!(body.contains(d));
    unsafe { wc_out_free(&raw mut out) };
}

/// A code the taxonomy does not know must not silently become a forward, and must not invent a
/// code either.
#[test]
fn an_unknown_refusal_code_becomes_config_invalid_not_a_forward() {
    let mut out = WcOut {
        ptr: std::ptr::null_mut(),
        len: 0,
        code: 0,
    };
    for bad in [0, -5, 9999, 70000] {
        // SAFETY: a null detail is explicitly allowed.
        let v = unsafe { wc_kong::wc_refusal(bad, std::ptr::null(), 0, &raw mut out) };
        assert_eq!(v, WC_REFUSE, "code {bad} must still refuse");
        assert_eq!(out.code, 8004, "code {bad} must map to WC-8004");
        unsafe { wc_out_free(&raw mut out) };
    }
}

/// An artifact that fails verification is dropped into `rejected`, and for a long time nothing
/// said so: two paths in, "1 contract(s) verified" out, and no line naming which failed. A count
/// that means less than it says is the same defect as a control that reads as configured and
/// does nothing, so the set reports the shortfall.
#[test]
fn a_rejected_artifact_is_reported_and_does_not_stop_the_others_verifying() {
    let d = dir("rejected");
    let good = d.join("good.jws");
    std::fs::write(&good, jws_with(&["get_balance"], Terms::default())).unwrap();

    // Expired an hour ago: verifies as a JWS, refuses as a contract.
    let stale = d.join("stale.jws");
    std::fs::write(&stale, expired_jws()).unwrap();

    let rpath = d.join("routes.toml");
    std::fs::write(
        &rpath,
        format!("[[route]]\ncluster = \"payments\"\ncallee = \"{CALLEE}\"\n"),
    )
    .unwrap();
    let cfg = json!({
        "contracts": [good.to_str().unwrap(), stale.to_str().unwrap()],
        "routes": rpath.to_str().unwrap(),
        "issuer_pub": PUB_PATH, "kid": KID,
        "mediator_id": MEDIATOR, "issuer_id": ISS, "identity": "tls"
    })
    .to_string();

    let h = init(&cfg).expect("one bad artifact must not cost the good one");
    // SAFETY: h is live.
    assert_eq!(
        unsafe { wc_contract_count(h) },
        1,
        "two artifacts in, one usable contract out"
    );
    unsafe { wc_free(h) };
}

// --- the decision trail ---------------------------------------------------

/// `terms.evidence` has been carried, narrowed and federated since the artifact was designed,
/// and nothing at runtime read it. These are the tests that field could not have had.
#[test]
fn every_verdict_reaches_the_trail_and_the_trail_verifies() {
    let d = dir("evidence");
    let trail = d.join("trail.jsonl");
    let _ = std::fs::remove_file(&trail);
    let mut cfg: Value =
        serde_json::from_str(&setup("evidence", &["get_balance"], "payments")).unwrap();
    cfg["evidence_path"] = json!(trail.to_str().unwrap());
    let h = init(&cfg.to_string()).unwrap();
    let p = peer("payments", Some(CERT));

    // A catalogue (allowed), then an uncontracted call (refused), then a batch (refused).
    verify_pin(h, &p);
    request(
        h,
        &p,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer_funds"}}"#,
    );
    request(h, &p, r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#);
    unsafe { wc_free(h) };

    let head = wc_mediator::evidence::verify(&trail).expect("the trail must verify");
    assert!(
        head.seq >= 3,
        "expected at least 3 records, got {}",
        head.seq
    );

    let text = std::fs::read_to_string(&trail).unwrap();
    assert!(
        text.contains("\"code\":\"WC-4002\""),
        "the refusal must be in the trail:\n{text}"
    );
    assert!(text.contains("\"decision\":\"deny\""), "{text}");
    assert!(
        text.contains("\"decision\":\"allow\""),
        "an allow is evidence too:\n{text}"
    );
    assert!(text.contains("\"tool\":\"transfer_funds\""), "{text}");
}

/// The record is what an auditor reads, so it has to carry the connection, not just the verdict.
#[test]
fn a_record_names_the_contract_the_caller_and_the_callee() {
    let d = dir("evidence-fields");
    let trail = d.join("trail.jsonl");
    let _ = std::fs::remove_file(&trail);
    let mut cfg: Value =
        serde_json::from_str(&setup("evidence-fields", &["get_balance"], "payments")).unwrap();
    cfg["evidence_path"] = json!(trail.to_str().unwrap());
    let h = init(&cfg.to_string()).unwrap();
    verify_pin(h, &peer("payments", Some(CERT)));
    unsafe { wc_free(h) };

    let text = std::fs::read_to_string(&trail).unwrap();
    for field in [
        "\"cid\":\"conn_7f3a91c4\"",
        "\"jti\":\"cx_84be0011\"",
        "\"caller\":\"spiffe://org/ns/agents/sa/recon-bot-7\"",
        "\"callee\":\"spiffe://org/ns/tools/sa/payments-mcp\"",
        "\"mode\":\"enforce\"",
    ] {
        assert!(text.contains(field), "missing {field} in:\n{text}");
    }
}

/// A caller with no contract is exactly who an auditor asks about, so the refusal is recorded
/// even though there are no terms to read a delivery mode from.
#[test]
fn a_refusal_with_no_contract_is_still_recorded() {
    let d = dir("evidence-nocontract");
    let trail = d.join("trail.jsonl");
    let _ = std::fs::remove_file(&trail);
    let mut cfg: Value =
        serde_json::from_str(&setup("evidence-nocontract", &["get_balance"], "payments")).unwrap();
    cfg["evidence_path"] = json!(trail.to_str().unwrap());
    let h = init(&cfg.to_string()).unwrap();
    let (v, _, code) = request(h, &peer("payments", None), TOOL_CALL);
    assert_eq!(v, WC_REFUSE);
    assert_eq!(code, 4001);
    unsafe { wc_free(h) };

    let text = std::fs::read_to_string(&trail).unwrap();
    assert!(text.contains("\"code\":\"WC-4001\""), "{text}");
    assert!(
        text.contains("\"cid\":\"\""),
        "no contract means an empty cid, not a missing row"
    );
    assert!(wc_mediator::evidence::verify(&trail).is_ok());
}

/// A trail that already does not verify must stop the worker starting, not be appended to.
#[test]
fn a_tampered_trail_stops_the_plugin_starting() {
    let d = dir("evidence-tampered");
    let trail = d.join("trail.jsonl");
    let _ = std::fs::remove_file(&trail);
    let mut cfg: Value =
        serde_json::from_str(&setup("evidence-tampered", &["get_balance"], "payments")).unwrap();
    cfg["evidence_path"] = json!(trail.to_str().unwrap());
    let h = init(&cfg.to_string()).unwrap();
    verify_pin(h, &peer("payments", Some(CERT)));
    unsafe { wc_free(h) };

    let text = std::fs::read_to_string(&trail).unwrap();
    std::fs::write(
        &trail,
        text.replace("\"decision\":\"allow\"", "\"decision\":\"deny\""),
    )
    .unwrap();

    let e = init(&cfg.to_string()).unwrap_err();
    assert!(e.contains("evidence"), "got {e}");
    assert!(
        e.contains("edited"),
        "the operator must be told what is wrong: {e}"
    );
}

/// Two workers appending to one file interleave two chains, and the result never verifies —
/// while every individual row still looks well-formed. That is not a corruption an operator
/// would spot, so it is refused at startup instead.
#[test]
fn a_trail_shared_by_several_workers_is_refused() {
    let d = dir("evidence-shared");
    let mut cfg: Value =
        serde_json::from_str(&setup("evidence-shared", &["get_balance"], "payments")).unwrap();
    cfg["evidence_path"] = json!(d.join("trail.jsonl").to_str().unwrap());
    cfg["workers"] = json!(4);
    let e = init(&cfg.to_string()).unwrap_err();
    assert!(e.contains("%w"), "the error must say how to fix it: {e}");
    assert!(e.contains("never verifies"), "{e}");

    // With %w it starts, and each worker lands on its own file.
    cfg["evidence_path"] = json!(d.join("trail-%w.jsonl").to_str().unwrap());
    cfg["worker_id"] = json!(3);
    let h = init(&cfg.to_string()).expect("a per-worker path is fine");
    unsafe { wc_free(h) };
    assert!(
        d.join("trail-3.jsonl").exists(),
        "worker 3 must write its own trail"
    );
}

/// `Cache::mark_used` was called only by the stdio gate, so the control plane's
/// re-certification view saw no traffic through either gateway binding — every contract enforced
/// at a gateway looked dormant, and the dormant view is what feeds a withdrawal decision.
#[test]
fn a_call_that_proceeds_is_reported_as_usage() {
    let h = init(&setup(
        "usage",
        &["get_balance", "list_transactions"],
        "payments",
    ))
    .unwrap();
    let p = peer("payments", Some(CERT));
    // SAFETY: h is live for the whole test.
    unsafe {
        assert!(
            (*h).contracts.cache().take_usage().is_empty(),
            "nothing has been called yet"
        );
        verify_pin(h, &p);
        let used = (*h).contracts.cache().take_usage();
        assert!(
            used.contains_key("conn_7f3a91c4"),
            "a forwarded call must report the connection as used, got {used:?}"
        );
        wc_free(h);
    }
}

/// And a refused call must NOT: a contract whose consumer connects on every deploy and is
/// refused every time is exactly the one a review should see as dormant.
#[test]
fn a_refused_call_is_not_reported_as_usage() {
    let h = init(&setup("usage-refused", &["get_balance"], "payments")).unwrap();
    let p = peer("payments", Some(CERT));
    verify_pin(h, &p);
    // SAFETY: h is live.
    unsafe {
        let _ = (*h).contracts.cache().take_usage();
    }
    let (v, _, code) = request(
        h,
        &p,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer_funds"}}"#,
    );
    assert_eq!(v, WC_REFUSE);
    assert_eq!(code, 4002);
    // SAFETY: h is live.
    unsafe {
        assert!(
            (*h).contracts.cache().take_usage().is_empty(),
            "a refusal is not usage"
        );
        wc_free(h);
    }
}
