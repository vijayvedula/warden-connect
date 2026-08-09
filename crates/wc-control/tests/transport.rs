//! What the transport must prove before a bearer token is believed (P0 #7).
//!
//! `connect serve` speaks plain HTTP on purpose — TLS is terminated in front of it in
//! every topology `docs/physical-architecture.md` describes. What was not on purpose
//! is that nothing stopped a non-loopback bind accepting approval tokens in clear: the
//! plan said a terminating proxy was mandatory and the binary had no opinion, which is
//! the shape of every other defect this repository has turned up.
//!
//! The requirement is now enforced per request rather than promised once at startup,
//! because a startup flag says only what an operator intended. `--behind-tls-proxy`
//! asserts termination happens in front; each authenticated request then has to carry
//! the evidence — an `X-Forwarded-Proto: https` from an address the operator named.
//!
//! Driven over a real socket, because the peer address comes from the accepted socket
//! and a handler-level test would have to invent it — which is exactly the thing being
//! checked.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use wc_control::api::{roles, Api, ControlPlane, Transport};
use wc_control::cpolicy::ConnectPolicy;
use wc_control::evidence::Evidence;
use wc_control::http::{self, Shutdown};
use wc_control::store::Store;
use wc_core::contract::{Algorithm, IssuerKey};
use wc_core::error::Code;

const ISSUER_PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");
const TOKEN: &str = "tok-reader";
static COUNTER: AtomicU32 = AtomicU32::new(0);

fn now() -> u64 {
    1_785_312_500
}

struct Rig {
    port: u16,
    shutdown: Arc<Shutdown>,
    dir: std::path::PathBuf,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.shutdown.request();
        // Unblock the accept loop so the thread notices, then clean up.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn rig(transport: Transport) -> Rig {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("wc-transport-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let (store, _) = Store::open(dir.join("state")).unwrap();
    let evidence = Evidence::open(dir.join("evidence")).unwrap();
    let signer = IssuerKey::ec_pem("k1", ISSUER_PRIV, Algorithm::ES256).unwrap();
    let policy =
        ConnectPolicy::parse("default = \"require_approval\"\nversion = \"t@v1\"\n").unwrap();

    let cp = ControlPlane::new(store, evidence, policy, signer, "https://c.internal", now)
        .with_transport(transport)
        .with_token(TOKEN, &[roles::READ]);

    let api = Arc::new(Api(Arc::new(cp)));
    let shutdown = Arc::new(Shutdown::default());
    let serve_shutdown = Arc::clone(&shutdown);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = http::serve("127.0.0.1:0", api, serve_shutdown, |addr| {
            let _ = tx.send(addr.port());
        });
    });
    let port = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the server must bind");

    Rig {
        port,
        shutdown,
        dir,
    }
}

/// `GET /v1/entities` with a bearer token and whatever extra headers a case needs.
fn status(port: u16, extra: &[(&str, &str)]) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut head = String::from("GET /v1/entities HTTP/1.1\r\nhost: localhost\r\n");
    head.push_str(&format!("Authorization: Bearer {TOKEN}\r\n"));
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("content-length: 0\r\n\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

// ===========================================================================

#[test]
fn loopback_admits_a_token_from_loopback() {
    // The default, and the baseline the rest of this file is measured against. If this
    // failed, every refusal below would be meaningless.
    let r = rig(Transport::Loopback);
    assert_eq!(status(r.port, &[]), 200);
}

#[test]
fn behind_a_proxy_a_request_that_did_not_come_through_it_is_refused() {
    // The actual attack: something already inside the network reaching the pod
    // directly rather than through the ingress. It has a valid token and no
    // `x-forwarded-proto`, because nothing forwarded it.
    let r = rig(Transport::TlsProxy {
        trusted: vec!["127.0.0.1".parse().unwrap()],
    });
    assert_eq!(
        status(r.port, &[]),
        401,
        "a token with no forwarding evidence must not authenticate"
    );
}

#[test]
fn behind_a_proxy_the_forwarded_request_is_admitted() {
    let r = rig(Transport::TlsProxy {
        trusted: vec!["127.0.0.1".parse().unwrap()],
    });
    assert_eq!(status(r.port, &[("X-Forwarded-Proto", "https")]), 200);
    // Header names are matched case-insensitively, so the proxy's choice of casing is
    // not a security-relevant detail.
    assert_eq!(status(r.port, &[("x-forwarded-proto", "HTTPS")]), 200);
}

#[test]
fn a_proxy_that_terminated_plaintext_is_refused() {
    // `x-forwarded-proto: http` means the credential crossed the network in clear
    // before it got here. The header being present is not the point; what it says is.
    let r = rig(Transport::TlsProxy {
        trusted: vec!["127.0.0.1".parse().unwrap()],
    });
    assert_eq!(status(r.port, &[("X-Forwarded-Proto", "http")]), 401);
}

#[test]
fn the_header_is_only_believed_from_the_named_address() {
    // Otherwise the control is a formality: anything that can reach the port can set
    // its own `x-forwarded-proto` and assert its own security. Same reasoning as
    // `wc_mediator::peer::MeshTrust` — a forwarding header is worth exactly as much as
    // the hop that set it.
    let r = rig(Transport::TlsProxy {
        trusted: vec!["10.9.9.9".parse().unwrap()],
    });
    assert_eq!(
        status(r.port, &[("X-Forwarded-Proto", "https")]),
        401,
        "the request came from loopback, not from the trusted proxy"
    );
}

#[test]
fn loopback_refuses_a_token_that_did_not_come_from_loopback() {
    // Not reachable over a loopback socket, so this asserts the decision function
    // directly. `describe` is the other half — a posture nobody can see is a posture
    // nobody checks, so it has to name what was chosen.
    let d = Transport::Loopback.describe();
    assert!(d.contains("loopback-only"), "{d}");
    assert!(d.contains("refused from off-box"), "{d}");

    let insecure = Transport::Insecure.describe();
    assert!(
        insecure.contains("INSECURE"),
        "the unsafe choice has to be loud in the banner: {insecure}"
    );

    // An empty trusted list is legitimate — a sidecar in its own network namespace —
    // but the operator has to be told what it means rather than left to assume.
    let any = Transport::TlsProxy { trusted: vec![] }.describe();
    assert!(any.contains("ANY source address"), "{any}");
}

#[test]
fn insecure_admits_anything_because_that_is_what_it_says() {
    // Offered deliberately: a test rig and a local demo are real, and an operator who
    // cannot say "yes I mean it" reaches for something worse. It is named so it appears
    // in the process list and in the startup banner.
    let r = rig(Transport::Insecure);
    assert_eq!(status(r.port, &[]), 200);
}

#[test]
fn an_unauthenticated_route_is_unaffected() {
    // The transport check hangs off token resolution, so `/healthz` — which needs no
    // credential — must still answer. A liveness probe that fails because of a
    // credential policy would take the pod down for the wrong reason.
    let r = rig(Transport::TlsProxy {
        trusted: vec!["10.9.9.9".parse().unwrap()],
    });
    let mut stream = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\n\r\n")
        .unwrap();
    stream.flush().unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "{}",
        &text[..40.min(text.len())]
    );
}

// ===========================================================================
// CIDR-scoped proxy trust
// ===========================================================================
//
// Exact addresses made the *strong* configuration unusable in two of the four topologies
// `docs/physical-architecture.md` documents: an AWS ALB answers from many addresses, and a
// Kubernetes Ingress pod gets a new one every restart. So an operator either enumerated
// addresses that changed underneath them or omitted `--trusted-proxy` — and omitting it
// believes the header from anywhere, which on a flat pod network restricts nothing.
//
// A control whose correct setting is impractical is a control everybody turns off. Found by
// putting a real terminating proxy in front of a real listener, not by reading the flag.

use wc_control::api::TrustedSource;

#[test]
fn a_cidr_block_admits_the_proxy_and_excludes_everything_else() {
    let net: TrustedSource = "10.0.1.0/24".parse().unwrap();
    assert!(
        net.contains("10.0.1.5".parse().unwrap()),
        "inside the block"
    );
    assert!(
        net.contains("10.0.1.255".parse().unwrap()),
        "the broadcast address is inside"
    );
    assert!(
        !net.contains("10.0.2.1".parse().unwrap()),
        "the next block is outside"
    );
    assert!(!net.contains("127.0.0.1".parse().unwrap()));
    assert_eq!(net.describe(), "10.0.1.0/24");
}

#[test]
fn a_host_bit_in_the_block_is_masked_rather_than_refused() {
    // `10.0.1.5/24` is what an operator types when they copy the proxy's address and add a
    // prefix. Refusing it would be pedantry; treating it as a /32 would silently narrow the
    // block to one address and break the next Ingress restart — the failure this whole
    // change exists to prevent.
    let net: TrustedSource = "10.0.1.5/24".parse().unwrap();
    assert_eq!(net.describe(), "10.0.1.0/24");
    assert!(net.contains("10.0.1.200".parse().unwrap()));
}

#[test]
fn a_slash_thirtytwo_is_exactly_one_address() {
    // The shift boundary: `u32::MAX << 0` must be all ones, not zero. A wrapping shift here
    // would make /32 match every address — the widest possible failure from the narrowest
    // possible config.
    let net: TrustedSource = "10.0.1.5/32".parse().unwrap();
    assert!(net.contains("10.0.1.5".parse().unwrap()));
    assert!(!net.contains("10.0.1.6".parse().unwrap()));
    assert!(!net.contains("10.0.2.5".parse().unwrap()));
}

#[test]
fn a_slash_zero_is_refused_because_it_reads_as_a_restriction() {
    // It parses, it looks like a policy, and it matches every address in existence. That is
    // exactly the defect class this repository keeps finding, so it is refused and the error
    // names the honest alternative.
    for raw in ["0.0.0.0/0", "10.0.1.0/0", "::/0"] {
        let err = raw.parse::<TrustedSource>().unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID, "{raw}");
        assert!(
            format!("{err}").contains("restricts nothing"),
            "{raw}: {err}"
        );
    }
}

#[test]
fn a_v4_address_does_not_match_a_v6_block_or_the_reverse() {
    // Masking alone would compare a mapped form and quietly say yes, which would let an
    // IPv4 client through a v6-only trust list.
    let v6: TrustedSource = "2001:db8::/32".parse().unwrap();
    assert!(v6.contains("2001:db8::1".parse().unwrap()));
    assert!(!v6.contains("10.0.1.5".parse().unwrap()));

    let v4: TrustedSource = "10.0.0.0/8".parse().unwrap();
    assert!(!v4.contains("2001:db8::1".parse().unwrap()));
}

#[test]
fn a_prefix_wider_than_the_address_is_refused() {
    for raw in ["10.0.1.0/33", "2001:db8::/129"] {
        let err = raw.parse::<TrustedSource>().unwrap_err();
        assert!(format!("{err}").contains("wider than"), "{raw}: {err}");
    }
}

#[test]
fn an_exact_address_still_works_and_is_still_exact() {
    // The existing behaviour, unchanged. Every test above this section uses it.
    let one: TrustedSource = "10.0.1.5".parse().unwrap();
    assert!(one.contains("10.0.1.5".parse().unwrap()));
    assert!(!one.contains("10.0.1.6".parse().unwrap()));
    assert_eq!(one.describe(), "10.0.1.5");
}

#[test]
fn a_request_from_inside_a_trusted_block_is_admitted_over_a_socket() {
    // The whole point, driven over a real socket: loopback is inside 127.0.0.0/8, so a
    // forwarded request is believed — which is how an operator would write it for an
    // Ingress whose address moves.
    let r = rig(Transport::TlsProxy {
        trusted: vec!["127.0.0.0/8".parse().unwrap()],
    });
    assert_eq!(status(r.port, &[("X-Forwarded-Proto", "https")]), 200);

    // And a block that excludes loopback still refuses it.
    let elsewhere = rig(Transport::TlsProxy {
        trusted: vec!["10.9.0.0/16".parse().unwrap()],
    });
    assert_eq!(
        status(elsewhere.port, &[("X-Forwarded-Proto", "https")]),
        401,
        "the request came from loopback, which is outside 10.9.0.0/16"
    );
}
