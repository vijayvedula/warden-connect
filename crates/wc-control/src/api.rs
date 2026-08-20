//! The control-plane HTTP surface (`docs/08-lld.md` §8.5.10).
//!
//! Everything the CLI does, over `/v1` — so CI, a portal and the mediators do not
//! have to shell out. Plus the two endpoints the data plane needs: a contract-set
//! delta to pull, and an ACK to post back.
//!
//! # Authentication
//!
//! Bearer tokens mapped to roles, from configuration. Deliberately simple and
//! deliberately explicit: the LLD's end state is a verified Warden session token
//! with an AuthZEN passthrough (§7.6), and pretending a half-built JWT scheme is
//! that would be worse than naming the gap. What *is* final is the shape — every
//! route declares the role it needs, and an unauthenticated request never reaches a
//! handler.
//!
//! # Idempotency
//!
//! Every mutating route requires an `Idempotency-Key`. A replay with the same key
//! and the same body returns the first response; the same key with a *different*
//! body is a conflict, because that is a client bug rather than a retry.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde_json::{json, Value};

use wc_core::contract::{ContractStatus, IssuerKey, Surface, Terms};
use wc_core::error::{Code, Mode, Result, WcError};
use wc_core::model::{Entity, EntityId, HumanRef, Lifecycle, Posture};
use wc_core::util::sha256_hex;

use crate::cpolicy::ConnectPolicy;
use crate::evidence::Evidence;
use crate::http::{self, Request, Response};
use crate::issuance::{
    ApprovalProof, ApproverRegistry, Issued, Issuer, Outcome, PendingRequest, RequestInput,
    RequestStatus,
};
use crate::store::{Actor, Store};

/// Roles the surface recognises.
pub mod roles {
    /// Read the estate.
    pub const READ: &str = "connect.read";
    /// Register and admit parties.
    pub const REGISTER: &str = "connect.register";
    /// Request and renew connections.
    pub const REQUEST: &str = "connect.request";
    /// Approve or deny a request.
    pub const APPROVE: &str = "connect.approve";
    /// Contain a party.
    pub const SECOPS: &str = "connect.secops";
    /// Pull contract sets and post acknowledgements.
    pub const MEDIATOR: &str = "connect.mediator";
    /// Produce registers and evidence exports.
    pub const COMPLIANCE: &str = "connect.compliance";
}

/// How long an idempotency record is kept.
pub const IDEMPOTENCY_TTL_SECS: u64 = 24 * 3_600;

/// A caller's identity and authority.
#[derive(Debug, Clone)]
pub struct Caller {
    /// Who they are.
    pub subject: String,
    /// What they may do.
    pub roles: Vec<String>,
}

impl Caller {
    /// Whether this caller holds a role.
    #[must_use]
    pub fn holds(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// Request counters, rendered at `/metrics`.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Requests served.
    pub requests: AtomicU64,
    /// Requests refused for lack of a role or a token.
    pub denied: AtomicU64,
    /// Contracts minted.
    pub minted: AtomicU64,
    /// Requests routed to a human.
    pub escalated: AtomicU64,
    /// Idempotent replays served from the cache.
    pub replays: AtomicU64,
    /// Contract-set pulls served.
    pub pulls: AtomicU64,
    /// Credentials refused because the transport could not be trusted.
    pub transport_refused: AtomicU64,
}

impl Metrics {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Everything a request handler needs.
pub struct ControlPlane {
    /// State, single-writer behind a mutex.
    pub store: Mutex<Store>,
    /// The evidence chain.
    pub evidence: Mutex<Evidence>,
    /// Connection policy, swappable for a hot reload.
    pub policy: RwLock<Arc<ConnectPolicy>>,
    /// Contract signing key.
    pub signer: IssuerKey,
    /// Who may approve.
    pub approvers: ApproverRegistry,
    /// Issuer URL stamped into artifacts.
    pub iss: String,
    /// Enforce or observe.
    pub mode: Mode,
    /// Bearer token → roles.
    pub tokens: HashMap<String, Vec<String>>,
    /// What the transport must prove before a bearer token is believed.
    pub transport: Transport,
    /// Public JWKS served at `/v1/jwks.json`, as pre-rendered JSON.
    pub jwks: String,
    /// Mediator acknowledgements of the **contract set**, and where they are persisted.
    ///
    /// This used to be a bare `Mutex<HashMap<_, _>>` that was never loaded or saved, so a
    /// control-plane restart zeroed it — and a deploy gate built on it would have blocked every
    /// deploy until every mediator happened to refresh. The in-memory copy is still the hot one
    /// (a mediator acks on every poll), and it is written through so a restart resumes from what
    /// the estate actually confirmed.
    pub acks: Mutex<crate::dist::SetAckLedger>,
    /// Where [`ControlPlane::acks`] is persisted. `None` keeps the old in-memory-only behaviour,
    /// which is what a test wants and what no deployment should have.
    pub acks_path: Option<std::path::PathBuf>,
    /// Whether this plane owns the state log.
    ///
    /// `true` means it was opened with [`crate::store::Store::open_read_only`] and holds no writer
    /// lock, because something else does — normally the pipelines that run `offer publish` and
    /// `need apply`. Every state-mutating route is refused up front, so an operator gets one clear
    /// answer instead of a `WC-8003` from somewhere deep in a handler. Acknowledging a contract
    /// set is **not** a state mutation and still works: it writes the ack ledger, which is the
    /// whole reason a read-only plane is worth running.
    pub read_only: bool,
    /// Serve the read-only portal at `GET /portal`.
    ///
    /// Off by default. A page is a different exposure from a JSON API even when it carries the same
    /// data behind the same role, because a browser is a much easier thing to point at a host than
    /// curl is — so it is opted into.
    pub portal: bool,
    /// The discovery sweep the portal's shadow-usage view reads, if one was supplied.
    ///
    /// A file rather than a live scan: scanning needs a source-host shim and a token, and a serving
    /// control plane should not hold either. The sweep runs on its own schedule and leaves its
    /// answer here.
    pub inventory_path: Option<std::path::PathBuf>,
    /// The signed revocation feed, served to mediators at `/v1/revocations`.
    ///
    /// Optional because a control plane can run without one — and when it does,
    /// the endpoint says so rather than serving an empty feed. An empty feed and
    /// no feed are different answers: the first means "nothing is revoked", the
    /// second means "this control plane cannot tell you".
    pub revocations: Option<Mutex<crate::contain::RevocationFeed>>,
    /// Counters.
    pub metrics: Metrics,
    /// The §8.14 metric families (P1 #11).
    ///
    /// Beside `Metrics` rather than replacing it: the seven raw atomics are read directly
    /// by tests and by `Metrics::bump` call sites all over this file, and rewriting those
    /// in the same change that introduces the registry would make a regression in either
    /// hard to attribute. The registry is the *exposition*; `Metrics` feeds it.
    pub registry: wc_core::obs::Registry,
    /// Idempotency records: key → (expiry, body hash, response body).
    idempotency: Mutex<HashMap<String, (u64, String, String)>>,
    /// Injected clock.
    now: fn() -> u64,
}

impl std::fmt::Debug for ControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlane")
            .field("iss", &self.iss)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl ControlPlane {
    /// Assemble a control plane.
    pub fn new(
        store: Store,
        evidence: Evidence,
        policy: ConnectPolicy,
        signer: IssuerKey,
        iss: &str,
        now: fn() -> u64,
    ) -> ControlPlane {
        ControlPlane {
            revocations: None,
            store: Mutex::new(store),
            evidence: Mutex::new(evidence),
            policy: RwLock::new(Arc::new(policy)),
            signer,
            approvers: ApproverRegistry::new(),
            iss: iss.to_string(),
            mode: Mode::Observe,
            tokens: HashMap::new(),
            transport: Transport::default(),
            jwks: r#"{"keys":[]}"#.to_string(),
            acks: Mutex::new(crate::dist::SetAckLedger::default()),
            // Off unless asked for. A page is easier to point a browser at than an API is.
            portal: false,
            inventory_path: None,
            acks_path: None,
            read_only: false,
            metrics: Metrics::default(),
            registry: {
                let r = wc_core::obs::Registry::new();
                crate::obs::register(&r);
                r
            },
            idempotency: Mutex::new(HashMap::new()),
            now,
        }
    }

    /// Set what the transport must prove before a bearer token is believed.
    #[must_use]
    pub fn with_transport(mut self, transport: Transport) -> ControlPlane {
        self.transport = transport;
        self
    }

    /// Register a bearer token and the roles it carries.
    #[must_use]
    pub fn with_token(mut self, token: &str, roles: &[&str]) -> ControlPlane {
        self.tokens.insert(
            token.to_string(),
            roles.iter().map(|r| (*r).to_string()).collect(),
        );
        self
    }

    /// Set the approver registry.
    #[must_use]
    pub fn with_approvers(mut self, approvers: ApproverRegistry) -> ControlPlane {
        self.approvers = approvers;
        self
    }

    /// Set the mode.
    #[must_use]
    pub fn with_mode(mut self, mode: Mode) -> ControlPlane {
        self.mode = mode;
        self
    }

    /// Serve without owning the state log.
    #[must_use]
    pub fn read_only(mut self) -> ControlPlane {
        self.read_only = true;
        self
    }

    /// Serve the read-only portal, optionally with a discovery sweep for the shadow-usage view.
    ///
    /// The sweep is read from disk on each request rather than cached, so replacing the file is how
    /// you refresh it — no restart, and no scan inside a serving process.
    #[must_use]
    pub fn with_portal(mut self, inventory: Option<std::path::PathBuf>) -> ControlPlane {
        self.portal = true;
        self.inventory_path = inventory;
        self
    }

    /// Persist contract-set acknowledgements at `path`, loading whatever is already there.
    ///
    /// Loading is the half that matters. A control plane that only wrote would look durable and
    /// still start every restart with nothing confirmed, which a deploy gate reads as "no
    /// mediator has the set" — so the gate would block on every restart rather than resume.
    pub fn with_ack_ledger(mut self, path: &std::path::Path) -> Result<ControlPlane> {
        let ledger = crate::dist::SetAckLedger::open(path)?;
        self.acks = Mutex::new(ledger);
        self.acks_path = Some(path.to_path_buf());
        Ok(self)
    }

    /// Publish a JWKS document.
    #[must_use]
    pub fn with_jwks(mut self, jwks: &str) -> ControlPlane {
        self.jwks = jwks.to_string();
        self
    }

    /// Replace the live policy — a hot reload.
    ///
    /// A policy with lint errors is refused and the last-known-good is kept
    /// (§8.13, `WC-8001`): a control plane that swallows a broken policy is one
    /// that silently stops enforcing what an operator thinks it enforces.
    pub fn reload_policy(&self, candidate: ConnectPolicy) -> Result<()> {
        let report = candidate.lint();
        if !report.is_usable() {
            return Err(WcError::with_detail(
                Code::POLICY_INVALID,
                format!(
                    "keeping last-known-good: {} error(s): {}",
                    report.errors.len(),
                    report.errors.join("; ")
                ),
            ));
        }
        let mut live = match self.policy.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *live = Arc::new(candidate);
        Ok(())
    }

    fn policy(&self) -> Arc<ConnectPolicy> {
        match self.policy.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Resolve a bearer token to a caller.
    ///
    /// The transport check lives here rather than in the router because every
    /// authenticated route goes through this one function, and a check a route can
    /// forget to call is a check that one route eventually will.
    fn authenticate(&self, req: &Request) -> Option<Caller> {
        let token = req.bearer()?;
        if let Err(why) = self.transport.admits(req) {
            // Counted, so "nobody can authenticate" is visible as a number rather than
            // discovered by an operator reading logs after the fact.
            Metrics::bump(&self.metrics.transport_refused);
            let _ = why;
            return None;
        }
        let roles = self.tokens.get(token)?;
        Some(Caller {
            subject: format!("token:{}", &sha256_hex(token)[..12]),
            roles: roles.clone(),
        })
    }
}

/// What the transport must prove before a bearer token is believed.
///
/// `connect serve` speaks plain HTTP. That is deliberate — TLS is terminated in front
/// of it in every topology `docs/physical-architecture.md` describes, and an
/// in-process listener would be a security-critical code path almost nobody would
/// use. What was **not** deliberate is that nothing stopped an operator binding
/// `0.0.0.0` and shipping approval tokens in plaintext: the plan said "a terminating
/// proxy is mandatory" and the binary had no opinion.
///
/// So the requirement is enforced, and enforced per request rather than as a promise
/// made once at startup. `--behind-tls-proxy` asserts termination happens in front;
/// this then requires every authenticated request to *carry the evidence* — an
/// `X-Forwarded-Proto: https` from an address the operator named. A request that
/// reaches the listener directly, bypassing the proxy, has no such header and is
/// refused. Which is the actual attack: something already inside the network talking
/// to the pod rather than through the ingress.
///
/// The same shape as `wc_mediator::peer::MeshTrust`, and for the same reason: a
/// forwarding header is worth exactly as much as the hop that set it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Transport {
    /// Loopback only. No forwarding header needed, because nothing can reach it from
    /// off-box — this is the default and the only safe one without a proxy.
    #[default]
    Loopback,
    /// Behind a terminating proxy at one of these addresses.
    ///
    /// Empty means "believe the header from anywhere", which is offered because a
    /// sidecar-only network namespace makes it true, and refused by
    /// [`Transport::describe`] telling the operator plainly what they chose.
    TlsProxy {
        /// Sources whose `x-forwarded-proto` may be believed.
        trusted: Vec<TrustedSource>,
        /// A secret the proxy sets in `x-warden-proxy-secret` and this listener
        /// requires, when one is configured.
        ///
        /// The address check's honest limit was that **a process at a trusted address
        /// can forge the header**. For a localhost-terminating sidecar — a common shape
        /// — `--trusted-proxy 127.0.0.1` is satisfied by anything on the box, so a local
        /// process could present a bearer token over plaintext and be believed. No CIDR
        /// is narrow enough to fix that, because the forger shares the address.
        ///
        /// With a secret, forging needs the secret rather than the position. It is
        /// checked in constant time and it is checked **in addition to** the address, so
        /// configuring one narrows and never widens.
        secret: Option<ProxySecret>,
    },
    /// No requirement at all. For a test, or a deployment that has accepted the
    /// consequence in writing.
    Insecure,
}

/// The header the proxy secret travels in.
pub const PROXY_SECRET_HEADER: &str = "x-warden-proxy-secret";

/// A shared secret between the terminating proxy and this listener.
///
/// Stored as a digest, not as the secret: a `Debug` on the config, a panic message or a
/// `/healthz` body that echoed it would hand over the thing it exists to protect. The
/// comparison is therefore digest-against-digest, which is also what makes it constant
/// time — `sha256` of the presented value against `sha256` of the configured one, compared
/// byte by byte with no early return.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxySecret {
    /// Hex `sha256`, via `wc_core::util` rather than a new dependency — §8.3 caps the
    /// dependency count and this needs no crate that is not already here.
    digest: String,
}

impl std::fmt::Debug for ProxySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Not even the digest: a digest is a verifier for a low-entropy secret.
        f.write_str("ProxySecret(<redacted>)")
    }
}

impl ProxySecret {
    /// The minimum length worth calling a secret.
    ///
    /// A short shared secret is guessable by exactly the local process this control is
    /// for, and it would be worse than none because the banner would claim the strong
    /// posture. Refused at startup rather than accepted with a warning.
    pub const MIN_LEN: usize = 32;

    /// Build from the configured value, refusing one too short to be worth having.
    pub fn new(raw: &str) -> Result<ProxySecret> {
        if raw.len() < Self::MIN_LEN {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "--proxy-secret is {} characters; at least {} are required, because a \
                     guessable secret would let the banner claim a posture the listener does \
                     not have. Generate one with `openssl rand -hex 32`",
                    raw.len(),
                    Self::MIN_LEN
                ),
            ));
        }
        Ok(ProxySecret {
            digest: wc_core::util::sha256_hex(raw),
        })
    }

    /// Whether a presented value matches, in constant time.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        let got = wc_core::util::sha256_hex(presented);
        // Fold every byte before deciding. `==` on strings compares lengths first and
        // then short-circuits, and the timing of that short-circuit is a byte-at-a-time
        // oracle. Both sides are a fixed-width hex digest, so lengths always agree and
        // the loop always runs to the end.
        if got.len() != self.digest.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.digest.as_bytes().iter().zip(got.as_bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// One source `x-forwarded-proto` may be believed from: an address, or a network.
///
/// Networks exist because exact addresses made the **strong** configuration unusable in two
/// of the four topologies `docs/physical-architecture.md` documents. An AWS ALB answers from
/// many addresses; a Kubernetes Ingress pod gets a new one every restart. With exact matching
/// an operator either enumerates addresses that change underneath them, or omits
/// `--trusted-proxy` entirely — and omitting it means *believe the header from anywhere*,
/// which on a flat pod network is no restriction at all.
///
/// A control whose correct setting is impractical is a control everybody turns off. Found by
/// putting a real terminating proxy in front of a real listener rather than by reading the
/// flag's documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedSource {
    /// Exactly this address.
    Exact(IpAddr),
    /// Any address inside this network.
    Network {
        /// The network address, already masked.
        base: IpAddr,
        /// Prefix length in bits.
        prefix: u8,
    },
}

impl TrustedSource {
    /// Parse `10.0.1.5` or `10.0.1.0/24`.
    ///
    /// Refuses a `/0`. It parses, it reads as a restriction, and it matches every address in
    /// existence — which is exactly the shape of defect this repository keeps finding. An
    /// operator who means "anywhere" omits the flag and is told so by the startup banner.
    pub fn parse(raw: &str) -> Result<TrustedSource> {
        let Some((addr, bits)) = raw.split_once('/') else {
            return raw
                .parse::<IpAddr>()
                .map(TrustedSource::Exact)
                .map_err(|_| {
                    WcError::with_detail(
                        Code::CONFIG_INVALID,
                        format!("--trusted-proxy {raw:?} is not an IP address or CIDR block"),
                    )
                });
        };

        let base: IpAddr = addr.parse().map_err(|_| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("--trusted-proxy {raw:?}: {addr:?} is not an IP address"),
            )
        })?;
        let prefix: u8 = bits.parse().map_err(|_| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("--trusted-proxy {raw:?}: {bits:?} is not a prefix length"),
            )
        })?;

        let width = if base.is_ipv4() { 32 } else { 128 };
        if prefix > width {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("--trusted-proxy {raw:?}: /{prefix} is wider than the {width}-bit address"),
            ));
        }
        if prefix == 0 {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "--trusted-proxy {raw:?} matches every address, so it restricts nothing. \
                     Omit --trusted-proxy if that is what you mean — the startup banner then \
                     says so plainly instead of a CIDR implying otherwise"
                ),
            ));
        }

        Ok(TrustedSource::Network {
            base: mask(base, prefix),
            prefix,
        })
    }

    /// Whether an address is this source.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match self {
            TrustedSource::Exact(want) => *want == ip,
            TrustedSource::Network { base, prefix } => {
                // A v4 address must not match a v6 network, and the reverse. Masking alone
                // would compare a mapped form and quietly say yes.
                if base.is_ipv4() != ip.is_ipv4() {
                    return false;
                }
                mask(ip, *prefix) == *base
            }
        }
    }

    /// How this source reads in the startup banner.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            TrustedSource::Exact(ip) => ip.to_string(),
            TrustedSource::Network { base, prefix } => format!("{base}/{prefix}"),
        }
    }
}

impl std::str::FromStr for TrustedSource {
    type Err = WcError;

    /// So `"10.0.1.0/24".parse()` works, which is what a caller reaches for.
    fn from_str(raw: &str) -> std::result::Result<TrustedSource, WcError> {
        TrustedSource::parse(raw)
    }
}

/// Zero every bit below the prefix.
fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            // `checked_shl` rather than `<<`: shifting a u32 by 32 is undefined-ish and in
            // release builds wraps to a no-op, which would make /32 match everything.
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            IpAddr::V4(std::net::Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            IpAddr::V6(std::net::Ipv6Addr::from(bits & m))
        }
    }
}

impl Transport {
    /// Whether a bearer token may be believed on this request.
    fn admits(&self, req: &Request) -> std::result::Result<(), &'static str> {
        match self {
            Transport::Insecure => Ok(()),
            Transport::Loopback => match req.peer {
                // `is_loopback` on a parsed address, not `starts_with("127.")` — the
                // string form accepts `127.0.0.1.evil.example`, which is the same bug
                // this codebase already fixed once in `peer`.
                Some(ip) if ip.is_loopback() => Ok(()),
                Some(_) => Err("this listener accepts credentials on loopback only; \
                                start with --behind-tls-proxy to accept forwarded ones"),
                None => Err("the peer address is unknown, so loopback cannot be proved"),
            },
            Transport::TlsProxy { trusted, secret } => {
                let from_trusted = trusted.is_empty()
                    || req
                        .peer
                        .is_some_and(|ip| trusted.iter().any(|t| t.contains(ip)));
                if !from_trusted {
                    return Err("not from a trusted proxy address");
                }
                // Checked after the address and before the protocol claim, so a
                // configured secret only ever narrows. This is what makes forging cost
                // the secret rather than the position: a local process at
                // `--trusted-proxy 127.0.0.1` passes the check above and fails here.
                if let Some(secret) = secret {
                    match req.headers.get(PROXY_SECRET_HEADER) {
                        Some(presented) if secret.matches(presented) => {}
                        Some(_) => return Err("the proxy secret does not match"),
                        None => {
                            return Err("no proxy secret: this request did not come through \
                                        the terminating proxy, whatever its source address")
                        }
                    }
                }
                match req.headers.get("x-forwarded-proto").map(String::as_str) {
                    Some(p) if p.eq_ignore_ascii_case("https") => Ok(()),
                    Some(_) => Err("x-forwarded-proto is not https, so the credential \
                                    crossed the network in clear"),
                    None => Err("no x-forwarded-proto: this request did not come \
                                 through the terminating proxy"),
                }
            }
        }
    }

    /// One line for the startup banner and `/healthz`, because a posture nobody can
    /// see is a posture nobody checks.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Transport::Loopback => "loopback-only (credentials refused from off-box)".into(),
            Transport::TlsProxy { trusted, secret } if trusted.is_empty() => {
                if secret.is_some() {
                    "behind a TLS proxy, any source address, but a proxy secret is \
                     required — forging x-forwarded-proto needs the secret, not an address"
                        .into()
                } else {
                    "behind a TLS proxy, ANY source address trusted for \
                     x-forwarded-proto — correct only if nothing else can reach this port"
                        .into()
                }
            }
            Transport::TlsProxy { trusted, secret } => format!(
                "behind a TLS proxy at {} (x-forwarded-proto: https required{})",
                trusted
                    .iter()
                    .map(TrustedSource::describe)
                    .collect::<Vec<_>>()
                    .join(", "),
                if secret.is_some() {
                    ", proxy secret required"
                } else {
                    // Named on the banner rather than left to the reader, because the
                    // gap is invisible: the configuration looks strict and a process
                    // sharing the address can still forge the header.
                    ", NO proxy secret — any process at that address can forge the header"
                }
            ),
            Transport::Insecure => {
                "INSECURE — bearer tokens accepted over plaintext from anywhere".into()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// The router. Wrapping `ControlPlane` so it can be an `http::Handler`.
#[derive(Debug)]
pub struct Api(pub Arc<ControlPlane>);

impl http::Handler for Api {
    fn handle(&self, req: &Request) -> Response {
        let cp = &self.0;
        Metrics::bump(&cp.metrics.requests);

        // Unauthenticated: liveness and the public key set. Nothing here reveals
        // anything about the estate.
        match (req.method.as_str(), req.segments().as_slice()) {
            ("GET", ["healthz"]) => return Response::json(200, r#"{"status":"ok"}"#),
            ("GET", ["readyz"]) => return ready(cp),
            ("GET", ["metrics"]) => return metrics(cp),
            ("GET", ["v1", "jwks.json"]) => {
                return Response::json(200, cp.jwks.clone());
            }
            _ => {}
        }

        let Some(caller) = cp.authenticate(req) else {
            Metrics::bump(&cp.metrics.denied);
            return error(
                401,
                Code::IDENTITY_UNVERIFIABLE,
                "a bearer token is required",
            );
        };

        match route(cp, &caller, req) {
            Ok(response) => response,
            Err(e) => from_error(&e),
        }
    }
}

/// Dispatch an authenticated request.
fn route(cp: &Arc<ControlPlane>, caller: &Caller, req: &Request) -> Result<Response> {
    let segments = req.segments();

    // A read-only plane refuses every state mutation here, before a handler can reach the log and
    // fail with `WC-8003` from somewhere an operator cannot map back to a decision. The
    // acknowledgement route is deliberately exempt: it writes the ack ledger, not the state log,
    // and it is the reason a read-only plane exists at all.
    if cp.read_only
        && matches!(req.method.as_str(), "POST" | "PUT" | "DELETE" | "PATCH")
        && !matches!(segments.as_slice(), ["v1", "mediators", _, "ack"])
    {
        return Ok(error(
            409,
            Code::CONFIG_INVALID,
            "this control plane is read-only: it serves contract sets and records \
             acknowledgements, and does not own the state log. The writer is whatever \
             holds the lock — normally the pipelines that run `offer publish` and \
             `need apply`. Send this to the writing plane, or run one without \
             --read-only.",
        ));
    }

    match (req.method.as_str(), segments.as_slice()) {
        // --- registry ---
        ("GET", ["v1", "entities"]) => {
            require_role(cp, caller, roles::READ)?;
            list_entities(cp)
        }
        ("GET", ["v1", "entities", id]) => {
            require_role(cp, caller, roles::READ)?;
            get_entity(cp, id)
        }
        ("POST", ["v1", "entities", id, "activate"]) => {
            require_role(cp, caller, roles::REGISTER)?;
            idempotent(cp, req, |cp| activate_entity(cp, caller, id))
        }
        // --- the portal ---
        ("GET", ["portal"]) => {
            require_role(cp, caller, roles::READ)?;
            if !cp.portal {
                return Ok(error(
                    404,
                    Code::CONTRACT_NOT_FOUND,
                    "the portal is not enabled on this control plane; start `serve --portal`",
                ));
            }
            portal_page(cp, req)
        }

        ("GET", ["v1", "posture"]) => {
            require_role(cp, caller, roles::READ)?;
            posture(cp, req)
        }

        // --- the catalogue ---
        ("GET", ["v1", "offers"]) => {
            require_role(cp, caller, roles::READ)?;
            offers(cp, req)
        }

        // --- connections ---
        ("POST", ["v1", "connections"]) => {
            require_role(cp, caller, roles::REQUEST)?;
            idempotent(cp, req, |cp| create_connection(cp, caller, req))
        }
        ("GET", ["v1", "connections"]) => {
            require_role(cp, caller, roles::READ)?;
            list_connections(cp)
        }
        ("GET", ["v1", "connections", cid]) => {
            require_role(cp, caller, roles::READ)?;
            get_connection(cp, cid)
        }
        ("GET", ["v1", "requests"]) => {
            require_role(cp, caller, roles::READ)?;
            list_requests(cp, req)
        }
        ("POST", ["v1", "requests", id, "approve"]) => {
            require_role(cp, caller, roles::APPROVE)?;
            idempotent(cp, req, |cp| approve_request(cp, caller, id, req))
        }
        ("POST", ["v1", "requests", id, "deny"]) => {
            require_role(cp, caller, roles::APPROVE)?;
            idempotent(cp, req, |cp| deny_request(cp, caller, id, req))
        }

        // --- containment ---
        ("POST", ["v1", "quarantine"]) => {
            require_role(cp, caller, roles::SECOPS)?;
            idempotent(cp, req, |cp| quarantine(cp, caller, req))
        }
        // Lifting had no route and no CLI command, which made quarantine a one-way door:
        // a false positive bricked a party for good, recoverable only by hand-editing a
        // hash-linked log. Same role as ordering it, and dual control is enforced below
        // by the registry — clearing is the more dangerous direction, because it restores
        // a party the estate decided to cut.
        ("POST", ["v1", "quarantine", "clear"]) => {
            require_role(cp, caller, roles::SECOPS)?;
            idempotent(cp, req, |cp| clear_quarantine(cp, caller, req))
        }

        // --- the data plane ---
        ("GET", ["v1", "mediators", mid, "contracts"]) => {
            require_role(cp, caller, roles::MEDIATOR)?;
            contract_set(cp, mid, req)
        }
        ("POST", ["v1", "mediators", mid, "ack"]) => {
            require_role(cp, caller, roles::MEDIATOR)?;
            record_ack(cp, mid, req)
        }
        ("GET", ["v1", "mediators"]) => {
            require_role(cp, caller, roles::READ)?;
            mediator_status(cp)
        }
        ("GET", ["v1", "revocations"]) => {
            require_role(cp, caller, roles::MEDIATOR)?;
            revocation_feed(cp, req)
        }

        // --- evidence ---
        ("GET", ["v1", "audit", "verify"]) => {
            require_role(cp, caller, roles::COMPLIANCE)?;
            audit_verify(cp)
        }

        ("GET" | "POST" | "PUT" | "DELETE" | "PATCH", _) => Ok(error(
            404,
            Code::ENTITY_NOT_FOUND,
            &format!("no route for {} {}", req.method, req.path),
        )),
        _ => Ok(error(405, Code::FRAME_MALFORMED, "unsupported method")),
    }
}

fn require_role(cp: &Arc<ControlPlane>, caller: &Caller, role: &str) -> Result<()> {
    if caller.holds(role) {
        return Ok(());
    }
    Metrics::bump(&cp.metrics.denied);
    Err(WcError::with_detail(
        Code::APPROVER_ROLE_MISSING,
        format!("this route needs {role:?}"),
    ))
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

/// Wrap a mutating handler so a retry cannot double-apply it.
///
/// The same key with the same body replays the first response. The same key with a
/// *different* body is `409`: that is a client reusing a key, not a retry, and
/// silently applying it would be the worst of both readings.
fn idempotent(
    cp: &Arc<ControlPlane>,
    req: &Request,
    handler: impl FnOnce(&Arc<ControlPlane>) -> Result<Response>,
) -> Result<Response> {
    let Some(key) = req.header("idempotency-key").map(str::to_string) else {
        return Ok(error(
            400,
            Code::FRAME_MALFORMED,
            "an Idempotency-Key header is required on mutating requests",
        ));
    };
    let body_hash = sha256_hex(&String::from_utf8_lossy(&req.body));
    let now = (cp.now)();

    {
        let mut cache = lock(&cp.idempotency);
        cache.retain(|_, (expiry, _, _)| *expiry > now);
        if let Some((_, seen_hash, response)) = cache.get(&key) {
            if seen_hash == &body_hash {
                Metrics::bump(&cp.metrics.replays);
                return Ok(
                    Response::json(200, response.clone()).with_header("idempotent-replay", "true")
                );
            }
            return Ok(error(
                409,
                Code::ENTITY_DUPLICATE,
                "this Idempotency-Key was used with a different body",
            ));
        }
    }

    let response = handler(cp)?;
    if (200..300).contains(&response.status) {
        let body = String::from_utf8_lossy(&response.body).into_owned();
        lock(&cp.idempotency).insert(key, (now + IDEMPOTENCY_TTL_SECS, body_hash, body));
    }
    Ok(response)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// ---------------------------------------------------------------------------
// Handlers — reads
// ---------------------------------------------------------------------------

fn ready(cp: &Arc<ControlPlane>) -> Response {
    // Readiness is about being able to *decide*, not about being up: a control
    // plane with no usable policy must not claim it can issue.
    let policy = cp.policy();
    let report = policy.lint();
    if report.is_usable() {
        Response::json(
            200,
            json!({"status": "ready", "policy": policy.version}).to_string(),
        )
    } else {
        Response::json(
            503,
            json!({"status": "not_ready", "errors": report.errors}).to_string(),
        )
    }
}

/// `/metrics` — the §8.14 families, Prometheus text or JSON.
///
/// Counters are folded in from `Metrics` and gauges are derived from the projection on
/// each scrape, so a number here and a number from `connect posture` cannot disagree.
/// See `crate::obs` for why that division rather than incremental gauges.
///
/// The seven original unlabelled series are kept as aliases at the bottom. They are what
/// an existing dashboard is scraping, and silently renaming a metric breaks every panel
/// and every alert built on it — the alert does not error, it goes blank, which is the
/// failure mode this whole item is about.
fn metrics(cp: &Arc<ControlPlane>) -> Response {
    let m = &cp.metrics;
    let r = &cp.registry;

    // Counters this file already maintains, published under their §8.14 names.
    r.set(
        crate::obs::API_REQUESTS,
        &[],
        m.requests.load(Ordering::Relaxed),
    );
    r.set(
        crate::obs::API_REPLAYS,
        &[],
        m.replays.load(Ordering::Relaxed),
    );
    r.set(
        crate::obs::CONTRACT_PULLS,
        &[],
        m.pulls.load(Ordering::Relaxed),
    );
    r.set(
        crate::obs::MINTED,
        &[("approval_mode", "any")],
        m.minted.load(Ordering::Relaxed),
    );
    r.set(
        crate::obs::ESCALATED,
        &[],
        m.escalated.load(Ordering::Relaxed),
    );
    r.set(
        crate::obs::TRANSPORT_REFUSED,
        &[],
        m.transport_refused.load(Ordering::Relaxed),
    );

    let store = lock(&cp.store);
    let entities = store.projection.entities.len();
    let contracts = store
        .projection
        .contracts
        .values()
        .filter(|c| c.status == ContractStatus::Active)
        .count();
    let pending = store
        .projection
        .requests
        .values()
        .filter(|r| r.status == RequestStatus::Pending)
        .count();

    let now = (cp.now)();
    // A control plane with no feed can still record a quarantine and report it as done
    // while no mediator ever hears, so "serving a feed at all" is a gauge rather than a
    // footnote. Whether a feed *verifies* is a mediator-side state this process cannot
    // observe — see `obs::REVOCATION_SERVING`.
    let feed = cp
        .revocations
        .as_ref()
        .map(|feed| (true, lock(feed).len() as u64));

    let (chain_len, newest_anchor) = {
        let evidence = lock(&cp.evidence);
        (evidence.head().0, evidence.newest_anchor().map(|c| c.ts))
    };

    crate::obs::snapshot(
        r,
        &store.projection,
        &crate::contain::AckLedger::default(),
        chain_len,
        newest_anchor,
        feed,
        now,
    );
    drop(store);

    let acks = lock(&cp.acks).acked.len();

    let mut body = r.to_prometheus();
    body.push_str(&format!(
        "# HELP wc_api_denied_total Requests refused for lack of a role or a token.\n\
         # TYPE wc_api_denied_total counter\n\
         wc_api_denied_total {}\n\
         # HELP wc_mediators_acked Mediators that have acknowledged at least one set.\n\
         # TYPE wc_mediators_acked gauge\n\
         wc_mediators_acked {acks}\n\
         # HELP wc_entities_total Registered entities, unlabelled. Superseded by wc_entities.\n\
         # TYPE wc_entities_total gauge\n\
         wc_entities_total {entities}\n\
         # HELP wc_contracts_active_total Active contracts, unlabelled. Superseded by wc_contracts_active.\n\
         # TYPE wc_contracts_active_total gauge\n\
         wc_contracts_active_total {contracts}\n\
         # HELP wc_requests_pending_total Requests awaiting a human, unlabelled.\n\
         # TYPE wc_requests_pending_total gauge\n\
         wc_requests_pending_total {pending}\n",
        m.denied.load(Ordering::Relaxed),
    ));
    Response::text(200, body)
}

fn entity_json(e: &Entity) -> Value {
    json!({
        "id": e.id.as_str(),
        "kind": format!("{:?}", e.kind),
        "owner": e.owner.as_str(),
        "service": e.service,
        "tier": e.tier.as_u8(),
        "zone": e.zone.as_str(),
        "trust_level": format!("{:?}", e.zone.trust_level()),
        "posture": format!("{:?}", e.posture),
        "lifecycle": format!("{:?}", e.lifecycle),
        "data_classes": e.data_classes,
        "jurisdictions": e.jurisdictions,
        // Never the endpoint: reachability is granted by a contract, not by a
        // lookup, so discovery must not hand out addresses (§8.5.6).
        "pin": { "alg": e.pin.alg, "manifest": e.pin.manifest, "items": e.pin.items.len() },
        "reattest_every": e.reattest_every,
    })
}

fn list_entities(cp: &Arc<ControlPlane>) -> Result<Response> {
    let store = lock(&cp.store);
    let mut rows: Vec<&Entity> = store.projection.entities.values().collect();
    rows.sort_unstable_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    let body = json!({
        "entities": rows.iter().map(|e| entity_json(e)).collect::<Vec<_>>(),
        "count": rows.len(),
    });
    Ok(Response::json(200, body.to_string()))
}

fn get_entity(cp: &Arc<ControlPlane>, id: &str) -> Result<Response> {
    let entity_id = EntityId::new(id)?;
    let store = lock(&cp.store);
    match store.projection.entities.get(&entity_id) {
        Some(e) => Ok(Response::json(200, entity_json(e).to_string())),
        None => Ok(error(404, Code::ENTITY_NOT_FOUND, "no such entity")),
    }
}

/// `GET /v1/offers?as=<consumer>` — the catalogue as one consumer sees it.
///
/// `as` is required and is not optional-with-a-default. A default would have to be either "every
/// offer" — the enumerable catalogue this design refuses to publish — or "nothing", which reads as
/// a bug. Making the caller name the consumer keeps the filter the only way through.
///
/// The token's `read` role is not enough on its own to see any particular row: the row still has to
/// be inside the audience the *provider* named. Two independent gates, and the second one belongs
/// to somebody the platform team does not speak for.
fn offers(cp: &Arc<ControlPlane>, req: &Request) -> Result<Response> {
    let now = req.param_u64("now").unwrap_or_else(|| (cp.now)());
    let asker = req.param("as").ok_or_else(|| {
        WcError::with_detail(
            Code::CONFIG_INVALID,
            "`as` names the consumer to filter for and is required; there is no unfiltered form of \
             this endpoint",
        )
    })?;
    let asker = EntityId::new(asker)?;
    let store = lock(&cp.store);
    let me = store.projection.entity(&asker).ok_or_else(|| {
        WcError::with_detail(
            Code::ENTITY_NOT_FOUND,
            format!("{asker} is not registered, so it has no audience to filter by"),
        )
    })?;
    if me.lifecycle != Lifecycle::Active {
        return Err(WcError::with_detail(
            Code::ILLEGAL_TRANSITION,
            format!("{asker} is {:?}, not active", me.lifecycle),
        ));
    }
    let mut rows: Vec<crate::offer::CatalogueEntry> = store
        .projection
        .offers
        .values()
        .filter_map(|o| o.as_seen_by(me.zone.as_str(), me.tier, now))
        .collect();
    rows.sort_by(|a, b| a.asset.as_str().cmp(b.asset.as_str()));
    Ok(Response::json(
        200,
        json!({ "consumer": asker.as_str(), "zone": me.zone.as_str(), "offers": rows }).to_string(),
    ))
}

/// `GET /portal[?as=<consumer>]` — the read-only page.
///
/// Rendered server-side, so no credential ever reaches the browser. Everything it shows is
/// obtainable from the JSON API by the same caller with the same role; the page adds legibility, not
/// access.
fn portal_page(cp: &Arc<ControlPlane>, req: &Request) -> Result<Response> {
    let now = req.param_u64("now").unwrap_or_else(|| (cp.now)());
    let store = lock(&cp.store);
    let p = &store.projection;

    // Named consumer, if any. An unknown or inactive one is not an error — the page falls back to
    // the picker and says nothing about which ids exist beyond what `entities` already shows.
    let as_consumer = req
        .param("as")
        .and_then(|s| EntityId::new(s).ok())
        .and_then(|id| p.entity(&id))
        .filter(|e| e.lifecycle == Lifecycle::Active);

    let catalogue = as_consumer.map_or_else(Vec::new, |me| {
        let mut rows: Vec<crate::offer::CatalogueEntry> = p
            .offers
            .values()
            .filter_map(|o| o.as_seen_by(me.zone.as_str(), me.tier, now))
            .collect();
        rows.sort_by(|a, b| a.asset.as_str().cmp(b.asset.as_str()));
        rows
    });

    // A scanned target counts as registered when some entity's endpoint or id accounts for it. The
    // comparison is by target rather than by the name a team chose, because a local label is a local
    // decision and two teams naming one server differently is still one server.
    let mut known_targets = std::collections::BTreeMap::new();
    for e in p.entities.values() {
        if let Some(ep) = &e.endpoint {
            known_targets.insert(ep.clone(), e.id.clone());
        }
    }

    // Read, parsed, and the failure kept. `.ok()` on both steps was the first version, and it made
    // an unreadable file indistinguishable from no file — see `View::inventory_error`.
    let mut inventory = None;
    let mut inventory_error = None;
    if let Some(path) = cp.inventory_path.as_ref() {
        match std::fs::read_to_string(path) {
            Err(e) => inventory_error = Some(format!("cannot read {}: {e}", path.display())),
            Ok(text) => match serde_json::from_str::<crate::inventory::Inventory>(&text) {
                Err(e) => {
                    inventory_error = Some(format!("{} is not an inventory: {e}", path.display()));
                }
                Ok(inv) => inventory = Some(inv),
            },
        }
    }

    let entities: Vec<&Entity> = p.entities.values().collect();
    let pending = crate::portal::open_requests(&p.requests, |id| p.entity(id), now);

    let view = crate::portal::View {
        as_consumer,
        catalogue,
        entities,
        pending,
        inventory: inventory.as_ref(),
        inventory_error,
        known_targets,
        contracts: p.contracts.len(),
        iss: &cp.iss,
    };
    Ok(Response::html(200, crate::portal::render(&view)))
}

fn posture(cp: &Arc<ControlPlane>, req: &Request) -> Result<Response> {
    let now = req.param_u64("now").unwrap_or_else(|| (cp.now)());
    let store = lock(&cp.store);
    let all: Vec<&Entity> = store.projection.entities.values().collect();

    let by_posture = |want: Posture| -> Vec<&str> {
        all.iter()
            .filter(|e| e.posture == want)
            .map(|e| e.id.as_str())
            .collect()
    };
    let overdue: Vec<&str> = all
        .iter()
        .filter(|e| e.lifecycle == Lifecycle::Active && e.reattest_overdue(now))
        .map(|e| e.id.as_str())
        .collect();

    Ok(Response::json(
        200,
        json!({
            "total": all.len(),
            "unattested": by_posture(Posture::Unattested),
            "degraded": by_posture(Posture::Degraded),
            "quarantined": by_posture(Posture::Quarantined),
            "reattest_overdue": overdue,
        })
        .to_string(),
    ))
}

fn list_connections(cp: &Arc<ControlPlane>) -> Result<Response> {
    let store = lock(&cp.store);
    let mut rows: Vec<_> = store.projection.contracts.values().collect();
    rows.sort_unstable_by(|a, b| a.cid.as_str().cmp(b.cid.as_str()));
    Ok(Response::json(
        200,
        json!({
            "connections": rows.iter().map(|c| json!({
                "cid": c.cid.as_str(),
                "status": format!("{:?}", c.status),
                "caller": c.caller.as_str(),
                "callee": c.callee.as_str(),
                "surface": c.surface.items(),
                "exp": c.exp,
                "approval_mode": format!("{:?}", c.approval.mode),
                "policy_version": c.policy_version,
            })).collect::<Vec<_>>(),
            "count": rows.len(),
        })
        .to_string(),
    ))
}

fn get_connection(cp: &Arc<ControlPlane>, cid: &str) -> Result<Response> {
    let store = lock(&cp.store);
    match store
        .projection
        .contracts
        .values()
        .find(|c| c.cid.as_str() == cid)
    {
        Some(record) => Ok(Response::json(
            200,
            serde_json::to_string(record).unwrap_or_else(|_| "{}".to_string()),
        )),
        None => Ok(error(404, Code::CONTRACT_NOT_FOUND, "no such connection")),
    }
}

/// A pending request, in full.
///
/// The complete surface, terms and mediator list are published deliberately: an
/// approver signs a digest that covers all of them, so a client that cannot
/// reproduce the digest cannot verify it is signing what it was shown — and the
/// whole point of a signed approval is that it binds to exactly that.
fn request_json(r: &PendingRequest) -> Value {
    json!({
        "id": r.id,
        "status": format!("{:?}", r.status),
        "caller": r.caller.as_str(),
        "callee": r.callee.as_str(),
        "surface": r.surface.items(),
        "resources": r.surface.resources(),
        "terms": r.terms,
        "mediators": r.mediators,
        "created_at": r.created_at,
        "ttl_secs": r.ttl_secs,
        "justification": r.justification,
        "requester": r.requester.as_str(),
        "approver_role": r.approver_role,
        "dual_control": r.dual_control,
        "digest": r.digest(),
        "expires_at": r.expires_at,
        "policy_version": r.policy_version,
        "reason": r.policy_reason,
        "trace": r.policy_trace,
    })
}

fn list_requests(cp: &Arc<ControlPlane>, req: &Request) -> Result<Response> {
    let all = req.param("all").is_some();
    let store = lock(&cp.store);
    let mut rows: Vec<&PendingRequest> = store
        .projection
        .requests
        .values()
        .filter(|r| all || r.status == RequestStatus::Pending)
        .collect();
    rows.sort_unstable_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    Ok(Response::json(
        200,
        json!({
            "requests": rows.iter().map(|r| request_json(r)).collect::<Vec<_>>(),
            "count": rows.len(),
        })
        .to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Handlers — writes
// ---------------------------------------------------------------------------

fn body_json(req: &Request) -> Result<Value> {
    if req.body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&req.body)
        .map_err(|e| WcError::with_detail(Code::FRAME_MALFORMED, "body is not JSON").with_source(e))
}

fn field<'a>(body: &'a Value, name: &str) -> Result<&'a str> {
    body.get(name).and_then(Value::as_str).ok_or_else(|| {
        WcError::with_detail(
            Code::FRAME_MALFORMED,
            format!("{name:?} is required and must be a string"),
        )
    })
}

fn string_list(body: &Value, name: &str) -> Vec<String> {
    body.get(name)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn actor_for(caller: &Caller) -> Actor {
    Actor::Service {
        id: caller.subject.clone(),
    }
}

fn activate_entity(cp: &Arc<ControlPlane>, caller: &Caller, id: &str) -> Result<Response> {
    let entity_id = EntityId::new(id)?;
    let now = (cp.now)();
    let mut store = lock(&cp.store);
    store.registry(actor_for(caller), now).transition(
        &entity_id,
        Lifecycle::Active,
        "activated over the api",
    )?;
    Ok(Response::json(
        200,
        json!({"id": entity_id.as_str(), "lifecycle": "Active"}).to_string(),
    ))
}

fn issued_json(issued: &Issued) -> Value {
    json!({
        "outcome": "issued",
        "cid": issued.record.cid.as_str(),
        "jti": issued.record.jti.as_str(),
        "surface": issued.record.surface.items(),
        "surface_digest": issued.record.surface_digest,
        "aud": issued.record.aud,
        "exp": issued.record.exp,
        "approval_mode": format!("{:?}", issued.record.approval.mode),
        "policy_version": issued.record.policy_version,
        "evidence_seq": issued.evidence_seq,
        "artifacts": issued.artifacts.iter()
            .map(|(aud, jws)| json!({"aud": aud, "jws": jws}))
            .collect::<Vec<_>>(),
    })
}

/// Run a closure with an issuer built over the live state.
fn with_issuer<T>(
    cp: &Arc<ControlPlane>,
    caller: &Caller,
    f: impl FnOnce(&mut Issuer<'_>) -> Result<T>,
) -> Result<T> {
    let policy = cp.policy();
    let mut store = lock(&cp.store);
    let mut evidence = lock(&cp.evidence);
    let mut issuer = Issuer::new(
        &mut store,
        &mut evidence,
        &policy,
        &cp.signer,
        &cp.iss,
        (cp.now)(),
        actor_for(caller),
    );
    issuer.mode = cp.mode;
    f(&mut issuer)
}

fn create_connection(cp: &Arc<ControlPlane>, caller: &Caller, req: &Request) -> Result<Response> {
    let body = body_json(req)?;
    let input = RequestInput {
        caller: EntityId::new(field(&body, "from")?)?,
        callee: EntityId::new(field(&body, "to")?)?,
        surface: Surface {
            tools: string_list(&body, "tools"),
            skills: string_list(&body, "skills"),
            resources: string_list(&body, "resources"),
        },
        terms: Terms {
            data_classes: string_list(&body, "data_classes"),
            jurisdictions: string_list(&body, "jurisdictions"),
            ..Default::default()
        },
        ttl_secs: body
            .get("ttl_secs")
            .and_then(Value::as_u64)
            .unwrap_or(30 * 86_400),
        justification: field(&body, "justification")?.to_string(),
        requester: HumanRef::new(field(&body, "requester")?)?,
        mediators: string_list(&body, "mediators"),
        // A direct human request carries no offer, so the provider-owner gate does not apply;
        // this path is governed by connect-policy alone.
        owner_must_approve: false,
    };

    let outcome = with_issuer(cp, caller, |issuer| issuer.request(&input))?;
    match outcome {
        Outcome::Issued(issued) => {
            Metrics::bump(&cp.metrics.minted);
            Ok(Response::json(201, issued_json(&issued).to_string()))
        }
        Outcome::AwaitingApproval(pending) => {
            Metrics::bump(&cp.metrics.escalated);
            // 202: accepted, not complete. A client polls or waits for the approver.
            Ok(Response::json(
                202,
                json!({"outcome": "awaiting_approval", "request": request_json(&pending)})
                    .to_string(),
            ))
        }
        Outcome::Denied { reason, trace } => Ok(Response::json(
            403,
            json!({"outcome": "denied", "reason": reason, "trace": trace}).to_string(),
        )),
    }
}

fn approve_request(
    cp: &Arc<ControlPlane>,
    caller: &Caller,
    id: &str,
    req: &Request,
) -> Result<Response> {
    let body = body_json(req)?;
    let entries = body
        .get("approvals")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            WcError::with_detail(
                Code::FRAME_MALFORMED,
                "\"approvals\" must be an array of {by, jws}",
            )
        })?;

    let mut proofs = Vec::new();
    for entry in entries {
        proofs.push(ApprovalProof {
            by: HumanRef::new(field(entry, "by")?)?,
            jws: field(entry, "jws")?.to_string(),
        });
    }

    // The control plane only ever *verifies*: signing happens in the approver's own
    // client, so a compromised control plane cannot manufacture an approval.
    let approvers = &cp.approvers;
    let issued = with_issuer(cp, caller, |issuer| issuer.approve(id, &proofs, approvers))?;
    Metrics::bump(&cp.metrics.minted);
    Ok(Response::json(201, issued_json(&issued).to_string()))
}

fn deny_request(
    cp: &Arc<ControlPlane>,
    caller: &Caller,
    id: &str,
    req: &Request,
) -> Result<Response> {
    let body = body_json(req)?;
    let reason = field(&body, "reason")?.to_string();
    with_issuer(cp, caller, |issuer| issuer.deny(id, &reason))?;
    Ok(Response::json(
        200,
        json!({"request": id, "status": "Denied"}).to_string(),
    ))
}

fn quarantine(cp: &Arc<ControlPlane>, caller: &Caller, req: &Request) -> Result<Response> {
    let body = body_json(req)?;
    let party = EntityId::new(field(&body, "party")?)?;
    let reason = field(&body, "reason")?.to_string();
    let approvers: Vec<HumanRef> = string_list(&body, "approvers")
        .into_iter()
        .map(HumanRef::new)
        .collect::<Result<Vec<_>>>()?;

    let now = (cp.now)();
    let outcome = {
        let mut store = lock(&cp.store);
        store
            .registry(actor_for(caller), now)
            .quarantine(&party, &reason, &approvers)?
    };

    {
        let mut evidence = lock(&cp.evidence);
        evidence.record(
            &crate::evidence::LifecycleEvent::new(
                crate::evidence::EventKind::Quarantine,
                caller.subject.clone(),
            )
            .with_entities([party.as_str()])
            .with_reason(reason)
            .with_detail(json!({
                "revoked": outcome.revoked.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                "impacted_services": outcome.impacted_services,
            })),
            now,
        )?;
    }

    Ok(Response::json(
        202,
        json!({
            "party": outcome.party.as_str(),
            "revoked": outcome.revoked.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            "impacted_services": outcome.impacted_services,
        })
        .to_string(),
    ))
}

/// Lift a quarantine, returning the party to `Pending` for full re-admission.
///
/// The one place `wc_quarantine_duration_seconds` is observed. It is a histogram over
/// clearings, so it is recorded here — where the pairing is a single field read — rather
/// than derived at scrape time from the evidence chain, which grows monotonically and
/// would make every scrape slower than the last.
fn clear_quarantine(cp: &Arc<ControlPlane>, caller: &Caller, req: &Request) -> Result<Response> {
    let body = body_json(req)?;
    let party = EntityId::new(field(&body, "party")?)?;
    let approvers: Vec<HumanRef> = string_list(&body, "approvers")
        .into_iter()
        .map(HumanRef::new)
        .collect::<Result<Vec<_>>>()?;
    let why = body
        .get("why")
        .and_then(|v| v.as_str())
        .unwrap_or("quarantine lifted")
        .to_string();

    let now = (cp.now)();
    let held_for = {
        let mut store = lock(&cp.store);
        store
            .registry(actor_for(caller), now)
            .clear_quarantine(&party, &approvers)?
    };

    if let Some(seconds) = held_for {
        crate::obs::quarantine_duration(&cp.registry, seconds);
    }

    {
        let mut evidence = lock(&cp.evidence);
        evidence.record(
            &crate::evidence::LifecycleEvent::new(
                crate::evidence::EventKind::QuarantineCleared,
                caller.subject.clone(),
            )
            .with_entities([party.as_str()])
            .with_reason(why)
            .with_detail(json!({
                "approvers": approvers.iter().map(HumanRef::as_str).collect::<Vec<_>>(),
                "held_for_seconds": held_for,
                // Said in the record, not only in the prose: "cleared" reads like
                // "restored", and it is not.
                "contracts_restored": false,
            })),
            now,
        )?;
    }

    Ok(Response::json(
        202,
        json!({
            "party": party.as_str(),
            "posture": "unattested",
            "lifecycle": "pending",
            "held_for_seconds": held_for,
            "contracts_restored": false,
        })
        .to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Handlers — the data plane
// ---------------------------------------------------------------------------

/// The contract set a mediator should hold (§8.7.9).
///
/// Pull, not push: a distribution failure is then *visible* as ACK lag rather than
/// silently lost. `since` lets a mediator skip work it already has, but the set is
/// always complete — a delta that could drift out of sync would be a worse trade
/// than re-sending a few kilobytes.
fn contract_set(cp: &Arc<ControlPlane>, mediator: &str, req: &Request) -> Result<Response> {
    Metrics::bump(&cp.metrics.pulls);
    let since = req.param_u64("since").unwrap_or(0);
    let now = (cp.now)();

    let store = lock(&cp.store);
    // One implementation of the set hash, shared with whatever wants to know the expected
    // value — a deploy gate most of all. A second copy here would be a digest that can
    // disagree with itself.
    let view = store.projection.contract_set_for(mediator, now);
    let seq = view.seq;
    let set_hash = view.set_hash.clone();
    let removed: Vec<&str> = view
        .removed
        .iter()
        .map(wc_core::model::Cid::as_str)
        .collect();
    let active: Vec<&wc_core::contract::ContractRecord> = view
        .active
        .iter()
        .filter_map(|cid| store.projection.contracts.get(cid))
        .collect();

    Ok(Response::json(
        200,
        json!({
            "mediator": mediator,
            "seq": seq,
            "since": since,
            "set_hash": set_hash,
            "full": true,
            "active": active.iter().map(|c| json!({
                "cid": c.cid.as_str(),
                "jti": c.jti.as_str(),
                "caller": c.caller.as_str(),
                "callee": c.callee.as_str(),
                "surface": c.surface.items(),
                "exp": c.exp,
                "jws_sha256": c.jws_sha256,
                // The artifact itself, not just its digest: a mediator verifies the
                // signed document, and a set that only described it would be
                // unusable.
                "jws": store.read_artifact(c.cid.as_str(), mediator),
            })).collect::<Vec<_>>(),
            "removed": removed,
        })
        .to_string(),
    ))
}

/// Record a mediator's acknowledgement.
fn record_ack(cp: &Arc<ControlPlane>, mediator: &str, req: &Request) -> Result<Response> {
    let body = body_json(req)?;
    let ack = crate::dist::SetAck {
        set_hash: field(&body, "set_hash")?.to_string(),
        seq: body.get("seq").and_then(Value::as_u64).unwrap_or(0),
        at: (cp.now)(),
        revoked: string_list(&body, "revoked"),
        aborted: body.get("aborted").and_then(Value::as_u64).unwrap_or(0),
        rejected: body.get("rejected").and_then(Value::as_u64).unwrap_or(0),
    };

    // Persist while the lock is held, so a concurrent ack cannot write a file that disagrees
    // with the map. Two mediators acking at once is the ordinary case, not the rare one.
    let used: std::collections::BTreeMap<String, u64> = body
        .get("used")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_u64().map(|at| (k.clone(), at)))
                .collect()
        })
        .unwrap_or_default();

    let mut ledger = lock(&cp.acks);
    let moved = ledger.record(mediator, ack);
    // Usage is recorded even when the ack itself did not move the ledger. A mediator re-acking the
    // same set is the ordinary steady state — nothing new to distribute, calls still flowing — and
    // discarding usage in that case would make every stable connection look dormant.
    let used_moved = !used.is_empty();
    if used_moved {
        ledger.record_usage(mediator, &used);
    }
    if moved || used_moved {
        if let Some(path) = &cp.acks_path {
            // A failed write is reported and does not fail the ack. The mediator has already
            // applied the set; refusing here would make it retry a state change it has made,
            // and the durable record is a convenience for a gate rather than the authority for
            // what a mediator is enforcing.
            if let Err(e) = ledger.save(path) {
                eprintln!("connect: contract-set ack not persisted: {e}");
            }
        }
    }
    drop(ledger);
    Ok(Response::empty(204))
}

/// Serve the signed revocation feed from `since`.
///
/// Every entry carries its own signature, so a mediator verifies each one against
/// the revocation key it was configured with. That is what makes a compromised
/// control plane unable to forge a cut — and equally unable to hide one, because
/// the sequence is contiguous and a gap is visible to the puller.
fn revocation_feed(cp: &Arc<ControlPlane>, req: &Request) -> Result<Response> {
    let Some(feed) = &cp.revocations else {
        // Not an empty feed. A mediator must be able to tell "nothing is revoked"
        // from "this control plane has no feed", because the second one means it
        // should not treat the absence of revocations as reassurance.
        return Err(WcError::with_detail(
            Code::REVOCATION_FEED_UNWRITABLE,
            "this control plane serves no revocation feed",
        ));
    };
    let since = req
        .query
        .get("since")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let feed = lock(feed);
    let events: Vec<Value> = feed
        .since(since)
        .into_iter()
        .map(|e| json!({ "event": e.event, "jws": e.jws, "kid": e.kid }))
        .collect();
    Ok(Response::json(
        200,
        json!({
            "since": since,
            "head_seq": feed.next_seq() - 1,
            "head_digest": feed.head_digest(),
            "events": events,
        })
        .to_string(),
    ))
}

/// Which mediators have confirmed, and which have not.
///
/// A mediator that has not acked is reported as **unconfirmed**, never as
/// contained (§8.7.7). Absence of a confirmation is not a confirmation.
fn mediator_status(cp: &Arc<ControlPlane>) -> Result<Response> {
    let now = (cp.now)();
    let store = lock(&cp.store);
    let mut expected: Vec<String> = store
        .projection
        .contracts
        .values()
        .flat_map(|c| c.aud.clone())
        .collect();
    drop(store);
    expected.sort_unstable();
    expected.dedup();

    let acks = lock(&cp.acks);
    let rows: Vec<Value> = expected
        .iter()
        .map(|mediator| match acks.ack_for(mediator) {
            Some(ack) => json!({
                "mediator": mediator,
                "confirmed": true,
                "set_hash": ack.set_hash,
                "seq": ack.seq,
                "lag_secs": now.saturating_sub(ack.at),
                "revoked": ack.revoked,
                "aborted": ack.aborted,
            }),
            None => json!({
                "mediator": mediator,
                "confirmed": false,
                "why": "no acknowledgement received; treated as unconfirmed, never as contained",
            }),
        })
        .collect();

    let unconfirmed = rows
        .iter()
        .filter(|r| r["confirmed"] == json!(false))
        .count();
    Ok(Response::json(
        200,
        json!({"mediators": rows, "unconfirmed": unconfirmed}).to_string(),
    ))
}

fn audit_verify(cp: &Arc<ControlPlane>) -> Result<Response> {
    let evidence = lock(&cp.evidence);
    let (seq, hash) = evidence.head();
    drop(evidence);
    Ok(Response::json(
        200,
        json!({"head_seq": seq, "head_hash": hash}).to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn error(status: u16, code: Code, detail: &str) -> Response {
    Response::json(
        status,
        json!({"error": code.summary(), "code": code.to_string(), "detail": detail}).to_string(),
    )
}

/// Map a domain error onto an HTTP response, using the code table's own status
/// rather than a per-handler guess (§8.11).
fn from_error(e: &WcError) -> Response {
    let status = e
        .code()
        .spec()
        .and_then(|s| s.http)
        .unwrap_or(match e.code().category() {
            wc_core::error::Category::Verification => 403,
            _ => 400,
        });
    error(status, e.code(), e.detail())
}
