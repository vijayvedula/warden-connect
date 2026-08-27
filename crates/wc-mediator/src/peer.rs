//! Where peer identity actually comes from (`docs/08-lld.md` §8.6.6).
//!
//! Check 6 and check 7 compare the contract's caller and callee against the
//! *authenticated* peers. Everything the mediator enforces rests on those two
//! names being real, which makes this the shortest and most load-bearing module
//! in the crate.
//!
//! # The rule
//!
//! **Peer identity is never taken from a claim in the request body.** A JSON-RPC
//! payload saying `"caller": "spiffe://org/ns/agents/sa/finance-bot"` is a
//! statement by whoever wrote the payload, which is the party we are trying to
//! constrain. Identity comes from the transport, or from a signed token with a
//! proof of possession, and from nowhere else.
//!
//! # Four sources, and what each one actually trusts
//!
//! | Mode | Source | Trust rests on |
//! |---|---|---|
//! | [`PeerSource::Configured`] | operator configuration | the sidecar owning exactly one agent and one upstream |
//! | [`PeerSource::Mtls`] | SAN URI from a completed TLS handshake | the handshake |
//! | [`PeerSource::Mesh`] | `x-forwarded-client-cert`, **only** from a configured local origin | the local socket plus the mesh's own mTLS |
//! | [`PeerSource::JwtSvid`] | a signed JWT-SVID | the signature, the audience, and the expiry |
//!
//! `Configured` is honest for the stdio sidecar and wrong for a shared gateway,
//! so it records that it is configuration rather than authentication and the
//! resulting [`Peer::verified`] is `false`.
//!
//! # The mesh case is the one that goes wrong
//!
//! Header-based identity that is trusted from anywhere is not identity — it is a
//! request field with a hyphen in it. Any client that can reach the mediator
//! directly can set `x-forwarded-client-cert` to whatever it likes. So the header
//! is honoured only when the connection arrived over a configured local origin,
//! and from anywhere else it is refused as [`Code::PEER_HEADER_UNTRUSTED`] and
//! recorded as a spoofing attempt rather than quietly ignored.

use std::collections::BTreeMap;

use wc_core::contract::{IssuerKeys, PeerIdentity};
use wc_core::error::{Code, Result, WcError};
use wc_core::model::EntityId;

/// Where a connection arrived from, as the server observed it.
///
/// Observed, not claimed: this comes from the accepted socket, never from a
/// header. That is the entire distinction the mesh mode rests on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A unix domain socket at this path.
    UnixSocket {
        /// The socket path the connection arrived on.
        path: String,
    },
    /// A TCP peer address.
    Tcp {
        /// The remote address, as the OS reported it.
        addr: String,
    },
    /// Standard input — the sidecar case, where there is no network at all.
    Stdio,
}

impl Origin {
    /// Whether this origin is loopback or a local socket.
    ///
    /// Loopback is necessary but nowhere near sufficient: on a shared host every
    /// process is on loopback. It is one half of the mesh check, and
    /// [`MeshTrust`] carries the other.
    #[must_use]
    pub fn is_local(&self) -> bool {
        match self {
            Origin::UnixSocket { .. } | Origin::Stdio => true,
            Origin::Tcp { addr } => {
                // Parsed as an address, never prefix-matched. `starts_with("127.")`
                // accepts the *hostname* `127.0.0.1.evil.example`, which resolves
                // wherever its owner likes — caught by this module's own test.
                let host = addr.rsplit_once(':').map_or(addr.as_str(), |(h, _)| h);
                let host = host.trim_start_matches('[').trim_end_matches(']');
                host.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            }
        }
    }

    /// A label for logs and findings.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Origin::UnixSocket { path } => format!("unix:{path}"),
            Origin::Tcp { addr } => format!("tcp:{addr}"),
            Origin::Stdio => "stdio".to_string(),
        }
    }
}

/// What a mesh deployment will accept a peer header from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MeshTrust {
    /// The exact unix socket the mesh sidecar connects over.
    pub socket: Option<String>,
    /// TCP addresses the sidecar may connect from, if it uses TCP.
    pub addrs: Vec<String>,
}

impl MeshTrust {
    /// Trust one unix socket.
    #[must_use]
    pub fn socket(path: impl Into<String>) -> MeshTrust {
        MeshTrust {
            socket: Some(path.into()),
            addrs: Vec::new(),
        }
    }

    /// Whether a header from this origin may be believed.
    ///
    /// An empty configuration trusts **nothing**. A default that trusted loopback
    /// would mean every co-located process on the host can assert any identity,
    /// and "we forgot to configure it" would look identical to "it is configured".
    #[must_use]
    pub fn accepts(&self, origin: &Origin) -> bool {
        if self.socket.is_none() && self.addrs.is_empty() {
            return false;
        }
        match origin {
            Origin::UnixSocket { path } => self.socket.as_deref() == Some(path.as_str()),
            Origin::Tcp { addr } => origin.is_local() && self.addrs.iter().any(|a| a == addr),
            // The sidecar does not speak to us over stdio; if it did there would
            // be no header.
            Origin::Stdio => false,
        }
    }
}

// ---------------------------------------------------------------------------
// The resolved peer
// ---------------------------------------------------------------------------

/// An authenticated peer pair, with how it was established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The identities checks 6 and 7 compare against.
    pub identity: PeerIdentity,
    /// How they were established, for the audit row.
    pub method: String,
    /// Whether this was authentication or configuration.
    ///
    /// `false` means the identities are asserted by the operator rather than
    /// proved by the transport. That is correct for a sidecar owning one agent,
    /// and the field exists so nothing downstream can mistake it for a handshake.
    pub verified: bool,
}

/// How a mediator establishes peer identity.
pub enum PeerSource {
    /// Operator-supplied, for the stdio sidecar.
    Configured {
        /// The calling party.
        caller: EntityId,
        /// The called party.
        callee: EntityId,
    },
    /// From the SAN URI of a completed TLS handshake.
    ///
    /// The handshake happens above this module; the caller passes what it
    /// authenticated. The callee is the mediator's own upstream, which is
    /// configuration either way.
    Mtls {
        /// Fixed callee — the upstream this mediator fronts.
        callee: EntityId,
    },
    /// From `x-forwarded-client-cert`, honoured only from a trusted origin.
    Mesh {
        /// Where the header may be believed from.
        trust: MeshTrust,
        /// Fixed callee.
        callee: EntityId,
    },
    /// From a JWT-SVID presented by the caller.
    JwtSvid {
        /// Trust bundle.
        keys: IssuerKeys,
        /// Audience this mediator answers to.
        audience: String,
        /// Clock leeway, seconds.
        leeway: u64,
        /// Fixed callee.
        callee: EntityId,
    },
}

impl std::fmt::Debug for PeerSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerSource::Configured { caller, callee } => f
                .debug_struct("Configured")
                .field("caller", caller)
                .field("callee", callee)
                .finish(),
            PeerSource::Mtls { callee } => f.debug_struct("Mtls").field("callee", callee).finish(),
            PeerSource::Mesh { trust, callee } => f
                .debug_struct("Mesh")
                .field("trust", trust)
                .field("callee", callee)
                .finish(),
            PeerSource::JwtSvid {
                audience, callee, ..
            } => f
                .debug_struct("JwtSvid")
                .field("audience", audience)
                .field("callee", callee)
                .finish_non_exhaustive(),
        }
    }
}

/// What the transport observed about one connection.
#[derive(Debug, Clone, Default)]
pub struct Presented {
    /// Where the connection came from.
    pub origin: Option<Origin>,
    /// SAN URI from a completed handshake, if TLS terminated here.
    pub san_uri: Option<String>,
    /// Headers, lowercased.
    pub headers: BTreeMap<String, String>,
    /// A bearer JWT-SVID, if one was presented.
    pub token: Option<String>,
}

impl Presented {
    /// From a completed mTLS handshake.
    #[must_use]
    pub fn mtls(san_uri: impl Into<String>, origin: Origin) -> Presented {
        Presented {
            origin: Some(origin),
            san_uri: Some(san_uri.into()),
            ..Presented::default()
        }
    }

    /// From a mesh sidecar.
    #[must_use]
    pub fn mesh(xfcc: impl Into<String>, origin: Origin) -> Presented {
        let mut headers = BTreeMap::new();
        headers.insert("x-forwarded-client-cert".to_string(), xfcc.into());
        Presented {
            origin: Some(origin),
            headers,
            ..Presented::default()
        }
    }
}

impl PeerSource {
    /// The mode name, for logs and the ACK.
    #[must_use]
    pub fn mode(&self) -> &'static str {
        match self {
            PeerSource::Configured { .. } => "configured",
            PeerSource::Mtls { .. } => "mtls",
            PeerSource::Mesh { .. } => "mesh",
            PeerSource::JwtSvid { .. } => "jwt-svid",
        }
    }

    /// Parse a mode name.
    ///
    /// An unrecognised mode is an error rather than a fallback: silently selecting
    /// `configured` when an operator asked for `mtls` would turn a typo into an
    /// unauthenticated deployment that reports success.
    pub fn parse_mode(name: &str) -> Result<&'static str> {
        match name.trim() {
            "configured" => Ok("configured"),
            "mtls" => Ok("mtls"),
            "mesh" => Ok("mesh"),
            "jwt-svid" => Ok("jwt-svid"),
            other => Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("--peer-mode must be configured|mtls|mesh|jwt-svid, got {other:?}"),
            )),
        }
    }

    /// Establish the peer pair for one connection.
    pub fn resolve(&self, presented: &Presented) -> Result<Peer> {
        match self {
            PeerSource::Configured { caller, callee } => Ok(Peer {
                identity: PeerIdentity {
                    caller: caller.clone(),
                    callee: callee.clone(),
                },
                method: "configured by the operator; not authenticated".to_string(),
                // Not a handshake, and nothing downstream may mistake it for one.
                verified: false,
            }),

            PeerSource::Mtls { callee } => {
                let san = presented.san_uri.as_deref().ok_or_else(|| {
                    WcError::with_detail(
                        Code::CALLER_PEER_MISMATCH,
                        "mtls mode but the connection presented no client certificate",
                    )
                })?;
                let caller = spiffe_id(san)?;
                Ok(Peer {
                    identity: PeerIdentity {
                        caller,
                        callee: callee.clone(),
                    },
                    method: format!("x509-svid san={san}"),
                    verified: true,
                })
            }

            PeerSource::Mesh { trust, callee } => {
                let origin = presented.origin.as_ref().ok_or_else(|| {
                    WcError::with_detail(
                        Code::PEER_HEADER_UNTRUSTED,
                        "mesh mode but the connection origin was not observed",
                    )
                })?;
                let header = presented
                    .headers
                    .get("x-forwarded-client-cert")
                    .ok_or_else(|| {
                        WcError::with_detail(
                            Code::CALLER_PEER_MISMATCH,
                            "mesh mode but no x-forwarded-client-cert was presented",
                        )
                    })?;

                // The whole of mesh mode. A header believed from anywhere is a
                // request field with a hyphen in it.
                if !trust.accepts(origin) {
                    return Err(WcError::with_detail(
                        Code::PEER_HEADER_UNTRUSTED,
                        format!(
                            "x-forwarded-client-cert presented from {}, which is not the configured \
                             mesh origin; treating as a spoofing attempt",
                            origin.describe()
                        ),
                    ));
                }

                let caller = spiffe_id(&xfcc_peer_uri(header)?)?;
                Ok(Peer {
                    identity: PeerIdentity {
                        caller,
                        callee: callee.clone(),
                    },
                    method: format!("mesh xfcc via {}", origin.describe()),
                    verified: true,
                })
            }

            PeerSource::JwtSvid {
                keys,
                audience,
                leeway,
                callee,
            } => {
                let token = presented.token.as_deref().ok_or_else(|| {
                    WcError::with_detail(
                        Code::CALLER_PEER_MISMATCH,
                        "jwt-svid mode but no token was presented",
                    )
                })?;
                let (subject, kid) = verify_svid(token, keys, audience, *leeway)?;
                Ok(Peer {
                    identity: PeerIdentity {
                        caller: spiffe_id(&subject)?,
                        callee: callee.clone(),
                    },
                    method: format!("jwt-svid kid={kid} aud={audience}"),
                    verified: true,
                })
            }
        }
    }
}

/// Validate a SPIFFE ID and wrap it.
fn spiffe_id(raw: &str) -> Result<EntityId> {
    let trimmed = raw.trim();
    if !trimmed.starts_with("spiffe://") {
        return Err(WcError::with_detail(
            Code::CALLER_PEER_MISMATCH,
            format!("peer identity {trimmed:?} is not a SPIFFE ID"),
        ));
    }
    EntityId::new(trimmed)
}

// ---------------------------------------------------------------------------
// x-forwarded-client-cert
// ---------------------------------------------------------------------------

/// The peer's SAN URI from an `x-forwarded-client-cert` header.
///
/// The header is a comma-separated list, one element per hop, each a
/// semicolon-separated set of `Key=Value` pairs with optionally quoted values.
///
/// **More than one element is refused.** Each element is only as trustworthy as
/// the hop that wrote it, and with several there is no way to tell which one is
/// the peer that actually authenticated to the sidecar in front of us. A mediator
/// sits behind exactly one sidecar; anything else means the deployment is not what
/// this mode assumes, and guessing which element to believe is how a
/// multi-hop path becomes an identity-spoofing path.
pub fn xfcc_peer_uri(header: &str) -> Result<String> {
    let elements = split_xfcc_elements(header);
    if elements.is_empty() {
        return Err(WcError::with_detail(
            Code::CALLER_PEER_MISMATCH,
            "x-forwarded-client-cert is empty",
        ));
    }
    if elements.len() > 1 {
        return Err(WcError::with_detail(
            Code::PEER_HEADER_UNTRUSTED,
            format!(
                "x-forwarded-client-cert has {} elements; each is only as trustworthy as the hop \
                 that wrote it, and this mediator sits behind exactly one sidecar",
                elements.len()
            ),
        ));
    }

    let mut uri: Option<String> = None;
    for (key, value) in parse_xfcc_pairs(&elements[0]) {
        // `URI=` is the peer's identity. `By=` is the *proxy's* own identity, and
        // reading it would authenticate the sidecar as the caller.
        if key.eq_ignore_ascii_case("URI") {
            if uri.is_some() {
                return Err(WcError::with_detail(
                    Code::PEER_HEADER_UNTRUSTED,
                    "x-forwarded-client-cert element carries more than one URI",
                ));
            }
            uri = Some(value);
        }
    }
    uri.ok_or_else(|| {
        WcError::with_detail(
            Code::CALLER_PEER_MISMATCH,
            "x-forwarded-client-cert carries no URI= SAN",
        )
    })
}

/// Split on commas that are not inside a quoted value.
fn split_xfcc_elements(header: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for c in header.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ',' if !in_quotes => {
                if !current.trim().is_empty() {
                    out.push(current.trim().to_string());
                }
                current = String::new();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

/// Split one element into `Key=Value` pairs, unquoting values.
fn parse_xfcc_pairs(element: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    let push = |raw: &str, out: &mut Vec<(String, String)>| {
        if let Some((k, v)) = raw.split_once('=') {
            out.push((k.trim().to_string(), unquote(v.trim())));
        }
    };

    for c in element.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ';' if !in_quotes => {
                push(&current, &mut out);
                current = String::new();
            }
            _ => current.push(c),
        }
    }
    push(&current, &mut out);
    out
}

fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        trimmed[1..trimmed.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        trimmed.to_string()
    }
}

// ---------------------------------------------------------------------------
// JWT-SVID
// ---------------------------------------------------------------------------

/// Verify a JWT-SVID and return its subject and the key that signed it.
fn verify_svid(
    token: &str,
    keys: &IssuerKeys,
    audience: &str,
    leeway: u64,
) -> Result<(String, String)> {
    use base64::Engine as _;

    if audience.trim().is_empty() {
        // An empty audience makes `validate_aud` vacuous, so a token minted for
        // any other service would authenticate here.
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            "jwt-svid audience must be set; an unbound audience accepts tokens minted for anyone",
        ));
    }
    if keys.is_empty() {
        return Err(WcError::with_detail(
            Code::CALLER_PEER_MISMATCH,
            "jwt-svid mode with no trust bundle keys",
        ));
    }

    let header_seg = token.split('.').next().unwrap_or_default();
    let header: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_seg)
            .map_err(|e| {
                WcError::with_detail(Code::CALLER_PEER_MISMATCH, "SVID header is not base64url")
                    .with_source(e)
            })?,
    )
    .map_err(|e| {
        WcError::with_detail(Code::CALLER_PEER_MISMATCH, "SVID header is not JSON").with_source(e)
    })?;

    // `alg` is read as a string before any JOSE library sees it, so `alg: none`
    // reports "not asymmetric" rather than "malformed".
    let alg = header
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !wc_core::contract::ACCEPTED_ALG_NAMES.contains(&alg) {
        return Err(WcError::with_detail(
            Code::ALG_NOT_ASYMMETRIC,
            format!("SVID uses {alg:?}"),
        ));
    }
    let kid = header
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            WcError::with_detail(
                Code::CALLER_PEER_MISMATCH,
                "SVID has no `kid`; there is no way to choose a trusted key",
            )
        })?
        .to_string();

    let (registered, key) = keys.get(&kid).ok_or_else(|| {
        WcError::with_detail(
            Code::CALLER_PEER_MISMATCH,
            format!("SVID `kid` {kid:?} is not in the trust bundle"),
        )
    })?;
    if alg != format!("{registered:?}") {
        return Err(WcError::with_detail(
            Code::CALLER_PEER_MISMATCH,
            format!("SVID header says {alg:?} but the key is registered for {registered:?}"),
        ));
    }

    #[derive(serde::Deserialize)]
    struct Claims {
        sub: String,
    }
    let mut validation = jsonwebtoken::Validation::new(*registered);
    validation.leeway = leeway;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "aud", "sub"]);

    let data = jsonwebtoken::decode::<Claims>(token, key, &validation).map_err(|e| {
        WcError::with_detail(Code::CALLER_PEER_MISMATCH, "SVID verification failed").with_source(e)
    })?;
    Ok((data.claims.sub, kid))
}

// ---------------------------------------------------------------------------
// X.509 SAN extraction
// ---------------------------------------------------------------------------

/// The SPIFFE ID out of a peer certificate's URI SAN.
///
/// # Where this sits in the trust chain, and what it is NOT
///
/// This does not verify anything. The chain, the expiry and the CA are the TLS terminator's
/// job — nginx with `ssl_verify_client on`, Envoy with a validation context — and a binding
/// must refuse before calling this unless that verification *succeeded*. What this does is read
/// an identity out of a certificate somebody else has already decided to trust.
///
/// That ordering is the whole safety argument. A mis-parse here yields a wrong identity or no
/// identity, and a wrong identity resolves to no contract; it cannot yield a *forged* one,
/// because an attacker cannot get an arbitrary certificate past the verifier in the first
/// place. Reverse the order — parse first, verify later, or never — and the same code becomes
/// an identity forgery path.
///
/// # Why exactly one URI
///
/// The SPIFFE X.509-SVID spec allows exactly one URI SAN. Zero is not an SVID. More than one is
/// ambiguous, and picking the first would let a certificate carrying two identities be used as
/// whichever one the parser happened to reach first. Both are refused.
///
/// # Errors
///
/// [`Code::IDENTITY_UNVERIFIABLE`] when the certificate carries no usable SPIFFE URI SAN, naming which of
/// the three cases it was so an operator can tell "wrong certificate" from "wrong CA".
pub fn spiffe_from_cert_pem(pem: &str) -> Result<String> {
    let der = first_certificate_der(pem)
        .ok_or_else(|| WcError::with_detail(Code::IDENTITY_UNVERIFIABLE, "no CERTIFICATE block in the peer PEM"))?;
    let uris = uri_sans(&der).ok_or_else(|| {
        WcError::with_detail(
            Code::IDENTITY_UNVERIFIABLE,
            "the peer certificate could not be parsed for subjectAltName",
        )
    })?;
    let mut spiffe = uris.iter().filter(|u| u.starts_with("spiffe://"));
    let first = spiffe.next().ok_or_else(|| {
        WcError::with_detail(
            Code::IDENTITY_UNVERIFIABLE,
            if uris.is_empty() {
                "the peer certificate has no URI subjectAltName, so it is not an X.509-SVID"
            } else {
                "the peer certificate's URI subjectAltName is not a spiffe:// id"
            },
        )
    })?;
    if spiffe.next().is_some() {
        return Err(WcError::with_detail(
            Code::IDENTITY_UNVERIFIABLE,
            "the peer certificate carries more than one spiffe:// URI subjectAltName, which is \
             not a valid X.509-SVID and would let the holder pick an identity",
        ));
    }
    Ok(first.clone())
}

/// DER of the first `CERTIFICATE` block in a PEM. The leaf, by convention of every chain
/// serialiser: the peer's own certificate is first and its issuers follow.
fn first_certificate_der(pem: &str) -> Option<Vec<u8>> {
    const B: &str = "-----BEGIN CERTIFICATE-----";
    const E: &str = "-----END CERTIFICATE-----";
    let start = pem.find(B)? + B.len();
    let end = pem[start..].find(E)? + start;
    let body: String = pem[start..end].chars().filter(|c| !c.is_whitespace()).collect();
    wc_core::util::base64_decode(&body)
}

/// One DER tag-length-value.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    /// How many bytes this TLV occupied, header included.
    total: usize,
}

/// Read one TLV at the front of `b`.
///
/// Refuses indefinite-length encoding (`0x80`), which is legal BER and never legal DER, and any
/// length that runs past the buffer. Both are `None` rather than a truncated read.
fn tlv(b: &[u8]) -> Option<Tlv<'_>> {
    let tag = *b.first()?;
    let l0 = *b.get(1)?;
    let (len, hdr) = if l0 & 0x80 == 0 {
        (usize::from(l0), 2)
    } else {
        let n = usize::from(l0 & 0x7F);
        // 0x80 is indefinite length: not DER. A long form longer than a usize cannot be
        // represented and is refused rather than wrapped.
        if n == 0 || n > core::mem::size_of::<usize>() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = len.checked_mul(256)?.checked_add(usize::from(*b.get(2 + i)?))?;
        }
        (len, 2 + n)
    };
    let value = b.get(hdr..hdr.checked_add(len)?)?;
    Some(Tlv {
        tag,
        value,
        total: hdr + len,
    })
}

/// Every TLV in `b`, in order. Stops at the first malformed one.
fn children(b: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        let Some(t) = tlv(rest) else { break };
        let step = t.total;
        out.push(t);
        // A zero-length step would spin. Cannot happen with a valid header, but this parser
        // reads attacker-adjacent bytes and a loop bound is cheaper than an argument.
        if step == 0 {
            break;
        }
        rest = &rest[step..];
    }
    out
}

/// `id-ce-subjectAltName`, OID 2.5.29.17, as its DER content bytes.
const OID_SAN: &[u8] = &[0x55, 0x1D, 0x11];

/// Every `uniformResourceIdentifier` in the certificate's SubjectAltName.
///
/// Walks by tag rather than by field position: the certificate's own structure is not
/// interpreted beyond "the first child of the outer SEQUENCE is the TBS, and somewhere in it is
/// a `[3]` holding extensions". Nothing here needs to know what a validity period is.
fn uri_sans(der: &[u8]) -> Option<Vec<String>> {
    let cert = tlv(der)?;
    if cert.tag != 0x30 {
        return None;
    }
    let tbs = children(cert.value).into_iter().next()?;
    if tbs.tag != 0x30 {
        return None;
    }
    // [3] EXPLICIT Extensions. Absent is a certificate with no extensions at all, which is
    // legal and simply has no SAN — an empty list, not a parse failure.
    let Some(ext_holder) = children(tbs.value).into_iter().find(|t| t.tag == 0xA3) else {
        return Some(Vec::new());
    };
    let extensions = children(ext_holder.value).into_iter().next()?;
    if extensions.tag != 0x30 {
        return None;
    }
    for ext in children(extensions.value) {
        if ext.tag != 0x30 {
            continue;
        }
        let parts = children(ext.value);
        let Some(oid) = parts.first() else { continue };
        if oid.tag != 0x06 || oid.value != OID_SAN {
            continue;
        }
        // extnValue is the last element: the optional `critical` BOOLEAN sits between the OID
        // and it, so a fixed index would read the wrong field on a critical SAN.
        let Some(octets) = parts.last() else { continue };
        if octets.tag != 0x04 {
            continue;
        }
        let names = tlv(octets.value)?;
        if names.tag != 0x30 {
            return None;
        }
        let mut out = Vec::new();
        for n in children(names.value) {
            // [6] IA5String uniformResourceIdentifier, primitive.
            if n.tag == 0x86 {
                out.push(String::from_utf8_lossy(n.value).into_owned());
            }
        }
        return Some(out);
    }
    Some(Vec::new())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const CALLER: &str = "spiffe://org/ns/agents/sa/recon";
    const CALLEE: &str = "spiffe://org/ns/tools/sa/payments-mcp";

    fn id(s: &str) -> EntityId {
        EntityId::new(s).unwrap()
    }

    fn upstream() -> EntityId {
        id(CALLEE)
    }

    // --- origins -----------------------------------------------------------

    #[test]
    fn loopback_and_local_sockets_are_local_and_nothing_else_is() {
        assert!(Origin::Stdio.is_local());
        assert!(Origin::UnixSocket {
            path: "/run/mesh.sock".to_string()
        }
        .is_local());
        assert!(Origin::Tcp {
            addr: "127.0.0.1:15001".to_string()
        }
        .is_local());
        assert!(Origin::Tcp {
            addr: "[::1]:15001".to_string()
        }
        .is_local());
        assert!(!Origin::Tcp {
            addr: "10.1.2.3:443".to_string()
        }
        .is_local());
        assert!(Origin::Tcp {
            addr: "127.9.9.9:80".to_string()
        }
        .is_local());
        // The ones that look local and are not. A hostname that merely starts with
        // "127." resolves wherever its owner likes.
        for pretender in [
            "127.0.0.1.evil.example:443",
            "127-0-0-1.evil.example:443",
            "localhost.evil.example:443",
            "0177.0.0.1:80",
        ] {
            assert!(
                !Origin::Tcp {
                    addr: pretender.to_string()
                }
                .is_local(),
                "{pretender} must not read as loopback"
            );
        }
    }

    // --- configured --------------------------------------------------------

    #[test]
    fn configured_identity_reports_that_it_is_not_authenticated() {
        // Correct for a sidecar owning one agent, wrong for a shared gateway. The
        // field exists so nothing downstream can mistake it for a handshake.
        let source = PeerSource::Configured {
            caller: id(CALLER),
            callee: upstream(),
        };
        let peer = source.resolve(&Presented::default()).unwrap();
        assert_eq!(peer.identity.caller.as_str(), CALLER);
        assert!(!peer.verified);
        assert!(peer.method.contains("not authenticated"));
    }

    // --- mtls --------------------------------------------------------------

    #[test]
    fn mtls_takes_the_caller_from_the_handshake() {
        let source = PeerSource::Mtls { callee: upstream() };
        let peer = source
            .resolve(&Presented::mtls(
                CALLER,
                Origin::Tcp {
                    addr: "10.1.2.3:52000".to_string(),
                },
            ))
            .unwrap();
        assert_eq!(peer.identity.caller.as_str(), CALLER);
        assert!(peer.verified);
        assert!(peer.method.starts_with("x509-svid"));
    }

    #[test]
    fn mtls_without_a_client_certificate_is_refused() {
        let source = PeerSource::Mtls { callee: upstream() };
        let err = source.resolve(&Presented::default()).unwrap_err();
        assert_eq!(err.code(), Code::CALLER_PEER_MISMATCH);
    }

    #[test]
    fn a_non_spiffe_san_is_refused() {
        let source = PeerSource::Mtls { callee: upstream() };
        let err = source
            .resolve(&Presented::mtls("https://example.com/x", Origin::Stdio))
            .unwrap_err();
        assert!(err.to_string().contains("not a SPIFFE ID"));
    }

    // --- mesh: the mode that goes wrong ------------------------------------

    fn xfcc(uri: &str) -> String {
        format!(
            "By=spiffe://org/ns/mesh/sa/sidecar;Hash=abc123;Subject=\"CN=recon,O=org\";URI={uri}"
        )
    }

    fn mesh_source() -> PeerSource {
        PeerSource::Mesh {
            trust: MeshTrust::socket("/run/mesh.sock"),
            callee: upstream(),
        }
    }

    #[test]
    fn mesh_accepts_the_header_from_the_configured_socket() {
        let peer = mesh_source()
            .resolve(&Presented::mesh(
                xfcc(CALLER),
                Origin::UnixSocket {
                    path: "/run/mesh.sock".to_string(),
                },
            ))
            .unwrap();
        assert_eq!(peer.identity.caller.as_str(), CALLER);
        assert!(peer.verified);
        assert!(peer.method.contains("/run/mesh.sock"));
    }

    #[test]
    fn mesh_refuses_the_same_header_from_anywhere_else() {
        // Header-based identity trusted from anywhere is a request field with a
        // hyphen in it. Any client that can reach the mediator can set it.
        for origin in [
            Origin::Tcp {
                addr: "10.1.2.3:443".to_string(),
            },
            // Loopback is necessary and nowhere near sufficient: on a shared host
            // every process is on loopback.
            Origin::Tcp {
                addr: "127.0.0.1:9999".to_string(),
            },
            Origin::UnixSocket {
                path: "/tmp/other.sock".to_string(),
            },
            Origin::Stdio,
        ] {
            let err = mesh_source()
                .resolve(&Presented::mesh(xfcc(CALLER), origin.clone()))
                .unwrap_err();
            assert_eq!(
                err.code(),
                Code::PEER_HEADER_UNTRUSTED,
                "must refuse a header from {origin:?}"
            );
            assert!(err.to_string().contains("spoofing attempt"));
        }
    }

    #[test]
    fn an_unconfigured_mesh_trusts_nothing() {
        // "We forgot to configure it" must not look identical to "it is
        // configured", so an empty trust set accepts no origin at all.
        let source = PeerSource::Mesh {
            trust: MeshTrust::default(),
            callee: upstream(),
        };
        let err = source
            .resolve(&Presented::mesh(
                xfcc(CALLER),
                Origin::UnixSocket {
                    path: "/run/mesh.sock".to_string(),
                },
            ))
            .unwrap_err();
        assert_eq!(err.code(), Code::PEER_HEADER_UNTRUSTED);
    }

    #[test]
    fn mesh_without_a_header_is_a_mismatch_not_a_pass() {
        let err = mesh_source()
            .resolve(&Presented {
                origin: Some(Origin::UnixSocket {
                    path: "/run/mesh.sock".to_string(),
                }),
                ..Presented::default()
            })
            .unwrap_err();
        assert_eq!(err.code(), Code::CALLER_PEER_MISMATCH);
    }

    #[test]
    fn an_unobserved_origin_is_refused_rather_than_assumed_local() {
        let err = mesh_source()
            .resolve(&Presented {
                headers: [("x-forwarded-client-cert".to_string(), xfcc(CALLER))]
                    .into_iter()
                    .collect(),
                ..Presented::default()
            })
            .unwrap_err();
        assert_eq!(err.code(), Code::PEER_HEADER_UNTRUSTED);
    }

    // --- xfcc parsing ------------------------------------------------------

    #[test]
    fn the_uri_field_is_read_and_the_by_field_is_not() {
        // `By=` is the proxy's own identity. Reading it would authenticate the
        // sidecar as the caller — which always succeeds, and always with the
        // wrong answer.
        let header = format!("By=spiffe://org/ns/mesh/sa/sidecar;Hash=deadbeef;URI={CALLER}");
        assert_eq!(xfcc_peer_uri(&header).unwrap(), CALLER);
    }

    #[test]
    fn quoted_values_with_separators_parse_correctly() {
        // Envoy quotes values containing `,` or `;`. A naive split turns a
        // Subject containing a comma into two elements and changes the meaning.
        let header =
            format!("By=spiffe://org/sidecar;Subject=\"CN=recon,OU=platform,O=org\";URI={CALLER}");
        assert_eq!(xfcc_peer_uri(&header).unwrap(), CALLER);

        let escaped = format!("Subject=\"CN=say \\\"hi\\\",O=org\";URI={CALLER}");
        assert_eq!(xfcc_peer_uri(&escaped).unwrap(), CALLER);
    }

    #[test]
    fn more_than_one_element_is_refused() {
        // Each element is only as trustworthy as the hop that wrote it, and with
        // several there is no way to tell which is the peer that authenticated to
        // the sidecar in front of us. Guessing is how a multi-hop path becomes an
        // identity-spoofing path.
        let two = format!("{},{}", xfcc("spiffe://org/ns/x/sa/upstream"), xfcc(CALLER));
        let err = xfcc_peer_uri(&two).unwrap_err();
        assert_eq!(err.code(), Code::PEER_HEADER_UNTRUSTED);
        assert!(err.to_string().contains("2 elements"));
    }

    #[test]
    fn a_comma_inside_a_quoted_value_does_not_make_two_elements() {
        // The reason the splitter is quote-aware rather than a `split(',')`: this
        // header is one hop, and refusing it as "two elements" would break every
        // certificate with a comma in its subject.
        let header = format!("Subject=\"CN=recon,O=org\";URI={CALLER}");
        assert_eq!(xfcc_peer_uri(&header).unwrap(), CALLER);
    }

    #[test]
    fn a_header_with_no_uri_or_two_uris_is_refused() {
        assert_eq!(
            xfcc_peer_uri("By=spiffe://org/sidecar;Hash=abc")
                .unwrap_err()
                .code(),
            Code::CALLER_PEER_MISMATCH
        );
        // Two URIs in one element is ambiguous, and picking either is a guess.
        let err =
            xfcc_peer_uri(&format!("URI={CALLER};URI=spiffe://org/ns/x/sa/other")).unwrap_err();
        assert_eq!(err.code(), Code::PEER_HEADER_UNTRUSTED);
    }

    #[test]
    fn an_empty_header_is_refused() {
        assert!(xfcc_peer_uri("").is_err());
        assert!(xfcc_peer_uri("   ").is_err());
    }

    // --- modes -------------------------------------------------------------

    #[test]
    fn a_mistyped_mode_refuses_to_start_rather_than_falling_back() {
        // Silently selecting `configured` when an operator asked for `mtls` turns
        // a typo into an unauthenticated deployment that reports success.
        assert_eq!(
            PeerSource::parse_mode("mlts").unwrap_err().code(),
            Code::CONFIG_INVALID
        );
        for mode in ["configured", "mtls", "mesh", "jwt-svid"] {
            assert_eq!(PeerSource::parse_mode(mode).unwrap(), mode);
        }
    }

    #[test]
    fn mode_names_match_the_variants() {
        assert_eq!(
            PeerSource::Configured {
                caller: id(CALLER),
                callee: upstream()
            }
            .mode(),
            "configured"
        );
        assert_eq!(PeerSource::Mtls { callee: upstream() }.mode(), "mtls");
        assert_eq!(mesh_source().mode(), "mesh");
    }

    // --- jwt-svid ----------------------------------------------------------

    fn keys_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/keys")
    }

    fn trust_bundle() -> IssuerKeys {
        let pem = std::fs::read(keys_dir().join("test_issuer_es256_pub.pem")).unwrap();
        let mut keys = IssuerKeys::new();
        keys.add_ec_pem("spiffe-ca", &pem, wc_core::contract::Algorithm::ES256)
            .unwrap();
        keys
    }

    fn svid(sub: &str, aud: &str, exp: u64) -> String {
        let pem = std::fs::read(keys_dir().join("test_issuer_es256_priv.pem")).unwrap();
        let key = jsonwebtoken::EncodingKey::from_ec_pem(&pem).unwrap();
        let mut header = jsonwebtoken::Header::new(wc_core::contract::Algorithm::ES256);
        header.kid = Some("spiffe-ca".to_string());
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "sub": sub, "aud": aud, "exp": exp }),
            &key,
        )
        .unwrap()
    }

    fn svid_source() -> PeerSource {
        PeerSource::JwtSvid {
            keys: trust_bundle(),
            audience: "warden:mediator:apac".to_string(),
            leeway: 60,
            callee: upstream(),
        }
    }

    #[test]
    fn a_valid_svid_authenticates_the_caller() {
        let peer = svid_source()
            .resolve(&Presented {
                token: Some(svid(CALLER, "warden:mediator:apac", 4_000_000_000)),
                ..Presented::default()
            })
            .unwrap();
        assert_eq!(peer.identity.caller.as_str(), CALLER);
        assert!(peer.verified);
        assert!(peer.method.contains("kid=spiffe-ca"));
    }

    #[test]
    fn an_svid_for_another_mediator_is_refused() {
        // The audience is what stops a token minted for one mediator
        // authenticating at another.
        let err = svid_source()
            .resolve(&Presented {
                token: Some(svid(CALLER, "warden:mediator:emea", 4_000_000_000)),
                ..Presented::default()
            })
            .unwrap_err();
        assert_eq!(err.code(), Code::CALLER_PEER_MISMATCH);
    }

    #[test]
    fn an_expired_svid_is_refused() {
        let err = svid_source()
            .resolve(&Presented {
                token: Some(svid(CALLER, "warden:mediator:apac", 1_600_000_000)),
                ..Presented::default()
            })
            .unwrap_err();
        assert_eq!(err.code(), Code::CALLER_PEER_MISMATCH);
    }

    #[test]
    fn alg_none_reports_as_not_asymmetric() {
        use base64::Engine as _;
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let token = format!(
            "{}.{}.",
            b64(br#"{"alg":"none","kid":"spiffe-ca"}"#),
            b64(br#"{"sub":"spiffe://org/x","aud":"warden:mediator:apac","exp":9999999999}"#)
        );
        let err = svid_source()
            .resolve(&Presented {
                token: Some(token),
                ..Presented::default()
            })
            .unwrap_err();
        assert_eq!(err.code(), Code::ALG_NOT_ASYMMETRIC);
    }

    #[test]
    fn an_empty_audience_is_a_config_error_not_a_permissive_default() {
        let source = PeerSource::JwtSvid {
            keys: trust_bundle(),
            audience: String::new(),
            leeway: 60,
            callee: upstream(),
        };
        let err = source
            .resolve(&Presented {
                token: Some(svid(CALLER, "anything", 4_000_000_000)),
                ..Presented::default()
            })
            .unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
    }

    #[test]
    fn no_source_ever_reads_identity_from_a_request_body() {
        // The rule the whole module exists for. `Presented` has no field a
        // JSON-RPC payload could populate — this asserts the shape rather than a
        // behaviour, which is the only way to assert an absence.
        let presented = Presented::default();
        assert!(presented.origin.is_none());
        assert!(presented.san_uri.is_none());
        assert!(presented.token.is_none());
        assert!(presented.headers.is_empty());

        // And every authenticating mode refuses when nothing was presented.
        for source in [
            PeerSource::Mtls { callee: upstream() },
            mesh_source(),
            svid_source(),
        ] {
            assert!(
                source.resolve(&presented).is_err(),
                "{} accepted an empty presentation",
                source.mode()
            );
        }
    }
}

#[cfg(test)]
mod x509_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const SPIFFE: &str = include_str!("../../../fixtures/keys/test_peer_spiffe.pem");
    const TWO: &str = include_str!("../../../fixtures/keys/test_peer_two_uris.pem");
    const DNS: &str = include_str!("../../../fixtures/keys/test_peer_dns_only.pem");
    const NONE: &str = include_str!("../../../fixtures/keys/test_peer_no_san.pem");
    const HTTPS: &str = include_str!("../../../fixtures/keys/test_peer_not_spiffe.pem");

    #[test]
    fn a_spiffe_uri_san_is_read_out_of_a_real_certificate() {
        assert_eq!(
            spiffe_from_cert_pem(SPIFFE).expect("a valid SVID"),
            "spiffe://org/ns/agents/sa/recon-bot-7"
        );
    }

    /// Two identities in one certificate is not an SVID, and picking the first would let the
    /// holder be whichever one the parser reached first.
    #[test]
    fn two_spiffe_uris_are_refused_rather_than_resolved_to_the_first() {
        let e = spiffe_from_cert_pem(TWO).expect_err("ambiguous");
        assert_eq!(e.code(), Code::IDENTITY_UNVERIFIABLE);
        assert!(e.detail().contains("more than one"), "{}", e.detail());
    }

    #[test]
    fn a_certificate_with_only_dns_and_ip_sans_has_no_identity_here() {
        let e = spiffe_from_cert_pem(DNS).expect_err("not an SVID");
        assert!(e.detail().contains("no URI"), "{}", e.detail());
    }

    #[test]
    fn a_certificate_with_no_san_extension_at_all_parses_and_yields_nothing() {
        let e = spiffe_from_cert_pem(NONE).expect_err("not an SVID");
        assert_eq!(e.code(), Code::IDENTITY_UNVERIFIABLE);
        assert!(e.detail().contains("no URI"), "{}", e.detail());
    }

    /// A URI SAN that is not a SPIFFE id must not be accepted as one — the contract's caller
    /// field is an `EntityId`, and letting `https://` through would put an unattestable string
    /// where an identity belongs.
    #[test]
    fn a_non_spiffe_uri_san_is_not_an_identity() {
        let e = spiffe_from_cert_pem(HTTPS).expect_err("not a spiffe id");
        assert!(e.detail().contains("not a spiffe://"), "{}", e.detail());
    }

    #[test]
    fn a_pem_with_no_certificate_block_is_refused() {
        let e = spiffe_from_cert_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")
            .expect_err("not a certificate");
        assert!(e.detail().contains("no CERTIFICATE block"), "{}", e.detail());
    }

    // --- the parser against bytes nobody generated -------------------------

    #[test]
    fn truncated_der_is_none_not_a_partial_read() {
        let der = first_certificate_der(SPIFFE).expect("decodes");
        for cut in [1, 2, 3, 8, 40, der.len() / 2, der.len() - 1] {
            // Must not panic and must not invent a SAN.
            let got = uri_sans(&der[..cut]);
            assert!(
                got.is_none() || got.as_deref() == Some(&[]),
                "a truncated certificate yielded {got:?}"
            );
        }
    }

    #[test]
    fn indefinite_length_is_refused_because_it_is_ber_and_never_der() {
        // 0x30 0x80 ... is a legal BER SEQUENCE and an illegal DER one. Accepting it would mean
        // parsing a structure the verifier upstream never agreed to.
        assert!(tlv(&[0x30, 0x80, 0x00, 0x00]).is_none());
    }

    #[test]
    fn a_length_running_past_the_buffer_is_refused() {
        assert!(tlv(&[0x30, 0x7F, 0x01, 0x02]).is_none());
        assert!(tlv(&[0x30, 0x82, 0xFF, 0xFF, 0x01]).is_none());
    }

    #[test]
    fn a_long_form_length_that_cannot_fit_a_usize_is_refused_not_wrapped() {
        let mut b = vec![0x30, 0x8F];
        b.extend_from_slice(&[0xFF; 15]);
        assert!(tlv(&b).is_none());
    }

    #[test]
    fn children_of_garbage_terminates() {
        // The loop reads attacker-adjacent bytes; the property under test is that it stops.
        let junk: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let _ = children(&junk);
    }

    /// The `critical` BOOLEAN sits between the OID and extnValue when present, so a parser that
    /// took `parts[1]` would read the boolean as the extension value on any certificate that
    /// marks its SAN critical — which is common when the subject is empty.
    #[test]
    fn extnvalue_is_taken_as_the_last_element_not_a_fixed_index() {
        let der = first_certificate_der(SPIFFE).expect("decodes");
        let uris = uri_sans(&der).expect("parses");
        assert_eq!(uris, vec!["spiffe://org/ns/agents/sa/recon-bot-7"]);
    }
}
