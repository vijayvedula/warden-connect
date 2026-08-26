//! The Envoy `ext_proc` verifier (E5).
//!
//! Contract enforcement for internal HTTP/SSE MCP servers, as an external processor. The
//! decisions are `warden_connect_gateway::Filter`; this binary is the adapter that drives it from
//! Envoy's phase callbacks and nothing more. Anything that decides something belongs in the
//! sync crate, where it is shared with the mediator's checks and covered by the same vectors.
//!
//! # Why this lives outside the workspace
//!
//! It carries tokio, which `deny.toml` bans for every crate in `crates/`. That ban protects one
//! specific property: `wc-core` is linked into processes this project does not own — warden's
//! proxy, a provider's Python server through a wheel, a gateway filter — and a crate that brings
//! its own runtime is unembeddable. This binary owns its `main` and is linked into nothing, so
//! the harm the ban names cannot happen here. The async stops at this file.
//!
//! # Fail-closed, deliberately
//!
//! Envoy must be configured with `failure_mode_allow: false`. If this process is unreachable the
//! traffic is denied, which is the only safe reading of "the verifier is not there".

mod contracts;
mod routes;

use std::pin::Pin;

use contracts::{ContractSet, Contracts};
use envoy_types::pb::envoy::r#type::v3::HttpStatus;
use envoy_types::pb::envoy::service::ext_proc::v3::{
    external_processor_server::{ExternalProcessor, ExternalProcessorServer},
    processing_request, processing_response, BodyResponse, CommonResponse, HeadersResponse,
    HttpBody, HttpHeaders, ImmediateResponse, ProcessingRequest, ProcessingResponse,
};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tonic::{transport::Server, Request, Response, Status, Streaming};
use warden_connect_gateway::{BodyAction, BodyMode, Filter, Verdict};

/// The caller's SPIFFE id, or `None` when identity could not be established.
///
/// Delegated to `wc_mediator::peer` rather than parsed here. An earlier version of this file
/// read the XFCC header directly: it parsed the identity correctly and never checked which
/// origin the header arrived from, which is the half that makes it believable. A second
/// implementation of identity is also exactly the divergence this component exists to avoid.
fn resolve_caller(
    h: &HttpHeaders,
    trust: &wc_mediator::peer::MeshTrust,
    origin: &wc_mediator::peer::Origin,
) -> Option<String> {
    let xfcc = header(h, "x-forwarded-client-cert")?;
    // `resolve` needs a callee to build a `Peer`; only the caller half is read back, and the
    // real callee is configuration held on the Verifier.
    let callee = wc_core::model::EntityId::new("spiffe://placeholder/ns/x/sa/callee").ok()?;
    let source = wc_mediator::peer::PeerSource::Mesh {
        trust: trust.clone(),
        callee,
    };
    let presented = wc_mediator::peer::Presented::mesh(xfcc, origin.clone());
    match source.resolve(&presented) {
        Ok(p) => Some(p.identity.caller.as_str().to_string()),
        // Logged, not swallowed. An identity that failed to resolve and a caller with no
        // contract both end as "refused", and an operator staring at WC-4001 has no way to tell
        // a spoofing attempt from a missing contract without this line. The origin is named
        // because a mesh-trust mismatch is the most common cause and the hardest to guess.
        Err(e) => {
            eprintln!(
                "wc-extproc: peer identity not established from {}: {} {}",
                origin.describe(),
                e.code(),
                e.detail()
            );
            None
        }
    }
}

/// Where the callee for a stream comes from.
enum CalleeSource {
    /// One upstream, named on the command line.
    Single(wc_core::model::EntityId),
    /// A table on disk, reloaded when it changes.
    Table(std::sync::Arc<routes::Routes>),
}

impl CalleeSource {
    /// The callee this route fronts, or `None` if the route is not mapped.
    fn callee(
        &self,
        cluster: Option<&str>,
        route: Option<&str>,
    ) -> Option<wc_core::model::EntityId> {
        match self {
            CalleeSource::Single(id) => Some(id.clone()),
            CalleeSource::Table(r) => r.table().lookup(cluster, route).cloned(),
        }
    }
}

/// A callee id for a stream whose route is unmapped.
///
/// Never used to admit anything: the filter it is handed to has no contract, so every frame on
/// that stream is refused. It exists because `Filter` needs an entity to bind a pin to, and an
/// `Option` there would be a second way to express "no contract".
fn placeholder_callee() -> wc_core::model::EntityId {
    wc_core::model::EntityId::new("spiffe://unmapped.invalid/ns/x/sa/unmapped")
        .expect("the placeholder callee is a valid id")
}

/// A named attribute out of `ProcessingRequest.attributes`.
///
/// The map is keyed by the filter that produced the values, and the attribute names sit inside
/// the `Struct`. Rather than assume the outer key, every entry is searched for the field — the
/// namespace has changed between Envoy versions and hard-coding it would make the route lookup
/// fail silently, which fails closed but reads as a missing route rather than a config skew.
fn attribute(req: &ProcessingRequest, name: &str) -> Option<String> {
    for st in req.attributes.values() {
        if let Some(v) = st.fields.get(name) {
            if let Some(envoy_types::pb::google::protobuf::value::Kind::StringValue(s)) = &v.kind {
                if !s.is_empty() {
                    return Some(s.clone());
                }
            }
        }
    }
    None
}

/// Header lookup, case-insensitive, over Envoy's header map.
fn header<'a>(h: &'a HttpHeaders, name: &str) -> Option<&'a str> {
    let map = h.headers.as_ref()?;
    map.headers.iter().find_map(|hv| {
        if hv.key.eq_ignore_ascii_case(name) {
            // Envoy moved header values to `raw_value`; `value` stays populated for
            // compatibility. Reading only one of them silently misses half the deployments.
            if !hv.value.is_empty() {
                Some(hv.value.as_str())
            } else {
                std::str::from_utf8(&hv.raw_value).ok()
            }
        } else {
            None
        }
    })
}

/// A JSON-RPC error frame, shaped the way the mediator shapes a refusal so an agent sees the
/// same thing whichever enforcement point refused it.
fn refusal_body(code: wc_core::error::Code, detail: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": serde_json::Value::Null,
        "error": {
            "code": -32001,
            "message": format!("BLOCKED by warden-connect: {code} {detail}"),
            "data": { "code": code.to_string(), "summary": detail }
        }
    })
    .to_string()
}

fn immediate_refusal(code: wc_core::error::Code, detail: &str) -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                // 200 with a JSON-RPC error, not an HTTP error: MCP clients surface a transport
                // failure as "the server is broken" and a JSON-RPC error as a refused call. The
                // agent needs to be able to tell those apart.
                status: Some(HttpStatus { code: 200 }),
                body: refusal_body(code, detail).into_bytes(),
                details: code.to_string(),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

fn cont_headers() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::RequestHeaders(
            HeadersResponse::default(),
        )),
        ..Default::default()
    }
}

struct Verifier<C: Contracts> {
    /// Behind an `Arc` because the processing loop runs detached: it must own what it reads,
    /// and it outlives the `&self` borrow that started it.
    contracts: std::sync::Arc<C>,
    mode: wc_core::error::Mode,
    /// Where `x-forwarded-client-cert` may be believed from. An empty configuration trusts
    /// nothing, which is `MeshTrust`'s deliberate default and the right one: "we forgot to
    /// configure it" must not look identical to "it is configured".
    mesh_trust: wc_mediator::peer::MeshTrust,
    /// How a route maps to the callee it fronts.
    ///
    /// Never from the request. A caller that could name its own callee could name one it holds a
    /// contract for while the traffic goes elsewhere, and the verifier would check the wrong
    /// service's contract.
    routes: std::sync::Arc<CalleeSource>,
}

#[tonic::async_trait]
impl<C: Contracts> ExternalProcessor for Verifier<C> {
    type ProcessStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ProcessingResponse, Status>> + Send>>;

    async fn process(
        &self,
        request: Request<Streaming<ProcessingRequest>>,
    ) -> Result<Response<Self::ProcessStream>, Status> {
        // The origin of the gRPC connection Envoy made to this process. `PeerSource::Mesh`
        // refuses an XFCC header that did not arrive from the configured origin, which is the
        // half of mesh identity that makes it authentication rather than a request field.
        //
        // The PORT is dropped deliberately. `MeshTrust` compares the origin string exactly, and
        // a client's source port is ephemeral — so keeping it would mean no configured TCP
        // origin could ever match, and mesh trust would refuse every request while looking
        // configured. The origin of a connection is the peer host; the source port is not an
        // identity. For a UDS deployment the origin is the socket path, which is stable.
        let origin = match request.remote_addr() {
            Some(a) => wc_mediator::peer::Origin::Tcp {
                addr: a.ip().to_string(),
            },
            None => wc_mediator::peer::Origin::Stdio,
        };
        let mut inbound = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(8);

        let contracts_mode = self.mode;
        let mesh = self.mesh_trust.clone();

        let admitted_slot = std::sync::Arc::new(std::sync::Mutex::new(None));

        // The filter for this stream. `Filter::new` is given the admitted connection once the
        // headers phase has established who the caller is.
        let mut filter: Option<Filter> = None;
        let slot = std::sync::Arc::clone(&admitted_slot);

        // The processing loop MUST run detached, and the response stream must be returned to
        // Envoy now. Returning it after draining the inbound stream — which is what this did
        // first — means Envoy never receives a ProcessingResponse for the request phase, so it
        // waits for a verdict that only arrives when the stream closes, times out and fails the
        // request. Against the in-process test client it looked correct: that client sends a
        // fixed set of messages and closes, which ends the loop and delivers everything at once.
        // A real Envoy holds the stream open and this deadlocked every request.
        let contracts = std::sync::Arc::clone(&self.contracts);
        let routes = std::sync::Arc::clone(&self.routes);
        tokio::spawn(async move {
            while let Some(msg) = inbound.next().await {
                // A transport error ends this stream. There is nothing to answer and nothing
                // to answer on; Envoy sees the stream close and fails the request closed.
                let Ok(msg) = msg else { break };
                // `msg.request` is consumed by the match below, and the attributes sit beside it.
                let msg_attrs = ProcessingRequest {
                    attributes: msg.attributes.clone(),
                    ..Default::default()
                };
                let out = match msg.request {
                    Some(processing_request::Request::RequestHeaders(h)) => {
                        // The callee is whatever route Envoy chose, looked up in the operator's
                        // table. An unmapped route yields no callee, so no contract resolves and
                        // the stream is refused — a route nobody mapped is not a route that is
                        // exempt.
                        let cluster = attribute(&msg_attrs, "xds.cluster_name");
                        let route = attribute(&msg_attrs, "xds.route_name");
                        let callee_id = routes.callee(cluster.as_deref(), route.as_deref());
                        let caller = resolve_caller(&h, &mesh, &origin);
                        let resolved = match (&callee_id, &caller) {
                            (Some(cid), Some(_)) => {
                                contracts.resolve(caller.as_deref(), cid.as_str())
                            }
                            _ => None,
                        };
                        let (admitted, contract) = match resolved {
                            Some(r) => (Some(r.admitted), Some(r.contract)),
                            None => (None, None),
                        };
                        *slot.lock().expect("slot") = admitted.clone();
                        // With no callee there is nothing for gate 8 to bind a digest to, so the
                        // filter is built with no contract and refuses the stream.
                        let bound = callee_id.unwrap_or_else(placeholder_callee);
                        filter = Some(Filter::new(
                            admitted,
                            contracts_mode,
                            contract,
                            bound,
                            now(),
                        ));
                        cont_headers()
                    }
                    Some(processing_request::Request::RequestBody(b)) => {
                        let f = filter.get_or_insert_with(|| {
                            // No pin and no contract: this stream is refused outright.
                            // No headers phase was sent. Configuring the filter to skip it and then
                            // trusting the body is how a caller reaches the upstream with no identity
                            // established at all, so this fails closed rather than assuming.
                            Filter::new(None, contracts_mode, None, placeholder_callee(), now())
                        });
                        on_request_body(f, &b)
                    }
                    Some(processing_request::Request::ResponseHeaders(h)) => {
                        let ct = header(&h, "content-type").unwrap_or_default().to_string();
                        match filter.as_mut() {
                            Some(f) => on_response_headers(f, &ct),
                            None => immediate_refusal(
                                wc_core::error::Code::NO_CONTRACT,
                                "no request phase was observed for this stream",
                            ),
                        }
                    }
                    Some(processing_request::Request::ResponseBody(b)) => match filter.as_mut() {
                        Some(f) => on_response_body(f, &b),
                        None => immediate_refusal(
                            wc_core::error::Code::NO_CONTRACT,
                            "no request phase was observed for this stream",
                        ),
                    },
                    // Trailers and anything this build does not know: continue without inspecting.
                    // A trailer cannot carry a tool call, and refusing an unknown phase would deny
                    // traffic on an Envoy newer than this binary.
                    _ => ProcessingResponse::default(),
                };
                if tx.send(Ok(out)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// The request-body phase: the frame is parsed and the verdict taken.
///
/// A body this cannot parse is refused. Envoy sends the buffered body here, so an unparseable
/// one is either not JSON-RPC — in which case it is not a request this filter should be passing
/// to an MCP server — or truncated because the buffer filled, which is the same answer.
fn on_request_body(filter: &mut Filter, body: &HttpBody) -> ProcessingResponse {
    let Ok(frame) = serde_json::from_slice::<serde_json::Value>(&body.body) else {
        return immediate_refusal(
            wc_core::error::Code::FRAME_MALFORMED,
            "the request body is not a JSON-RPC frame",
        );
    };
    // A batch carries several calls, some of which this filter would allow and some not. There
    // is no partial answer to give, and letting the array through would forward the ones it
    // would have refused, so an array is refused whole.
    if frame.is_array() {
        return immediate_refusal(
            wc_core::error::Code::FRAME_MALFORMED,
            "a JSON-RPC batch cannot be verified per call; send one frame per request",
        );
    }
    let method = frame.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = frame
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    match filter.on_request(method, &params) {
        Verdict::Forward => ProcessingResponse {
            response: Some(processing_response::Response::RequestBody(
                BodyResponse::default(),
            )),
            ..Default::default()
        },
        Verdict::Refuse { code, detail } => immediate_refusal(code, &detail),
    }
}

/// The response-headers phase: the only place Envoy honours a body-mode override.
fn on_response_headers(filter: &mut Filter, content_type: &str) -> ProcessingResponse {
    use envoy_types::pb::envoy::extensions::filters::http::ext_proc::v3::processing_mode::BodySendMode;
    use envoy_types::pb::envoy::extensions::filters::http::ext_proc::v3::ProcessingMode;

    let (body_mode, refusal) = match filter.on_response_headers(content_type) {
        BodyMode::Buffer => (BodySendMode::Buffered, None),
        BodyMode::Skip => (BodySendMode::None, None),
        BodyMode::Refuse { code, detail } => (BodySendMode::None, Some((code, detail))),
    };
    if let Some((code, detail)) = refusal {
        return immediate_refusal(code, detail);
    }
    // When the body is going to be replaced, `content-length` must go with it. Envoy forwards
    // the header it already has, so a rewritten catalogue — always a different length from the
    // one the server sent — arrives truncated or padded and the client cannot parse it. Removing
    // it makes Envoy fall back to chunked encoding and send what the filter actually produced.
    //
    // Found by the Envoy drill: gate 8 passed, which proved the body was being buffered and
    // inspected, while the filtered catalogue came back unparseable. No amount of testing
    // against a simulated proxy would have shown this.
    let headers = if body_mode == BodySendMode::Buffered {
        HeadersResponse {
            response: Some(CommonResponse {
                header_mutation: Some(
                    envoy_types::pb::envoy::service::ext_proc::v3::HeaderMutation {
                        remove_headers: vec!["content-length".to_string()],
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }),
        }
    } else {
        HeadersResponse::default()
    };
    ProcessingResponse {
        response: Some(processing_response::Response::ResponseHeaders(headers)),
        // Set here and nowhere else. An override sent from the body phase is silently ignored by
        // Envoy, so a filter that decided there would buffer nothing and filter nothing while
        // appearing to work.
        mode_override: Some(ProcessingMode {
            response_body_mode: body_mode.into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The response-body phase: filter the catalogue, or refuse it.
fn on_response_body(filter: &mut Filter, body: &HttpBody) -> ProcessingResponse {
    match filter.on_response_body(&body.body) {
        BodyAction::Pass => ProcessingResponse {
            response: Some(processing_response::Response::ResponseBody(
                BodyResponse::default(),
            )),
            ..Default::default()
        },
        BodyAction::Rewrite(frame) => {
            let replacement = frame.to_string().into_bytes();
            ProcessingResponse {
                response: Some(processing_response::Response::ResponseBody(BodyResponse {
                    response: Some(CommonResponse {
                        body_mutation: Some(
                            envoy_types::pb::envoy::service::ext_proc::v3::BodyMutation {
                                mutation: Some(
                                    envoy_types::pb::envoy::service::ext_proc::v3::body_mutation::Mutation::Body(
                                        replacement,
                                    ),
                                ),
                            },
                        ),
                        ..Default::default()
                    }),
                })),
                ..Default::default()
            }
        }
        BodyAction::Refuse { code, detail } => immediate_refusal(code, &detail),
    }
}

fn usage() -> &'static str {
    "\
wc-extproc — the warden-connect Envoy ext_proc verifier

USAGE
  wc-extproc --listen ADDR --callee SPIFFE_ID --mediator-id ID --issuer-id URL \\
             (--issuer-pub PEM --kid KID) --contract FILE [--contract FILE ...]

  --listen ADDR        where to serve gRPC, e.g. 127.0.0.1:9002
  --callee SPIFFE_ID   the single party this listener fronts
  --routes FILE        a route table, for a listener fronting several. Reloaded when
                       the file changes; a file that does not validate is NOT installed
                       and the previous table keeps serving
                       Exactly one of --callee or --routes. The callee comes from
                       CONFIGURATION and the route Envoy chose, never from the request:
                       a caller that could name its own callee could name one it holds
                       a contract for while the traffic goes somewhere else
  --mediator-id ID     this verifier's id; must equal each contract's aud
  --issuer-id URL      the control plane it obeys; must equal each contract's iss
  --issuer-pub PEM     the contract issuer's public key
  --kid KID            the key id it is registered under
  --contract FILE      a contract artifact to load (repeatable); the air-gapped
                       alternative to --contracts
  --contracts URL      control plane to pull the contract set from
  --token TOKEN        bearer token with the connect.mediator role
  --refresh N          seconds between pulls (default: 5)
  --max-stale N        seconds the set may go without a SUCCESSFUL refresh before
                       every call is refused (default: 3600; only with --contracts).
                       A verifier that serves a cached set forever cannot be
                       contained: a withdrawal lands in the control plane and never
                       reaches here, so refusing is the only honest answer once the
                       set is too old to vouch for
  --mesh-origin PATH   the unix socket Envoy connects from, if XFCC is only to be
                       believed from there. Omit only when Envoy is on loopback and
                       nothing else can reach this port
  --any-zone           permit any zone pair (observe deployments only)
  --observe            record findings instead of denying

REFRESH, WITHDRAWAL AND THE DEPLOY GATE
  With --contracts the set is re-pulled on --refresh and the acknowledgement goes to
  the same endpoint a mediator uses, so `connect distribution` sees this verifier
  once its --mediator-id is in the mediators file. Only a CLEAN refresh counts as
  fresh: a partial one leaves this process holding a set the control plane did not
  fully hand over, and treating that as current is how a withdrawn contract keeps
  working. A withdrawn contract is simply absent from the next set.

THE PIN, AND WHAT THIS DOES NOT YET DO
  Gate 8 compares the callee's presented surface against the digest the contract
  pinned. This filter runs it whenever a `tools/list` response passes, and refuses
  the catalogue on a mismatch (WC-3108).
  What it does NOT do is check the pin on a stream that carries no catalogue. A
  client that calls `tools/call` without ever calling `tools/list` is not pinned on
  that request. The mediator closes this by fetching a catalogue itself; a filter
  cannot fetch anything, so closing it here needs per-SESSION state keyed on
  Mcp-Session-Id, which is not built. Everything else still applies on those
  streams: the surface ceiling, the ceilings and revocation.

ENVOY MUST BE CONFIGURED WITH
  failure_mode_allow: false     this process being unreachable has to deny, not allow
  allow_mode_override: true     without it the catalogue is never buffered or filtered
  request_body_mode: BUFFERED   the tool name is in the body
  request_attributes:           with --routes, the route lookup needs what Envoy chose
    - xds.cluster_name          after routing. Without these the attribute is absent,
    - xds.route_name            no route matches, and EVERY request is refused
  and the filter scoped to MCP routes only, or every body in the mesh is buffered."
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let key = format!("--{name}");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(rest) = a.strip_prefix(&format!("{key}=")) {
            return Some(rest.to_string());
        }
        if a == &key {
            return it.next().cloned();
        }
    }
    None
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Everything `main` needs to start serving.
struct Started {
    verifier: Verifier<ContractSet>,
    addr: std::net::SocketAddr,
    /// Where to pull contracts from, if anywhere.
    pull_from: Option<String>,
    pull_token: String,
    refresh_secs: u64,
    /// The trust the refresh loop verifies with. It MOVES into the loop rather than being
    /// rebuilt from the PEM there: a rebuilt copy would refresh contracts every tick against
    /// keys that never rotate, so `--jwks-url` would look configured and never arrive.
    refresh_trust: wc_mediator::jwks::KeySource,
    mediator_id: String,
    issuer_id: String,
}

fn run() -> Result<Started, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{}", usage());
        std::process::exit(0);
    }

    let listen = flag(&args, "listen").ok_or("--listen is required")?;
    // One upstream or many, and never both: two answers to "what is the callee" is two beliefs
    // about what is being verified, and resolving that by precedence would check the wrong
    // service's contract.
    let routes = match (flag(&args, "callee"), flag(&args, "routes")) {
        (Some(_), Some(_)) => return Err("--callee and --routes are mutually exclusive".into()),
        (None, None) => return Err("--callee or --routes is required".into()),
        (Some(c), None) => CalleeSource::Single(
            wc_core::model::EntityId::new(&c).map_err(|e| format!("--callee {c:?}: {e}"))?,
        ),
        (None, Some(path)) => {
            let r = routes::Routes::load(&path)?;
            eprintln!(
                "wc-extproc: route table {path} ({} key(s))",
                r.table().len()
            );
            CalleeSource::Table(std::sync::Arc::new(r))
        }
    };
    let mediator_id = flag(&args, "mediator-id").ok_or("--mediator-id is required")?;
    let issuer_id = flag(&args, "issuer-id").ok_or("--issuer-id is required")?;
    let pem = flag(&args, "issuer-pub").ok_or("--issuer-pub is required")?;
    let kid = flag(&args, "kid").ok_or("--kid is required")?;

    let mode = if args.iter().any(|a| a == "--observe") {
        wc_core::error::Mode::Observe
    } else {
        wc_core::error::Mode::Enforce
    };
    let artifacts: Vec<String> = args
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "--contract")
        .filter_map(|(i, _)| args.get(i + 1))
        .map(|p| std::fs::read_to_string(p).map(|t| t.trim().to_string()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|e| format!("read contract: {e}"))?;
    if artifacts.is_empty() {
        // Starting with no contract source means denying everything while looking healthy,
        // which is the failure that takes longest to diagnose.
        return Err(
            "--contract is required; with no contract set this verifier denies \
                    every call while appearing to run"
                .to_string(),
        );
    }

    let pem_bytes = std::fs::read(&pem).map_err(|e| format!("read issuer key: {e}"))?;
    let mut keys = wc_core::contract::IssuerKeys::new();
    keys.add_ec_pem(&kid, &pem_bytes, wc_core::contract::Algorithm::ES256)
        .map_err(|e| format!("issuer key: {e}"))?;
    let mut trust = wc_mediator::jwks::KeySource::Pinned(keys);

    let zones: std::sync::Arc<dyn wc_core::contract::ZoneRule + Send + Sync> =
        if args.iter().any(|a| a == "--any-zone") {
            std::sync::Arc::new(wc_core::contract::AnyZone)
        } else {
            std::sync::Arc::new(wc_core::contract::SameTrustLevel)
        };

    // A pull source makes staleness meaningful; without one the set is immutable and its only
    // containment is contract expiry, so the bound is off and a warning says so.
    let pulling = flag(&args, "contracts").is_some();
    let max_stale: u64 = if pulling {
        flag(&args, "max-stale")
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600)
    } else {
        0
    };
    let set = ContractSet::from_artifacts(
        &artifacts,
        &mut trust,
        &mediator_id,
        &issuer_id,
        zones,
        mode,
        now,
        max_stale,
    )?;
    let loaded = set.len();
    if loaded == 0 && !artifacts.is_empty() {
        return Err(format!(
            "{} contract artifact(s) were read and none verified against kid {kid}; \
             check --mediator-id matches their aud and --issuer-id their iss",
            artifacts.len()
        ));
    }

    // Required, not optional. An unset `MeshTrust` accepts NO origin, so a daemon started
    // without this refuses every request — and a flag whose absence silently denies everything
    // is worse than one that refuses to start.
    let mesh_origin = flag(&args, "mesh-origin").ok_or(
        "--mesh-origin is required: an unconfigured mesh trust believes no \
         x-forwarded-client-cert from any origin, so every request would be refused",
    )?;
    let mesh_trust = if mesh_origin.starts_with('/') {
        wc_mediator::peer::MeshTrust::socket(mesh_origin.clone())
    } else {
        wc_mediator::peer::MeshTrust {
            socket: None,
            addrs: vec![mesh_origin.clone()],
        }
    };

    eprintln!(
        "wc-extproc: {loaded} contract(s) verified, {} read",
        artifacts.len()
    );
    eprintln!("wc-extproc: mediator {mediator_id}, issuer {issuer_id} ({mode:?})");
    eprintln!("wc-extproc: XFCC believed only from {mesh_origin}");
    eprintln!(
        "wc-extproc: Envoy must set failure_mode_allow=false and allow_mode_override=true; \
         without the second, catalogues are never filtered"
    );

    let addr: std::net::SocketAddr = listen.parse().map_err(|e| format!("--listen: {e}"))?;
    let pull_from = flag(&args, "contracts");
    let pull_token = match (&pull_from, flag(&args, "token")) {
        (Some(_), Some(t)) => t,
        (Some(_), None) => return Err("--contracts requires --token".to_string()),
        (None, Some(_)) => return Err("--token is only used with --contracts".to_string()),
        (None, None) => String::new(),
    };
    let refresh_secs: u64 = flag(&args, "refresh")
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);

    Ok(Started {
        verifier: Verifier {
            contracts: std::sync::Arc::new(set),
            mode,
            routes: std::sync::Arc::new(routes),
            mesh_trust,
        },
        addr,
        pull_from,
        pull_token,
        refresh_secs,
        refresh_trust: trust,
        mediator_id,
        issuer_id,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Started {
        verifier,
        addr,
        pull_from,
        pull_token,
        refresh_secs,
        refresh_trust,
        mediator_id,
        issuer_id,
    } = match run() {
        Ok(v) => v,
        Err(why) => {
            eprintln!("wc-extproc: {why}");
            std::process::exit(1);
        }
    };
    // --- the refresh loop -----------------------------------------------------------------
    // A plain thread, not a tokio task: `ControlPlaneClient` is blocking (ureq), and putting a
    // blocking pull on the async runtime would stall the reactor that is answering Envoy.
    if let Some(url) = pull_from {
        let client = wc_mediator::client::ControlPlaneClient::new(&url, &mediator_id, &pull_token);
        let cache = verifier.contracts.cache();
        let set = std::sync::Arc::clone(&verifier.contracts);
        let (med, iss) = (mediator_id.clone(), issuer_id.clone());
        std::thread::spawn(move || {
            let mut trust = refresh_trust;
            let mut seq = 0u64;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(refresh_secs));
                let at = now();
                let (keys, key_failure) = trust.keys(at);
                if let Some(e) = key_failure {
                    eprintln!("wc-extproc: issuer key set refresh failed: {e}");
                }
                let keys = match keys {
                    // Contracts are not pulled in this state: pulling them would mean verifying
                    // against a trust set this process has already decided it cannot vouch for.
                    // The staleness bound is what eventually turns this into a refusal.
                    Err(e) => {
                        eprintln!("wc-extproc: not refreshing contracts — {e}");
                        continue;
                    }
                    Ok(keys) => keys,
                };
                let trusted = wc_mediator::cache::Trust {
                    keys,
                    mediator_id: &med,
                    issuer: &iss,
                };
                match wc_mediator::client::refresh(&client, &cache, &trusted, seq, at) {
                    Ok(report) => {
                        seq = report.seq;
                        // Only a clean refresh counts as fresh. A partial one leaves this
                        // process holding a set the control plane did not fully hand over, and
                        // treating that as current is how a withdrawn contract keeps working.
                        if report.is_clean() {
                            set.mark_fresh(at);
                        } else {
                            eprintln!(
                                "wc-extproc: refresh not clean — {} missing, {} rejected, \
                                 acked={}; the set is NOT marked fresh",
                                report.missing.len(),
                                report.rejected.len(),
                                report.acked
                            );
                        }
                        if !report.removed.is_empty() {
                            eprintln!(
                                "wc-extproc: {} contract(s) withdrawn by the control plane",
                                report.removed.len()
                            );
                        }
                    }
                    Err(e) => eprintln!("wc-extproc: refresh failed, keeping last set: {e}"),
                }
            }
        });
    } else {
        // The same warning `connect-mediate` prints, for the same reason: with no pull source a
        // quarantine cannot reach this process and containment is contract expiry alone.
        eprintln!(
            "wc-extproc: WARNING no --contracts, so contracts came from disk and a withdrawal \
             cannot reach this process. Containment here is contract expiry only"
        );
    }

    // The route table is polled rather than watched: a filesystem notification API is another
    // dependency and another failure mode, and a table that lands a few seconds late is not a
    // safety property — an unmapped route denies until it is mapped.
    if let CalleeSource::Table(r) = verifier.routes.as_ref() {
        let r = std::sync::Arc::clone(r);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tick.tick().await;
                match r.reload_if_changed() {
                    routes::Reload::Unchanged => {}
                    routes::Reload::Installed(n) => {
                        eprintln!("wc-extproc: route table reloaded, {n} key(s)");
                    }
                    // Loud, because the operator edited the file and it did not take. The
                    // previous table is still serving, so this is not an outage yet — but the
                    // next thing they do will be based on believing the edit landed.
                    routes::Reload::Failed(why) => {
                        eprintln!("wc-extproc: route table NOT reloaded, previous kept: {why}");
                    }
                }
            }
        });
    }

    eprintln!("wc-extproc: serving ext_proc on {addr}");
    Server::builder()
        .add_service(ExternalProcessorServer::new(verifier))
        .serve(addr)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Driven through the real generated gRPC client against a real server on an ephemeral
    //! port. A compiling ext_proc service that answers nothing looks identical to a working one
    //! from the outside, which is the whole reason these are not unit tests on the handlers.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};
    use envoy_types::pb::envoy::extensions::filters::http::ext_proc::v3::processing_mode::BodySendMode;
    use envoy_types::pb::envoy::service::ext_proc::v3::external_processor_client::ExternalProcessorClient;

    const PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");
    const PUB: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_pub.pem");
    const KID: &str = "wc-test-es256";
    const MED: &str = "warden:mediator:extproc-test";
    const ISS: &str = "https://connect.internal";
    const T_NOW: u64 = 1_800_000_000;
    const CALLER: &str = "spiffe://org/ns/agents/sa/recon-bot";
    const CALLEE: &str = "spiffe://org/ns/tools/sa/payments-mcp";

    /// One real contract, resolved for one caller. A minted-and-verified artifact rather than a
    /// hand-built `Admitted`, so gate 8 has something to compare against and the phase loop is
    /// driven by the same objects production uses.
    struct OneContract {
        caller: String,
        resolved: std::sync::Arc<wc_core::contract::VerifiedContract>,
        admitted: wc_core::contract::Admitted,
    }

    impl Contracts for OneContract {
        fn resolve(&self, caller: Option<&str>, _callee: &str) -> Option<contracts::Resolved> {
            match caller {
                Some(c) if c == self.caller => Some(contracts::Resolved {
                    admitted: self.admitted.clone(),
                    contract: std::sync::Arc::clone(&self.resolved),
                }),
                _ => None,
            }
        }
    }

    /// The catalogue the stub callee presents, and what a contract pins against.
    fn served() -> serde_json::Value {
        serde_json::json!({"tools":[
            {"name":"summarize_statement","description":"a"},
            {"name":"initiate_payment","description":"b"}
        ]})
    }

    fn one_contract(tools: &str) -> OneContract {
        use wc_core::contract as c;
        let callee = wc_core::model::EntityId::new(CALLEE).unwrap();
        let pin = wc_core::canon::pin(
            wc_core::canon::SurfaceKind::McpTools,
            &callee,
            &served(),
            &wc_core::canon::Limits::default(),
            T_NOW,
        )
        .unwrap();
        let surface = c::Surface {
            tools: tools.split(',').map(|s| s.to_string()).collect(),
            skills: Vec::new(),
            resources: Vec::new(),
        };
        let digest = pin.surface_digest(&surface.items()).unwrap();
        let mut payload = c::ContractPayload::new(
            wc_core::model::Cid::new("conn_7f3a91c4").unwrap(),
            wc_core::model::Jti::new("cx_84be0011").unwrap(),
            ISS,
            MED,
            c::Party {
                id: wc_core::model::EntityId::new(CALLER).unwrap(),
                zone: wc_core::model::ZoneId::new("internal.ops").unwrap(),
                tier: wc_core::model::Tier::TWO,
                card: None,
                manifest: None,
                surface_digest: None,
            },
            c::Party {
                id: callee,
                zone: wc_core::model::ZoneId::new("internal.payments").unwrap(),
                tier: wc_core::model::Tier::TWO,
                card: None,
                manifest: Some(pin.manifest.clone()),
                surface_digest: Some(digest),
            },
        );
        payload.iat = T_NOW - 100;
        payload.nbf = T_NOW - 100;
        payload.exp = T_NOW + 3_600;
        payload.surface = surface;
        payload.terms = c::Terms::default();
        payload.assurance = c::Assurance::default();

        let jws = c::mint(
            &payload,
            &c::IssuerKey::ec_pem(KID, PRIV, c::Algorithm::ES256).unwrap(),
        )
        .unwrap();
        let mut keys = c::IssuerKeys::new();
        keys.add_ec_pem(KID, PUB, c::Algorithm::ES256).unwrap();
        let verified = c::verify_artifact(
            &jws,
            &c::VerifyOpts {
                keys: &keys,
                mediator_id: MED,
                expected_iss: Some(ISS),
                now: T_NOW,
                leeway: 0,
                revoked: &c::NoRevocations,
            },
        )
        .unwrap();
        let admitted = wc_core::contract::Admitted {
            cid: wc_core::model::Cid::new("conn_7f3a91c4").unwrap(),
            jti: wc_core::model::Jti::new("cx_84be0011").unwrap(),
            items: tools.split(',').map(|s| s.to_string()).collect(),
            resources: Vec::new(),
            terms: c::Terms::default(),
            exp: u64::MAX,
            findings: Vec::new(),
        };
        OneContract {
            caller: CALLER.to_string(),
            resolved: std::sync::Arc::new(verified),
            admitted,
        }
    }

    /// Start a server on an ephemeral port; return its address.
    async fn serve(tools: &str) -> String {
        let v = Verifier {
            contracts: std::sync::Arc::new(one_contract(tools)),
            mode: wc_core::error::Mode::Enforce,
            routes: std::sync::Arc::new(CalleeSource::Single(
                wc_core::model::EntityId::new(CALLEE).unwrap(),
            )),
            // Loopback TCP, which is the origin the test client connects from.
            mesh_trust: wc_mediator::peer::MeshTrust {
                socket: None,
                addrs: vec!["127.0.0.1".to_string()],
            },
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            Server::builder()
                .add_service(ExternalProcessorServer::new(v))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        format!("http://{addr}")
    }

    fn hdrs(pairs: &[(&str, &str)]) -> HttpHeaders {
        HttpHeaders {
            headers: Some(HeaderMap {
                headers: pairs
                    .iter()
                    .map(|(k, v)| HeaderValue {
                        key: (*k).to_string(),
                        raw_value: (*v).as_bytes().to_vec(),
                        ..Default::default()
                    })
                    .collect(),
            }),
            ..Default::default()
        }
    }

    fn req_headers(xfcc: &str) -> ProcessingRequest {
        ProcessingRequest {
            request: Some(processing_request::Request::RequestHeaders(hdrs(&[(
                "x-forwarded-client-cert",
                xfcc,
            )]))),
            ..Default::default()
        }
    }

    fn req_body(json: &str) -> ProcessingRequest {
        ProcessingRequest {
            request: Some(processing_request::Request::RequestBody(HttpBody {
                body: json.as_bytes().to_vec(),
                end_of_stream: true,
            })),
            ..Default::default()
        }
    }

    /// Drive one stream through the phases and collect what came back.
    async fn exchange(addr: &str, msgs: Vec<ProcessingRequest>) -> Vec<ProcessingResponse> {
        let channel = tonic::transport::Channel::from_shared(addr.to_string())
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = ExternalProcessorClient::new(channel);
        let n = msgs.len();
        let stream = tokio_stream::iter(msgs);
        let mut out = client.process(stream).await.unwrap().into_inner();
        let mut got = Vec::new();
        for _ in 0..n {
            match out.next().await {
                Some(Ok(r)) => got.push(r),
                _ => break,
            }
        }
        got
    }

    const XFCC: &str = "By=spiffe://c/x;URI=spiffe://org/ns/agents/sa/recon-bot";

    fn immediate(r: &ProcessingResponse) -> Option<&ImmediateResponse> {
        match &r.response {
            Some(processing_response::Response::ImmediateResponse(i)) => Some(i),
            _ => None,
        }
    }

    #[tokio::test]
    async fn a_contracted_tool_call_is_allowed_through() {
        let addr = serve("summarize_statement").await;
        let got = exchange(
            &addr,
            vec![
                req_headers(XFCC),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summarize_statement","arguments":{}}}"#),
            ],
        )
        .await;
        assert_eq!(got.len(), 2);
        assert!(
            immediate(&got[1]).is_none(),
            "a contracted call was refused: {:?}",
            immediate(&got[1]).map(|i| String::from_utf8_lossy(&i.body).to_string())
        );
    }

    #[tokio::test]
    async fn an_uncontracted_tool_call_is_refused_with_4002() {
        let addr = serve("summarize_statement").await;
        let got = exchange(
            &addr,
            vec![
                req_headers(XFCC),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"initiate_payment","arguments":{"amount":9999}}}"#),
            ],
        )
        .await;
        let i = immediate(&got[1]).expect("the uncontracted call was FORWARDED");
        let body = String::from_utf8_lossy(&i.body);
        assert!(body.contains("WC-4002"), "{body}");
        assert_eq!(
            i.status.as_ref().unwrap().code,
            200,
            "must be a JSON-RPC error, not an HTTP one"
        );
    }

    #[tokio::test]
    async fn an_unknown_caller_gets_no_contract_and_is_refused() {
        let addr = serve("summarize_statement").await;
        let got = exchange(
            &addr,
            vec![
                req_headers("By=spiffe://c/x;URI=spiffe://org/ns/agents/sa/somebody-else"),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summarize_statement","arguments":{}}}"#),
            ],
        )
        .await;
        let i = immediate(&got[1]).expect("an unknown caller was admitted");
        assert!(String::from_utf8_lossy(&i.body).contains("WC-4001"));
    }

    #[tokio::test]
    async fn a_request_with_no_identity_is_refused() {
        // No XFCC at all. Absent identity must not resolve to a contract.
        let addr = serve("summarize_statement").await;
        let got = exchange(
            &addr,
            vec![
                ProcessingRequest {
                    request: Some(processing_request::Request::RequestHeaders(hdrs(&[]))),
                    ..Default::default()
                },
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summarize_statement","arguments":{}}}"#),
            ],
        )
        .await;
        assert!(
            immediate(&got[1]).is_some(),
            "a caller with no established identity was admitted"
        );
    }

    #[tokio::test]
    async fn xfcc_from_an_untrusted_origin_is_not_believed() {
        // The half of mesh identity that is not parsing. The header names a caller who DOES
        // hold a contract; it arrives from an origin the operator did not configure, and must
        // be refused anyway — otherwise any process that can reach this port asserts any id.
        let v = Verifier {
            contracts: std::sync::Arc::new(one_contract("summarize_statement")),
            mode: wc_core::error::Mode::Enforce,
            routes: std::sync::Arc::new(CalleeSource::Single(
                wc_core::model::EntityId::new(CALLEE).unwrap(),
            )),
            mesh_trust: wc_mediator::peer::MeshTrust {
                socket: None,
                // Not the loopback the test client connects from.
                addrs: vec!["10.9.9.9".to_string()],
            },
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            Server::builder()
                .add_service(ExternalProcessorServer::new(v))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let got = exchange(
            &addr,
            vec![
                req_headers(XFCC),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summarize_statement","arguments":{}}}"#),
            ],
        )
        .await;
        assert!(
            immediate(&got[1]).is_some(),
            "an XFCC header from an unconfigured origin was believed"
        );
    }

    #[tokio::test]
    async fn an_unconfigured_mesh_trust_believes_nothing() {
        // MeshTrust's deliberate default. A daemon started without --mesh-origin would refuse
        // everything, which is why that flag is required rather than optional.
        let v = Verifier {
            contracts: std::sync::Arc::new(one_contract("summarize_statement")),
            mode: wc_core::error::Mode::Enforce,
            routes: std::sync::Arc::new(CalleeSource::Single(
                wc_core::model::EntityId::new(CALLEE).unwrap(),
            )),
            mesh_trust: wc_mediator::peer::MeshTrust {
                socket: None,
                addrs: Vec::new(),
            },
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            Server::builder()
                .add_service(ExternalProcessorServer::new(v))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let got = exchange(
            &addr,
            vec![
                req_headers(XFCC),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summarize_statement","arguments":{}}}"#),
            ],
        )
        .await;
        assert!(
            immediate(&got[1]).is_some(),
            "an empty mesh trust admitted a caller"
        );
    }

    #[tokio::test]
    async fn a_pin_mismatch_refuses_the_catalogue() {
        // Gate 8 through the daemon: the callee serves a surface the contract did not pin.
        let addr = serve("summarize_statement").await;
        let moved = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"summarize_statement","description":"CHANGED"},{"name":"initiate_payment","description":"b"}]}}"#;
        let got = exchange(
            &addr,
            vec![
                req_headers(XFCC),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
                ProcessingRequest {
                    request: Some(processing_request::Request::ResponseHeaders(hdrs(&[(
                        "content-type",
                        "application/json",
                    )]))),
                    ..Default::default()
                },
                ProcessingRequest {
                    request: Some(processing_request::Request::ResponseBody(HttpBody {
                        body: moved.as_bytes().to_vec(),
                        end_of_stream: true,
                    })),
                    ..Default::default()
                },
            ],
        )
        .await;
        let i = immediate(&got[3]).expect("a moved surface was served to the agent");
        assert!(String::from_utf8_lossy(&i.body).contains("WC-3108"));
    }

    /// Serve with a route table rather than a single callee.
    async fn serve_routed(tools: &str, table: &str) -> String {
        let dir = std::env::temp_dir().join(format!("wc-rt-{}-{:p}", std::process::id(), table));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("routes.toml");
        std::fs::write(&path, table).unwrap();
        let v = Verifier {
            contracts: std::sync::Arc::new(one_contract(tools)),
            mode: wc_core::error::Mode::Enforce,
            routes: std::sync::Arc::new(CalleeSource::Table(std::sync::Arc::new(
                routes::Routes::load(&path).unwrap(),
            ))),
            mesh_trust: wc_mediator::peer::MeshTrust {
                socket: None,
                addrs: vec!["127.0.0.1".to_string()],
            },
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            Server::builder()
                .add_service(ExternalProcessorServer::new(v))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        addr
    }

    /// RequestHeaders carrying the attributes Envoy reports after routing.
    fn req_headers_routed(xfcc: &str, cluster: &str) -> ProcessingRequest {
        use envoy_types::pb::google::protobuf::{value::Kind, Struct, Value};
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "xds.cluster_name".to_string(),
            Value {
                kind: Some(Kind::StringValue(cluster.to_string())),
            },
        );
        let mut attributes = std::collections::HashMap::new();
        attributes.insert(
            "envoy.filters.http.ext_proc".to_string(),
            Struct {
                fields: fields.into_iter().collect(),
            },
        );
        ProcessingRequest {
            request: Some(processing_request::Request::RequestHeaders(hdrs(&[(
                "x-forwarded-client-cert",
                xfcc,
            )]))),
            attributes,
            ..Default::default()
        }
    }

    const TABLE: &str =
        "[[route]]\ncluster = \"payments\"\ncallee = \"spiffe://org/ns/tools/sa/payments-mcp\"\n";

    #[tokio::test]
    async fn a_mapped_route_resolves_its_callee_and_allows_the_call() {
        let addr = serve_routed("summarize_statement", TABLE).await;
        let got = exchange(
            &addr,
            vec![
                req_headers_routed(XFCC, "payments"),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summarize_statement","arguments":{}}}"#),
            ],
        )
        .await;
        assert!(
            immediate(&got[1]).is_none(),
            "a mapped route was refused: {:?}",
            immediate(&got[1]).map(|i| String::from_utf8_lossy(&i.body).to_string())
        );
    }

    #[tokio::test]
    async fn an_unmapped_route_is_refused() {
        // A route nobody mapped is not a route that is exempt.
        let addr = serve_routed("summarize_statement", TABLE).await;
        let got = exchange(
            &addr,
            vec![
                req_headers_routed(XFCC, "some-other-cluster"),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summarize_statement","arguments":{}}}"#),
            ],
        )
        .await;
        assert!(
            immediate(&got[1]).is_some(),
            "an unmapped cluster was allowed to reach its upstream"
        );
    }

    #[tokio::test]
    async fn an_absent_route_attribute_is_refused() {
        // Envoy configured without `request_attributes` sends no attribute at all. That must
        // deny rather than fall through to some default callee.
        let addr = serve_routed("summarize_statement", TABLE).await;
        let got = exchange(
            &addr,
            vec![
                req_headers(XFCC),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summarize_statement","arguments":{}}}"#),
            ],
        )
        .await;
        assert!(
            immediate(&got[1]).is_some(),
            "a stream with no route attribute was admitted"
        );
    }

    #[tokio::test]
    async fn a_batch_is_refused_whole() {
        let addr = serve("summarize_statement").await;
        let got = exchange(
            &addr,
            vec![
                req_headers(XFCC),
                req_body(r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summarize_statement"}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"initiate_payment"}}]"#),
            ],
        )
        .await;
        let i = immediate(&got[1]).expect("a batch was forwarded, including the uncontracted call");
        assert!(String::from_utf8_lossy(&i.body).contains("batch"));
    }

    #[tokio::test]
    async fn a_json_catalogue_is_buffered_then_filtered() {
        let addr = serve("summarize_statement").await;
        let catalogue = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"summarize_statement","description":"a"},{"name":"initiate_payment","description":"b"}]}}"#;
        let got = exchange(
            &addr,
            vec![
                req_headers(XFCC),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
                ProcessingRequest {
                    request: Some(processing_request::Request::ResponseHeaders(hdrs(&[(
                        "content-type",
                        "application/json",
                    )]))),
                    ..Default::default()
                },
                ProcessingRequest {
                    request: Some(processing_request::Request::ResponseBody(HttpBody {
                        body: catalogue.as_bytes().to_vec(),
                        end_of_stream: true,
                    })),
                    ..Default::default()
                },
            ],
        )
        .await;
        assert_eq!(got.len(), 4);

        // The mode override must be set at the RESPONSE HEADERS phase, or nothing is buffered.
        let m = got[2]
            .mode_override
            .as_ref()
            .expect("no mode_override was sent");
        assert_eq!(
            m.response_body_mode,
            BodySendMode::Buffered as i32,
            "response body was not set to BUFFERED"
        );

        // And the body actually replaced.
        let body_mut = match &got[3].response {
            Some(processing_response::Response::ResponseBody(b)) => b
                .response
                .as_ref()
                .and_then(|r| r.body_mutation.as_ref())
                .and_then(|m| m.mutation.as_ref()),
            _ => None,
        }
        .expect("the catalogue was not rewritten");
        let bytes = match body_mut {
            envoy_types::pb::envoy::service::ext_proc::v3::body_mutation::Mutation::Body(b) => {
                b.clone()
            }
            _ => panic!("unexpected mutation kind"),
        };
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let names: Vec<&str> = v["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["summarize_statement"],
            "the catalogue was not filtered"
        );
    }

    #[tokio::test]
    async fn a_streamed_catalogue_is_refused_rather_than_passed_whole() {
        let addr = serve("summarize_statement").await;
        let got = exchange(
            &addr,
            vec![
                req_headers(XFCC),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
                ProcessingRequest {
                    request: Some(processing_request::Request::ResponseHeaders(hdrs(&[(
                        "content-type",
                        "text/event-stream",
                    )]))),
                    ..Default::default()
                },
            ],
        )
        .await;
        assert!(
            immediate(&got[2]).is_some(),
            "an unfilterable catalogue was allowed through whole"
        );
    }

    #[tokio::test]
    async fn a_tool_call_response_is_not_buffered() {
        let addr = serve("summarize_statement").await;
        let got = exchange(
            &addr,
            vec![
                req_headers(XFCC),
                req_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summarize_statement","arguments":{}}}"#),
                ProcessingRequest {
                    request: Some(processing_request::Request::ResponseHeaders(hdrs(&[(
                        "content-type",
                        "text/event-stream",
                    )]))),
                    ..Default::default()
                },
            ],
        )
        .await;
        let m = got[2].mode_override.as_ref().expect("no mode_override");
        // NONE, not BUFFERED: buffering an SSE tool result would stall the stream.
        assert_eq!(
            m.response_body_mode,
            BodySendMode::None as i32,
            "an SSE tool result was going to be buffered"
        );
    }
}
