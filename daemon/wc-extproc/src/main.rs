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

mod xfcc;

use std::pin::Pin;

use envoy_types::pb::envoy::r#type::v3::HttpStatus;
use envoy_types::pb::envoy::service::ext_proc::v3::{
    external_processor_server::{ExternalProcessor, ExternalProcessorServer},
    processing_request, processing_response, BodyResponse, CommonResponse, HeadersResponse,
    HttpBody, HttpHeaders, ImmediateResponse, ProcessingRequest, ProcessingResponse,
};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tonic::{transport::Server, Request, Response, Status, Streaming};
use warden_connect_gateway::{BodyAction, BodyMode, Filter, Verdict};

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

/// Where a contract for this stream comes from.
///
/// Increment 2 loads one admitted connection from configuration so the phase loop can be
/// exercised end to end. The real source is a per-cluster contract set pulled by `client.rs`,
/// keyed on (caller, callee) — that is the next increment, and it changes this trait's
/// implementation and nothing else in this file.
trait Contracts: Send + Sync + 'static {
    /// The admitted connection for this caller and callee, if there is one.
    fn resolve(&self, caller: Option<&str>, callee: &str) -> Option<wc_core::contract::Admitted>;
}

struct Verifier<C: Contracts> {
    contracts: C,
    mode: wc_core::error::Mode,
    /// The callee this listener fronts. Taken from configuration, never from the request: a
    /// caller that could name its own callee could pick a contract it was not given.
    callee: String,
}

#[tonic::async_trait]
impl<C: Contracts> ExternalProcessor for Verifier<C> {
    type ProcessStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ProcessingResponse, Status>> + Send>>;

    async fn process(
        &self,
        request: Request<Streaming<ProcessingRequest>>,
    ) -> Result<Response<Self::ProcessStream>, Status> {
        let mut inbound = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(8);

        let contracts_mode = self.mode;
        let callee = self.callee.clone();
        // One admitted connection resolved per stream. Peer identity arrives on the header
        // phase, so the resolve happens there rather than here.
        let resolve = |caller: Option<&str>| self.contracts.resolve(caller, &callee);
        let admitted_slot = std::sync::Arc::new(std::sync::Mutex::new(None));

        // The filter for this stream. `Filter::new` is given the admitted connection once the
        // headers phase has established who the caller is.
        let mut filter: Option<Filter> = None;
        let slot = std::sync::Arc::clone(&admitted_slot);

        while let Some(msg) = inbound.next().await {
            let msg = msg?;
            let out = match msg.request {
                Some(processing_request::Request::RequestHeaders(h)) => {
                    let caller =
                        header(&h, "x-forwarded-client-cert").and_then(xfcc::spiffe_from_xfcc);
                    let admitted = resolve(caller.as_deref());
                    *slot.lock().expect("slot") = admitted.clone();
                    filter = Some(Filter::new(admitted, contracts_mode));
                    cont_headers()
                }
                Some(processing_request::Request::RequestBody(b)) => {
                    let f = filter.get_or_insert_with(|| {
                        // No headers phase was sent. Configuring the filter to skip it and then
                        // trusting the body is how a caller reaches the upstream with no identity
                        // established at all, so this fails closed rather than assuming.
                        Filter::new(None, contracts_mode)
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
    ProcessingResponse {
        response: Some(processing_response::Response::ResponseHeaders(
            HeadersResponse::default(),
        )),
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

/// A single admitted connection, from configuration.
///
/// The stand-in for the per-cluster contract set, so the phase loop can be run against a real
/// Envoy before the puller exists. It resolves for one caller and refuses every other, which is
/// the correct shape: a caller with no contract gets nothing.
struct OneContract {
    caller: String,
    admitted: wc_core::contract::Admitted,
}

impl Contracts for OneContract {
    fn resolve(&self, caller: Option<&str>, _callee: &str) -> Option<wc_core::contract::Admitted> {
        // Absent identity resolves to nothing. This is the line that decides an unauthenticated
        // caller is not a permitted one.
        match caller {
            Some(c) if c == self.caller => Some(self.admitted.clone()),
            _ => None,
        }
    }
}

fn usage() -> &'static str {
    "\
wc-extproc — the warden-connect Envoy ext_proc verifier

USAGE
  wc-extproc --listen ADDR --callee SPIFFE_ID --caller SPIFFE_ID --tools a,b [--observe]

  --listen ADDR      where to serve gRPC, e.g. 127.0.0.1:9002 or unix:/run/wc.sock
  --callee SPIFFE_ID the party this listener fronts, from configuration
  --caller SPIFFE_ID the caller this build admits (stand-in for the contract set)
  --tools a,b        the contracted surface for that caller
  --observe          record findings instead of denying

ENVOY MUST BE CONFIGURED WITH
  failure_mode_allow: false     this process being unreachable has to deny, not allow
  allow_mode_override: true     without it the catalogue is never buffered and never filtered
  request_body_mode: BUFFERED   the tool name is in the body
  and the filter scoped to MCP routes only, or every body in the mesh is buffered and parsed."
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{}", usage());
        return Ok(());
    }

    let listen = flag(&args, "listen").ok_or("--listen is required")?;
    let callee = flag(&args, "callee").ok_or("--callee is required")?;
    let caller = flag(&args, "caller").ok_or("--caller is required")?;
    let tools = flag(&args, "tools").ok_or("--tools is required")?;
    let mode = if args.iter().any(|a| a == "--observe") {
        wc_core::error::Mode::Observe
    } else {
        wc_core::error::Mode::Enforce
    };

    let admitted = wc_core::contract::Admitted {
        cid: wc_core::model::Cid::new("conn_0000dead")?,
        jti: wc_core::model::Jti::new("jti_0000dead")?,
        items: tools.split(',').map(|s| s.trim().to_string()).collect(),
        resources: Vec::new(),
        terms: wc_core::contract::Terms::default(),
        exp: u64::MAX,
        findings: Vec::new(),
    };

    let verifier = Verifier {
        contracts: OneContract {
            caller: caller.clone(),
            admitted,
        },
        mode,
        callee: callee.clone(),
    };

    eprintln!("wc-extproc: serving ext_proc on {listen}");
    eprintln!("wc-extproc: fronting {callee}, admitting {caller} for [{tools}] ({mode:?})");
    eprintln!(
        "wc-extproc: Envoy must set failure_mode_allow=false and allow_mode_override=true; \
         without the second, catalogues are never filtered"
    );

    let addr: std::net::SocketAddr = listen.parse()?;
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

    /// Start a server on an ephemeral port; return its address.
    async fn serve(tools: &str) -> String {
        let admitted = wc_core::contract::Admitted {
            cid: wc_core::model::Cid::new("conn_0000dead").unwrap(),
            jti: wc_core::model::Jti::new("jti_0000dead").unwrap(),
            items: tools.split(',').map(|s| s.to_string()).collect(),
            resources: Vec::new(),
            terms: wc_core::contract::Terms::default(),
            exp: u64::MAX,
            findings: Vec::new(),
        };
        let v = Verifier {
            contracts: OneContract {
                caller: "spiffe://bank.example/ns/laptop/sa/recon-bot".to_string(),
                admitted,
            },
            mode: wc_core::error::Mode::Enforce,
            callee: "spiffe://bank.example/ns/aws/sa/payments-mcp".to_string(),
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

    const XFCC: &str = "By=spiffe://c/x;URI=spiffe://bank.example/ns/laptop/sa/recon-bot";

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
                req_headers("By=spiffe://c/x;URI=spiffe://bank.example/ns/laptop/sa/somebody-else"),
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
