//! Contract enforcement shaped for a gateway filter (E5), with no transport in it.
//!
//! # Why this is not `wc-mediator`
//!
//! [`crate::Filter`] and `wc_mediator::gate::MediatedUpstream` enforce the same rules, and the
//! obvious move is to share the orchestration between them. It was tried and backed out. The
//! mediator is built around synchronous request/response: it forwards a frame and reads the
//! answer on the next line, and several of its checks — the lazy pin verification most of all —
//! work by *fetching* something on its own behalf.
//!
//! A gateway filter has no such ability. Envoy hands it four separate phase callbacks and it may
//! only inspect and mutate what somebody else chose to send. Forcing one abstraction over both
//! produced a worse version of each.
//!
//! So the orchestration differs and the **checks** are shared: the 14 gates are
//! `wc_core::contract`, the catalogue allowlist is `wc_mediator::filter`, and neither is
//! reimplemented here. The mechanism that keeps the two paths from diverging is the conformance
//! vector set, which both run — not shared control flow.
//!
//! # The phase shape
//!
//! One [`Filter`] per HTTP stream, driven in this order:
//!
//! | Call | Envoy phase | Answers |
//! |---|---|---|
//! | [`Filter::on_request`] | `RequestBody` | may this frame be forwarded at all |
//! | [`Filter::on_response_headers`] | `ResponseHeaders` | must the response body be buffered |
//! | [`Filter::on_response_body`] | `ResponseBody` | is the body acceptable, and rewritten how |
//!
//! Skipping a phase is not a way past a check: [`Filter::on_request`] refuses anything it cannot
//! account for, and a stream that never reaches [`Filter::on_response_body`] never had a
//! catalogue to filter.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde_json::Value;
use wc_core::error::Code;

/// What may happen to a request frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Forward it upstream unchanged.
    Forward,
    /// Do not forward. The adapter turns this into an immediate JSON-RPC error response.
    Refuse {
        /// The taxonomy code, which is what an operator greps for.
        code: Code,
        /// Why, in one line, for the response and the decision log.
        detail: String,
    },
}

/// How the response body of this stream must be treated.
///
/// Envoy honours a `mode_override` only from a header phase, so this is decided at
/// `ResponseHeaders` and cannot be revisited once the body starts arriving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyMode {
    /// Buffer it and hand it to [`Filter::on_response_body`]. Only for a catalogue.
    Buffer,
    /// Stream it through untouched. The verdict was already taken on the request.
    Skip,
    /// Refuse the stream: this body would have had to be filtered and cannot be.
    Refuse {
        /// The taxonomy code.
        code: Code,
        /// Why.
        detail: &'static str,
    },
}

/// What to do with a buffered response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyAction {
    /// Send it on unchanged.
    Pass,
    /// Replace it with this JSON frame.
    Rewrite(Box<Value>),
    /// Refuse after the fact — the pin did not match what the server presented.
    Refuse {
        /// The taxonomy code.
        code: Code,
        /// Why.
        detail: String,
    },
}

/// Per-stream state. One [`Filter`] per HTTP stream; nothing is shared between streams, which is
/// what makes scaling out a matter of adding instances.
#[derive(Debug)]
pub struct Filter {
    /// The connection this stream belongs to, once `initialize` has been admitted.
    admitted: Option<wc_core::contract::Admitted>,
    /// What this stream turned out to be, learned at the request phase and needed at the
    /// response phase — the two are different Envoy callbacks and `mode_override` is only
    /// honoured in the second.
    kind: StreamKind,
    /// Enforce or observe.
    mode: wc_core::error::Mode,
}

/// What the request frame on this stream was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamKind {
    /// Nothing parsed yet.
    Unknown,
    /// A catalogue request; its response has to be filtered.
    Catalog(wc_mediator::filter::Catalog),
    /// A tool call; the verdict was taken on the request and the response is not inspected.
    ToolCall,
    /// Anything else on a live connection.
    Other,
}

impl Filter {
    /// A filter for one stream, on a connection that has already been admitted.
    ///
    /// Admission is not this type's job: at a gateway the contract is resolved per session, and
    /// the session outlives the stream. `None` means no admitted connection, and every frame on
    /// the stream is then refused — absent is not permissive.
    #[must_use]
    pub fn new(
        admitted: Option<wc_core::contract::Admitted>,
        mode: wc_core::error::Mode,
    ) -> Filter {
        Filter {
            admitted,
            kind: StreamKind::Unknown,
            mode,
        }
    }

    /// The request phase: may this frame be forwarded?
    ///
    /// Records what the stream is, so the response phase knows whether it must buffer.
    pub fn on_request(&mut self, method: &str, params: &Value) -> Verdict {
        // No contract, no traffic. In observe mode the finding is recorded by the adapter and
        // the frame goes through, which is the documented softening — and the only one.
        let Some(admitted) = self.admitted.clone() else {
            self.kind = StreamKind::Other;
            return match self.mode {
                wc_core::error::Mode::Observe => Verdict::Forward,
                wc_core::error::Mode::Enforce => Verdict::Refuse {
                    code: Code::NO_CONTRACT,
                    detail: "no contract for this caller and callee".to_string(),
                },
            };
        };

        if let Some(catalog) = wc_mediator::filter::Catalog::from_method(method) {
            self.kind = StreamKind::Catalog(catalog);
            return Verdict::Forward;
        }

        if method == "tools/call" {
            self.kind = StreamKind::ToolCall;
            let Some((tool, _args)) = wc_mediator::mcp::parse_tool_call(params) else {
                return Verdict::Refuse {
                    code: Code::FRAME_MALFORMED,
                    detail: "malformed tools/call".to_string(),
                };
            };
            // The surface is a ceiling. This is the check the whole component exists for.
            if !admitted.items.contains(&tool) {
                return Verdict::Refuse {
                    code: Code::TOOL_UNCONTRACTED,
                    detail: format!("{tool} is not in the contracted surface"),
                };
            }
            return Verdict::Forward;
        }

        self.kind = StreamKind::Other;
        Verdict::Forward
    }

    /// The response-headers phase: must the body be buffered?
    ///
    /// This is the last phase in which Envoy honours a `mode_override`, so the decision is taken
    /// here from what the request turned out to be plus the content type — not at the body phase,
    /// where an override is silently ignored.
    pub fn on_response_headers(&mut self, content_type: &str) -> BodyMode {
        let ct = content_type.to_ascii_lowercase();
        match self.kind {
            StreamKind::Catalog(_) if ct.contains("application/json") => BodyMode::Buffer,
            // A streamed catalogue cannot be filtered before the agent sees the first frame of
            // it, and a catalogue that cannot be filtered is refused rather than passed through
            // — the same disposition the mediator gives it.
            StreamKind::Catalog(_) => BodyMode::Refuse {
                code: Code::SURFACE_UNOBTAINABLE,
                detail: "the catalogue was streamed and cannot be filtered",
            },
            _ => BodyMode::Skip,
        }
    }

    /// The response-body phase: filter the catalogue down to the contracted items.
    ///
    /// Only ever called for a stream this filter asked to buffer.
    pub fn on_response_body(&mut self, body: &[u8]) -> BodyAction {
        let StreamKind::Catalog(catalog) = self.kind else {
            return BodyAction::Pass;
        };
        let Some(admitted) = &self.admitted else {
            return BodyAction::Pass;
        };
        let Ok(mut frame) = serde_json::from_slice::<Value>(body) else {
            // An unparseable catalogue is not an empty one. Passing it through would hand the
            // agent the server's full tool list.
            return BodyAction::Refuse {
                code: Code::SURFACE_UNOBTAINABLE,
                detail: "the catalogue response is not JSON and cannot be filtered".to_string(),
            };
        };
        let permitted = permitted_for(admitted, catalog);
        let _stat = wc_mediator::filter::filter_catalog(catalog, &permitted, &mut frame);
        BodyAction::Rewrite(Box::new(frame))
    }

    /// What this stream was, for the decision log.
    #[must_use]
    pub fn is_catalog(&self) -> bool {
        matches!(self.kind, StreamKind::Catalog(_))
    }
}

/// The permitted item set for a catalogue kind.
///
/// Tools and prompts share the contracted item set; resources are a separate pattern list.
fn permitted_for(
    admitted: &wc_core::contract::Admitted,
    catalog: wc_mediator::filter::Catalog,
) -> std::collections::BTreeSet<String> {
    match catalog {
        wc_mediator::filter::Catalog::Tools | wc_mediator::filter::Catalog::Prompts => {
            admitted.items.clone()
        }
        wc_mediator::filter::Catalog::Resources => admitted.resources.iter().cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use serde_json::json;
    use wc_core::contract::Admitted;
    use wc_core::error::Mode;
    use wc_mediator::filter::Catalog;

    fn admitted(items: &[&str]) -> Admitted {
        Admitted {
            cid: wc_core::model::Cid::new("conn_0123abcd").unwrap(),
            jti: wc_core::model::Jti::new("jti_0123abcd").unwrap(),
            items: items.iter().map(|s| (*s).to_string()).collect(),
            resources: Vec::new(),
            terms: wc_core::contract::Terms::default(),
            exp: u64::MAX,
            findings: Vec::new(),
        }
    }

    fn live(items: &[&str]) -> Filter {
        Filter::new(Some(admitted(items)), Mode::Enforce)
    }

    fn call(tool: &str) -> (String, Value) {
        (
            "tools/call".to_string(),
            json!({"name": tool, "arguments": {}}),
        )
    }

    #[test]
    fn a_contracted_tool_is_forwarded() {
        let (m, p) = call("summarize_statement");
        assert_eq!(
            live(&["summarize_statement"]).on_request(&m, &p),
            Verdict::Forward
        );
    }

    #[test]
    fn an_uncontracted_tool_is_refused_with_4002() {
        let (m, p) = call("initiate_payment");
        let v = live(&["summarize_statement"]).on_request(&m, &p);
        match v {
            Verdict::Refuse { code, ref detail } => {
                assert_eq!(code, Code::TOOL_UNCONTRACTED);
                assert!(detail.contains("initiate_payment"), "{detail}");
            }
            Verdict::Forward => panic!("an uncontracted tool was forwarded"),
        }
    }

    #[test]
    fn a_malformed_tool_call_is_refused_rather_than_forwarded() {
        // No `name`. Forwarding it would reach the server with something the ceiling never saw.
        let v = live(&["x"]).on_request("tools/call", &json!({"arguments": {}}));
        assert!(matches!(
            v,
            Verdict::Refuse {
                code: Code::FRAME_MALFORMED,
                ..
            }
        ));
    }

    #[test]
    fn no_contract_refuses_in_enforce_and_forwards_in_observe() {
        let (m, p) = call("anything");
        assert!(matches!(
            Filter::new(None, Mode::Enforce).on_request(&m, &p),
            Verdict::Refuse {
                code: Code::NO_CONTRACT,
                ..
            }
        ));
        assert_eq!(
            Filter::new(None, Mode::Observe).on_request(&m, &p),
            Verdict::Forward
        );
    }

    #[test]
    fn a_json_catalogue_is_buffered_and_a_streamed_one_is_refused() {
        let mut f = live(&["a"]);
        f.on_request("tools/list", &json!({}));
        assert_eq!(
            f.on_response_headers("application/json; charset=utf-8"),
            BodyMode::Buffer
        );

        let mut g = live(&["a"]);
        g.on_request("tools/list", &json!({}));
        // Fails closed: an unfilterable catalogue is refused, not passed through whole.
        assert!(matches!(
            g.on_response_headers("text/event-stream"),
            BodyMode::Refuse { .. }
        ));
    }

    #[test]
    fn a_tool_call_response_is_never_buffered() {
        // Buffering an SSE tool result would stall the stream, and there is nothing to filter:
        // the verdict was taken on the request.
        let mut f = live(&["a"]);
        f.on_request(&call("a").0, &call("a").1);
        assert_eq!(f.on_response_headers("text/event-stream"), BodyMode::Skip);
        assert_eq!(f.on_response_headers("application/json"), BodyMode::Skip);
    }

    #[test]
    fn the_catalogue_is_filtered_to_the_contracted_items() {
        let mut f = live(&["summarize_statement"]);
        f.on_request("tools/list", &json!({}));
        let body = json!({"jsonrpc":"2.0","id":1,"result":{"tools":[
            {"name":"summarize_statement","description":"a"},
            {"name":"initiate_payment","description":"b"}
        ]}});
        let out = f.on_response_body(body.to_string().as_bytes());
        let BodyAction::Rewrite(frame) = out else {
            panic!("the catalogue was not rewritten");
        };
        let names: Vec<&str> = frame["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["summarize_statement"]);
    }

    #[test]
    fn an_unparseable_catalogue_is_refused_not_passed_through() {
        // The failure that matters: passing it through hands the agent the server's whole list.
        let mut f = live(&["a"]);
        f.on_request("tools/list", &json!({}));
        assert!(matches!(
            f.on_response_body(b"<html>gateway error</html>"),
            BodyAction::Refuse { .. }
        ));
    }

    #[test]
    fn a_body_phase_without_a_request_phase_filters_nothing_and_leaks_nothing() {
        // A stream the filter never saw the request for must not be treated as a catalogue.
        let mut f = live(&["a"]);
        assert_eq!(f.on_response_body(b"{}"), BodyAction::Pass);
        assert!(!f.is_catalog());
    }

    #[test]
    fn resources_use_the_resource_list_not_the_tool_items() {
        let mut a = admitted(&["some_tool"]);
        a.resources = vec!["file:///allowed".to_string()];
        assert_eq!(
            permitted_for(&a, Catalog::Resources)
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["file:///allowed".to_string()]
        );
        assert!(permitted_for(&a, Catalog::Tools).contains("some_tool"));
    }
}
