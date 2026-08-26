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

/// When each contract's pin was last verified.
///
/// Gate 8 can only run when a catalogue passes, and a filter cannot fetch one. Without a record
/// of what has been verified, a caller that issues `tools/call` and never `tools/list` is never
/// pinned at all — the callee could have changed its surface an hour ago.
///
/// # Keyed by contract, not by session and not by callee
///
/// Per SESSION is the obvious choice and it is wrong twice: a stateless MCP server issues no
/// `Mcp-Session-Id`, so every stream would be its own unverifiable session; and a session is not
/// what the pin is a property of.
///
/// Per CALLEE is also wrong. The pinned digest covers exactly the CONTRACTED items, so two
/// contracts over different subsets of one callee carry different digests — and a ledger keyed
/// by callee would let contract X's verification vouch for contract Y, which was never checked.
///
/// So it is keyed by `jti`. Any stream on that contract that carries a catalogue verifies it for
/// every other stream on the same contract, which is exactly as far as the evidence reaches.
#[derive(Debug, Default)]
pub struct PinLedger {
    verified: std::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl PinLedger {
    /// A ledger with nothing verified.
    #[must_use]
    pub fn new() -> PinLedger {
        PinLedger::default()
    }

    /// Record that this contract's pin matched what the callee presented.
    pub fn record(&self, jti: &str, at: u64) {
        let mut m = match self.verified.lock() {
            Ok(m) => m,
            // A poisoned lock means a thread panicked holding it. The records are still valid
            // and dropping them would only refuse more, so the poison is stepped over.
            Err(p) => p.into_inner(),
        };
        m.insert(jti.to_string(), at);
    }

    /// Drop any record for this contract, so a tool call on it is refused until a catalogue
    /// matches again.
    pub fn forget(&self, jti: &str) {
        let mut m = match self.verified.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        m.remove(jti);
    }

    /// When this contract's pin was last verified, if ever.
    #[must_use]
    pub fn verified_at(&self, jti: &str) -> Option<u64> {
        let m = match self.verified.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        m.get(jti).copied()
    }
}

/// What every stream on this verifier shares.
///
/// Split from [`Filter::new`]'s arguments because the two halves have different lifetimes and
/// different owners: these four are deployment configuration, decided once at startup, while
/// the admitted connection, its contract and its ceilings belong to one stream. The argument
/// list had grown to eight and every call site had to be edited whenever a control was added,
/// which is how a caller ends up passing `None` in the wrong position.
#[derive(Clone)]
pub struct FilterCfg {
    /// Enforce or observe.
    pub mode: wc_core::error::Mode,
    /// The callee the pin is bound to. Configuration, never from the request.
    pub callee: wc_core::model::EntityId,
    /// What has been pinned. `None` disables the requirement entirely.
    pub pins: Option<std::sync::Arc<PinLedger>>,
    /// Seconds a pin verification stays good. Zero means it never expires.
    pub pin_max_age: u64,
}

/// Per-stream state. One [`Filter`] per HTTP stream; nothing is shared between streams, which is
/// what makes scaling out a matter of adding instances.
#[derive(Debug)]
pub struct Filter {
    /// The connection this stream belongs to, once `initialize` has been admitted.
    admitted: Option<wc_core::contract::Admitted>,
    /// The callee's pinned surface digest, from the contract.
    ///
    /// The contract itself, so gate 8 runs through `VerifiedContract::check_pin`.
    ///
    /// An earlier version of this carried the pinned digest and compared it to the presented
    /// manifest. That was wrong twice: the contract pins a digest over **exactly the contracted
    /// items**, not the whole manifest, so it mismatched whenever the callee served more tools
    /// than were contracted — which is the normal case; and a contract carrying no digest was
    /// treated as "gate 8 off" where `check_pin` refuses it. Calling the shared check is both
    /// correct and the reason this crate does not reimplement any of them.
    contract: Option<std::sync::Arc<wc_core::contract::VerifiedContract>>,
    /// The callee id the pin is bound to. A digest is over (entity, surface), so comparing one
    /// computed for a different entity would always mismatch.
    callee: wc_core::model::EntityId,
    /// Canonicalisation bounds for the presented surface.
    limits: wc_core::canon::Limits,
    /// Clock, injected so a test can pin it.
    now: u64,
    /// The contract's ceilings, SHARED between every stream on the same contract.
    ///
    /// The mediator keeps these on its own stack because one process is one connection. A
    /// gateway sees one HTTP stream per call, so per-stream counters would reset on every
    /// request and a rate ceiling of 10/min would admit 10 per REQUEST — a ceiling that reads as
    /// configured and counts nothing. They are keyed by the contract, upstream of this type.
    ceilings: Option<std::sync::Arc<wc_mediator::ceiling::Ceilings>>,
    /// Held for the life of the stream; released when this filter is dropped.
    slot: Option<wc_mediator::ceiling::OwnedSlot>,
    /// What has been pinned, shared across streams. `None` disables the requirement.
    pins: Option<std::sync::Arc<PinLedger>>,
    /// Seconds a pin verification stays good. Zero means it never expires.
    pin_max_age: u64,
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
        contract: Option<std::sync::Arc<wc_core::contract::VerifiedContract>>,
        ceilings: Option<std::sync::Arc<wc_mediator::ceiling::Ceilings>>,
        now: u64,
        cfg: &FilterCfg,
    ) -> Filter {
        Filter {
            admitted,
            contract,
            callee: cfg.callee.clone(),
            limits: wc_core::canon::Limits::default(),
            now,
            ceilings,
            slot: None,
            pins: cfg.pins.clone(),
            pin_max_age: cfg.pin_max_age,
            kind: StreamKind::Unknown,
            mode: cfg.mode,
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

            // Gate 8, for a stream that carries no catalogue of its own. Before the ceilings
            // for the same reason the surface check is: `reserve` records the call, and a call
            // that is about to be refused must not consume the caller's budget.
            if let Some(pins) = &self.pins {
                let jti = admitted.jti.as_str();
                match pins.verified_at(jti) {
                    None => {
                        return Verdict::Refuse {
                            code: Code::SURFACE_UNOBTAINABLE,
                            detail: "this contract's pin has not been verified: no tools/list \
                                     has passed through, so the callee's surface is unchecked"
                                .to_string(),
                        }
                    }
                    Some(at)
                        if self.pin_max_age > 0
                            && self.now.saturating_sub(at) > self.pin_max_age =>
                    {
                        return Verdict::Refuse {
                            code: Code::SURFACE_UNOBTAINABLE,
                            detail: format!(
                                "this contract's pin was last verified {}s ago, beyond the {}s \
                                 bound; the callee's surface may have moved since",
                                self.now.saturating_sub(at),
                                self.pin_max_age
                            ),
                        }
                    }
                    Some(_) => {}
                }
            }

            // The contract's terms, which until now were carried and enforced by nothing on
            // this path. Order matters: the rate ceiling RECORDS the call, so it goes after the
            // surface check — otherwise a refused tool would still consume the caller's budget.
            if let Some(ceilings) = &self.ceilings {
                if let Err(e) = ceilings.reserve(&admitted.terms, self.now) {
                    return Verdict::Refuse {
                        code: e.code(),
                        detail: e.detail().to_string(),
                    };
                }
                match ceilings.enter_owned(&admitted.terms) {
                    // Held on the filter, so the slot is released when the stream ends. A slot
                    // dropped here instead would make every concurrency ceiling unreachable.
                    Ok(slot) => self.slot = slot,
                    Err(e) => {
                        return Verdict::Refuse {
                            code: e.code(),
                            detail: e.detail().to_string(),
                        }
                    }
                }
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
        // Gate 8, and the only moment a filter can run it: this is the callee's surface as
        // actually presented. The mediator fetches a catalogue when a client skips discovery; a
        // filter cannot, so a stream that carries none is not pinned — named in the crate docs
        // rather than hidden.
        if let (Some(contract), Some(result)) = (&self.contract, frame.get("result")) {
            let presented = match wc_core::canon::pin(
                wc_core::canon::SurfaceKind::McpTools,
                &self.callee,
                result,
                &self.limits,
                self.now,
            ) {
                Ok(p) => p,
                // A surface that cannot be canonicalised cannot be compared, and an
                // uncomparable surface is not a matching one.
                Err(e) => {
                    return BodyAction::Refuse {
                        code: e.code(),
                        detail: e.detail().to_string(),
                    }
                }
            };
            if let Err(e) = contract.check_pin(&presented) {
                // A mismatch REVOKES any earlier verification. Refusing only this catalogue
                // would leave the recorded pin standing, so tool calls would keep flowing on a
                // contract whose callee has demonstrably moved — the drift detected and then
                // ignored, which is worse than not looking.
                if let (Some(pins), Some(a)) = (&self.pins, &self.admitted) {
                    pins.forget(a.jti.as_str());
                }
                return BodyAction::Refuse {
                    code: e.code(),
                    detail: e.detail().to_string(),
                };
            }
            // Recorded only on a match. A mismatch must not mark the contract pinned, or one
            // bad catalogue would unlock every later tool call on it.
            if let (Some(pins), Some(a)) = (&self.pins, &self.admitted) {
                pins.record(a.jti.as_str(), self.now);
            }
        }

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

    /// The shared configuration these tests use: enforce, no pin requirement.
    fn cfg(mode: Mode) -> FilterCfg {
        FilterCfg {
            mode,
            callee: callee(),
            pins: None,
            pin_max_age: 0,
        }
    }

    fn callee() -> wc_core::model::EntityId {
        wc_core::model::EntityId::new("spiffe://bank.example/ns/aws/sa/payments-mcp").unwrap()
    }

    /// A live stream with no contract carried, so these exercise the phase machine alone.
    /// Gate 8 needs a real minted contract and lives in `tests/pin.rs`.
    fn live(items: &[&str]) -> Filter {
        Filter::new(Some(admitted(items)), None, None, 0, &cfg(Mode::Enforce))
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

    /// A live stream whose contract carries `terms`, with ceilings shared as `c`.
    fn live_limited(
        items: &[&str],
        terms: wc_core::contract::Terms,
        c: &std::sync::Arc<wc_mediator::ceiling::Ceilings>,
    ) -> Filter {
        let mut a = admitted(items);
        a.terms = terms;
        Filter::new(
            Some(a),
            None,
            Some(std::sync::Arc::clone(c)),
            0,
            &cfg(Mode::Enforce),
        )
    }

    #[test]
    fn the_rate_ceiling_counts_across_streams_not_within_one() {
        // The failure this exists to prevent: per-stream counters reset every request, so a
        // ceiling of 2/window would admit 2 per REQUEST and count nothing.
        let terms = wc_core::contract::Terms {
            max_calls_per_hour: Some(2),
            ..wc_core::contract::Terms::default()
        };
        let c = std::sync::Arc::new(wc_mediator::ceiling::Ceilings::new());
        let (m, p) = call("summarize_statement");

        for i in 1..=2 {
            let mut f = live_limited(&["summarize_statement"], terms.clone(), &c);
            assert_eq!(f.on_request(&m, &p), Verdict::Forward, "call {i} refused");
        }
        // A THIRD stream, a fresh Filter, and the ceiling must still bite.
        let mut third = live_limited(&["summarize_statement"], terms, &c);
        match third.on_request(&m, &p) {
            Verdict::Refuse { code, .. } => assert_eq!(code, Code::RATE_CEILING),
            Verdict::Forward => panic!("the rate ceiling did not carry across streams"),
        }
    }

    #[test]
    fn an_uncontracted_tool_does_not_consume_the_rate_budget() {
        // Order matters: `reserve` records the call, so it must run after the surface check.
        // Otherwise a caller could burn a victim's budget with tools it may not even name.
        let terms = wc_core::contract::Terms {
            max_calls_per_hour: Some(1),
            ..wc_core::contract::Terms::default()
        };
        let c = std::sync::Arc::new(wc_mediator::ceiling::Ceilings::new());
        let mut f = live_limited(&["allowed"], terms.clone(), &c);
        let (m, p) = call("not_allowed");
        assert!(matches!(f.on_request(&m, &p), Verdict::Refuse { .. }));
        assert_eq!(c.calls_in_window(), 0, "a refused tool consumed the budget");

        // And the one contracted call still gets through.
        let mut g = live_limited(&["allowed"], terms, &c);
        assert_eq!(
            g.on_request(&call("allowed").0, &call("allowed").1),
            Verdict::Forward
        );
    }

    #[test]
    fn the_concurrency_slot_is_held_for_the_stream_and_released_with_it() {
        let terms = wc_core::contract::Terms {
            max_concurrent: Some(1),
            ..wc_core::contract::Terms::default()
        };
        let c = std::sync::Arc::new(wc_mediator::ceiling::Ceilings::new());
        let (m, p) = call("summarize_statement");

        let mut first = live_limited(&["summarize_statement"], terms.clone(), &c);
        assert_eq!(first.on_request(&m, &p), Verdict::Forward);
        assert_eq!(c.in_flight(), 1, "the slot was not taken");

        // A second concurrent stream is refused while the first is open.
        let mut second = live_limited(&["summarize_statement"], terms.clone(), &c);
        assert!(matches!(
            second.on_request(&m, &p),
            Verdict::Refuse {
                code: Code::CONCURRENCY_CEILING,
                ..
            }
        ));

        // The first stream ends. Its slot must go with it.
        drop(first);
        assert_eq!(
            c.in_flight(),
            0,
            "the slot was not released when the stream ended"
        );
        let mut third = live_limited(&["summarize_statement"], terms, &c);
        assert_eq!(third.on_request(&m, &p), Verdict::Forward);
    }

    #[test]
    fn a_contract_with_no_terms_is_not_rate_limited_into_the_ground() {
        // No ceiling in the terms means no ceiling, not a ceiling of zero.
        let c = std::sync::Arc::new(wc_mediator::ceiling::Ceilings::new());
        let (m, p) = call("summarize_statement");
        for _ in 0..50 {
            let mut f = live_limited(
                &["summarize_statement"],
                wc_core::contract::Terms::default(),
                &c,
            );
            assert_eq!(f.on_request(&m, &p), Verdict::Forward);
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
            Filter::new(None, None, None, 0, &cfg(Mode::Enforce)).on_request(&m, &p),
            Verdict::Refuse {
                code: Code::NO_CONTRACT,
                ..
            }
        ));
        assert_eq!(
            Filter::new(None, None, None, 0, &cfg(Mode::Observe)).on_request(&m, &p),
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
