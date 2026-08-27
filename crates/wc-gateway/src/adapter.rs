//! What every binding needs, so that no binding reimplements it.
//!
//! [`Filter`](crate::Filter) is the decision. A binding — Envoy `ext_proc`, a Kong cdylib,
//! anything next — is the wiring that feeds it. The four things here are the parts of that
//! wiring that must be *identical* across bindings rather than merely similar:
//!
//! | | Why it cannot be per-binding |
//! |---|---|
//! | [`refusal_frame`] | an agent must see the same refusal whichever PEP refused it |
//! | [`Registry`] | a rate ceiling counted per binding is a different ceiling |
//! | [`placeholder_callee`] | the "no contract" path must not become a second way to say it |
//! | [`set_binding`] | a diagnostic that names the wrong binary sends the reader to the wrong log |
//! | [`parse_request_frame`] | refusing a batch is a security property, not a parsing detail |
//!
//! The last one is here because of a real regression: `contracts` and `routes` were lifted out
//! of the Envoy daemon carrying `eprintln!("wc-extproc: ...")`, which would have told a Kong
//! operator to go and look at a binary they do not run.

use std::sync::OnceLock;

static BINDING: OnceLock<&'static str> = OnceLock::new();

/// Name this binding, once, for every diagnostic the shared modules emit.
///
/// Called at startup by the binding — `wc-extproc`, `wc-kong`. The first call wins and later
/// ones are ignored, so a test that sets it cannot make another test's output lie.
pub fn set_binding(name: &'static str) {
    let _ = BINDING.set(name);
}

/// The name to prefix a diagnostic with. `wc-gateway` until a binding says otherwise.
#[must_use]
pub fn binding() -> &'static str {
    BINDING.get().copied().unwrap_or("wc-gateway")
}

/// A JSON-RPC error frame, shaped the way the mediator shapes a refusal.
///
/// # Why 200 and not an HTTP error
///
/// This is the *body*; the binding sets the status. Both bindings send 200, because an MCP
/// client surfaces a transport failure as "the server is broken" and a JSON-RPC error as a
/// refused call. An agent has to be able to tell those apart — and an operator reading a
/// dashboard of 5xx wants the ones that are actually the server.
#[must_use]
pub fn refusal_frame(code: wc_core::error::Code, detail: &str) -> String {
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

/// One JSON-RPC request frame out of a request body.
///
/// # Why a batch is refused whole
///
/// A batch carries several calls, some of which the filter would allow and some not. There is
/// no partial answer to give, and forwarding the array would forward the ones it would have
/// refused. Every binding has to do this, and a binding that forgot would not fail any test it
/// wrote for itself — it would simply stop enforcing whenever a client batched.
///
/// # Errors
///
/// The code and the one-line detail a binding should refuse with.
pub fn parse_request_frame(
    body: &[u8],
) -> Result<(String, serde_json::Value), (wc_core::error::Code, &'static str)> {
    let Ok(frame) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Err((
            wc_core::error::Code::FRAME_MALFORMED,
            "the request body is not a JSON-RPC frame",
        ));
    };
    if frame.is_array() {
        return Err((
            wc_core::error::Code::FRAME_MALFORMED,
            "a JSON-RPC batch cannot be verified per call; send one frame per request",
        ));
    }
    let method = frame
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let params = frame
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Ok((method, params))
}

/// A callee id for a stream whose route is unmapped.
///
/// Never used to admit anything: the filter it is handed to has no contract, so every frame on
/// that stream is refused. It exists because [`Filter`](crate::Filter) needs an entity to bind
/// a pin to, and an `Option` there would be a second way to express "no contract".
#[must_use]
pub fn placeholder_callee() -> wc_core::model::EntityId {
    wc_core::model::EntityId::new("spiffe://unmapped.invalid/ns/x/sa/unmapped")
        .expect("the placeholder callee is a valid id")
}

/// Ceiling state per contract, shared by every stream on that contract.
///
/// # Why this is not per-stream
///
/// A gateway sees one HTTP stream per call. Per-stream counters reset on every request, so a
/// rate ceiling of 10/min would admit 10 per *request* — a ceiling that reads as configured and
/// counts nothing. They are keyed by the contract's `jti`, which is the thing the ceiling is a
/// property of.
///
/// # What it does not solve
///
/// One registry is one process. Two processes enforcing the same contract each get the whole
/// ceiling, so the effective ceiling is `configured × instances`. That is true of `wc-extproc`
/// behind more than one Envoy and it is true of a cdylib in more than one nginx worker. A
/// binding that can be multiply instantiated has to say so out loud rather than let an operator
/// read the configured number and believe it.
#[derive(Default)]
pub struct Registry {
    by_jti: std::sync::Mutex<
        std::collections::HashMap<String, std::sync::Arc<wc_mediator::ceiling::Ceilings>>,
    >,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Registry {
        Registry::default()
    }

    /// The ceilings for one contract, created on first sight.
    ///
    /// Nothing evicts these. A contract that expires leaves its counters behind, which is a
    /// bounded leak — one small struct per contract this process has ever admitted — and the
    /// safe direction: evicting on expiry would hand a caller a fresh budget by waiting.
    #[must_use]
    pub fn for_contract(&self, jti: &str) -> std::sync::Arc<wc_mediator::ceiling::Ceilings> {
        let mut map = match self.by_jti.lock() {
            Ok(m) => m,
            // A poisoned lock means another thread panicked holding it. The counters are still
            // readable and a fresh map would reset every budget, so the poison is stepped over
            // rather than allowed to become a way past the ceilings.
            Err(poisoned) => poisoned.into_inner(),
        };
        std::sync::Arc::clone(
            map.entry(jti.to_string())
                .or_insert_with(|| std::sync::Arc::new(wc_mediator::ceiling::Ceilings::new())),
        )
    }

    /// How many contracts have counters here.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.by_jti.lock() {
            Ok(m) => m.len(),
            Err(p) => p.into_inner().len(),
        }
    }

    /// Whether no contract has been seen yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wc_core::error::Code;

    #[test]
    fn refusal_frame_carries_the_code_in_data_and_message() {
        let f = refusal_frame(Code::TOOL_UNCONTRACTED, "nope");
        let v: serde_json::Value = serde_json::from_str(&f).expect("valid json");
        assert_eq!(v["error"]["data"]["code"], "WC-4002");
        assert_eq!(v["error"]["code"], -32001);
        assert_eq!(v["jsonrpc"], "2.0");
        assert!(v["id"].is_null(), "a refusal answers no particular id");
        assert!(
            v["error"]["message"]
                .as_str()
                .expect("message is a string")
                .contains("WC-4002"),
            "the code has to be greppable in the message an agent prints"
        );
    }

    #[test]
    fn one_registry_entry_per_contract_not_per_call() {
        let r = Registry::new();
        let a = r.for_contract("jti-a");
        let b = r.for_contract("jti-a");
        let c = r.for_contract("jti-b");
        assert!(
            std::sync::Arc::ptr_eq(&a, &b),
            "two streams on one contract must share counters, or the ceiling counts nothing"
        );
        assert!(!std::sync::Arc::ptr_eq(&a, &c));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn a_batch_is_refused_whole_never_partially_forwarded() {
        let body = br#"[{"method":"tools/call"},{"method":"tools/list"}]"#;
        let (code, detail) = parse_request_frame(body).expect_err("a batch must not parse");
        assert_eq!(code, Code::FRAME_MALFORMED);
        assert!(detail.contains("batch"));
    }

    #[test]
    fn a_body_that_is_not_json_is_refused_not_treated_as_an_empty_method() {
        let (code, _) = parse_request_frame(b"not json").expect_err("must not parse");
        assert_eq!(code, Code::FRAME_MALFORMED);
    }

    #[test]
    fn a_frame_without_params_yields_null_not_an_error() {
        let (method, params) =
            parse_request_frame(br#"{"jsonrpc":"2.0","method":"tools/list"}"#).expect("parses");
        assert_eq!(method, "tools/list");
        assert!(params.is_null());
    }

    #[test]
    fn the_placeholder_callee_is_not_a_real_id_anyone_could_hold() {
        let p = placeholder_callee();
        assert!(p.as_str().contains("unmapped.invalid"));
    }

    #[test]
    fn binding_defaults_and_never_changes_under_a_second_caller() {
        // Cannot assert the default here — another test in this binary may have set it first,
        // and OnceLock is process-wide. What IS testable is that a second set does not win.
        set_binding("first-caller");
        let seen = binding();
        set_binding("second-caller");
        assert_eq!(binding(), seen, "the first name must win, so output cannot lie");
    }
}
