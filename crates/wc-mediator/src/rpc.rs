//! JSON-RPC 2.0 — the wire format MCP uses over stdio.
//!
//! # Why these types are ours
//!
//! They were `warden::jsonrpc`. §8.3 permitted that: `wc-mediator` compiles *into* the
//! Warden proxy, so the coupling was the deployment model rather than a dependency choice.
//!
//! That premise no longer holds. A deployment may run **warden-connect alone** — connection
//! enforcement without adopting Warden core's per-action policy — and until now it could not,
//! because `connect-mediate` required a `warden.policy.toml`, constructed a `warden::Gateway`,
//! and every type on the mediation path was Warden's. "Independent enforcement point" was a
//! stated goal contradicted by the imports.
//!
//! The coupling was at the *type* level, not the logic level: JSON-RPC 2.0 is a short
//! specification and `Upstream` is a two-method trait. So the direction is inverted rather
//! than the dependency removed — these are the mediator's own types, and interoperating with
//! Warden's proxy becomes an adapter over them (`docs/08-lld.md` §8.6.1).
//!
//! Deliberately wire-compatible with `warden::jsonrpc`, field for field, because they
//! describe the same specification and a divergence would be a bug in one of them rather
//! than a difference of opinion.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A JSON-RPC request, or a notification when `id` is absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Always `"2.0"` on the wire.
    pub jsonrpc: String,
    /// Absent for notifications, which expect no response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// The method name, e.g. `tools/call`.
    pub method: String,
    /// Method parameters. `Value::Null` when omitted.
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC response. Exactly one of `result` or `error` is populated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Always `"2.0"` on the wire.
    pub jsonrpc: String,
    /// Echoes the request's id, so a caller can correlate.
    pub id: Option<Value>,
    /// The success payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The failure payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    /// JSON-RPC error code. Application codes live below `-32000`.
    pub code: i64,
    /// Human-readable summary.
    pub message: String,
    /// Structured detail. The mediator puts its `WC-*` code here, which is what
    /// `blocked_with` in the test suite reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl Request {
    /// A request with a numeric id.
    #[must_use]
    pub fn new(id: i64, method: &str, params: Value) -> Request {
        Request {
            jsonrpc: "2.0".to_string(),
            id: Some(Value::from(id)),
            method: method.to_string(),
            params,
        }
    }

    /// Whether this is a notification — no id, so no response is expected.
    ///
    /// Named rather than inlined as `id.is_none()`, because "notification" is the
    /// protocol's word for it and the distinction decides whether a refusal can be
    /// delivered at all.
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

impl Response {
    /// A success response.
    #[must_use]
    pub fn ok(id: Option<Value>, result: Value) -> Response {
        Response {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// A failure response with no structured detail.
    #[must_use]
    pub fn error(id: Option<Value>, code: i64, message: impl Into<String>) -> Response {
        Response {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// A failure response carrying structured detail.
    ///
    /// The mediator's refusals go through here: `data` carries the `WC-*` code, so an
    /// agent — or a test — can tell *which* control refused rather than only that
    /// something did.
    #[must_use]
    pub fn error_with_data(
        id: Option<Value>,
        code: i64,
        message: impl Into<String>,
        data: Value,
    ) -> Response {
        Response {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: Some(data),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use serde_json::json;

    #[test]
    fn a_request_round_trips_and_keeps_jsonrpc_two_point_zero() {
        let req = Request::new(7, "tools/call", json!({"name": "alpha"}));
        let wire = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.jsonrpc, "2.0");
        assert_eq!(back.method, "tools/call");
        assert_eq!(back.id, Some(json!(7)));
    }

    #[test]
    fn a_notification_serialises_without_an_id_field_at_all() {
        // Not `"id": null` — a JSON-RPC notification omits the member. A peer that
        // distinguishes the two would answer a notification, which is a protocol error
        // and, on the mediation path, a response nobody is waiting for.
        let note = Request {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: "notifications/initialized".to_string(),
            params: Value::Null,
        };
        let wire = serde_json::to_string(&note).unwrap();
        assert!(!wire.contains("\"id\""), "{wire}");
        assert!(note.is_notification());
    }

    #[test]
    fn params_default_to_null_when_the_member_is_absent() {
        // MCP peers omit `params` for methods that take none. Requiring it would refuse
        // well-formed traffic.
        let req: Request =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#).unwrap();
        assert_eq!(req.params, Value::Null);
    }

    #[test]
    fn a_response_carries_result_or_error_but_never_both_members() {
        let ok = Response::ok(Some(json!(1)), json!({"tools": []}));
        let wire = serde_json::to_string(&ok).unwrap();
        assert!(!wire.contains("\"error\""), "{wire}");

        let bad = Response::error(Some(json!(1)), -32001, "refused");
        let wire = serde_json::to_string(&bad).unwrap();
        assert!(!wire.contains("\"result\""), "{wire}");
    }

    #[test]
    fn structured_detail_survives_the_wire_because_the_wc_code_lives_there() {
        let resp = Response::error_with_data(
            Some(json!(2)),
            -32001,
            "BLOCKED by warden-connect",
            json!({"code": "WC-3105"}),
        );
        let wire = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&wire).unwrap();
        assert_eq!(
            back.error.unwrap().data.unwrap()["code"],
            json!("WC-3105"),
            "the WC code is how an operator tells which control refused"
        );
    }

    #[test]
    fn the_wire_shape_matches_what_an_mcp_peer_sends() {
        // A real `tools/call` frame, parsed. If this ever fails the mediator has stopped
        // speaking the protocol its peers speak, which no unit test of our own types
        // would otherwise catch.
        let frame = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call",
                        "params":{"name":"get_balance","arguments":{"id":"ACC-1"}}}"#;
        let req: Request = serde_json::from_str(frame).unwrap();
        assert_eq!(req.method, "tools/call");
        assert_eq!(req.params["name"], json!("get_balance"));
        assert_eq!(req.params["arguments"]["id"], json!("ACC-1"));
    }
}
