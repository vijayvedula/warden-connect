//! The few MCP shapes the mediation path needs.
//!
//! These were `warden::mcp`. They are ours now for the reason given in [`crate::rpc`]: a
//! deployment may run warden-connect without Warden core, and it could not while every type
//! on the path belonged to Warden.
//!
//! Deliberately small. This is not an MCP implementation — the mediator forwards frames it
//! does not interpret, and interprets only what a contract is written in terms of: which tool
//! is being called, and how to say no.

use serde_json::{json, Value};

/// The tool name and arguments from a `tools/call` request's params.
///
/// `None` when the frame is malformed. The caller must treat that as a refusal rather than a
/// pass: a `tools/call` whose name cannot be read is a call whose contract cannot be checked,
/// and the mediator answers it with `FRAME_MALFORMED`.
#[must_use]
pub fn parse_tool_call(params: &Value) -> Option<(String, Value)> {
    let name = params.get("name")?.as_str()?.to_string();
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Some((name, arguments))
}

/// A tool result carrying text, flagged as success.
#[must_use]
pub fn tool_text_result(text: impl Into<String>) -> Value {
    json!({
        "content": [{ "type": "text", "text": text.into() }],
        "isError": false
    })
}

/// A tool result flagged as an error.
///
/// This is how a refused *call* comes back, as distinct from a refused *connection*. The
/// agent sees a clean tool failure it can reason about, rather than a transport fault that
/// looks like the server is broken — which matters, because an agent that reads a policy
/// refusal as an outage will retry it.
#[must_use]
pub fn tool_error_result(text: impl Into<String>) -> Value {
    json!({
        "content": [{ "type": "text", "text": text.into() }],
        "isError": true
    })
}

/// Whether a `tools/call` result is an MCP tool error.
#[must_use]
pub fn result_is_tool_error(result: &Value) -> bool {
    result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn a_well_formed_call_yields_its_name_and_arguments() {
        let (name, args) =
            parse_tool_call(&json!({"name": "get_balance", "arguments": {"id": "ACC-1"}})).unwrap();
        assert_eq!(name, "get_balance");
        assert_eq!(args["id"], json!("ACC-1"));
    }

    #[test]
    fn absent_arguments_become_an_empty_object_not_a_refusal() {
        // A no-argument tool is a normal tool. Refusing here would break valid traffic.
        let (name, args) = parse_tool_call(&json!({"name": "ping"})).unwrap();
        assert_eq!(name, "ping");
        assert_eq!(args, json!({}));
    }

    #[test]
    fn a_name_that_is_not_a_string_is_unparseable_rather_than_coerced() {
        // `42` and `"42"` must not become the same tool name. Coercion here would let a
        // caller address a contracted tool by a value the contract does not contain.
        assert!(parse_tool_call(&json!({"name": 42})).is_none());
        assert!(parse_tool_call(&json!({"arguments": {}})).is_none());
        assert!(parse_tool_call(&Value::Null).is_none());
    }

    #[test]
    fn an_error_result_is_flagged_so_an_agent_does_not_read_a_refusal_as_an_outage() {
        let refused = tool_error_result("BLOCKED by warden-connect: WC-4001 no contract");
        assert!(result_is_tool_error(&refused));
        assert!(refused["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("WC-4001"));

        let fine = tool_text_result("42");
        assert!(!result_is_tool_error(&fine));
    }

    #[test]
    fn a_result_with_no_is_error_member_is_not_an_error() {
        // Servers omit `isError` on success. Defaulting to `true` would turn every
        // successful call into a reported failure.
        assert!(!result_is_tool_error(&json!({"content": []})));
    }
}
