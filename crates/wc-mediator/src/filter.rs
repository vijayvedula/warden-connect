//! Catalogue filtering (`docs/08-lld.md` §8.6.4).
//!
//! This is the highest-leverage control in the product. An agent's model can only
//! be induced to call a tool it can see, so reducing the catalogue to the
//! contracted surface makes prompt injection against an uncontracted tool
//! **structurally impossible** rather than improbable. Everything else in
//! warden-connect exists to make this filter trustworthy.
//!
//! Every rule below exists because its absence is a bypass.

use std::collections::BTreeSet;

use serde_json::Value;

/// Which list a response carries, and therefore which part of the contracted
/// surface filters it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Catalog {
    /// `tools/list` — filtered by contracted tool names.
    Tools,
    /// `resources/list` — filtered by contracted resource patterns.
    Resources,
    /// `prompts/list` — filtered by contracted prompt names.
    ///
    /// Prompts are an injection vector too: leaving them unfiltered would
    /// reintroduce exactly the exposure tool filtering removes.
    Prompts,
}

impl Catalog {
    /// The method name this catalogue answers.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Catalog::Tools => "tools/list",
            Catalog::Resources => "resources/list",
            Catalog::Prompts => "prompts/list",
        }
    }

    /// The JSON member holding the array.
    #[must_use]
    pub const fn member(self) -> &'static str {
        match self {
            Catalog::Tools => "tools",
            Catalog::Resources => "resources",
            Catalog::Prompts => "prompts",
        }
    }

    /// The field naming each entry.
    #[must_use]
    pub const fn key_field(self) -> &'static str {
        match self {
            // A resource is named by its URI, not by a display name.
            Catalog::Resources => "uri",
            _ => "name",
        }
    }

    /// Resolve a method name to a catalogue, if it is one.
    #[must_use]
    pub fn from_method(method: &str) -> Option<Catalog> {
        match method {
            "tools/list" => Some(Catalog::Tools),
            "resources/list" => Some(Catalog::Resources),
            "prompts/list" => Some(Catalog::Prompts),
            _ => None,
        }
    }
}

/// What filtering did, for the per-connection record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterStat {
    /// Entries the agent may see.
    pub exposed: usize,
    /// Entries removed.
    pub hidden: usize,
    /// Names removed, for the evidence record — an operator wants to know the
    /// catalogue went from 23 tools to 2, and which 21 went.
    pub hidden_names: Vec<String>,
    /// True when the response could not be understood and was replaced with an
    /// empty list.
    pub failed_closed: bool,
    /// True when pagination was truncated rather than followed.
    pub truncated: bool,
}

/// Reduce a catalogue response to the contracted surface, in place.
///
/// Fails closed: a response this function cannot understand becomes an **empty**
/// list, never a pass-through. An unfilterable catalogue is an empty catalogue.
pub fn filter_catalog(
    catalog: Catalog,
    permitted: &BTreeSet<String>,
    resp: &mut Value,
) -> FilterStat {
    let mut stat = FilterStat::default();

    // The result must be an object; anything else and we cannot locate the list.
    let Some(result) = resp.get_mut("result").and_then(Value::as_object_mut) else {
        *resp = empty_result(resp, catalog);
        stat.failed_closed = true;
        return stat;
    };

    // A `nextCursor` means the upstream has more entries. We do not hand the
    // cursor on: the agent would page around the filter by talking to the
    // upstream cursor directly. Callers that need full coverage drain pages
    // themselves before filtering (see `Gate::drain_catalog`).
    if result.remove("nextCursor").is_some() {
        stat.truncated = true;
    }

    let Some(entries) = result
        .get_mut(catalog.member())
        .and_then(Value::as_array_mut)
    else {
        *resp = empty_result(resp, catalog);
        stat.failed_closed = true;
        return stat;
    };

    // `retain` rather than building a kept list: the previous version cloned every
    // *permitted* entry, and a tool entry is a nested object, so filtering a
    // 256-tool catalogue meant a deep clone per surviving tool. That put this at a
    // p99 of ~190 µs against §8.10.3's 50 µs ceiling. Retaining moves the `Value`
    // enum — 128 memmoves of a tagged union instead of 128 deep copies of the heap
    // behind it. Found by the gate that measures this, the first time it ran.
    let mut hidden = 0usize;
    let mut hidden_names: Vec<String> = Vec::new();
    entries.retain(|entry| {
        // An entry we cannot name is dropped, not passed. A malformed entry is
        // exactly what an upstream would send to smuggle a tool past a filter
        // keyed on names.
        let Some(name) = entry
            .get(catalog.key_field())
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty())
        else {
            hidden += 1;
            hidden_names.push("<unnamed>".to_string());
            return false;
        };

        if permitted.contains(name) {
            true
        } else {
            hidden += 1;
            hidden_names.push(name.to_string());
            false
        }
    });

    stat.hidden = hidden;
    stat.hidden_names = hidden_names;
    stat.exposed = entries.len();
    stat
}

/// An empty catalogue response with the same id as the original.
fn empty_result(original: &Value, catalog: Catalog) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("jsonrpc".to_string(), Value::from("2.0"));
    if let Some(id) = original.get("id") {
        out.insert("id".to_string(), id.clone());
    }
    let mut result = serde_json::Map::new();
    result.insert(catalog.member().to_string(), Value::Array(Vec::new()));
    out.insert("result".to_string(), Value::Object(result));
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use serde_json::json;

    fn permitted(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    fn tools_response(names: &[&str]) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": names.iter().map(|n| json!({
                    "name": n,
                    "description": format!("The {n} tool."),
                    "inputSchema": {"type": "object"}
                })).collect::<Vec<_>>()
            }
        })
    }

    fn visible(resp: &Value) -> Vec<String> {
        resp["result"]["tools"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|t| t["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn only_contracted_tools_survive() {
        let mut resp = tools_response(&["get_balance", "list_transactions", "wire_funds"]);
        let stat = filter_catalog(
            Catalog::Tools,
            &permitted(&["get_balance", "list_transactions"]),
            &mut resp,
        );

        assert_eq!(
            visible(&resp),
            vec!["get_balance".to_string(), "list_transactions".to_string()]
        );
        assert_eq!(stat.exposed, 2);
        assert_eq!(stat.hidden, 1);
        assert_eq!(stat.hidden_names, vec!["wire_funds".to_string()]);
        assert!(!stat.failed_closed);
    }

    #[test]
    fn the_uncontracted_tool_never_enters_the_response() {
        // The property the whole product rests on: an injected instruction cannot
        // name a tool the model was never shown.
        let mut resp = tools_response(&["get_balance", "wire_funds", "exfiltrate"]);
        filter_catalog(Catalog::Tools, &permitted(&["get_balance"]), &mut resp);
        let rendered = resp.to_string();
        assert!(!rendered.contains("wire_funds"));
        assert!(!rendered.contains("exfiltrate"));
    }

    #[test]
    fn an_empty_contract_exposes_nothing() {
        let mut resp = tools_response(&["get_balance"]);
        let stat = filter_catalog(Catalog::Tools, &permitted(&[]), &mut resp);
        assert!(visible(&resp).is_empty());
        assert_eq!(stat.exposed, 0);
    }

    #[test]
    fn a_contracted_tool_the_server_stopped_offering_is_simply_absent() {
        let mut resp = tools_response(&["get_balance"]);
        let stat = filter_catalog(
            Catalog::Tools,
            &permitted(&["get_balance", "list_transactions"]),
            &mut resp,
        );
        assert_eq!(visible(&resp), vec!["get_balance".to_string()]);
        assert_eq!(stat.exposed, 1);
        assert_eq!(stat.hidden, 0);
    }

    // --- failing closed ---

    #[test]
    fn a_response_with_no_result_becomes_an_empty_list() {
        let mut resp = json!({"jsonrpc": "2.0", "id": 7, "error": {"code": -1, "message": "nope"}});
        let stat = filter_catalog(Catalog::Tools, &permitted(&["get_balance"]), &mut resp);
        assert!(stat.failed_closed);
        assert!(visible(&resp).is_empty());
        assert_eq!(
            resp["id"], 7,
            "the id must survive so the agent can correlate"
        );
    }

    #[test]
    fn a_result_with_no_tools_array_becomes_an_empty_list() {
        let mut resp = json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": "not an array"}});
        let stat = filter_catalog(Catalog::Tools, &permitted(&["get_balance"]), &mut resp);
        assert!(stat.failed_closed);
        assert!(visible(&resp).is_empty());
    }

    #[test]
    fn unnamed_entries_are_dropped_not_passed() {
        // A nameless entry cannot be matched against the contract, so passing it
        // would be a hole exactly the shape of the filter.
        let mut resp = json!({
            "jsonrpc": "2.0", "id": 2,
            "result": {"tools": [
                {"name": "get_balance"},
                {"description": "no name at all"},
                {"name": ""},
                {"name": 42},
                "not even an object"
            ]}
        });
        let stat = filter_catalog(Catalog::Tools, &permitted(&["get_balance"]), &mut resp);
        assert_eq!(visible(&resp), vec!["get_balance".to_string()]);
        assert_eq!(stat.hidden, 4);
    }

    #[test]
    fn pagination_is_not_handed_to_the_agent() {
        // Passing `nextCursor` on would let the agent page around the filter.
        let mut resp = json!({
            "jsonrpc": "2.0", "id": 2,
            "result": {"tools": [{"name": "get_balance"}], "nextCursor": "abc123"}
        });
        let stat = filter_catalog(Catalog::Tools, &permitted(&["get_balance"]), &mut resp);
        assert!(stat.truncated);
        assert!(resp["result"].get("nextCursor").is_none());
    }

    // --- other catalogues ---

    #[test]
    fn resources_filter_on_uri() {
        let mut resp = json!({
            "jsonrpc": "2.0", "id": 3,
            "result": {"resources": [
                {"uri": "ledger://apac/2026", "name": "APAC ledger"},
                {"uri": "ledger://emea/2026", "name": "EMEA ledger"}
            ]}
        });
        let stat = filter_catalog(
            Catalog::Resources,
            &permitted(&["ledger://apac/2026"]),
            &mut resp,
        );
        assert_eq!(stat.exposed, 1);
        assert_eq!(resp["result"]["resources"][0]["uri"], "ledger://apac/2026");
    }

    #[test]
    fn prompts_are_filtered_too() {
        let mut resp = json!({
            "jsonrpc": "2.0", "id": 4,
            "result": {"prompts": [{"name": "summarise"}, {"name": "exfiltrate"}]}
        });
        let stat = filter_catalog(Catalog::Prompts, &permitted(&["summarise"]), &mut resp);
        assert_eq!(stat.exposed, 1);
        assert_eq!(stat.hidden_names, vec!["exfiltrate".to_string()]);
    }

    #[test]
    fn catalogues_map_to_their_methods() {
        for (method, catalog) in [
            ("tools/list", Catalog::Tools),
            ("resources/list", Catalog::Resources),
            ("prompts/list", Catalog::Prompts),
        ] {
            assert_eq!(Catalog::from_method(method), Some(catalog));
            assert_eq!(catalog.method(), method);
        }
        assert_eq!(Catalog::from_method("tools/call"), None);
        assert_eq!(Catalog::from_method("initialize"), None);
    }

    #[test]
    fn the_subset_property_holds_for_arbitrary_catalogues() {
        // ∀ response, ∀ contract: visible ⊆ contracted (§8.6.4).
        let contracts: Vec<BTreeSet<String>> = vec![
            permitted(&[]),
            permitted(&["a"]),
            permitted(&["a", "c"]),
            permitted(&["z"]),
        ];
        let catalogues: Vec<Vec<&str>> = vec![
            vec![],
            vec!["a"],
            vec!["a", "b", "c"],
            vec!["b", "b", "a"],
            vec!["x", "y", "z"],
        ];
        for contract in &contracts {
            for names in &catalogues {
                let mut resp = tools_response(names);
                filter_catalog(Catalog::Tools, contract, &mut resp);
                for seen in visible(&resp) {
                    assert!(
                        contract.contains(&seen),
                        "{seen} escaped a contract of {contract:?}"
                    );
                }
            }
        }
    }
}
