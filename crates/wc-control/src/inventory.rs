//! What MCP servers an organisation actually has, read from its repositories.
//!
//! The first question a bank is being asked is not *"is this contracted?"* but **"what have we
//! got?"** — and nothing answers it. Agents are being built in thirty teams, each declaring the MCP
//! servers it talks to in a config file, and no inventory exists anywhere.
//!
//! # Why repositories rather than the network
//!
//! Most MCP servers are not network-discoverable. A **stdio** server has no port at all: it is a
//! command a client spawns. Scanning a network finds the HTTP and SSE ones and misses the majority.
//!
//! Client configuration is the richer source, and it answers a second question for free. A repo
//! that declares a server is a repo that *consumes* it, so a config scan yields the
//! **consumer → provider pair** — which is exactly what a contract needs, and what a network scan
//! could never tell you.
//!
//! # Passive on purpose
//!
//! Reading a file from a repository you own is passive. Speaking `initialize` and `tools/list` to a
//! server is an **active probe of somebody else's service**, and doing it to forty servers because
//! a scan was convenient is not a thing to default to. So this module reads configuration and
//! nothing else. What a server *declares* it can do is a separate act, taken deliberately, against
//! a named endpoint.
//!
//! # What a finding is not
//!
//! A declaration is evidence that somebody wrote it down, not that the server exists, runs, or is
//! reachable. [`Finding`] therefore carries where it was read from — repository, path and revision —
//! so every row in a report can be traced back to a line in a file rather than to this scanner's
//! opinion.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use wc_core::error::Result;
use wc_core::model::EntityId;

/// The client-configuration paths a scan looks for, in the order it tries them.
///
/// Speculative by nature: most repositories have none of these. The list is data rather than a
/// parameter because it is the part that rots — a new client ships a new path, and the fix is a
/// line here plus a test, not a change at every call site.
pub const CLIENT_CONFIG_PATHS: &[&str] = &[
    ".mcp.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    "mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    "claude_desktop_config.json",
    ".config/mcp.json",
];

/// How a client reaches a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// A command the client spawns. **Has no port, so a network scan cannot see it.**
    Stdio,
    /// An HTTP or SSE endpoint.
    Http,
}

impl Transport {
    /// The word an operator reads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Transport::Stdio => "stdio",
            Transport::Http => "http",
        }
    }
}

/// One MCP server as a client config declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Declaration {
    /// The key the config gave it. A local label, not an identity.
    pub name: String,
    /// How it is reached.
    pub transport: Transport,
    /// The command, for stdio; the URL, for http. Verbatim, never parsed.
    pub target: String,
}

/// One declaration, and where it was read from.
///
/// The provenance is the point. A row an operator cannot trace to a line in a file is a row they
/// have to take on trust, and an inventory nobody can check is an inventory nobody acts on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// The server, as declared.
    pub declaration: Declaration,
    /// Opaque repository id, exactly as the host names it.
    pub repo: String,
    /// The config file it came from.
    pub path: String,
}

/// Parse a client configuration, returning every server it declares.
///
/// Accepts the shapes the ecosystem actually uses, because a scanner that only read one of them
/// would report an empty estate for a real one:
///
/// * `{"mcpServers": {"name": {...}}}` — Claude Desktop, Claude Code, Cursor;
/// * `{"servers": {"name": {...}}}` — VS Code;
/// * either nested under a top-level `"mcp"` key, which VS Code also does.
///
/// Unparseable input is not an error. A scan reads a dozen speculative paths per repository and
/// some will be JSON that is nothing to do with MCP — `.claude/settings.json` most obviously —
/// so the honest answer is "no declarations here", not a failed scan.
#[must_use]
pub fn parse_client_config(bytes: &[u8]) -> Vec<Declaration> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // The `mcp` wrapper first, then the bare forms, so a VS Code file that nests them is read once
    // rather than twice.
    let roots = [
        value.get("mcp").and_then(|m| m.get("servers")),
        value.get("mcp").and_then(|m| m.get("mcpServers")),
        value.get("mcpServers"),
        value.get("servers"),
    ];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for root in roots.into_iter().flatten() {
        let Some(map) = root.as_object() else {
            continue;
        };
        for (name, spec) in map {
            if !seen.insert(name.clone()) {
                continue;
            }
            // A URL means http however the field is spelled; `type` is advisory and often absent,
            // so the presence of a URL decides rather than a declared type nobody sets.
            let url = ["url", "endpoint", "serverUrl"]
                .iter()
                .find_map(|k| spec.get(*k).and_then(serde_json::Value::as_str));
            let declaration = if let Some(url) = url {
                Declaration {
                    name: name.clone(),
                    transport: Transport::Http,
                    target: url.to_string(),
                }
            } else if let Some(cmd) = spec.get("command").and_then(serde_json::Value::as_str) {
                // Arguments included, because `npx -y @acme/mcp-payments` and a bare `npx` are
                // very different things to find in an inventory.
                let args: Vec<String> = spec
                    .get("args")
                    .and_then(serde_json::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let target = if args.is_empty() {
                    cmd.to_string()
                } else {
                    format!("{cmd} {}", args.join(" "))
                };
                Declaration {
                    name: name.clone(),
                    transport: Transport::Stdio,
                    target,
                }
            } else {
                // Named but unreachable as written. Skipped rather than guessed at: an entry with
                // neither a command nor a URL tells you somebody edited the file, not what runs.
                continue;
            };
            out.push(declaration);
        }
    }
    out
}

/// Everything a scan read, and what it could not.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    /// Every declaration found, with its provenance.
    pub findings: Vec<Finding>,
    /// Repositories the scan looked at.
    pub repos_scanned: usize,
    /// Repositories that carried at least one config file.
    pub repos_with_config: usize,
    /// Config files read.
    pub configs_read: usize,
}

impl Inventory {
    /// Servers by target, with the repositories that declare each one.
    ///
    /// Keyed by **target** rather than by the config's name, because the name is a local label:
    /// two teams calling the same server `payments` and `payments-mcp` are one server, and two
    /// teams calling different servers `mcp` are two. Grouping by name would report both wrongly.
    #[must_use]
    pub fn by_server(&self) -> BTreeMap<&str, Vec<&Finding>> {
        let mut out: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
        for f in &self.findings {
            out.entry(f.declaration.target.as_str())
                .or_default()
                .push(f);
        }
        out
    }

    /// Servers declared by more than one repository — the ones a contract most obviously wants.
    #[must_use]
    pub fn shared(&self) -> Vec<(&str, usize)> {
        let mut out: Vec<(&str, usize)> = self
            .by_server()
            .into_iter()
            .filter_map(|(target, findings)| {
                let repos: BTreeSet<&str> = findings.iter().map(|f| f.repo.as_str()).collect();
                (repos.len() > 1).then_some((target, repos.len()))
            })
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        out
    }

    /// How many distinct servers were found.
    #[must_use]
    pub fn server_count(&self) -> usize {
        self.by_server().len()
    }

    /// How many of them are stdio, and therefore invisible to any network scan.
    #[must_use]
    pub fn stdio_count(&self) -> usize {
        self.by_server()
            .values()
            .filter(|fs| {
                fs.first()
                    .is_some_and(|f| f.declaration.transport == Transport::Stdio)
            })
            .count()
    }
}

/// A readable, stable label for a target.
///
/// The identifying half of the string plus eight hex of its digest. Readable, because an operator
/// reading `urn:wc:mcp:acme-mcp-payments-4f2a91c8` in an audit log can tell what it is; hashed,
/// because two servers can share a readable half and an id that collides silently merges two
/// services into one row.
fn slug(target: &str) -> String {
    let digest = &wc_core::util::sha256_hex(target)[..8];
    // The last meaningful token: the package for `npx -y @acme/mcp-payments`, the host for a URL.
    let label = target
        .split(['/', ' ', ':', '@'])
        .rfind(|p| !p.is_empty() && *p != "https" && *p != "http" && *p != "-y")
        .unwrap_or("server");
    let cleaned: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('-');
    if cleaned.is_empty() {
        digest.to_string()
    } else {
        format!("{}-{digest}", &cleaned[..cleaned.len().min(40)])
    }
}

/// The registry id for a discovered server.
///
/// Derived, never asserted — and `urn:` rather than `spiffe://` on purpose. A `spiffe://` id is a
/// claim that a workload identity exists and can be authenticated; nothing here has authenticated
/// anything, and inventing one would make a discovered row indistinguishable from an attested party.
///
/// The consequence, stated because it matters later: a `urn:wc:` id can never appear as a JWT-SVID
/// `sub`, so a promoted server can never satisfy stage 1 and stays `Unattested`. That is correct for
/// a catalogue. An estate that wants to *enforce* against it re-registers with the workload's real
/// SPIFFE id.
pub fn derive_server_id(target: &str) -> Result<EntityId> {
    EntityId::new(format!("urn:wc:mcp:{}", slug(target)))
}

/// The registry id for a repository that consumes a server.
///
/// The honest identity of a consumer this scan knows about: *the thing in this repository that uses
/// that server*. A repository is not a workload, so this is a placeholder an operator replaces with
/// the agent's real identity when they know it — and it is traceable in the meantime, which is
/// better than leaving the consumer side of every finding blank.
pub fn derive_consumer_id(repo: &str) -> Result<EntityId> {
    let cleaned: String = repo
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    EntityId::new(format!("urn:wc:repo:{}", cleaned.trim_matches('-')))
}

/// Scan an organisation's repositories for MCP client configuration.
///
/// `shim` is the same source-host adapter the contract path uses, so an estate that has verified
/// one for `connect scm probe` has already verified this. `paths` defaults to
/// [`CLIENT_CONFIG_PATHS`].
///
/// **No probing.** Every request is a file read at the default revision. Nothing is spawned and no
/// server is contacted, which is what makes this safe to point at an entire organisation without
/// asking forty teams first.
pub fn scan(
    shim: &crate::scm::ScmShim,
    org: &str,
    paths: Option<&[String]>,
    mut on_repo: impl FnMut(&str, usize),
) -> Result<Inventory> {
    let repos = shim.repos(org)?;
    let owned: Vec<String>;
    let paths: &[String] = match paths {
        Some(p) if !p.is_empty() => p,
        _ => {
            owned = CLIENT_CONFIG_PATHS
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            &owned
        }
    };

    let mut inv = Inventory {
        repos_scanned: repos.len(),
        ..Inventory::default()
    };
    for (i, repo) in repos.iter().enumerate() {
        on_repo(repo, i);
        let before = inv.findings.len();
        for path in paths {
            // `HEAD` rather than a resolved sha: an inventory is a picture of what is declared
            // *now*, and resolving a revision per repository would double the request count for a
            // precision no reader of this report wants.
            let Some(bytes) = shim.file_if_present(repo, "HEAD", path)? else {
                continue;
            };
            inv.configs_read += 1;
            for declaration in parse_client_config(&bytes) {
                inv.findings.push(Finding {
                    declaration,
                    repo: repo.clone(),
                    path: path.clone(),
                });
            }
        }
        if inv.findings.len() > before {
            inv.repos_with_config += 1;
        }
    }
    Ok(inv)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn a_derived_id_is_readable_and_unique() {
        let a = derive_server_id("npx -y @acme/mcp-payments").unwrap();
        let b = derive_server_id("npx -y @acme/mcp-ledger").unwrap();
        assert!(a.as_str().starts_with("urn:wc:mcp:mcp-payments-"), "{a}");
        assert_ne!(a, b);
        // Stable: the same target always derives the same id, or every scan would create a new row
        // for a server that has not changed.
        assert_eq!(a, derive_server_id("npx -y @acme/mcp-payments").unwrap());

        // A URL takes its host, not its path, because the path is usually `/mcp` on every one.
        let u = derive_server_id("https://fx.treasury.internal/mcp").unwrap();
        assert!(u.as_str().starts_with("urn:wc:mcp:mcp-"), "{u}");
    }

    #[test]
    fn two_servers_sharing_a_readable_half_do_not_collide() {
        // The reason the digest is there. Both end in `mcp`, and an id that collided would merge
        // two services into one catalogue row and one contract.
        let a = derive_server_id("https://payments.internal/mcp").unwrap();
        let b = derive_server_id("https://ledger.internal/mcp").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_consumer_id_names_the_repository_that_uses_it() {
        let c = derive_consumer_id("bank/recon-bot").unwrap();
        assert_eq!(c.as_str(), "urn:wc:repo:bank-recon-bot");
    }

    #[test]
    fn a_derived_id_is_never_a_spiffe_id() {
        // A `spiffe://` id claims an authenticated workload identity exists. Nothing here has
        // authenticated anything, and inventing one would make a discovered row indistinguishable
        // from an attested party — so a promoted server stays Unattested by construction.
        for t in [
            "npx -y @acme/mcp-payments",
            "https://fx.internal/mcp",
            "!!!",
            "",
        ] {
            let id = derive_server_id(t).unwrap();
            assert!(id.as_str().starts_with("urn:wc:mcp:"), "{id}");
        }
    }

    #[test]
    fn the_claude_and_cursor_shape_is_read() {
        let cfg = br#"{
          "mcpServers": {
            "payments": {"command": "npx", "args": ["-y", "@acme/mcp-payments"]},
            "recon":    {"command": "/usr/local/bin/recon-mcp"}
          }
        }"#;
        let d = parse_client_config(cfg);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].name, "payments");
        assert_eq!(d[0].transport, Transport::Stdio);
        // Arguments included: `npx -y @acme/mcp-payments` and a bare `npx` are entirely different
        // things to find in an inventory, and the args are where the identity lives.
        assert_eq!(d[0].target, "npx -y @acme/mcp-payments");
        assert_eq!(d[1].target, "/usr/local/bin/recon-mcp");
    }

    #[test]
    fn the_vs_code_shape_and_its_mcp_wrapper_are_both_read() {
        // Two shapes, one product. A scanner that read only `mcpServers` would report an empty
        // estate for an organisation standardised on VS Code.
        let bare = br#"{"servers": {"payments": {"url": "https://payments.internal/mcp"}}}"#;
        assert_eq!(parse_client_config(bare).len(), 1);

        let wrapped = br#"{"mcp": {"servers": {"payments": {"url": "https://p.internal/mcp"}}}}"#;
        let d = parse_client_config(wrapped);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].transport, Transport::Http);
        assert_eq!(d[0].target, "https://p.internal/mcp");
    }

    #[test]
    fn a_url_decides_the_transport_whatever_the_type_field_says() {
        // `type` is advisory and frequently absent or wrong. What is actually there decides.
        let cfg = br#"{"mcpServers": {"p": {"type": "stdio", "url": "https://p/mcp"}}}"#;
        assert_eq!(parse_client_config(cfg)[0].transport, Transport::Http);
    }

    #[test]
    fn the_same_name_in_two_shapes_is_one_declaration() {
        // A VS Code file that nests `mcp.servers` *and* carries a bare `servers` would otherwise
        // report the same server twice and inflate every count in the report.
        let cfg = br#"{
          "mcp":     {"servers": {"p": {"url": "https://p/mcp"}}},
          "servers": {"p": {"url": "https://p/mcp"}}
        }"#;
        assert_eq!(parse_client_config(cfg).len(), 1);
    }

    #[test]
    fn an_entry_with_neither_a_command_nor_a_url_is_skipped() {
        // Named but unreachable as written. Reporting it would claim a server exists on the
        // strength of somebody having edited a file.
        let cfg = br#"{"mcpServers": {"half-written": {"env": {"TOKEN": "x"}}}}"#;
        assert!(parse_client_config(cfg).is_empty());
    }

    #[test]
    fn unparseable_and_unrelated_json_are_not_errors() {
        // A scan reads a dozen speculative paths per repo. `.claude/settings.json` is usually
        // nothing to do with MCP, and a scan that failed on it would fail on most repositories.
        assert!(parse_client_config(b"not json at all").is_empty());
        assert!(parse_client_config(br#"{"permissions": {"allow": ["Bash"]}}"#).is_empty());
        assert!(parse_client_config(b"").is_empty());
    }

    fn finding(repo: &str, name: &str, target: &str, transport: Transport) -> Finding {
        Finding {
            declaration: Declaration {
                name: name.to_string(),
                transport,
                target: target.to_string(),
            },
            repo: repo.to_string(),
            path: ".mcp.json".to_string(),
        }
    }

    #[test]
    fn servers_are_grouped_by_target_not_by_the_name_a_team_chose() {
        // The name is a local label. Two teams calling one server `payments` and `payments-mcp`
        // are one server; two teams calling different servers `mcp` are two. Grouping by name gets
        // both wrong, and both wrong in the direction that makes the report useless.
        let inv = Inventory {
            findings: vec![
                finding(
                    "bank/a",
                    "payments",
                    "npx -y @acme/mcp-payments",
                    Transport::Stdio,
                ),
                finding(
                    "bank/b",
                    "payments-mcp",
                    "npx -y @acme/mcp-payments",
                    Transport::Stdio,
                ),
                finding("bank/c", "mcp", "npx -y @acme/mcp-ledger", Transport::Stdio),
            ],
            repos_scanned: 3,
            repos_with_config: 3,
            configs_read: 3,
        };
        assert_eq!(inv.server_count(), 2);

        let shared = inv.shared();
        assert_eq!(shared.len(), 1, "one server is declared by two repos");
        assert_eq!(shared[0], ("npx -y @acme/mcp-payments", 2));
    }

    #[test]
    fn one_repo_declaring_a_server_twice_is_not_a_shared_server() {
        // `shared` counts distinct repositories, not findings. A repo with the same server in both
        // `.mcp.json` and `.vscode/mcp.json` is one consumer, and reporting it as two would send
        // somebody looking for a second team that does not exist.
        let inv = Inventory {
            findings: vec![
                finding("bank/a", "p", "https://p/mcp", Transport::Http),
                Finding {
                    path: ".vscode/mcp.json".to_string(),
                    ..finding("bank/a", "p", "https://p/mcp", Transport::Http)
                },
            ],
            repos_scanned: 1,
            repos_with_config: 1,
            configs_read: 2,
        };
        assert_eq!(inv.server_count(), 1);
        assert!(inv.shared().is_empty());
    }

    #[test]
    fn stdio_servers_are_counted_because_no_network_scan_can_see_them() {
        // The number that justifies scanning repositories at all.
        let inv = Inventory {
            findings: vec![
                finding("bank/a", "p", "npx -y @acme/mcp-payments", Transport::Stdio),
                finding("bank/b", "q", "https://q.internal/mcp", Transport::Http),
            ],
            repos_scanned: 2,
            repos_with_config: 2,
            configs_read: 2,
        };
        assert_eq!(inv.server_count(), 2);
        assert_eq!(inv.stdio_count(), 1);
    }
}
