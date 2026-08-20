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

/// Where a provider declares its terms. Reserved by warden-connect.
///
/// The reserved path is what makes discovery cheap and absence meaningful. [`CLIENT_CONFIG_PATHS`]
/// below is the opposite case and shows why: those are other ecosystems' files at eight speculative
/// locations, so a scan must try all eight per repository and a miss proves nothing. This path is
/// ours, so one read answers the question, and *not* having it is a fact rather than a maybe.
pub const OFFER_PATH: &str = "warden/offer.toml";

/// Where a provider declares the surface its terms cover.
pub const SURFACE_PATH: &str = "warden/surface.json";

/// Where a consumer declares what it needs.
pub const NEEDS_PATH: &str = "warden/needs.toml";

/// Every path warden-connect reserves, for a discovery sweep to read.
pub const DECLARED_PATHS: &[&str] = &[OFFER_PATH, SURFACE_PATH, NEEDS_PATH];

/// Whether `path` is the reserved location for this kind of declaration.
///
/// Compared after trimming a leading `./`, which is what shell tab-completion produces and which
/// would otherwise make an operator's correct path look wrong.
#[must_use]
pub fn is_reserved(path: &str, reserved: &str) -> bool {
    path.trim().trim_start_matches("./") == reserved
}

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
    /// Repositories skipped because they had not been pushed to since the watermark.
    #[serde(default)]
    pub repos_skipped: usize,
    /// The highest `pushed_at` this sweep saw, to pass as `--since` next time.
    ///
    /// Taken from the listing rather than from the clock. A wall-clock watermark would skip a push
    /// that landed between the listing and the read, and skipping is the one direction a discovery
    /// cursor must never be wrong in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watermark: Option<u64>,
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

/// Repository-to-zone mapping, generated from whatever owns that truth in your estate.
///
/// # Why this is a file and not a field in a repository
///
/// A zone decides which audiences a consumer matches, so a wrong zone is a wrong answer to "may
/// this party contract that item". The mapping therefore has to come from wherever the organisation
/// already tracks which service a repository belongs to — a CMDB or an ITAM system — and not from
/// the repository itself. A repository that could assert its own zone could read itself into any
/// provider's audience, which is the same defect `match_need` avoids by taking zone from the
/// registry rather than from a manifest.
///
/// It is also why the mapping is not an ITAM id carried per repository: 4,000 teams maintaining a
/// field is 4,000 chances for it to rot, and the repository name is something you already have.
/// Generate this file from the CMDB; do not ask anyone to write it by hand.
///
/// ```toml
/// [[repo]]
/// name    = "bank/estate-recon-bot"
/// zone    = "internal.apac"
/// service = "ITAM-9902"          # optional, recorded on the entity
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneMap {
    /// One row per repository.
    #[serde(default, rename = "repo")]
    pub repos: Vec<ZoneRow>,
}

/// One repository's zone, and the service it belongs to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneRow {
    /// Full repository name, exactly as the source host reports it.
    pub name: String,
    /// The trust zone that repository's party belongs in.
    pub zone: String,
    /// The service reference, recorded on the entity for later reconciliation.
    #[serde(default)]
    pub service: Option<String>,
}

impl ZoneMap {
    /// Parse a mapping, refusing anything it does not understand.
    pub fn parse(text: &str) -> Result<ZoneMap> {
        let map: ZoneMap = toml::from_str(text).map_err(|e| {
            wc_core::error::WcError::with_detail(
                wc_core::error::Code::CONFIG_INVALID,
                format!("zone map is not the expected shape: {e}"),
            )
        })?;
        // A repository named twice with two zones is a mapping nobody can act on, and picking one
        // silently would put a party in a zone the file does not obviously say.
        let mut seen = std::collections::BTreeSet::new();
        for r in &map.repos {
            if !seen.insert(r.name.as_str()) {
                return Err(wc_core::error::WcError::with_detail(
                    wc_core::error::Code::CONFIG_INVALID,
                    format!("{} appears twice in the zone map", r.name),
                ));
            }
        }
        Ok(map)
    }

    /// The row for a repository, if it has one.
    #[must_use]
    pub fn get(&self, repo: &str) -> Option<&ZoneRow> {
        self.repos.iter().find(|r| r.name == repo)
    }
}

/// Render a sweep as one deterministically ordered file, for a repository to hold.
///
/// # Why a repository, and why one file
///
/// A sweep's output is derived, non-authoritative data — exactly the kind that is safe in git, and
/// exactly the kind git is good at. Committing it turns "what changed since the last sweep" into a
/// diff a human reads in a pull request, which is the whole reconciliation problem solved by the
/// medium instead of by code.
///
/// **One file, not one per server.** The write op is a PUT; there is no delete. Per-server files
/// would make an appearance expressible and a *disappearance* not, so the inventory could only ever
/// grow — the classic delta-sync bug. A single ordered file expresses a removal as a removed line.
///
/// Ordering is total and content-derived, never insertion-ordered: a sweep that listed the same
/// estate in a different order would produce a diff full of moves, and a diff nobody can read is a
/// diff nobody reads.
#[must_use]
pub fn render_state(inv: &Inventory, org: &str) -> String {
    let mut out = String::new();
    out.push_str("# warden-connect discovery state — generated, do not edit by hand\n#\n");
    out.push_str("# Derived data: this records what a sweep FOUND, not what anybody approved.\n");
    out.push_str(
        "# Nothing here grants anything. A row appearing is a question, not a decision.\n",
    );
    out.push_str(
        "#\n# Ordered by target so a re-sweep of an unchanged estate produces no diff.\n\n",
    );
    out.push_str(&format!("org = \"{org}\"\n"));
    out.push_str(&format!("repos_scanned = {}\n", inv.repos_scanned));
    if inv.repos_skipped > 0 {
        out.push_str(&format!("repos_skipped = {}\n", inv.repos_skipped));
    }
    if let Some(w) = inv.watermark {
        out.push_str(&format!("watermark = {w}\n"));
    }

    for (target, decls) in inv.by_server() {
        out.push_str("\n[[server]]\n");
        out.push_str(&format!("target = {}\n", toml_str(target)));
        let mut transports: Vec<&str> = decls
            .iter()
            .map(|d| d.declaration.transport.as_str())
            .collect();
        transports.sort_unstable();
        transports.dedup();
        out.push_str(&format!(
            "transport = {}\n",
            toml_str(&transports.join(","))
        ));
        // Sorted, so two sweeps of one estate agree byte for byte.
        let mut callers: Vec<&str> = decls.iter().map(|d| d.repo.as_str()).collect();
        callers.sort_unstable();
        callers.dedup();
        out.push_str("callers = [");
        for (i, c) in callers.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&toml_str(c));
        }
        out.push_str("]\n");
        // The local labels, kept because they are how a team will recognise the row — and separate
        // from `target`, because a name is a local decision and the target is the thing itself.
        let mut names: Vec<&str> = decls.iter().map(|d| d.declaration.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        out.push_str("names = [");
        for (i, n) in names.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&toml_str(n));
        }
        out.push_str("]\n");
    }
    out
}

/// A TOML basic string. Escapes what TOML requires and nothing else.
fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// What a declaration sweep found, and how much it cost to find.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Declared {
    /// Repositories carrying [`OFFER_PATH`].
    pub providers: Vec<String>,
    /// Repositories carrying [`NEEDS_PATH`].
    pub consumers: Vec<String>,
    /// Requests made against the source host.
    pub calls: usize,
    /// Whether the host's search index answered, or the sweep read every repository.
    pub via_search: bool,
    /// Repositories not re-read because they had not been pushed to since the watermark.
    pub skipped: usize,
    /// The highest `pushed_at` seen, to pass as `--since` next time.
    pub watermark: Option<u64>,
}

/// Find every repository that declares an offer or a need.
///
/// Two orders of magnitude cheaper than [`scan`], for one reason: the paths are **ours**. `scan`
/// tries eight speculative locations per repository because they belong to other ecosystems and a
/// miss proves nothing. This reads one path per kind, and a miss is a fact.
///
/// Uses the host's search index when it has one, and falls back to reading the reserved paths per
/// repository when it does not. The fallback is the correct implementation rather than a degraded
/// one: a code-search index caps its results and lags a push, and [`crate::scm::ScmShim::search_path`]
/// answers `unsupported` rather than a short list when it cannot answer completely — so a sweep
/// never under-reports because an accelerator gave up quietly.
///
/// Both searches must succeed or neither is trusted. Half a sweep from the index and half from a
/// crawl would produce a count nobody can reason about.
pub fn declared(
    shim: &crate::scm::ScmShim,
    org: &str,
    since: Option<u64>,
    mut on_repo: impl FnMut(&str, usize),
) -> Result<Declared> {
    let mut out = Declared::default();

    let offers = shim.search_path(org, OFFER_PATH)?;
    out.calls += 1;
    if let Some(providers) = offers {
        let needs = shim.search_path(org, NEEDS_PATH)?;
        out.calls += 1;
        if let Some(consumers) = needs {
            out.providers = providers;
            out.consumers = consumers;
            out.providers.sort_unstable();
            out.consumers.sort_unstable();
            out.via_search = true;
            return Ok(out);
        }
    }

    let repos = shim.repos_with_cursor(org)?;
    out.calls += 1;
    for (i, r) in repos.iter().enumerate() {
        out.watermark = out.watermark.max(r.pushed_at);
        if !r.changed_since(since) {
            out.skipped += 1;
            continue;
        }
        on_repo(&r.name, i);
        if shim.file_if_present(&r.name, "HEAD", OFFER_PATH)?.is_some() {
            out.providers.push(r.name.clone());
        }
        out.calls += 1;
        if shim.file_if_present(&r.name, "HEAD", NEEDS_PATH)?.is_some() {
            out.consumers.push(r.name.clone());
        }
        out.calls += 1;
    }
    out.providers.sort_unstable();
    out.consumers.sort_unstable();
    Ok(out)
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
    since: Option<u64>,
    mut on_repo: impl FnMut(&str, usize),
) -> Result<Inventory> {
    let repos = shim.repos_with_cursor(org)?;
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
    for (i, r) in repos.iter().enumerate() {
        // Recorded before the skip test, so the watermark advances past repositories this run did
        // not read. Otherwise a quiet repository would be re-read on every sweep forever.
        inv.watermark = inv.watermark.max(r.pushed_at);
        if !r.changed_since(since) {
            inv.repos_skipped += 1;
            continue;
        }
        let repo = &r.name;
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
    fn an_undated_repository_is_always_swept() {
        use crate::scm::RepoRef;
        let dated = |t| RepoRef {
            name: "bank/a".to_string(),
            pushed_at: Some(t),
        };
        let undated = RepoRef {
            name: "bank/b".to_string(),
            pushed_at: None,
        };
        // No watermark: everything.
        assert!(dated(100).changed_since(None));
        assert!(undated.changed_since(None));
        // With one: only what moved after it.
        assert!(dated(200).changed_since(Some(100)));
        assert!(!dated(100).changed_since(Some(100)), "equal is not after");
        assert!(!dated(50).changed_since(Some(100)));
        // And anything the host could not date. Skipping the undateable would make a sweep quietly
        // incomplete, which is the one direction a discovery cursor must never be wrong in.
        assert!(
            undated.changed_since(Some(100)),
            "an undated repo must be swept, not skipped"
        );
    }

    #[test]
    fn the_watermark_advances_past_repositories_the_sweep_skipped() {
        // Otherwise a quiet repository is re-read on every sweep forever: the watermark would only
        // ever reach the newest repo that changed, and everything older than it stays in scope.
        //
        // **This tests the rule, not `scan`'s use of it.** It replicates the ordering rather than
        // driving `scan`, which needs a live shim process — so moving the watermark update after
        // the skip test inside `scan` leaves this green. Mutation testing said so. The real path is
        // asserted in `scripts/catalogue-drill.sh`, against the built binary and a stub host.
        let mut inv = Inventory::default();
        for pushed in [500u64, 900, 4000] {
            let r = crate::scm::RepoRef {
                name: format!("bank/{pushed}"),
                pushed_at: Some(pushed),
            };
            inv.watermark = inv.watermark.max(r.pushed_at);
            if !r.changed_since(Some(1000)) {
                inv.repos_skipped += 1;
            }
        }
        assert_eq!(inv.repos_skipped, 2, "500 and 900 are behind the watermark");
        assert_eq!(
            inv.watermark,
            Some(4000),
            "the watermark must reach the newest repo seen, skipped or not"
        );
    }

    #[test]
    fn the_state_file_is_byte_identical_for_the_same_estate_in_any_order() {
        // The property the whole discovery-repo idea rests on. If a re-sweep of an unchanged estate
        // produced a different file, every run would open a pull request full of moves, and a diff
        // nobody can read is a diff nobody reads.
        let mk = |order: &[(&str, &str, &str)]| {
            let mut inv = Inventory {
                repos_scanned: 3,
                ..Inventory::default()
            };
            for (repo, name, target) in order {
                inv.findings.push(Finding {
                    declaration: Declaration {
                        name: (*name).to_string(),
                        target: (*target).to_string(),
                        transport: Transport::Stdio,
                    },
                    repo: (*repo).to_string(),
                    path: ".mcp.json".to_string(),
                });
            }
            render_state(&inv, "bank")
        };
        let a = mk(&[
            ("bank/a", "pay", "npx -y @acme/pay"),
            ("bank/c", "other", "npx -y @x/other"),
            ("bank/b", "pay2", "npx -y @acme/pay"),
        ]);
        let b = mk(&[
            ("bank/b", "pay2", "npx -y @acme/pay"),
            ("bank/a", "pay", "npx -y @acme/pay"),
            ("bank/c", "other", "npx -y @x/other"),
        ]);
        assert_eq!(a, b, "the same estate rendered two ways");
        assert!(a.contains("callers = [\"bank/a\", \"bank/b\"]"), "{a}");
        // Order-independence alone does not pin the order. Reversing it would keep two renderings
        // equal to each other and produce a whole-file diff on the first sweep after the change —
        // mutation testing showed exactly that, so the direction is asserted too.
        let acme = a.find("@acme/pay").expect("acme row");
        let other = a.find("@x/other").expect("other row");
        assert!(acme < other, "servers must be ordered by target, ascending");
    }

    #[test]
    fn a_target_containing_a_quote_cannot_break_the_state_file() {
        // Targets are command lines from somebody else's repository. An unescaped quote would make
        // the generated TOML unparseable at best, and at worst change which keys it defines.
        let mut inv = Inventory::default();
        inv.findings.push(Finding {
            declaration: Declaration {
                name: "odd".to_string(),
                target: "npx \"a\" \\ b\nc".to_string(),
                transport: Transport::Stdio,
            },
            repo: "bank/a".to_string(),
            path: ".mcp.json".to_string(),
        });
        let out = render_state(&inv, "bank");
        let parsed: toml::Value = toml::from_str(&out).expect("must still be valid TOML");
        let got = parsed["server"][0]["target"].as_str().unwrap();
        assert_eq!(got, "npx \"a\" \\ b\nc", "the target did not round-trip");
    }

    #[test]
    fn a_zone_map_refuses_a_repository_named_twice() {
        // Two zones for one repository is a mapping nobody can act on, and choosing one silently
        // would put a party in a zone the file does not obviously say.
        let ok = ZoneMap::parse(
            "[[repo]]\nname = \"bank/a\"\nzone = \"internal.apac\"\nservice = \"ITAM-1\"\n",
        )
        .unwrap();
        assert_eq!(ok.get("bank/a").unwrap().zone, "internal.apac");
        assert_eq!(ok.get("bank/a").unwrap().service.as_deref(), Some("ITAM-1"));
        assert!(ok.get("bank/nope").is_none());

        let dup = ZoneMap::parse(
            "[[repo]]\nname = \"bank/a\"\nzone = \"internal.a\"\n\n[[repo]]\nname = \"bank/a\"\nzone = \"internal.b\"\n",
        );
        assert!(dup.is_err(), "a duplicate must be refused");
    }

    #[test]
    fn a_reserved_path_is_matched_after_a_leading_dot_slash() {
        // `./warden/offer.toml` is what shell tab-completion produces, and refusing it would tell
        // an operator their correct path is wrong.
        assert!(is_reserved("warden/offer.toml", OFFER_PATH));
        assert!(is_reserved("./warden/offer.toml", OFFER_PATH));
        assert!(is_reserved("  warden/offer.toml  ", OFFER_PATH));
        assert!(!is_reserved("warden/offers.toml", OFFER_PATH));
        assert!(!is_reserved("offer.toml", OFFER_PATH));
        assert!(!is_reserved("a/warden/offer.toml", OFFER_PATH));
    }

    #[test]
    fn the_reserved_paths_are_distinct_and_none_is_a_client_config_path() {
        // A reserved path colliding with a speculative one would make the two sweeps report the
        // same file as two different kinds of declaration.
        let mut seen = std::collections::BTreeSet::new();
        for p in DECLARED_PATHS {
            assert!(seen.insert(*p), "{p} is listed twice");
            assert!(
                !CLIENT_CONFIG_PATHS.contains(p),
                "{p} is both reserved and a client-config path"
            );
        }
        assert_eq!(seen.len(), 3);
    }

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
            repos_skipped: 0,
            watermark: None,
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
            repos_skipped: 0,
            watermark: None,
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
            repos_skipped: 0,
            watermark: None,
            configs_read: 2,
        };
        assert_eq!(inv.server_count(), 2);
        assert_eq!(inv.stdio_count(), 1);
    }
}
