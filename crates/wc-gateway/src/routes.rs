//! Which registered callee a route fronts.
//!
//! One verifier can sit in front of many upstreams, so the callee cannot be a single flag. It
//! also cannot come from the request: a caller that could name its own callee could name one it
//! holds a contract for while the traffic goes somewhere else entirely. So the callee is
//! resolved from **the route Envoy actually chose**, reported in `ProcessingRequest.attributes`,
//! against a map the operator supplies.
//!
//! # Why not the `:authority` header
//!
//! It is always present and it is the obvious key, and it is caller-controlled. Envoy routes on
//! it, but nothing stops a caller sending an authority that maps to callee A while the route
//! table sends the request to callee B — and the verifier would then check a contract for the
//! wrong service. `xds.cluster_name` and `xds.route_name` are computed by Envoy after routing,
//! which is what makes them safe to key on.
//!
//! # Hot reload
//!
//! The file is re-read when its mtime moves. A file that fails to parse or fails validation is
//! **not** installed and the previous map keeps serving: a typo during a rollout must not blank
//! the map, because an empty map denies every request and would read as an outage rather than a
//! bad edit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::Deserialize;
use wc_core::model::EntityId;

#[derive(Debug, Deserialize)]
struct File {
    #[serde(default, rename = "route")]
    routes: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    /// The Envoy cluster this rule matches, as `xds.cluster_name` reports it.
    #[serde(default)]
    cluster: Option<String>,
    /// The Envoy route name, as `xds.route_name` reports it.
    #[serde(default)]
    route: Option<String>,
    /// The registered party the route fronts.
    callee: String,
}

/// A resolved route table: cluster or route name to callee.
#[derive(Debug, Default)]
pub struct Table {
    by_cluster: BTreeMap<String, EntityId>,
    by_route: BTreeMap<String, EntityId>,
}

impl Table {
    /// Parse and validate a table.
    ///
    /// Every entry must name a callee that is a valid entity id and at least one key to match
    /// on. An entry that matches nothing is refused rather than ignored: it looks like coverage
    /// and provides none.
    pub fn parse(text: &str) -> Result<Table, String> {
        let file: File = toml::from_str(text).map_err(|e| format!("route table: {e}"))?;
        if file.routes.is_empty() {
            return Err(
                "route table has no [[route]] entries; an empty table denies every \
                        request"
                    .to_string(),
            );
        }
        let mut t = Table::default();
        for (i, e) in file.routes.iter().enumerate() {
            let callee = EntityId::new(&e.callee)
                .map_err(|err| format!("route table entry {i}: callee {:?}: {err}", e.callee))?;
            if e.cluster.is_none() && e.route.is_none() {
                return Err(format!(
                    "route table entry {i} names neither cluster nor route, so it can never \
                     match anything"
                ));
            }
            if let Some(c) = &e.cluster {
                if t.by_cluster.insert(c.clone(), callee.clone()).is_some() {
                    // Two rules for one cluster means one of them is dead, and which one is
                    // an accident of ordering. Refusing beats silently picking.
                    return Err(format!("route table: cluster {c:?} is mapped twice"));
                }
            }
            if let Some(r) = &e.route {
                if t.by_route.insert(r.clone(), callee.clone()).is_some() {
                    return Err(format!("route table: route {r:?} is mapped twice"));
                }
            }
        }
        Ok(t)
    }

    /// The callee for a cluster or route name, preferring the cluster.
    ///
    /// The cluster is the upstream that will actually be dialled; a route name can fan out to
    /// several, so where both are known the cluster is the more specific answer.
    #[must_use]
    pub fn lookup(&self, cluster: Option<&str>, route: Option<&str>) -> Option<&EntityId> {
        cluster
            .and_then(|c| self.by_cluster.get(c))
            .or_else(|| route.and_then(|r| self.by_route.get(r)))
    }

    /// How many distinct keys this table matches on.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_cluster.len() + self.by_route.len()
    }

    /// Whether the table matches on nothing.
    ///
    /// An empty table resolves no callee, so every request is refused `WC-4001`. A binding
    /// should report this at load, where it is one line, rather than per request.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A table on disk, reloaded when the file changes.
pub struct Routes {
    path: PathBuf,
    table: RwLock<Arc<Table>>,
    mtime: RwLock<Option<std::time::SystemTime>>,
}

impl Routes {
    /// Load a table, failing if it cannot be read or does not validate.
    pub fn load(path: impl AsRef<Path>) -> Result<Routes, String> {
        let path = path.as_ref().to_path_buf();
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let table = Table::parse(&text)?;
        let mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        Ok(Routes {
            path,
            table: RwLock::new(Arc::new(table)),
            mtime: RwLock::new(mtime),
        })
    }

    /// The current table.
    #[must_use]
    pub fn table(&self) -> Arc<Table> {
        Arc::clone(&self.table.read().expect("route table lock").clone())
    }

    /// Re-read the file if its mtime moved. Returns what happened, for the log.
    ///
    /// A parse or validation failure leaves the previous table in place. That is the whole point
    /// of doing the work before the swap: a half-edited file during a rollout must not become an
    /// empty table, because an empty table denies everything and reads as an outage.
    pub fn reload_if_changed(&self) -> Reload {
        let Ok(meta) = std::fs::metadata(&self.path) else {
            return Reload::Unchanged;
        };
        let now = meta.modified().ok();
        {
            let seen = self.mtime.read().expect("mtime lock");
            if *seen == now {
                return Reload::Unchanged;
            }
        }
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) => return Reload::Failed(format!("{}: {e}", self.path.display())),
        };
        match Table::parse(&text) {
            Ok(t) => {
                let n = t.len();
                *self.table.write().expect("route table lock") = Arc::new(t);
                *self.mtime.write().expect("mtime lock") = now;
                Reload::Installed(n)
            }
            // The mtime is deliberately NOT recorded on failure, so the next tick tries again
            // rather than treating a broken file as the current state.
            Err(why) => Reload::Failed(why),
        }
    }
}

/// The outcome of a reload attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Reload {
    /// The file has not moved.
    Unchanged,
    /// A new table is installed, with this many keys.
    Installed(usize),
    /// The file moved and did not validate. The previous table is still serving.
    Failed(String),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    const GOOD: &str = r#"
[[route]]
cluster = "payments-mcp"
callee = "spiffe://org/ns/tools/sa/payments-mcp"

[[route]]
route = "recon-route"
callee = "spiffe://org/ns/tools/sa/recon-mcp"
"#;

    #[test]
    fn a_cluster_and_a_route_key_both_resolve() {
        let t = Table::parse(GOOD).unwrap();
        assert_eq!(
            t.lookup(Some("payments-mcp"), None).unwrap().as_str(),
            "spiffe://org/ns/tools/sa/payments-mcp"
        );
        assert_eq!(
            t.lookup(None, Some("recon-route")).unwrap().as_str(),
            "spiffe://org/ns/tools/sa/recon-mcp"
        );
    }

    #[test]
    fn the_cluster_wins_when_both_are_known() {
        // A route name can fan out to several clusters; the cluster is the upstream that will
        // actually be dialled, so it is the more specific answer.
        let t = Table::parse(
            r#"
[[route]]
cluster = "payments-mcp"
callee = "spiffe://org/ns/tools/sa/by-cluster"

[[route]]
route = "shared"
callee = "spiffe://org/ns/tools/sa/by-route"
"#,
        )
        .unwrap();
        assert_eq!(
            t.lookup(Some("payments-mcp"), Some("shared"))
                .unwrap()
                .as_str(),
            "spiffe://org/ns/tools/sa/by-cluster"
        );
    }

    #[test]
    fn an_unmapped_route_resolves_to_nothing() {
        let t = Table::parse(GOOD).unwrap();
        assert!(t
            .lookup(Some("something-else"), Some("also-else"))
            .is_none());
        assert!(t.lookup(None, None).is_none());
    }

    #[test]
    fn an_empty_table_is_refused_at_parse() {
        // An empty table denies every request. Refusing to load it means the operator finds out
        // now rather than from a total outage.
        assert!(Table::parse("").is_err());
        assert!(Table::parse("# nothing here\n").is_err());
    }

    #[test]
    fn an_entry_matching_nothing_is_refused() {
        // Looks like coverage, provides none.
        let e = Table::parse("[[route]]\ncallee = \"spiffe://org/ns/tools/sa/x\"\n").unwrap_err();
        assert!(e.contains("neither cluster nor route"), "{e}");
    }

    #[test]
    fn a_duplicate_key_is_refused_rather_than_resolved_by_order() {
        let e = Table::parse(
            r#"
[[route]]
cluster = "c"
callee = "spiffe://org/ns/tools/sa/one"

[[route]]
cluster = "c"
callee = "spiffe://org/ns/tools/sa/two"
"#,
        )
        .unwrap_err();
        assert!(e.contains("mapped twice"), "{e}");
    }

    #[test]
    fn a_callee_that_is_not_an_entity_id_is_refused() {
        let e = Table::parse("[[route]]\ncluster = \"c\"\ncallee = \"not-an-id\"\n").unwrap_err();
        assert!(e.contains("callee"), "{e}");
    }

    #[test]
    fn a_broken_edit_does_not_replace_a_working_table() {
        // The reason validation happens before the swap. A half-saved file during a rollout must
        // not become an empty table, because an empty table denies everything.
        let dir = std::env::temp_dir().join(format!("wc-routes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("routes.toml");
        std::fs::write(&path, GOOD).unwrap();
        let r = Routes::load(&path).unwrap();
        assert_eq!(r.table().len(), 2);

        // Overwrite with something that will not parse, and force the mtime to differ.
        std::fs::write(&path, "[[route]]\nthis is not toml").unwrap();
        filetime_bump(&path);
        match r.reload_if_changed() {
            Reload::Failed(_) => {}
            other => panic!("a broken file was accepted: {other:?}"),
        }
        assert_eq!(r.table().len(), 2, "the working table was replaced");

        // And a good edit still lands.
        std::fs::write(
            &path,
            "[[route]]\ncluster = \"only\"\ncallee = \"spiffe://org/ns/tools/sa/only\"\n",
        )
        .unwrap();
        filetime_bump(&path);
        assert_eq!(r.reload_if_changed(), Reload::Installed(1));
        assert_eq!(
            r.table().lookup(Some("only"), None).unwrap().as_str(),
            "spiffe://org/ns/tools/sa/only"
        );
        assert!(r.table().lookup(Some("payments-mcp"), None).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Make the mtime observably different. Writing twice within one filesystem timestamp tick
    /// leaves mtime unchanged, and the reload would correctly decide nothing had happened —
    /// which would make the test above pass for the wrong reason.
    fn filetime_bump(path: &Path) {
        let now = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(now).unwrap();
    }

    #[test]
    fn a_missing_file_is_a_load_failure_not_an_empty_table() {
        assert!(Routes::load("/nonexistent/wc-routes.toml").is_err());
    }
}
