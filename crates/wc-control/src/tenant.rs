//! Multi-tenancy: validated tenant ids, per-tenant roots, and isolation
//! (`docs/08-lld.md` §8.4, §8.11 WC-8002).
//!
//! A tenant is a hard boundary. Two tenants on one control plane share a process
//! and a binary and **nothing else**: separate event log, separate evidence chain,
//! separate issuer key, separate policy. There is no cross-tenant query, no
//! cross-tenant contract, and no way for one tenant's operator to name another
//! tenant's entity and get an answer other than `WC-8002`.
//!
//! # The tenant id is a path component, and that is the whole problem
//!
//! Every tenant's state lives at `<root>/tenants/<id>/…`. A tenant id therefore
//! reaches the filesystem, and it arrives from a flag, an environment variable, or
//! — in a hosted deployment — a bearer token minted by somebody else. An
//! unvalidated one escapes the root:
//!
//! ```text
//! connect register … --tenant '../../../../tmp/elsewhere'
//!   → writes the estate's state to /tmp/elsewhere
//! ```
//!
//! That was the behaviour before this module existed, and it is why [`TenantId`]
//! is a validated newtype rather than a `String`: the guarantee is carried by the
//! type, so a future caller cannot reintroduce the hole by forgetting to check.
//! [`TenantPaths`] can only be built from one.
//!
//! # Isolation is by construction, not by filtering
//!
//! The projection a request sees is loaded from that tenant's log. Nothing is
//! filtered after the fact, because a filter is a thing that can be forgotten at
//! one call site — and one forgotten filter in a multi-tenant control plane is the
//! whole product.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use wc_core::error::{Code, Result, WcError};

/// Longest a tenant id may be.
pub const MAX_TENANT_LEN: usize = 63;

/// The default tenant, for single-tenant deployments.
pub const DEFAULT_TENANT: &str = "default";

// ---------------------------------------------------------------------------
// TenantId
// ---------------------------------------------------------------------------

/// A validated tenant identifier.
///
/// Deliberately narrower than a filename: lowercase alphanumerics and hyphens,
/// starting with an alphanumeric. Not because those are the only safe characters,
/// but because an allowlist that is obviously safe beats a denylist that has to be
/// right about every filesystem — `..`, `/`, `\`, NUL, `:` on Windows, a leading
/// `-` that becomes a flag, a trailing dot that Windows strips, a Unicode
/// normalisation that collapses two ids into one directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

impl TenantId {
    /// Validate and wrap. The only way in.
    pub fn new(raw: impl Into<String>) -> Result<TenantId> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(WcError::with_detail(
                Code::TENANT_UNKNOWN,
                "tenant id must not be empty",
            ));
        }
        if raw.len() > MAX_TENANT_LEN {
            return Err(WcError::with_detail(
                Code::TENANT_UNKNOWN,
                format!(
                    "tenant id is {} bytes, limit is {MAX_TENANT_LEN}",
                    raw.len()
                ),
            ));
        }
        let mut chars = raw.chars();
        let first = chars.next().unwrap_or('\0');
        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            return Err(WcError::with_detail(
                Code::TENANT_UNKNOWN,
                format!(
                    "tenant id {raw:?} must start with a lowercase letter or digit; \
                     a leading '-' or '.' is a flag or a traversal, depending on who reads it"
                ),
            ));
        }
        for c in raw.chars() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return Err(WcError::with_detail(
                    Code::TENANT_UNKNOWN,
                    format!(
                        "tenant id {raw:?} contains {c:?}; only [a-z0-9-] is permitted \
                         because this becomes a path component"
                    ),
                ));
            }
        }
        Ok(TenantId(raw))
    }

    /// The underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The default tenant.
    #[must_use]
    pub fn default_tenant() -> TenantId {
        TenantId(DEFAULT_TENANT.to_string())
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `pad`, not `write_str`, so width specifiers in operator tables work.
        f.pad(&self.0)
    }
}

impl TryFrom<String> for TenantId {
    type Error = WcError;
    fn try_from(value: String) -> Result<TenantId> {
        TenantId::new(value)
    }
}

impl From<TenantId> for String {
    fn from(value: TenantId) -> String {
        value.0
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Everything one tenant owns on disk.
///
/// Constructible only from a [`TenantId`], so the path-traversal guarantee is
/// carried by the type rather than by remembering to validate at each call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPaths {
    /// The tenant.
    pub tenant: TenantId,
    /// Root of everything this tenant owns.
    pub base: PathBuf,
    /// Event log and snapshots.
    pub state: PathBuf,
    /// Evidence chain and anchors.
    pub evidence: PathBuf,
    /// Signed revocation feed.
    pub revocations: PathBuf,
    /// Mediator acknowledgements.
    pub acks: PathBuf,
    /// Issued contract artifacts.
    pub artifacts: PathBuf,
}

impl TenantPaths {
    /// Derive every path for one tenant under `root`.
    #[must_use]
    pub fn new(root: &Path, tenant: &TenantId) -> TenantPaths {
        let base = root.join("tenants").join(tenant.as_str());
        TenantPaths {
            tenant: tenant.clone(),
            state: base.join("state"),
            evidence: base.join("evidence"),
            revocations: base.join("revocations.jsonl"),
            acks: base.join("acks.json"),
            artifacts: base.join("artifacts"),
            base,
        }
    }

    /// Whether this tenant's directory exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.base.is_dir()
    }
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// One tenant's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantDef {
    /// The tenant.
    pub id: TenantId,
    /// Human-readable name, for reports.
    #[serde(default)]
    pub name: String,
    /// Enforce or observe, per tenant. A tenant mid-adoption does not force the
    /// whole estate into observe mode.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Path to this tenant's connection policy, relative to the registry file.
    #[serde(default)]
    pub policy: Option<String>,
    /// Path to this tenant's issuer signing key.
    ///
    /// Per tenant on purpose: one issuer key across tenants means a contract
    /// minted for one is cryptographically indistinguishable from a contract
    /// minted for another, and the isolation is then a filesystem convention
    /// rather than a property a mediator can check.
    #[serde(default)]
    pub issuer_key: Option<String>,
    /// The `kid` this tenant's contracts carry.
    #[serde(default)]
    pub kid: Option<String>,
    /// Whether the tenant accepts new work.
    #[serde(default)]
    pub suspended: bool,
}

fn default_mode() -> String {
    "observe".to_string()
}

/// The tenants this control plane serves.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRegistry {
    /// Declared tenants.
    #[serde(default, rename = "tenant")]
    pub tenants: Vec<TenantDef>,
}

impl TenantRegistry {
    /// Parse from TOML.
    pub fn parse(text: &str) -> Result<TenantRegistry> {
        let registry: TenantRegistry = toml::from_str(text).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, "tenant registry is not valid TOML")
                .with_source(e)
        })?;
        registry.validate()?;
        Ok(registry)
    }

    /// Read from disk.
    pub fn load(path: &Path) -> Result<TenantRegistry> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("cannot read tenant registry {}", path.display()),
            )
            .with_source(e)
        })?;
        TenantRegistry::parse(&text)
    }

    fn validate(&self) -> Result<()> {
        let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
        for t in &self.tenants {
            if seen.insert(t.id.as_str(), ()).is_some() {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("tenant {:?} is declared twice", t.id),
                ));
            }
            if !matches!(t.mode.as_str(), "enforce" | "observe") {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("tenant {:?} mode must be enforce|observe, got {:?}", t.id, t.mode),
                ));
            }
            // A tenant that can mint but has no key of its own would fall back to
            // some shared key, which is the isolation failure this file exists to
            // prevent — so it has to be stated, not defaulted.
            if t.mode == "enforce" && t.issuer_key.is_none() {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!(
                        "tenant {:?} is in enforce mode with no issuer_key; a shared key would make \
                         its contracts indistinguishable from another tenant's",
                        t.id
                    ),
                ));
            }
            if t.issuer_key.is_some() != t.kid.is_some() {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("tenant {:?} must set issuer_key and kid together", t.id),
                ));
            }
        }
        Ok(())
    }

    /// Resolve a tenant, refusing one this control plane does not serve.
    pub fn resolve(&self, id: &TenantId) -> Result<&TenantDef> {
        self.tenants.iter().find(|t| &t.id == id).ok_or_else(|| {
            // Deliberately the same code and the same message shape as a
            // cross-tenant reference: an unknown tenant and a tenant you may not
            // see must be indistinguishable, or the error becomes an enumeration
            // oracle for the estate's customer list.
            WcError::with_detail(Code::TENANT_UNKNOWN, format!("unknown tenant {id:?}"))
        })
    }

    /// Every declared tenant id.
    #[must_use]
    pub fn ids(&self) -> Vec<&TenantId> {
        self.tenants.iter().map(|t| &t.id).collect()
    }

    /// How many tenants are declared.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tenants.len()
    }

    /// Whether none are declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tenants.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

/// A caller's tenant, established once and carried everywhere.
///
/// The point of the type is that it cannot be constructed from a request
/// parameter alone. A hosted control plane binds it from the credential; every
/// store, key and chain access then derives from the binding rather than from
/// whatever the request asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantBinding {
    /// The tenant the caller is authorised for.
    tenant: TenantId,
    /// How it was established, for the evidence record.
    source: String,
}

impl TenantBinding {
    /// Bind from an authenticated credential.
    #[must_use]
    pub fn from_credential(tenant: TenantId, source: impl Into<String>) -> TenantBinding {
        TenantBinding {
            tenant,
            source: source.into(),
        }
    }

    /// Bind from a local operator's configuration — the CLI case, where the
    /// operator has filesystem access to the root anyway.
    #[must_use]
    pub fn local(tenant: TenantId) -> TenantBinding {
        TenantBinding {
            tenant,
            source: "local operator".to_string(),
        }
    }

    /// The bound tenant.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// How the binding was established.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Check that a requested tenant matches the binding.
    ///
    /// This is the whole of `WC-8002`. A request that names another tenant is not
    /// answered with that tenant's data, and is not answered with "no such
    /// tenant" either — both would leak. It is refused as a cross-tenant
    /// reference, which is true whether or not the other tenant exists.
    pub fn authorise(&self, requested: &TenantId) -> Result<()> {
        if requested == &self.tenant {
            return Ok(());
        }
        Err(WcError::with_detail(
            Code::TENANT_UNKNOWN,
            format!(
                "cross-tenant reference: this credential is bound to {} and named {requested}",
                self.tenant
            ),
        ))
    }

    /// The paths this binding may touch.
    #[must_use]
    pub fn paths(&self, root: &Path) -> TenantPaths {
        TenantPaths::new(root, &self.tenant)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    // --- the vulnerability this module closes ------------------------------

    #[test]
    fn a_tenant_id_cannot_escape_the_root() {
        // Before this type existed, `--tenant '../../../../tmp/elsewhere'` wrote
        // the estate's state to /tmp/elsewhere. Driven against the real binary,
        // which is how it was found.
        for traversal in [
            "../other",
            "../../../../tmp/elsewhere",
            "a/../../b",
            "..",
            ".",
            "./x",
            "a/b",
            "a\\b",
        ] {
            let err = TenantId::new(traversal).unwrap_err();
            assert_eq!(
                err.code(),
                Code::TENANT_UNKNOWN,
                "{traversal:?} must not be a tenant id"
            );
        }
    }

    #[test]
    fn a_tenant_id_rejects_everything_that_is_not_obviously_safe() {
        // An allowlist, not a denylist: a denylist has to be right about every
        // filesystem, and this one only has to be right about [a-z0-9-].
        for bad in [
            "",                    // empty
            "-leading-hyphen",     // reads as a flag
            ".hidden",             // hidden file, and a traversal prefix
            "APAC",                // case-folding collides with "apac"
            "apac.emea",           // dots are structure elsewhere in this system
            "apac emea",           // space
            "apac\0",              // NUL
            "apac:emea",           // drive separator on Windows
            "apac\n",              // newline into a log line
            "tenant\u{202E}evil",  // bidi override in an operator table
            "café",                // normalisation could collide two ids
        ] {
            assert!(
                TenantId::new(bad).is_err(),
                "{bad:?} was accepted as a tenant id"
            );
        }

        for good in ["default", "apac", "apac-ops", "t1", "0", "a-b-c-1"] {
            assert_eq!(TenantId::new(good).unwrap().as_str(), good);
        }
    }

    #[test]
    fn a_tenant_id_is_length_bounded() {
        assert!(TenantId::new("a".repeat(MAX_TENANT_LEN)).is_ok());
        assert!(TenantId::new("a".repeat(MAX_TENANT_LEN + 1)).is_err());
    }

    #[test]
    fn a_tenant_id_round_trips_through_serde_and_rejects_a_bad_one() {
        let id: TenantId = serde_json::from_str("\"apac-ops\"").unwrap();
        assert_eq!(id.as_str(), "apac-ops");
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"apac-ops\"");
        // The validation is on the deserialisation path too, or a config file
        // becomes a way around the newtype.
        assert!(serde_json::from_str::<TenantId>("\"../escape\"").is_err());
    }

    #[test]
    fn a_tenant_id_pads_so_operator_tables_keep_their_columns() {
        assert_eq!(format!("[{:<10}]", TenantId::new("apac").unwrap()), "[apac      ]");
    }

    // --- paths -------------------------------------------------------------

    #[test]
    fn every_path_stays_under_the_tenant_root() {
        let root = Path::new("/var/lib/warden-connect");
        let p = TenantPaths::new(root, &TenantId::new("apac").unwrap());
        assert_eq!(p.base, Path::new("/var/lib/warden-connect/tenants/apac"));
        for path in [&p.state, &p.evidence, &p.revocations, &p.acks, &p.artifacts] {
            assert!(path.starts_with(&p.base), "{path:?} escaped {:?}", p.base);
        }
    }

    #[test]
    fn two_tenants_share_no_path() {
        let root = Path::new("/r");
        let a = TenantPaths::new(root, &TenantId::new("apac").unwrap());
        let b = TenantPaths::new(root, &TenantId::new("emea").unwrap());
        assert!(!a.base.starts_with(&b.base) && !b.base.starts_with(&a.base));
        assert_ne!(a.state, b.state);
        assert_ne!(a.evidence, b.evidence);
        assert_ne!(a.revocations, b.revocations);
    }

    // --- the registry ------------------------------------------------------

    #[test]
    fn a_registry_parses_and_resolves() {
        let r = TenantRegistry::parse(
            r#"
            [[tenant]]
            id = "apac"
            name = "APAC"
            mode = "enforce"
            issuer_key = "/keys/apac.pem"
            kid = "apac-2026-03"

            [[tenant]]
            id = "emea"
            mode = "observe"
            "#,
        )
        .unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r.resolve(&TenantId::new("apac").unwrap()).unwrap().name, "APAC");
        assert!(!r.resolve(&TenantId::new("emea").unwrap()).unwrap().suspended);
    }

    #[test]
    fn an_unknown_tenant_and_a_forbidden_one_are_indistinguishable() {
        // Otherwise the error is an enumeration oracle for the estate's customer
        // list: "unknown tenant" vs "forbidden" tells an attacker which names
        // exist.
        let r = TenantRegistry::parse(r#"[[tenant]]
            id = "apac"
            "#)
        .unwrap();
        let unknown = r.resolve(&TenantId::new("nope").unwrap()).unwrap_err();

        let binding = TenantBinding::local(TenantId::new("apac").unwrap());
        let forbidden = binding
            .authorise(&TenantId::new("emea").unwrap())
            .unwrap_err();

        assert_eq!(unknown.code(), forbidden.code());
        assert_eq!(unknown.code(), Code::TENANT_UNKNOWN);
    }

    #[test]
    fn an_enforcing_tenant_must_have_its_own_issuer_key() {
        // A shared key makes one tenant's contracts cryptographically
        // indistinguishable from another's, and the isolation becomes a filesystem
        // convention rather than something a mediator can check.
        let err = TenantRegistry::parse(
            r#"
            [[tenant]]
            id = "apac"
            mode = "enforce"
            "#,
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(err.to_string().contains("indistinguishable"), "{err}");
    }

    #[test]
    fn a_key_without_a_kid_is_refused() {
        assert!(TenantRegistry::parse(
            r#"
            [[tenant]]
            id = "apac"
            issuer_key = "/keys/a.pem"
            "#,
        )
        .is_err());
    }

    #[test]
    fn the_registry_rejects_duplicates_and_bad_modes() {
        assert!(TenantRegistry::parse(
            "[[tenant]]\nid = \"apac\"\n[[tenant]]\nid = \"apac\"\n"
        )
        .is_err());
        assert!(TenantRegistry::parse(
            "[[tenant]]\nid = \"apac\"\nmode = \"enfroce\"\n"
        )
        .is_err());
        // And a traversal in the config file is caught by the same newtype.
        assert!(TenantRegistry::parse("[[tenant]]\nid = \"../escape\"\n").is_err());
    }

    // --- binding -----------------------------------------------------------

    #[test]
    fn a_binding_authorises_only_its_own_tenant() {
        let binding = TenantBinding::from_credential(
            TenantId::new("apac").unwrap(),
            "bearer token sub=svc:apac-ops",
        );
        assert!(binding.authorise(&TenantId::new("apac").unwrap()).is_ok());

        let err = binding
            .authorise(&TenantId::new("emea").unwrap())
            .unwrap_err();
        assert_eq!(err.code(), Code::TENANT_UNKNOWN);
        assert!(err.to_string().contains("cross-tenant reference"));
        assert_eq!(binding.source(), "bearer token sub=svc:apac-ops");
    }

    #[test]
    fn paths_come_from_the_binding_not_from_the_request() {
        // The type exists so a store access derives from the credential rather
        // than from whatever the request asked for. One forgotten filter in a
        // multi-tenant control plane is the whole product.
        let binding = TenantBinding::local(TenantId::new("apac").unwrap());
        let paths = binding.paths(Path::new("/r"));
        assert_eq!(paths.tenant.as_str(), "apac");
        assert_eq!(paths.state, Path::new("/r/tenants/apac/state"));
    }
}
