//! What the plugin passes at init, and the process-wide state it produces.

use std::sync::Arc;

use serde::Deserialize;
use warden_connect_gateway::adapter::Registry;
use warden_connect_gateway::contracts::ContractSet;
use warden_connect_gateway::routes::Routes;
use warden_connect_gateway::PinLedger;
use wc_core::error::Mode;

/// Enforce, or watch and record.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ModeCfg {
    /// Refuse what the contract does not cover.
    #[default]
    Enforce,
    /// Forward everything; record what would have been refused.
    Observe,
}

impl From<ModeCfg> for Mode {
    fn from(m: ModeCfg) -> Mode {
        match m {
            ModeCfg::Enforce => Mode::Enforce,
            ModeCfg::Observe => Mode::Observe,
        }
    }
}

/// The plugin's configuration, as JSON.
///
/// JSON rather than a `#[repr(C)]` struct on purpose: a struct layout has to be kept in step
/// between this crate and a hand-written Lua `ffi.cdef`, and a field added on one side is a
/// silent misread on the other. A JSON blob fails loudly and versions itself.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Paths to contract artifacts (`*.jws`).
    pub contracts: Vec<String>,
    /// Path to `routes.toml`.
    pub routes: String,
    /// Path to a JWKS file holding the issuer's public keys.
    #[serde(default)]
    pub jwks_file: Option<String>,
    /// URL to fetch the issuer's JWKS from.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// A single PEM public key, as an alternative to a JWKS.
    #[serde(default)]
    pub issuer_pub: Option<String>,
    /// The key id to select, when the source holds more than one.
    #[serde(default)]
    pub kid: Option<String>,
    /// Who the contracts must be addressed to.
    pub mediator_id: String,
    /// Which control plane they must have come from.
    pub issuer_id: String,
    /// Enforce or observe.
    #[serde(default)]
    pub mode: ModeCfg,
    /// Seconds a pin verification stays good. Zero means it never expires.
    #[serde(default)]
    pub pin_max_age: u64,
    /// Seconds the contract set may go without a refresh before every call is refused.
    #[serde(default)]
    pub max_stale: u64,
    /// Allow any zone pair rather than requiring the same trust level.
    #[serde(default)]
    pub any_zone: bool,
    /// Disable the surface pin entirely. Off by default, because gate 8 is not optional.
    #[serde(default)]
    pub no_pin: bool,
}

/// One process-wide handle: the contract set, the route table, and the counters they share.
///
/// One of these per nginx worker. See [`Registry`] for what that means for a rate ceiling —
/// increment 6 makes the operator say it out loud.
pub struct Handle {
    /// Verified contracts, resolved by (caller, callee).
    pub contracts: ContractSet,
    /// Route key to callee.
    pub routes: Routes,
    /// Ceiling counters, keyed by contract.
    pub ceilings: Registry,
    /// What has been pinned. `None` only when `no_pin` was set.
    pub pins: Option<Arc<PinLedger>>,
    /// Seconds a pin verification stays good.
    pub pin_max_age: u64,
    /// Enforce or observe.
    pub mode: Mode,
}

impl Handle {
    /// Build a handle from configuration.
    ///
    /// # Errors
    ///
    /// One line naming what could not be read or verified. The caller refuses to start:
    /// a PEP that comes up with an unreadable configuration is a PEP that is not there.
    pub fn open(cfg: &Config) -> Result<Handle, String> {
        let at = crate::now();
        let spec = wc_mediator::jwks::TrustSpec {
            issuer_pub: cfg.issuer_pub.as_deref(),
            kid: cfg.kid.as_deref(),
            alg: None,
            jwks_url: cfg.jwks_url.as_deref(),
            jwks_file: cfg.jwks_file.as_deref(),
            jwks_ttl: None,
            jwks_max_stale: None,
        };
        let (mut trust, report) = wc_mediator::jwks::build_trust(&spec, at)?;
        if let Some(r) = &report {
            if !r.is_complete() {
                eprintln!(
                    "wc-kong: key set skipped {} key(s): {}",
                    r.skipped.len(),
                    r.skipped.join("; ")
                );
            }
        }

        let zones: Arc<dyn wc_core::contract::ZoneRule + Send + Sync> = if cfg.any_zone {
            Arc::new(wc_core::contract::AnyZone)
        } else {
            Arc::new(wc_core::contract::SameTrustLevel)
        };

        let routes = Routes::load(&cfg.routes)?;
        if routes.table().is_empty() {
            return Err(format!(
                "{} maps no route to a callee, so every request would be refused WC-4001",
                cfg.routes
            ));
        }

        // Paths in, contents to the verifier. The plugin passes paths because a Kong config
        // holds paths, and because a multi-kilobyte JWS crossing the FFI per worker start is
        // bytes nobody needs to move.
        if cfg.contracts.is_empty() {
            return Err("contracts is empty; with no contract set this filter denies every \
                        call while looking healthy, which is the failure that takes longest \
                        to diagnose"
                .to_string());
        }
        let artifacts: Vec<String> = cfg
            .contracts
            .iter()
            .map(|p| {
                std::fs::read_to_string(p)
                    .map(|t| t.trim().to_string())
                    .map_err(|e| format!("read contract {p}: {e}"))
            })
            .collect::<Result<Vec<_>, String>>()?;

        let contracts = ContractSet::from_artifacts(
            &artifacts,
            &mut trust,
            &cfg.mediator_id,
            &cfg.issuer_id,
            zones,
            cfg.mode.into(),
            crate::now,
            cfg.max_stale,
        )?;
        if contracts.is_empty() {
            return Err(
                "no contract verified, so every request would be refused WC-4001".to_string(),
            );
        }

        Ok(Handle {
            contracts,
            routes,
            ceilings: Registry::new(),
            pins: (!cfg.no_pin).then(|| Arc::new(PinLedger::new())),
            pin_max_age: cfg.pin_max_age,
            mode: cfg.mode.into(),
        })
    }
}

/// Who is calling, and where the route says it is going.
///
/// Increment 3 replaces `caller` with the peer certificate chain and a trusted
/// `x-forwarded-client-cert`. Until it does, this field is what the plugin was told, which is
/// why the Lua side is not shipped yet.
#[derive(Debug, Deserialize)]
pub struct Peer {
    /// The caller's entity id.
    pub caller: Option<String>,
    /// Kong's service name, matched against `routes.toml`.
    #[serde(default)]
    pub service: Option<String>,
    /// Kong's route name, matched against `routes.toml`.
    #[serde(default)]
    pub route: Option<String>,
}
