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

/// Where the caller's identity comes from.
///
/// There is no default, on purpose. Both sources are legitimate and they have different threat
/// models, so a binding that guessed — or that silently tried one and fell back to the other —
/// would be a PEP whose identity source an operator cannot state. Falling back is worse than
/// guessing: it means an attacker who can suppress one source selects the other.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IdentitySource {
    /// Kong terminated the mTLS handshake. Identity is the peer certificate's URI SAN, and
    /// `ssl_client_verify` must say `SUCCESS`.
    Tls,
    /// Kong is behind a mesh sidecar. Identity is `x-forwarded-client-cert`, believed only from
    /// the origin named in `mesh_origin`.
    Xfcc,
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
    /// Where the caller's identity comes from. Required.
    pub identity: IdentitySource,
    /// The unix socket or address `x-forwarded-client-cert` may be believed from.
    ///
    /// Required with `identity = "xfcc"` and meaningless without it. An empty mesh trust accepts
    /// nothing, so a missing value here refuses every request rather than trusting loopback —
    /// but that would look identical to "no contract", so it is a startup error instead.
    #[serde(default)]
    pub mesh_origin: Option<String>,
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
    /// Where identity comes from.
    pub identity: IdentitySource,
    /// Where an XFCC header may be believed from. Empty under `identity = "tls"`.
    pub mesh: wc_mediator::peer::MeshTrust,
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

        // Refuse at startup rather than per request: an unconfigured mesh trust accepts
        // nothing, which is the right behaviour and indistinguishable from "no contract" in the
        // access log.
        let mesh = match (cfg.identity, cfg.mesh_origin.as_deref()) {
            // A path is a unix socket; anything else is an address the sidecar connects from.
            // `accepts` additionally requires a TCP origin to be local, so this cannot be
            // widened into "trust any address" by configuration alone.
            (IdentitySource::Xfcc, Some(p)) if p.starts_with('/') => {
                wc_mediator::peer::MeshTrust::socket(p)
            }
            (IdentitySource::Xfcc, Some(p)) => wc_mediator::peer::MeshTrust {
                socket: None,
                addrs: vec![p.to_string()],
            },
            (IdentitySource::Xfcc, None) => {
                return Err(
                    "identity = \"xfcc\" requires mesh_origin: without it no header \
                            is believed from anywhere and every request is refused"
                        .to_string(),
                )
            }
            (IdentitySource::Tls, Some(_)) => {
                return Err(
                    "mesh_origin is set but identity = \"tls\", so no header is read. \
                            Pick one source; a PEP that tries both lets an attacker who can \
                            suppress one select the other"
                        .to_string(),
                )
            }
            (IdentitySource::Tls, None) => wc_mediator::peer::MeshTrust::default(),
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
            return Err(
                "contracts is empty; with no contract set this filter denies every \
                        call while looking healthy, which is the failure that takes longest \
                        to diagnose"
                    .to_string(),
            );
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
            identity: cfg.identity,
            mesh,
        })
    }
}

/// What the plugin observed about the caller, and where the route says the call is going.
///
/// There is deliberately no `caller` field. A field in which Lua states an identity is a field
/// in which anything that can reach Lua states an identity, and increment 2 shipped one only
/// because nothing was reading certificates yet. Identity is now derived from evidence:
/// a verified certificate, or a header from a trusted origin.
#[derive(Debug, Deserialize)]
pub struct Peer {
    /// The TLS terminator's verdict on the client chain — nginx's `ssl_client_verify`.
    /// `SUCCESS`, `NONE`, or `FAILED:<reason>`. Only `SUCCESS` is an identity.
    #[serde(default)]
    pub tls_verify: Option<String>,
    /// The peer certificate chain, PEM, leaf first — nginx's `ssl_client_raw_cert`.
    #[serde(default)]
    pub cert_pem: Option<String>,
    /// Where the request actually arrived from — nginx's `ssl_client_verify` peer, i.e.
    /// `ngx.var.remote_addr`, or `unix:<listener path>` on a unix socket listener.
    ///
    /// This is *evidence*, not configuration. An earlier draft of the XFCC path built the origin
    /// out of the configured `mesh_origin`, which made the origin always equal the trusted one
    /// and turned the mesh check into a no-op — any client able to set the header could assert
    /// any identity. The origin has to come from the request or it is not a check.
    #[serde(default)]
    pub remote: Option<String>,
    /// `x-forwarded-client-cert`, when Kong sits behind a mesh sidecar.
    #[serde(default)]
    pub xfcc: Option<String>,
    /// Kong's **service** name. Matched against the `cluster` column of `routes.toml`, which is
    /// what Envoy calls the same slot — one route table serves both bindings.
    #[serde(default)]
    pub service: Option<String>,
    /// Kong's route name. Matched against the `route` column of `routes.toml`.
    #[serde(default)]
    pub route: Option<String>,
}
