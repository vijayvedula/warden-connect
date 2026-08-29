//! What the plugin passes at init, and the process-wide state it produces.

use std::sync::Arc;

use serde::Deserialize;
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
    /// The control plane to pull contract sets and revocations from.
    ///
    /// Without it this worker holds whatever it loaded from disk at start, forever — and a
    /// revocation reaches it never. With it, each worker refreshes on its own background
    /// thread, which is also how it hears about containment.
    #[serde(default)]
    pub contracts_url: Option<String>,
    /// The bearer token for that plane. Needs the `connect.mediator` role.
    #[serde(default)]
    pub token: Option<String>,
    /// Seconds between pulls. Default 5.
    #[serde(default)]
    pub refresh_secs: Option<u64>,
    /// Allow any zone pair rather than requiring the same trust level.
    #[serde(default)]
    pub any_zone: bool,
    /// Disable the surface pin entirely. Off by default, because gate 8 is not optional.
    #[serde(default)]
    pub no_pin: bool,
    /// How many nginx workers share this configuration — `ngx.worker.count()`.
    #[serde(default)]
    pub workers: Option<u32>,
    /// This worker's id — `ngx.worker.id()`. Substituted for `%w` in `evidence_path`.
    #[serde(default)]
    pub worker_id: Option<u32>,
    /// Where to append the decision trail. Absent means no trail is written.
    ///
    /// **`%w` is replaced with the worker id**, and is required when more than one worker
    /// shares this configuration. Each worker keeps its own chain — two processes appending to
    /// one file interleave two chains, and the result never verifies. That is not a corruption
    /// an operator would notice: every row is well-formed and only the links are wrong.
    #[serde(default)]
    pub evidence_path: Option<String>,
    /// What a call with no contract gets, since it has no terms to read.
    /// `blocking` | `fail-safe`. Default `fail-safe`.
    #[serde(default)]
    pub evidence_delivery: Option<String>,
}

/// One process-wide handle: the contract set, the route table, and the counters they share.
///
/// One of these per nginx worker. See [`Registry`] for what that means for a rate ceiling —
/// increment 6 makes the operator say it out loud.
pub struct Handle {
    /// Verified contracts, resolved by (caller, callee).
    pub contracts: std::sync::Arc<ContractSet>,
    /// Route key to callee.
    pub routes: Routes,
    /// What has been pinned. `None` only when `no_pin` was set.
    pub pins: Option<Arc<PinLedger>>,
    /// Seconds a pin verification stays good.
    pub pin_max_age: u64,
    /// Enforce or observe.
    pub mode: Mode,
    /// Where identity comes from.
    pub identity: IdentitySource,
    /// Stops the refresh thread when the handle is freed.
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The decision trail, when one is configured.
    pub evidence: Option<Arc<wc_mediator::evidence::FileSink>>,
    /// Where an XFCC header may be believed from. Empty under `identity = "tls"`.
    pub mesh: wc_mediator::peer::MeshTrust,
}

impl Drop for Handle {
    /// Stop the refresh thread. It checks the flag once per interval, so a worker shutting down
    /// waits at most that long — and never blocks on it, because nothing joins.
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Handle {
    /// The contract set as a trait object, for reporting usage.
    #[must_use]
    pub fn contracts_arc(
        &self,
    ) -> std::sync::Arc<dyn warden_connect_gateway::contracts::Contracts> {
        std::sync::Arc::clone(&self.contracts)
            as std::sync::Arc<dyn warden_connect_gateway::contracts::Contracts>
    }

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

        // Opened before the first call, so a broken or unwritable trail is a startup error
        // rather than a surprise at request rate. `verify` refuses a chain that already does
        // not hold, which is the case an operator most needs to hear about early.
        let evidence = match &cfg.evidence_path {
            Some(p) => {
                let workers = cfg.workers.unwrap_or(1);
                if workers > 1 && !p.contains("%w") {
                    return Err(format!(
                        "evidence_path {p:?} is shared by {workers} workers and contains no \
                         %w. Each worker keeps its own hash chain, so they would interleave \
                         into a file that never verifies — and every row would still look \
                         well-formed. Use something like /var/log/kong/wc-%w.jsonl"
                    ));
                }
                let p = p.replace("%w", &cfg.worker_id.unwrap_or(0).to_string());
                let p = &p;
                let delivery = wc_mediator::evidence::Delivery::parse(
                    cfg.evidence_delivery.as_deref().unwrap_or("fail-safe"),
                );
                let sink = wc_mediator::evidence::FileSink::open(p, delivery)
                    .map_err(|e| format!("evidence: {e}"))?;
                eprintln!(
                    "wc-kong: decision trail at {} (delivery {:?}, resuming at seq {})",
                    sink.path().display(),
                    delivery,
                    sink.head().seq
                );
                Some(Arc::new(sink))
            }
            None => None,
        };

        // The refresh loop, on its own OS thread.
        //
        // NOT a Lua timer calling in: `ControlPlaneClient` is blocking (ureq), and a blocking
        // fetch from `ngx.timer` stalls the whole worker's event loop for as long as the
        // control plane takes to answer — unbounded if it hangs. A dedicated thread never
        // touches the loop, and `Cache` is already behind an `RwLock`, so installing a snapshot
        // from another thread is what it was built for.
        //
        // Started HERE, which is the first request in each worker, and that timing is
        // load-bearing: nginx forks its workers, and a thread created before the fork does not
        // survive into the child. Moving handle construction into Kong's `init` phase — as
        // opposed to `init_worker` or `access` — would silently produce workers whose refresher
        // is not running, and nothing about them would look wrong.
        let contracts = Arc::new(contracts);
        // Kong loads the same artifacts the mediator does, so it owes the same notice. Announced
        // here rather than only in `connect-mediate`, which is where it used to live and where
        // it covered one enforcement path of three. nginx captures stderr into the error log.
        wc_mediator::cache::announce_withdrawn_ceilings(
            &contracts.cache().snapshot(),
            "warden-connect[kong]",
        );
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        if let Some(url) = &cfg.contracts_url {
            let Some(token) = cfg.token.clone() else {
                return Err(
                    "contracts_url needs a token with the connect.mediator role; without one \
                     every pull is refused and this worker would silently keep a set that can \
                     never be revoked"
                        .to_string(),
                );
            };
            let every = cfg.refresh_secs.unwrap_or(5).max(1);
            let client =
                wc_mediator::client::ControlPlaneClient::new(url, &cfg.mediator_id, &token);
            let cache = contracts.cache();
            let set = Arc::clone(&contracts);
            let (med, iss) = (cfg.mediator_id.clone(), cfg.issuer_id.clone());
            let stop_flag = Arc::clone(&stop);
            let worker = cfg.worker_id.unwrap_or(0);
            std::thread::spawn(move || {
                let mut trust = trust;
                let (mut seq, mut rev_seq) = (0u64, 0u64);
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(every));
                    if stop_flag.load(std::sync::atomic::Ordering::SeqCst) {
                        return;
                    }
                    let at = crate::now();
                    let (keys, warn) = trust.keys(at);
                    if let Some(e) = warn {
                        eprintln!("wc-kong[{worker}]: issuer key set refresh failed: {e}");
                    }
                    let Ok(keys) = keys else {
                        // Contracts are not pulled in this state: verifying against a trust set
                        // this process has decided it cannot vouch for would be worse than
                        // holding the old one. `max_stale` turns it into a refusal eventually.
                        continue;
                    };
                    let trusted = wc_mediator::cache::Trust {
                        keys,
                        mediator_id: &med,
                        issuer: &iss,
                    };
                    match wc_mediator::client::refresh(&client, &cache, &trusted, seq, rev_seq, at)
                    {
                        Ok(report) => {
                            seq = report.seq;
                            if let Some(rev) = &report.revocations {
                                rev_seq = rev.applied_seq;
                                if rev.applied > 0 {
                                    eprintln!(
                                        "wc-kong[{worker}]: applied {} revocation(s), feed at \
                                         seq {}",
                                        rev.applied, rev.applied_seq
                                    );
                                }
                            }
                            // Only a CLEAN refresh counts as fresh. A partial one leaves this
                            // worker holding a set the plane did not fully hand over, and
                            // treating that as current is how a withdrawn contract keeps
                            // working.
                            if report.is_clean() {
                                set.mark_fresh(at);
                            }
                        }
                        Err(e) => eprintln!(
                            "wc-kong[{worker}]: refresh failed: {} {}",
                            e.code(),
                            e.detail()
                        ),
                    }
                }
            });
            eprintln!(
                "wc-kong: refreshing from {url} every {every}s; revocations reach this worker \
                 within one interval"
            );
        } else if !contracts.is_empty() {
            // Said out loud, because the alternative is a PEP that looks configured and cannot
            // be contained: it will serve what it loaded until those contracts expire.
            eprintln!(
                "wc-kong: no contracts_url, so this worker holds the artifacts it loaded and NO \
                 REVOCATION CAN REACH IT. Contract expiry is the only containment"
            );
        }

        Ok(Handle {
            contracts,
            routes,
            pins: (!cfg.no_pin).then(|| Arc::new(PinLedger::new())),
            pin_max_age: cfg.pin_max_age,
            mode: cfg.mode.into(),
            identity: cfg.identity,
            mesh,
            evidence,
            stop,
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
