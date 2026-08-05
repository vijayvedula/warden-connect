//! `connect-mediate` — the inline mediator (`docs/08-lld.md` §8.6.1, §7.9).
//!
//! Composes Warden core's shipped `Gateway` with warden-connect's `Upstream`
//! decorator in **one process**, so the data plane adds no second hop and Warden
//! core needs no modification. The whole integration is that the decorator wraps
//! the upstream Warden core was already going to talk to.
//!
//! ```text
//!   agent ──stdio──▶ Warden core Gateway ──▶ MediatedUpstream ──▶ real MCP server
//!                    (per-action policy)     (contract, filter, ceilings)
//! ```
//!
//! # Why a separate binary from `connect`
//!
//! The LLD names the command `connect mediate`. It ships as its own binary because
//! this is the only place that links Warden core: folding it into the `connect` CLI
//! would pull Warden core into the control plane, and the whole point of §8.3 is
//! that the control plane is independently adoptable.
//!
//! # Failing closed
//!
//! If a contract source is configured and the first refresh fails, the mediator
//! **refuses to start**. A mediator that silently degrades to pass-through is worse
//! than no mediator, because the estate believes it is protected.

use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use warden::approvals::Approvals;
use warden::audit::AuditLog;
use warden::gateway::Gateway;
use warden::jsonrpc::Request;
use warden::policy::PolicyConfig;
use warden::upstream::StdioUpstream;

use wc_core::contract::{Algorithm, IssuerKeys, PeerIdentity};
use wc_core::error::Mode;
use wc_core::model::EntityId;
use wc_mediator::cache::Cache;
use wc_mediator::ceiling::Ceilings;
use wc_mediator::client::{self, ControlPlaneClient};
use wc_mediator::gate::{GateCfg, MediatedUpstream};

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("connect-mediate: {message}");
            std::process::ExitCode::from(1)
        }
    }
}

/// A flag's value, or a default.
fn flag(args: &[String], name: &str) -> Option<String> {
    let key = format!("--{name}");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(rest) = arg.strip_prefix(&format!("{key}=")) {
            return Some(rest.to_string());
        }
        if arg == &key {
            return iter.next().cloned();
        }
    }
    None
}

fn present(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == &format!("--{name}"))
}

fn required(args: &[String], name: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("--{name} is required"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

const USAGE: &str = "\
connect-mediate — the warden-connect inline mediator

USAGE
  connect-mediate --upstream \"<command>\" --mediator-id ID \\
                  --caller SPIFFE_ID --callee SPIFFE_ID \\
                  --issuer-pub PEM --kid KID \\
                  [--contracts URL --token TOKEN] | [--contract FILE ...]

WARDEN CORE
  --upstream CMD          the real MCP server to spawn
  --policy FILE           warden policy (default: warden.policy.toml)
  --audit FILE            audit chain (default: .warden/audit.jsonl)
  --approvals FILE        held-call state (default: .warden/approvals.json)
  --agent NAME            agent label for audit rows (default: the caller id)
  --upstream-timeout N    seconds (default: 30)

CONNECT
  --mediator-id ID        this mediator's id; must equal each contract's aud
  --caller SPIFFE_ID      the authenticated calling party
  --callee SPIFFE_ID      the authenticated called party
  --issuer-pub PEM        the contract issuer's public key
  --kid KID               the key id it is registered under
  --alg ES256|ES384|EdDSA (default: ES256)
  --contracts URL         control plane to pull contract sets from
  --token TOKEN           bearer token with the connect.mediator role
  --contract FILE         a contract artifact to load directly (repeatable);
                          the air-gapped alternative to --contracts
  --refresh N             seconds between pulls (default: 5)
  --observe               record findings instead of denying
  --any-zone              permit any zone pair (observe deployments only)
  --peer-mode MODE        configured|mtls|mesh|jwt-svid (default: configured)
                          only `configured` applies to this stdio sidecar; the
                          others need a listening transport (§8.6.6)

Peer identity is supplied by configuration here, which is correct for a sidecar
owning one agent and one upstream — and is recorded as configuration, not as a
handshake. mTLS, mesh and JWT-SVID modes live in `wc_mediator::peer` for the
shared-gateway topology, where a flag is not an identity.
";

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return Ok(());
    }

    // --- connect configuration ---
    let mediator_id = required(&args, "mediator-id")?;
    let caller = EntityId::new(required(&args, "caller")?).map_err(|e| e.to_string())?;
    let callee = EntityId::new(required(&args, "callee")?).map_err(|e| e.to_string())?;

    let issuer_pub = required(&args, "issuer-pub")?;
    let kid = required(&args, "kid")?;
    let pem = std::fs::read(&issuer_pub).map_err(|e| format!("read {issuer_pub}: {e}"))?;
    let mut keys = IssuerKeys::new();
    match flag(&args, "alg")
        .unwrap_or_else(|| "ES256".to_string())
        .as_str()
    {
        "ES256" => keys.add_ec_pem(&kid, &pem, Algorithm::ES256),
        "ES384" => keys.add_ec_pem(&kid, &pem, Algorithm::ES384),
        "EdDSA" | "Ed25519" => keys.add_ed_pem(&kid, &pem),
        other => return Err(format!("{other:?} is not an accepted contract algorithm")),
    }
    .map_err(|e| e.to_string())?;

    let cache = Arc::new(Cache::new());
    let refresh_secs: u64 = flag(&args, "refresh")
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);

    // --- contracts: pulled, or loaded directly for an air-gapped estate ---
    let inline: Vec<String> = args
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "--contract")
        .filter_map(|(i, _)| args.get(i + 1))
        .map(|path| std::fs::read_to_string(path).map(|t| t.trim().to_string()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|e| format!("read contract: {e}"))?;

    let client = match (flag(&args, "contracts"), flag(&args, "token")) {
        (Some(url), Some(token)) => Some(ControlPlaneClient::new(&url, &mediator_id, &token)),
        (Some(_), None) => return Err("--contracts requires --token".to_string()),
        (None, Some(_)) => return Err("--token is only used with --contracts".to_string()),
        (None, None) => None,
    };

    if client.is_none() && inline.is_empty() {
        // Refusing beats starting blind: with no contract source the mediator would
        // deny every connection, which looks identical to a broken upstream.
        return Err(
            "no contract source: pass --contracts URL --token TOKEN, or --contract FILE"
                .to_string(),
        );
    }

    if !inline.is_empty() {
        let snapshot = wc_mediator::cache::Snapshot::build(&inline, &keys, &mediator_id, now());
        eprintln!(
            "connect-mediate: loaded {} contract(s) from disk, {} rejected",
            snapshot.len(),
            snapshot.rejected.len()
        );
        for (label, code) in &snapshot.rejected {
            eprintln!(
                "connect-mediate: rejected {label}…: {code} {}",
                code.summary()
            );
        }
        cache.install(snapshot);
    }

    if let Some(client) = &client {
        // The first refresh is a startup gate. If the control plane cannot be
        // reached now, this mediator would deny everything while looking healthy.
        let report = client::refresh(client, &cache, &keys, &mediator_id, 0, now())
            .map_err(|e| format!("first contract refresh failed, refusing to start: {e}"))?;
        eprintln!(
            "connect-mediate: {} contract(s) installed, set {} seq {}{}",
            report.installed,
            report.set_hash.chars().take(20).collect::<String>(),
            report.seq,
            if report.acked {
                ", acked"
            } else {
                ", NOT acked"
            }
        );
        for cid in &report.missing {
            eprintln!("connect-mediate: WARNING {cid} was named without an artifact");
        }
        for (label, code) in &report.rejected {
            eprintln!(
                "connect-mediate: rejected {label}…: {code} {}",
                code.summary()
            );
        }

        // Then keep pulling. Failures are logged and the last good snapshot is
        // kept: a control-plane outage must not take the estate down, but it must
        // not extend authority either — contracts still expire on their own `exp`.
        let loop_client = client.clone();
        let loop_cache = Arc::clone(&cache);
        let loop_keys_pem = pem.clone();
        let loop_kid = kid.clone();
        let loop_alg = flag(&args, "alg").unwrap_or_else(|| "ES256".to_string());
        let loop_mediator = mediator_id.clone();
        std::thread::spawn(move || {
            let mut keys = IssuerKeys::new();
            let registered = match loop_alg.as_str() {
                "EdDSA" | "Ed25519" => keys.add_ed_pem(&loop_kid, &loop_keys_pem),
                "ES384" => keys.add_ec_pem(&loop_kid, &loop_keys_pem, Algorithm::ES384),
                _ => keys.add_ec_pem(&loop_kid, &loop_keys_pem, Algorithm::ES256),
            };
            if registered.is_err() {
                eprintln!("connect-mediate: refresh thread has no usable issuer key");
                return;
            }
            let mut seq = 0u64;
            loop {
                std::thread::sleep(Duration::from_secs(refresh_secs));
                match client::refresh(&loop_client, &loop_cache, &keys, &loop_mediator, seq, now())
                {
                    Ok(report) => {
                        seq = report.seq;
                        if !report.is_clean() {
                            eprintln!(
                                "connect-mediate: refresh not clean — {} missing, {} rejected, acked={}",
                                report.missing.len(),
                                report.rejected.len(),
                                report.acked
                            );
                        }
                    }
                    Err(e) => eprintln!("connect-mediate: refresh failed, keeping last set: {e}"),
                }
            }
        });
    }

    // --- peer identity (§8.6.6) ---
    //
    // Everything the mediator enforces rests on checks 6 and 7 comparing the
    // contract against *authenticated* peers. In this stdio sidecar the identities
    // come from configuration, which is honest for one agent and one upstream —
    // and `Peer::verified` records that it was configuration rather than a
    // handshake, so nothing downstream can mistake the two.
    let peer_mode = wc_mediator::peer::PeerSource::parse_mode(
        flag(&args, "peer-mode").as_deref().unwrap_or("configured"),
    )
    .map_err(|e| e.to_string())?;
    let source = match peer_mode {
        "configured" => wc_mediator::peer::PeerSource::Configured {
            caller: caller.clone(),
            callee: callee.clone(),
        },
        // The other modes need a transport this binary does not terminate: it
        // speaks stdio to one agent. Refused rather than silently downgraded to
        // `configured`, which would report success while authenticating nothing.
        other => {
            return Err(format!(
                "--peer-mode {other} needs a listening transport; `connect-mediate` \
                 speaks stdio to one agent, so only `configured` applies here. \
                 The other modes are for a shared gateway (§7.9)."
            ))
        }
    };
    let peer = source
        .resolve(&wc_mediator::peer::Presented {
            origin: Some(wc_mediator::peer::Origin::Stdio),
            ..Default::default()
        })
        .map_err(|e| e.to_string())?;
    if !peer.verified {
        eprintln!(
            "connect-mediate: peer identity is {} — correct for a sidecar owning one agent, \
             not for a shared gateway",
            peer.method
        );
    }

    // --- the decorator ---
    let mut cfg = GateCfg::new(&mediator_id, peer.identity.clone(), now);
    if present(&args, "observe") {
        cfg.mode = Mode::Observe;
    }
    if present(&args, "any-zone") {
        cfg.zones = Box::new(wc_core::contract::AnyZone);
    }

    let upstream_cmd = required(&args, "upstream")?;
    let upstream_timeout: u64 = flag(&args, "upstream-timeout")
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let real = StdioUpstream::spawn(&upstream_cmd, Duration::from_secs(upstream_timeout))
        .map_err(|e| format!("spawn upstream: {e}"))?;

    let mediated = MediatedUpstream::new(Box::new(real), Arc::clone(&cache), cfg)
        .with_ceilings(Ceilings::new());

    // --- Warden core, unmodified ---
    let policy_path = flag(&args, "policy").unwrap_or_else(|| "warden.policy.toml".to_string());
    let policy = PolicyConfig::from_file(&policy_path).map_err(|e| e.to_string())?;
    let audit = AuditLog::new(flag(&args, "audit").unwrap_or_else(|| ".warden/audit.jsonl".into()));
    let approvals =
        Approvals::new(flag(&args, "approvals").unwrap_or_else(|| ".warden/approvals.json".into()));
    let agent_label = flag(&args, "agent").unwrap_or_else(|| caller.as_str().to_string());

    let gateway = Arc::new(Gateway::new(
        policy,
        audit,
        approvals,
        &agent_label,
        Box::new(mediated),
        Duration::from_secs(300),
    ));

    eprintln!(
        "connect-mediate: mediating {caller} → {callee} as {mediator_id} ({:?})",
        if present(&args, "observe") {
            Mode::Observe
        } else {
            Mode::Enforce
        }
    );

    // --- the stdio loop, the same shape as `warden proxy` ---
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let stdin = std::io::stdin();
    let mut workers = Vec::new();

    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("connect-mediate: skipping unparseable line: {e}");
                continue;
            }
        };
        if req.id.is_none() {
            gateway.notify(&req);
            continue;
        }
        let gateway = Arc::clone(&gateway);
        let stdout = Arc::clone(&stdout);
        workers.push(std::thread::spawn(move || {
            let response = gateway.handle_request(&req, None);
            if let Ok(line) = serde_json::to_string(&response) {
                if let Ok(mut out) = stdout.lock() {
                    let _ = writeln!(out, "{line}");
                    let _ = out.flush();
                }
            }
        }));
    }

    for worker in workers {
        let _ = worker.join();
    }
    gateway.checkpoint_audit();
    Ok(())
}
