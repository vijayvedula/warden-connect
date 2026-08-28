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
use std::sync::Arc;
#[cfg(feature = "warden-proxy")]
use std::sync::Mutex;
use std::time::Duration;

use wc_mediator::rpc::Request;
use wc_mediator::upstream::{
    check_upstream_url, parse_upstream_header, HttpUpstream, StdioUpstream, Upstream,
};

// Warden core is an ADAPTER now, not a dependency. Standalone is the default build: a
// deployment that wants connection enforcement without Warden core's per-action policy gets
// exactly that, which `docs/limitations.md` previously recorded as impossible.
#[cfg(feature = "warden-proxy")]
use warden::{approvals::Approvals, audit::AuditLog, gateway::Gateway, policy::PolicyConfig};

use wc_core::error::Mode;
use wc_core::model::EntityId;
use wc_mediator::cache::Cache;
use wc_mediator::ceiling::Ceilings;
use wc_mediator::client::{self, ControlPlaneClient};
use wc_mediator::gate::{GateCfg, MediatedUpstream};
use wc_mediator::jwks::KeySource;

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

/// Resolve issuer trust from the flags: one pinned PEM, or a key set that rotates.
///
/// Exactly one, and the ambiguous case is refused rather than resolved by precedence.
/// An operator who passes both has two different beliefs about where trust comes from,
/// and silently honouring one of them means the mediator is trusting something its
/// operator did not think it was.
fn build_trust(args: &[String]) -> Result<KeySource, String> {
    let ttl = |name: &str| -> Result<Option<u64>, String> {
        match flag(args, name) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|_| format!("--{name} {v:?} is not a number of seconds")),
        }
    };
    let (issuer_pub, kid, alg) = (
        flag(args, "issuer-pub"),
        flag(args, "kid"),
        flag(args, "alg"),
    );
    let (url, file) = (flag(args, "jwks-url"), flag(args, "jwks-file"));
    let spec = wc_mediator::jwks::TrustSpec {
        issuer_pub: issuer_pub.as_deref(),
        kid: kid.as_deref(),
        alg: alg.as_deref(),
        jwks_url: url.as_deref(),
        jwks_file: file.as_deref(),
        jwks_ttl: ttl("jwks-ttl")?,
        jwks_max_stale: ttl("jwks-max-stale")?,
    };
    let (source, report) = wc_mediator::jwks::build_trust(&spec, now())?;
    if let Some(report) = report {
        if !report.is_complete() {
            eprintln!(
                "connect-mediate: key set skipped {} key(s): {}",
                report.skipped.len(),
                report.skipped.join("; ")
            );
        }
    }
    Ok(source)
}

const USAGE: &str = r#"connect-mediate — the warden-connect inline mediator

USAGE
  connect-mediate (--upstream CMD | --upstream-url URL) \
                  --mediator-id ID --issuer-id URL \
                  --caller SPIFFE_ID --callee SPIFFE_ID \
                  (--issuer-pub PEM --kid KID | --jwks-url URL | --jwks-file F) \
                  ([--contracts URL --token TOKEN] | [--contract FILE ...])

UPSTREAM
  Exactly one of --upstream or --upstream-url. Both is an error: two upstreams is
  two beliefs about what is being mediated, and resolving that by precedence would
  mediate a server the operator did not point at. Every gate, the catalogue filter
  and the ceilings apply identically either way — the transport changes where the
  server lives, not what is enforced.

  --upstream CMD           the real MCP server, spawned as a child over stdio
  --upstream-url URL       a remote MCP server over Streamable HTTP; the response
                           may be application/json or text/event-stream, and an
                           Mcp-Session-Id handed back at initialize is echoed on
                           every later request
  --upstream-header 'N: V' header to send upstream, e.g. an Authorization for the
                           provider's own gateway (repeatable)
  --upstream-allow-plaintext
                           permit http:// to a host other than loopback. Refused
                           by default: tool calls and their arguments would cross
                           the network in the clear, and the mediator's decisions
                           are worth no more than the channel carrying them. Pass
                           it when something on this host terminates TLS
  --upstream-timeout N     seconds (default: 30)

WARDEN CORE (optional; requires the `warden-proxy` build feature)
  Omit all of these and connect-mediate runs STANDALONE: contract, surface pin,
  ceilings and revocation only, with no Warden core and no warden.policy.toml.
  Standalone is the default — passing these without the feature is an error
  rather than a silently ignored flag.

  --policy FILE            warden policy; giving it selects Warden-core mode
  --audit FILE             audit chain (default: .warden/audit.jsonl)
  --approvals FILE         held-call state (default: .warden/approvals.json)
  --agent NAME             agent label for audit rows (default: the caller id)

CONNECT
  --mediator-id ID         this mediator's id; must equal each contract's aud
  --issuer-id URL          the control plane this mediator obeys; must equal each
                           contract's iss. Required, and not defaulted: a default
                           would be the one value every estate shares, which is
                           the same as not checking. It matters once a keyring can
                           hold two planes' keys — a JWKS copied between
                           environments, a federation import — because aud is then
                           the only boundary left, and aud is commonly templated
                           to the same string in every plane
  --caller SPIFFE_ID       the authenticated calling party
  --callee SPIFFE_ID       the authenticated called party
  --issuer-pub PEM         the contract issuer's public key
  --kid KID                the key id it is registered under
  --alg ES256|ES384|EdDSA  (default: ES256)
  --jwks-url URL           the issuer's published key set, instead of a PEM;
                           re-fetched on the TTL, so rotating the issuer key is a
                           publish rather than a redeploy of every mediator
  --jwks-file FILE         a key set on disk — a SPIRE bundle or a mounted
                           ConfigMap — re-read on the same TTL
  --jwks-ttl N             seconds between key-set reads (default: 300)
  --jwks-max-stale N       how long a cached key set is still served while the
                           fetch is failing, before verification stops
                           (default: 3600); a set that can no longer be refreshed
                           is a set nobody can withdraw a key from
  --contracts URL          control plane to pull contract sets from
  --token TOKEN            bearer token with the connect.mediator role
  --contract FILE          a contract artifact to load directly (repeatable); the
                           air-gapped alternative to --contracts
  --refresh N              seconds between pulls (default: 5)
  --observe                record findings instead of denying
  --decision-log LEVEL     off|notable|all (default: notable). One JSON object per
                           decision on stderr, carrying cid, WC-* code and mode.
                           `notable` is denials and observe-mode findings; `all`
                           adds allows, which in front of a busy agent is a lot.
                           Counters are kept at every level, so turning the log
                           down costs detail rather than visibility
  --metrics-file PATH      write the Prometheus exposition here for a textfile
                           collector. This process has no listener by design, so
                           there is no /metrics to scrape
  --any-zone               permit any zone pair (observe deployments only)
  --peer-mode MODE         configured|mtls|mesh|jwt-svid (default: configured)
                           only `configured` applies to this stdio sidecar; the
                           others need a listening transport (§8.6.6)

  Peer identity is supplied by configuration here, which is correct for a sidecar
  owning one agent and one upstream — and is recorded as configuration, not as a
  handshake. mTLS, mesh and JWT-SVID modes live in `wc_mediator::peer` for the
  shared-gateway topology, where a flag is not an identity."#;

/// Which half of the family is in force, decided from the flags alone.
///
/// Standalone unless a Warden policy is named. Naming one — or naming any flag only Warden
/// core reads — is **refused rather than ignored**: a flag that reads as configured and does
/// nothing is this codebase's recurring defect (`docs/threat-model.md` Part 1), and here it
/// would mean an operator believing per-action policy or an audit chain was in force when
/// neither was.
fn which_mode(args: &[String]) -> Result<bool, String> {
    let warden_mode = flag(args, "policy").is_some();
    for f in ["audit", "approvals", "agent"] {
        if flag(args, f).is_some() && !warden_mode {
            return Err(format!(
                "--{f} configures Warden core, which is only in force when --policy is given; \
                 without it this mediator runs standalone and --{f} would do nothing"
            ));
        }
    }
    #[cfg(not(feature = "warden-proxy"))]
    if warden_mode {
        return Err(
            "--policy selects Warden-core mode, which this binary was not built with; \
                    rebuild with --features warden-proxy, or omit --policy to run standalone"
                .to_string(),
        );
    }
    Ok(warden_mode)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return Ok(());
    }

    // Configuration is validated BEFORE any work. Deciding the mode after keys were parsed
    // and contracts loaded meant an operator who typo'd `--policy` on a standalone build was
    // told so only after half a startup — and, if an earlier step failed first, never told.
    let warden_mode = which_mode(&args)?;

    // --- connect configuration ---
    let mediator_id = required(&args, "mediator-id")?;
    // Required, not defaulted. A default would be the one value every estate shares, which is
    // the same as not checking — and `iss` went unchecked for exactly as long as nobody had to
    // name it. The failure for a wrong value is a startup refusal with the mismatch printed.
    let issuer_id = required(&args, "issuer-id")?;
    let caller = EntityId::new(required(&args, "caller")?).map_err(|e| e.to_string())?;
    let callee = EntityId::new(required(&args, "callee")?).map_err(|e| e.to_string())?;

    let mut trust = build_trust(&args)?;
    eprintln!("connect-mediate: issuer trust — {}", trust.describe(now()));

    // --- telemetry (P1 #11) -----------------------------------------------
    //
    // The decision log is the only place a refused call is visible: the control plane sees
    // issuance, and issuance stays healthy while every call in the estate is denied. It is
    // on by default at `notable` — denials and observe-mode findings — because a default of
    // `off` would mean the stream exists and nobody's deployment has it.
    let level = match flag(&args, "decision-log") {
        None => wc_core::obs::LogLevel::default(),
        Some(word) => wc_core::obs::LogLevel::parse(&word)
            .ok_or_else(|| format!("--decision-log {word:?} is not off, notable or all"))?,
    };
    let mut telemetry = wc_mediator::obs::Telemetry::new(level);
    if let Some(path) = flag(&args, "metrics-file") {
        telemetry = telemetry.with_metrics_file(path);
    }
    let telemetry = Arc::new(telemetry);

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
        let (keys, _) = trust.keys(now());
        let keys = keys.map_err(|e| e.to_string())?;
        let trusted = wc_mediator::cache::Trust {
            keys,
            mediator_id: &mediator_id,
            issuer: &issuer_id,
        };
        let snapshot = wc_mediator::cache::Snapshot::build(&inline, &trusted, now());
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
        let (keys, _) = trust.keys(now());
        let keys = keys.map_err(|e| e.to_string())?;
        let trusted = wc_mediator::cache::Trust {
            keys,
            mediator_id: &mediator_id,
            issuer: &issuer_id,
        };
        let report = client::refresh(client, &cache, &trusted, 0, 0, now())
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
        let loop_mediator = mediator_id.clone();
        let loop_issuer = issuer_id.clone();
        let loop_telemetry = Arc::clone(&telemetry);
        // The trust itself moves into the loop rather than being rebuilt from the PEM
        // here, which is what it used to be. Rebuilding meant the thread held a *copy*
        // of the startup trust: contracts refreshed every tick and the keys they were
        // checked against never did, so `--jwks-url` would have looked configured and
        // rotation would never have arrived. `KeySource::keys` refreshes at the call site
        // so that gap has nowhere to reopen.
        std::thread::spawn(move || {
            let mut trust = trust;
            let mut seq = 0u64;
            // Tracked separately from the contract-set seq: the revocation feed has its own
            // sequence, and asking for revocations "since the contract seq" would either
            // re-fetch the whole feed every time or skip entries.
            let mut rev_seq = 0u64;
            let mut last_kids: Vec<String> = Vec::new();
            loop {
                std::thread::sleep(Duration::from_secs(refresh_secs));
                let at = now();
                let (keys, key_failure) = trust.keys(at);
                if let Some(e) = key_failure {
                    // Not fatal on its own: the cached set is still being served. It
                    // stops being served at the staleness bound, and then `keys` below
                    // is the error that says so.
                    eprintln!("connect-mediate: issuer key set refresh failed: {e}");
                }
                let keys = match keys {
                    Ok(keys) => keys,
                    Err(e) => {
                        // Contracts are not pulled at all in this state. Pulling them
                        // would mean verifying against a trust set this process has
                        // already decided it cannot vouch for.
                        eprintln!("connect-mediate: not refreshing contracts — {e}");
                        continue;
                    }
                };
                let kids = keys.kids();
                if kids != last_kids {
                    // The one event an operator wants in the log: rotation landed, and
                    // what it landed as.
                    if !last_kids.is_empty() {
                        eprintln!(
                            "connect-mediate: issuer keys changed — was [{}], now [{}]",
                            last_kids.join(", "),
                            kids.join(", ")
                        );
                    }
                    last_kids = kids;
                }

                loop_telemetry.cache_state(
                    loop_cache.revocations().distrusted().is_none(),
                    // This loop only runs when there is a control plane, so a feed
                    // exists by construction.
                    true,
                    loop_cache.snapshot().len() as u64,
                );
                let trusted = wc_mediator::cache::Trust {
                    keys,
                    mediator_id: &loop_mediator,
                    issuer: &loop_issuer,
                };
                match client::refresh(&loop_client, &loop_cache, &trusted, seq, rev_seq, at) {
                    Ok(report) => {
                        seq = report.seq;
                        if let Some(rev) = &report.revocations {
                            rev_seq = rev.applied_seq;
                        }
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

    // The gauges, once the cache actually holds something, and a first flush so the metrics
    // file exists from second zero. Without that flush a mediator living less than the
    // interval writes **no file at all** — a per-task agent invocation is exactly that — and
    // the staleness alert cannot tell "never started" from "started recently".
    if cache.snapshot().has_rate_or_spend_ceiling() {
        // The ceiling is honoured exactly, within this process. `max_calls_per_hour` is
        // signed into the contract and reads as an estate-wide rate; the counter is in
        // memory, so a restart starts it again. Measured: a 3-per-hour contract executed
        // 3 calls per process and 9 across three processes inside one hour.
        eprintln!(
            "connect-mediate: NOTE a contract sets a rate or spend ceiling. Ceilings count \
             within THIS process — a restart resets them, so a short-lived per-task mediator \
             enforces a fraction of an hourly figure. Keep this process alive for the window \
             you are limiting, or treat the ceiling as per-invocation"
        );
    }

    let has_revocation_source = client.is_some();
    if !has_revocation_source {
        // Said out loud for the same reason `--peer-mode configured` is: this process
        // will serve its contracts until they expire and **no containment order can
        // reach it**. It used to report `wc_revocation_trusted 1` while in this state,
        // so neither the banner nor the metrics said anything at all.
        eprintln!(
            "connect-mediate: WARNING no revocation source — contracts came from disk and \
             quarantine fan-out cannot reach this mediator. Containment here is contract \
             expiry only; wc_revocation_source_configured is 0"
        );
    }
    telemetry.cache_state(
        cache.revocations().distrusted().is_none(),
        has_revocation_source,
        cache.snapshot().len() as u64,
    );
    telemetry.flush();

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

    cfg.telemetry = Arc::clone(&telemetry);

    // --- the gauges the alerts depend on ----------------------------------
    //
    // `wc_revocation_trusted` and `wc_contracts_held` were **declared and never set**, so
    // the `wc_revocation_trusted == 0` alert — the most important of the four, a mediator
    // refusing every connection — could never fire, because the series did not exist on a
    // real mediator. `Telemetry::cache_state` existed with no caller. Exactly the defect
    // class this component is about, in the telemetry meant to detect it.
    //
    // Reported after the contract set is installed and again on every refresh tick, because
    // both answers change: a set is installed, and a feed can become distrusted at any pull.
    // Written once now rather than only after the first tick. Without this a mediator that
    // lives less than the flush interval writes **no file at all** — and a per-task agent
    // invocation is exactly that. It also makes the staleness alert meaningful: absence can
    // then only mean "never started", not "started recently".
    telemetry.flush();

    // A file is only useful if something rewrites it. On its own thread rather than on the
    // request path: flushing per call would put a filesystem write between the agent and
    // its tool, which is a latency cost paid on every call to make a number fresher than
    // any scrape interval needs.
    if flag(&args, "metrics-file").is_some() {
        let flusher = Arc::clone(&telemetry);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(10));
            flusher.flush();
        });
    }
    eprintln!(
        "connect-mediate: decision log {}{}",
        level.as_str(),
        match flag(&args, "metrics-file") {
            Some(p) => format!(", metrics to {p}"),
            None => ", no metrics file".to_string(),
        }
    );

    // --- upstream: a spawned stdio child, or a remote MCP server over Streamable HTTP ---
    //
    // Both are the same seam. `MediatedUpstream` decorates whichever one is built, so every gate,
    // the catalogue filter and the ceilings apply identically — the transport does not change what
    // is enforced, only where the server lives.
    let upstream_timeout = Duration::from_secs(
        flag(&args, "upstream-timeout")
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
    );
    let real: Box<dyn Upstream + Send> =
        match (flag(&args, "upstream"), flag(&args, "upstream-url")) {
            // Two upstreams is two different beliefs about what is being mediated. Picking one by
            // precedence would mediate a server the operator did not mean to point at.
            (Some(_), Some(_)) => {
                return Err("--upstream and --upstream-url are mutually exclusive".to_string());
            }
            (None, None) => return Err("--upstream or --upstream-url is required".to_string()),
            (Some(cmd), None) => Box::new(
                StdioUpstream::spawn(&cmd, upstream_timeout)
                    .map_err(|e| format!("spawn upstream: {e}"))?,
            ),
            (None, Some(url)) => {
                check_upstream_url(&url, present(&args, "upstream-allow-plaintext"))?;
                let mut http = HttpUpstream::new(&url, upstream_timeout);
                for (i, _) in args
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| *a == "--upstream-header")
                {
                    let raw = args
                        .get(i + 1)
                        .ok_or_else(|| "--upstream-header expects a value".to_string())?;
                    let (name, value) = parse_upstream_header(raw)?;
                    http = http.with_header(name, value);
                }
                Box::new(http)
            }
        };

    let mediated =
        MediatedUpstream::new(real, Arc::clone(&cache), cfg).with_ceilings(Ceilings::new());

    eprintln!(
        "connect-mediate: mediating {caller} → {callee} as {mediator_id} ({:?}, {})",
        if present(&args, "observe") {
            Mode::Observe
        } else {
            Mode::Enforce
        },
        if warden_mode {
            "with Warden core"
        } else {
            "standalone — connection enforcement only, no per-action policy"
        }
    );

    #[cfg(feature = "warden-proxy")]
    if let Some(policy_path) = flag(&args, "policy") {
        // The binding *is* the mode check, so there is no `expect` restating an invariant a
        // few lines above — the compiler carries it instead of a comment.
        let policy = PolicyConfig::from_file(&policy_path).map_err(|e| e.to_string())?;
        let audit =
            AuditLog::new(flag(&args, "audit").unwrap_or_else(|| ".warden/audit.jsonl".into()));
        let approvals = Approvals::new(
            flag(&args, "approvals").unwrap_or_else(|| ".warden/approvals.json".into()),
        );
        let agent_label = flag(&args, "agent").unwrap_or_else(|| caller.as_str().to_string());
        let gateway = Arc::new(Gateway::new(
            policy,
            audit,
            approvals,
            &agent_label,
            Box::new(WardenBridge(mediated)),
            Duration::from_secs(300),
        ));
        let status = warden_loop(&gateway);
        gateway.checkpoint_audit();
        flush_usage(client.as_ref(), &cache);
        telemetry.flush();
        return status;
    }

    let status = standalone_loop(mediated);
    flush_usage(client.as_ref(), &cache);
    telemetry.flush();
    status
}

/// Report connection usage one last time before exiting (W10).
///
/// The refresh loop drains usage on its tick, so anything recorded between the last tick and
/// shutdown would be lost — and for a **per-task mediator**, which is a topology this project
/// already documents for its effect on ceilings, that is *all* of it: such a process serves a
/// handful of calls and exits, usually without ever ticking. Without this flush the
/// re-certification view would report every per-task connection as never used, which is the most
/// destructive way that data can be wrong.
///
/// Best effort. A failed final ack loses one window, and blocking shutdown on an unreachable
/// control plane would be worse: usage is a reporting signal, and losing a window makes a contract
/// look *less* used rather than more.
fn flush_usage(client: Option<&ControlPlaneClient>, cache: &Arc<Cache>) {
    let Some(client) = client else {
        return;
    };
    let used = cache.take_usage();
    if used.is_empty() {
        return;
    }
    let snapshot = cache.snapshot();
    let n = used.len();
    if client
        .ack(&snapshot.set_hash, snapshot.seq, &[], 0, &used)
        .is_err()
    {
        eprintln!("connect-mediate: final usage report for {n} connection(s) could not be sent");
    }
}

/// The stdio loop when there is no Warden core.
///
/// **Sequential, unlike the Warden-core loop**, and deliberately. That loop runs a thread per
/// request because a Warden approval can block for minutes waiting on a human, so other calls
/// must proceed past it. Nothing on this path blocks on a human: the gate's decisions are
/// local and its state machine is per-connection, so concurrency would buy nothing and cost
/// response ordering. One agent, one call at a time, answers in the order asked.
fn standalone_loop(mediated: MediatedUpstream) -> Result<(), String> {
    let mut mediated = mediated;
    let mut out = std::io::stdout();
    let stdin = std::io::stdin();

    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                // Skipped, not fatal: one malformed frame from an agent must not take down
                // a session that is otherwise healthy.
                eprintln!("connect-mediate: skipping unparseable line: {e}");
                continue;
            }
        };
        if req.is_notification() {
            mediated.notify(&req);
            continue;
        }
        let response = mediated.request(&req);
        if let Ok(line) = serde_json::to_string(&response) {
            let _ = writeln!(out, "{line}");
            let _ = out.flush();
        }
    }
    Ok(())
}

/// Bridges the mediator's `Upstream` to Warden core's, so Warden's proxy can still wrap it.
///
/// The two traits are the same two methods over wire-compatible types, which is what made
/// inverting the dependency cheap. This is the entire adapter.
#[cfg(feature = "warden-proxy")]
struct WardenBridge(MediatedUpstream);

#[cfg(feature = "warden-proxy")]
impl warden::upstream::Upstream for WardenBridge {
    fn request(&mut self, req: &warden::jsonrpc::Request) -> warden::jsonrpc::Response {
        let ours = Request {
            jsonrpc: req.jsonrpc.clone(),
            id: req.id.clone(),
            method: req.method.clone(),
            params: req.params.clone(),
        };
        let r = Upstream::request(&mut self.0, &ours);
        warden::jsonrpc::Response {
            jsonrpc: r.jsonrpc,
            id: r.id,
            result: r.result,
            error: r.error.map(|e| warden::jsonrpc::RpcError {
                code: e.code,
                message: e.message,
                data: e.data,
            }),
        }
    }

    fn notify(&mut self, req: &warden::jsonrpc::Request) {
        let ours = Request {
            jsonrpc: req.jsonrpc.clone(),
            id: req.id.clone(),
            method: req.method.clone(),
            params: req.params.clone(),
        };
        Upstream::notify(&mut self.0, &ours);
    }
}

/// The Warden-core stdio loop, unchanged in shape from before the inversion.
#[cfg(feature = "warden-proxy")]
fn warden_loop(gateway: &Arc<Gateway>) -> Result<(), String> {
    // A thread per request, unlike the standalone loop: a Warden approval can block for
    // minutes on a human, so other calls must be able to pass it.
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let stdin = std::io::stdin();
    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();

    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let req: warden::jsonrpc::Request = match serde_json::from_str(&line) {
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
        let gateway = Arc::clone(gateway);
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
    // `checkpoint_audit` and `telemetry.flush()` are the caller's, so both loops share one
    // shutdown path. Telemetry missing from that path was the asymmetry that once hid a bug:
    // the audit was durable on exit and the counters were not, so a mediator that exited
    // lost up to a full interval — and one that exited quickly lost everything.
    Ok(())
}
