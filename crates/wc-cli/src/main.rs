//! `connect` — the warden-connect control-plane CLI (`docs/08-lld.md` §8.5.11).
//!
//! The P0 surface: register and admit parties, inspect the estate, contain a
//! party, and prove the evidence chain is untampered. Every command is an
//! operator path, so every one of them records a lifecycle event.
//!
//! Exit codes are meaningful, because CI needs to tell the cases apart without
//! scraping stderr:
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | success |
//! | 1 | operational error (I/O, network, config) |
//! | 2 | usage error |
//! | 3 | policy decision: denied |
//! | 4 | verification failed (chain, contract, provenance) |
//! | 5 | screening block or material drift |
//! | 6 | approval required and not granted |

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod args;

use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::{json, Value};

use std::sync::Arc;
use wc_control::admission::{
    self, AdmissionRequest, Declared, InlineSurface, McpHttpSurface, SurfaceSource,
};
use wc_control::chain::{ANCHOR_FILE, ANCHOR_KID};
use wc_control::signer::CommandSigner;

use wc_control::api::{Api, ControlPlane};
use wc_control::assurance;
use wc_control::attest;
use wc_control::broker;
use wc_control::contain;
use wc_control::cpolicy::{self as cpolicy, ConnectPolicy, StandingState};
use wc_control::evidence::{EventKind, Evidence, LifecycleEvent};
use wc_control::export;
use wc_control::federate;
use wc_control::http::{self, Shutdown};
use wc_control::issuance::{
    self as issuance, ApprovalProof, ApproverRegistry, Issued, Issuer, Outcome, PendingRequest,
    RequestInput, RequestStatus,
};
use wc_control::screen;
use wc_control::store::{Actor, Store};
use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::contract::{
    self, Algorithm, ApprovalMode, IssuerKey, IssuerKeys, Surface, Terms, VerifyOpts,
};
use wc_core::error::{Category, Code, Mode, Result, WcError};
use wc_core::model::{Entity, EntityId, HumanRef, Kind, Lifecycle, Posture, Tier, ZoneId};

use args::Args;

/// Where state and evidence live, by default.
const DEFAULT_ROOT: &str = ".connect";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() || argv[0] == "--help" || argv[0] == "-h" || argv[0] == "help" {
        print!("{}", usage());
        return ExitCode::from(if argv.is_empty() { 2 } else { 0 });
    }

    let args = Args::parse(argv);
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(message)) => {
            eprintln!("connect: {message}\n");
            eprint!("{}", usage());
            ExitCode::from(2)
        }
        Err(Failure::Wc(e)) => {
            eprintln!("connect: {e}");
            if let Some(source) = std::error::Error::source(&e) {
                eprintln!("  caused by: {source}");
            }
            ExitCode::from(exit_code(e.code()))
        }
    }
}

/// Why a command did not run. A usage mistake is not an operational failure and
/// must not share its exit code — CI needs to tell "I typed it wrong" from
/// "the estate refused".
enum Failure {
    /// The command line itself was wrong.
    Usage(String),
    /// The command ran and the system said no.
    Wc(WcError),
}

impl From<WcError> for Failure {
    fn from(e: WcError) -> Failure {
        Failure::Wc(e)
    }
}

/// Map an error code to a process exit code (§8.5.11).
fn exit_code(code: Code) -> u8 {
    match code {
        Code::SCREENING_BLOCKED | Code::DRIFT_MATERIAL => 5,
        // A trust chain that does not verify is an untrustworthy artifact, which
        // is what exit 4 means everywhere else. A CI gate on a partner onboarding
        // bundle needs to tell that apart from "the file was unreadable".
        Code::FEDERATION_ANCHOR_UNKNOWN
        | Code::FEDERATION_CHAIN_INVALID
        | Code::FEDERATION_STATEMENT_EXPIRED
        | Code::FEDERATION_METADATA_WIDENED => 4,
        // Overdue re-verification is not an invalid chain — it is a refusal to
        // issue against a valid one, which is a policy-shaped decision.
        Code::FEDERATION_ANCHOR_STALE => 3,
        // On the CLI there is no credential to bind against, so the only way to
        // reach this is a malformed `--tenant` — which is a usage error, not an
        // I/O one. The API maps the same code to 404 for the cross-tenant case.
        Code::TENANT_UNKNOWN => 2,
        Code::QUARANTINE_DUAL_CONTROL_MISSING | Code::APPROVER_ROLE_MISSING => 6,
        Code::CHAIN_BROKEN
        | Code::PROVENANCE_UNVERIFIABLE
        | Code::CARD_SIGNATURE_INVALID
        | Code::IDENTITY_UNVERIFIABLE => 4,
        Code::POLICY_DENIED | Code::ENTITY_QUARANTINED => 3,
        _ => match code.category() {
            // Every WC-31xx code is a contract that failed to verify — an expired
            // artifact and a bad signature are the same class of answer, and CI
            // should not have to distinguish them from an I/O error.
            Category::Verification => 4,
            // A policy-shaped refusal is a decision, not a malfunction.
            Category::ContractLifecycle => 3,
            _ => 1,
        },
    }
}

/// Commands that take two words, so a trailing positional id is never mistaken
/// for part of the command.
const TWO_WORD: &[&str] = &[
    "register server",
    "register agent",
    "audit verify",
    "policy lint",
    "policy dry-run",
    "policy show",
    "keys list",
    "keys new",
    "keys add",
    "keys rotate",
    "keys retire",
    "keys jwks",
    "keys note",
    "bundle export",
    "bundle verify",
    "caep ingest",
];

/// Every dispatchable command.
const COMMANDS: &[&str] = &[
    "register server",
    "register agent",
    "activate",
    "entities",
    "show",
    "posture",
    "discover",
    "blast-radius",
    "quarantine",
    "mediators",
    "federate",
    "keys list",
    "keys new",
    "keys add",
    "keys rotate",
    "keys retire",
    "keys jwks",
    "keys note",
    "bundle export",
    "bundle verify",
    "bench",
    "caep ingest",
    "tenants",
    "audit verify",
    "canon",
    "screen",
    "export",
    "verify",
    "policy lint",
    "policy dry-run",
    "policy show",
    "request",
    "approve",
    "deny",
    "requests",
    "contracts",
    "breakglass",
    "serve",
    "version",
];

/// Flags accepted by every command.
const GLOBAL_FLAGS: &[&str] = &[
    "root",
    "tenant",
    "by",
    "json",
    "anchor-key",
    "anchor-signer",
    "anchor-interval",
    "require-external-signing",
];

/// Flags accepted per command, beyond the global ones.
///
/// Unknown flags are a **usage error**, never ignored. A silently-dropped
/// `--anchor-ky` would leave an operator believing their evidence was anchored
/// when it was not, which is worse than any typo.
fn accepted_flags(command: &str) -> &'static [&'static str] {
    match command {
        "register server" => &[
            "endpoint",
            "surface",
            "id",
            "owner",
            "zone",
            "tier",
            "service",
            "data-classes",
            "jurisdictions",
            "enforce",
            "screen-rules",
            "acceptances",
            "screen-mode",
            "svid",
            "trust-key",
            "aud",
            "leeway",
            "card-key",
            "require-card-signature",
            "attest",
            "prov-key",
            "artifact-digest",
            "bind-surface",
            "builder",
        ],
        "register agent" => &[
            "card",
            "endpoint",
            "id",
            "owner",
            "zone",
            "tier",
            "service",
            "data-classes",
            "jurisdictions",
            "enforce",
            "screen-rules",
            "acceptances",
            "screen-mode",
            "svid",
            "trust-key",
            "aud",
            "leeway",
            "card-key",
            "require-card-signature",
            "attest",
            "prov-key",
            "artifact-digest",
            "bind-surface",
            "builder",
        ],
        "activate" => &["id", "why"],
        "quarantine" => &[
            "id",
            "reason",
            "approver",
            "revocation-key",
            "kid",
            "mediators",
            "federate",
            "tenants",
            "ack-deadline",
            "push-token",
        ],
        "mediators" => &["mediators", "revocation-pub", "kid"],
        "federate" => &["anchors", "chain", "now", "leeway"],
        "tenants" => &["registry"],
        "keys list" => &["keyring"],
        "keys new" => &["keyring", "kid", "alg", "out"],
        "keys add" => &["keyring", "kid", "alg", "public", "private-ref"],
        "keys rotate" => &["keyring", "kid"],
        "keys retire" => &["keyring", "kid"],
        "keys jwks" => &["keyring", "out"],
        "keys note" => &["keyring", "kid", "exp"],
        "bundle export" => &[
            "mediator",
            "keyring",
            "signing-key",
            "kid",
            "ttl",
            "out",
            "contracts",
        ],
        "bundle verify" => &[
            "file",
            "envelope-pub",
            "issuer-pub",
            "kid",
            "mediator",
            "now",
        ],
        "bench" => &[
            "iterations",
            "gate",
            "signing-key",
            "verify-pub",
            "kid",
            "scale",
        ],
        "caep ingest" => &["file", "transmitters", "now"],
        "show" => &["id"],
        "entities" => &[],
        "posture" => &["unattested", "expiring", "drift", "score", "id"],
        "discover" => &[
            "capability",
            "as",
            "jurisdiction",
            "data-class",
            "policy",
            "limit",
        ],
        "blast-radius" => &["id", "depth", "services"],
        "audit verify" => &["anchor-pub"],
        "export" => &["format", "as-of", "id", "anchor-pub", "out"],
        "canon" => &["file", "kind", "entity", "document"],
        "screen" => &[
            "file",
            "kind",
            "entity",
            "rules",
            "acceptances",
            "mode",
            "tier",
            "estate",
        ],
        "verify" => &[
            "file",
            "issuer-pub",
            "jwks",
            "kid",
            "alg",
            "mediator-id",
            "now",
            "leeway",
        ],
        "policy lint" | "policy show" => &["policy"],
        "policy dry-run" => &["policy", "now"],
        "request" => &[
            "enforce",
            "from",
            "to",
            "tools",
            "skills",
            "resources",
            "justify",
            "ttl",
            "mediator",
            "data-classes",
            "jurisdictions",
            "policy",
            "issuer-key",
            "signer",
            "kid",
            "iss",
            "out",
        ],
        "approve" => &[
            "enforce",
            "id",
            "approvers",
            "approver-key",
            "second-key",
            "second",
            "ticket",
            "policy",
            "issuer-key",
            "signer",
            "kid",
            "iss",
            "out",
        ],
        "deny" => &["id", "reason", "policy"],
        "serve" => &[
            "listen",
            "behind-tls-proxy",
            "trusted-proxy",
            "insecure-plaintext",
            "policy",
            "issuer-key",
            "signer",
            "kid",
            "iss",
            "jwks",
            "tokens",
            "approvers",
            "enforce",
        ],
        "breakglass" => &[
            "from",
            "to",
            "tools",
            "skills",
            "resources",
            "ttl",
            "incident",
            "justify",
            "mediator",
            "by",
            "approver-key",
            "second",
            "second-key",
            "issuer-key",
            "signer",
            "kid",
            "out",
            "max-ttl",
            "budget",
            "window",
        ],
        "requests" => &["all"],
        "contracts" => &["cid"],
        _ => &[],
    }
}

/// Reject any flag the command does not accept.
fn check_flags(command: &str, args: &Args) -> std::result::Result<(), Failure> {
    let accepted = accepted_flags(command);
    let unknown: Vec<&str> = args
        .flags
        .keys()
        .map(String::as_str)
        .filter(|k| !GLOBAL_FLAGS.contains(k) && !accepted.contains(k))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(Failure::Usage(format!(
        "`{command}` does not accept: {}\n  accepted here: {}\n  global: {}",
        unknown
            .iter()
            .map(|f| format!("--{f}"))
            .collect::<Vec<_>>()
            .join(", "),
        accepted
            .iter()
            .map(|f| format!("--{f}"))
            .collect::<Vec<_>>()
            .join(", "),
        GLOBAL_FLAGS
            .iter()
            .map(|f| format!("--{f}"))
            .collect::<Vec<_>>()
            .join(", "),
    )))
}

fn dispatch(args: &Args) -> std::result::Result<(), Failure> {
    // `connect activate <id>` puts the id in `verbs`, because it precedes any
    // flag. So match on at most the first two words and let the handler take the
    // rest as positional — matching on the whole joined verb path would make
    // every id look like part of the command.
    let two = args.verb_prefix(2);
    let one = args.verb_prefix(1);
    let command = if TWO_WORD.contains(&two.as_str()) {
        two.as_str()
    } else {
        one.as_str()
    };

    // Command shape first, then flags: told `register --owner x`, an operator
    // needs to hear "register needs a subject", not a complaint about the flag.
    if !COMMANDS.contains(&command) {
        return Err(Failure::Usage(match command {
            "register" => {
                "`register` needs a subject: `register server` or `register agent`".to_string()
            }
            "audit" => "`audit` needs a subject: `audit verify`".to_string(),
            "keys" => "`keys` needs a subject: list, new, add, rotate, retire or jwks".to_string(),
            other => format!("unknown command {other:?}"),
        }));
    }
    check_flags(command, args)?;
    // Before any command touches the filesystem. A tenant id is a path component,
    // so validating it once here is what keeps every later `paths()` call honest.
    tenant_id(args)?;

    match command {
        "register server" => register_server(args)?,
        "register agent" => register_agent(args)?,
        "activate" => activate(args)?,
        "entities" => entities(args)?,
        "show" => show(args)?,
        "posture" => posture(args)?,
        "discover" => discover_cmd(args)?,
        "blast-radius" => blast_radius_cmd(args)?,
        "quarantine" => quarantine(args)?,
        "mediators" => mediators_cmd(args)?,
        "federate" => federate_cmd(args)?,
        "tenants" => tenants_cmd(args)?,
        "keys list" => keys_list(args)?,
        "keys new" => keys_new(args)?,
        "keys add" => keys_add(args)?,
        "keys rotate" => keys_rotate(args)?,
        "keys retire" => keys_retire(args)?,
        "keys jwks" => keys_jwks(args)?,
        "keys note" => keys_note(args)?,
        "bundle export" => bundle_export(args)?,
        "bundle verify" => bundle_verify(args)?,
        "bench" => bench_cmd(args)?,
        "caep ingest" => caep_ingest(args)?,
        "audit verify" => audit_verify(args)?,
        "canon" => canon_cmd(args)?,
        "screen" => screen_cmd(args)?,
        "verify" => verify_cmd(args)?,
        "policy lint" => policy_lint(args)?,
        "policy dry-run" => policy_dry_run(args)?,
        "policy show" => policy_show(args)?,
        "request" => request_cmd(args)?,
        "approve" => approve_cmd(args)?,
        "deny" => deny_cmd(args)?,
        "serve" => serve_cmd(args)?,
        "breakglass" => breakglass_cmd(args)?,
        "requests" => requests_cmd(args)?,
        "contracts" => contracts_cmd(args)?,
        "export" => export(args)?,
        "version" => println!("connect {}", env!("CARGO_PKG_VERSION")),
        // Unreachable: COMMANDS is checked above, and this match covers it.
        other => return Err(Failure::Usage(format!("unhandled command {other:?}"))),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

/// Tenant-scoped paths (§8.8.1).
struct Paths {
    state: PathBuf,
    evidence: PathBuf,
    /// The signed revocation feed mediators pull. Beside the state, not inside the
    /// evidence chain: the chain records what happened, this instructs.
    revocations: PathBuf,
    /// Durable per-mediator acknowledgement state.
    acks: PathBuf,
}

/// The tenant this invocation acts on.
///
/// Validated, because it becomes a path component. An unvalidated `--tenant
/// '../../../../tmp/elsewhere'` wrote the estate's state outside the root — found
/// by running exactly that against the release binary.
fn tenant_id(args: &Args) -> Result<wc_control::tenant::TenantId> {
    let raw = args
        .get("tenant")
        .map(str::to_string)
        .or_else(|| std::env::var("WARDEN_CONNECT_TENANT").ok());
    match raw {
        Some(name) => wc_control::tenant::TenantId::new(name),
        None => Ok(wc_control::tenant::TenantId::default_tenant()),
    }
}

/// Paths for this invocation's tenant.
///
/// Fails closed on an invalid tenant rather than falling back to `default`: a
/// fallback would silently operate on the wrong estate, which is worse than
/// refusing.
fn paths_checked(args: &Args) -> Result<Paths> {
    let root = args
        .get("root")
        .map(PathBuf::from)
        .or_else(|| std::env::var("WARDEN_CONNECT_ROOT").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT));
    let derived = wc_control::tenant::TenantPaths::new(&root, &tenant_id(args)?);
    Ok(Paths {
        state: derived.state,
        evidence: derived.evidence,
        revocations: derived.revocations,
        acks: derived.acks,
    })
}

/// Paths, panicking-free but tenant-unchecked callers use this.
///
/// Kept as a thin wrapper so the many call sites stay readable; the validation
/// happens in `paths_checked` and an invalid tenant can never reach the
/// filesystem because every entry point runs `check_tenant` first.
fn paths(args: &Args) -> Paths {
    paths_checked(args).unwrap_or_else(|_| {
        // Unreachable: `dispatch` validates the tenant before any command runs.
        // Returning a path under an obviously-invalid directory rather than the
        // real root means even a future caller that bypasses dispatch cannot
        // write somewhere it should not.
        Paths {
            state: PathBuf::from("/nonexistent/invalid-tenant/state"),
            evidence: PathBuf::from("/nonexistent/invalid-tenant/evidence"),
            revocations: PathBuf::from("/nonexistent/invalid-tenant/revocations.jsonl"),
            acks: PathBuf::from("/nonexistent/invalid-tenant/acks.json"),
        }
    })
}

/// Open the state store, reporting a rebuild that was not clean rather than
/// letting it pass silently.
fn open_store(args: &Args) -> Result<Store> {
    let p = paths(args);
    let (store, report) = Store::open(&p.state)?;
    if !report.is_clean() {
        eprintln!(
            "connect: warning: state rebuild not clean — {} applied, {} unknown, {} inconsistent{}",
            report.applied,
            report.unknown,
            report.inconsistent.len(),
            if report.truncated_tail {
                ", truncated tail"
            } else {
                ""
            }
        );
        for problem in report.inconsistent.iter().take(5) {
            eprintln!("  {problem}");
        }
    }
    Ok(store)
}

/// What the transport must prove before a bearer token is believed.
///
/// `connect serve` speaks plain HTTP, deliberately: TLS is terminated in front of it in
/// every topology `docs/physical-architecture.md` describes, and an in-process listener
/// would be a security-critical code path almost nobody would use.
///
/// What was not deliberate is that nothing stopped a non-loopback bind from accepting
/// approval tokens in clear. The plan said a terminating proxy was mandatory and the
/// binary had no opinion, which is the shape of every other defect found in this
/// repository: a control that exists in a document.
fn transport_policy(args: &Args, listen: &str) -> Result<wc_control::api::Transport> {
    if args.has("insecure-plaintext") {
        // Offered, because a test rig and a local demo are real, and an operator who
        // cannot say "yes I mean it" reaches for something worse. Named so it appears
        // in the process list and in the banner.
        return Ok(wc_control::api::Transport::Insecure);
    }

    let trusted: Vec<std::net::IpAddr> = args
        .list("trusted-proxy")
        .iter()
        .map(|raw| {
            raw.parse().map_err(|_| {
                WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("--trusted-proxy {raw:?} is not an IP address"),
                )
            })
        })
        .collect::<Result<_>>()?;

    if args.has("behind-tls-proxy") {
        return Ok(wc_control::api::Transport::TlsProxy { trusted });
    }
    if !trusted.is_empty() {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            "--trusted-proxy is only meaningful with --behind-tls-proxy; \
             a trusted address that is not trusted for anything is a typo",
        ));
    }

    // The refusal. Parsed and asked `is_loopback`, never string-matched: `127.0.0.1
    // .evil.example` starts with "127." and is not loopback, which is a bug this
    // codebase has already fixed once in `wc_mediator::peer`.
    let host = listen.rsplit_once(':').map_or(listen, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false);
    if !loopback {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!(
                "--listen {listen} is not loopback, and bearer tokens would cross the \
                 network in clear. Terminate TLS in front and pass --behind-tls-proxy \
                 (with --trusted-proxy ADDR for the proxy), or --insecure-plaintext if \
                 you mean it"
            ),
        ));
    }
    Ok(wc_control::api::Transport::Loopback)
}

/// The evidence chain, with an anchor key when one is configured.
fn open_evidence(args: &Args) -> Result<Evidence> {
    let p = paths(args);
    let interval = args.number("anchor-interval").unwrap_or(100);

    // Posture before I/O. A refusal to run with a key on disk must not require first
    // opening — and locking — the chain it is refusing to sign.
    if external_signing_required(args) {
        if let Some(key_path) = args.get("anchor-key") {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "--require-external-signing is set and --anchor-key {key_path} is a key \
                     on this disk; use --anchor-signer COMMAND"
                ),
            ));
        }
    }

    let evidence = Evidence::open(&p.evidence)?;

    // The anchor is the first key that should leave this host: a checkpoint signed by
    // a key the control plane holds proves only that the control plane agrees with
    // itself, which is precisely what an anchor exists to rule out.
    if let Some(command) = args.get("anchor-signer") {
        if args.get("anchor-key").is_some() {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "--anchor-signer and --anchor-key both given; which key anchors the \
                 evidence must not be a guess",
            ));
        }
        let key = CommandSigner::parse(command)?.into_issuer_key(ANCHOR_KID, Algorithm::ES256)?;
        return Ok(evidence.with_anchor_signer(key, p.evidence.join(ANCHOR_FILE), interval));
    }

    match args.get("anchor-key") {
        Some(key_path) => {
            let key = std::fs::read(key_path).map_err(|e| {
                WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("cannot read anchor key {key_path}"),
                )
                .with_source(e)
            })?;
            evidence.with_anchor(&key, p.evidence.join(ANCHOR_FILE), interval)
        }
        None => Ok(evidence),
    }
}

/// The acting operator. Required for anything that writes, because an entity
/// with no accountable actor is exactly what invariant 1 exists to prevent.
fn actor(args: &Args) -> Result<Actor> {
    match args.get("by") {
        Some(id) => Ok(Actor::Human {
            id: HumanRef::new(id)?,
        }),
        None => match std::env::var("WARDEN_CONNECT_ACTOR") {
            Ok(id) => Ok(Actor::Human {
                id: HumanRef::new(id)?,
            }),
            Err(_) => Ok(Actor::Service {
                id: "cli".to_string(),
            }),
        },
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn require<'a>(args: &'a Args, flag: &str) -> Result<&'a str> {
    args.get(flag)
        .ok_or_else(|| WcError::with_detail(Code::CONFIG_INVALID, format!("--{flag} is required")))
}

fn mode(args: &Args) -> Mode {
    if args.has("enforce") {
        Mode::Enforce
    } else {
        // P0 is an observe-mode wedge: visibility before enforcement.
        Mode::Observe
    }
}

/// Render JSON for output.
///
/// Deliberately a local helper rather than `impl From<serde_json::Error> for
/// WcError`: a blanket conversion would pick the error code on the caller's
/// behalf, and the right code depends entirely on what was being serialised.
fn pretty(value: &Value) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| {
        WcError::with_detail(Code::EXPORT_FAILED, "cannot render output as json").with_source(e)
    })
}

fn read_json(path: &str) -> Result<Value> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
    })?;
    serde_json::from_str(&text).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("{path} is not JSON")).with_source(e)
    })
}

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------

fn declared(args: &Args) -> Result<Declared> {
    let requested_tier = match args.number("tier") {
        Some(t) => Some(Tier::new(u8::try_from(t).unwrap_or(255))?),
        None => None,
    };
    Ok(Declared {
        data_classes: args.list("data-classes"),
        jurisdictions: args.list("jurisdictions"),
        requested_tier,
        service: args.get("service").map(str::to_string),
    })
}

fn register_server(args: &Args) -> Result<()> {
    let endpoint = require(args, "endpoint")?.to_string();
    let request = AdmissionRequest {
        kind: Kind::McpServer,
        id: match args.get("id") {
            Some(id) => Some(EntityId::new(id)?),
            None => Some(EntityId::new(derive_urn(&endpoint))?),
        },
        card: None,
        endpoint: Some(endpoint),
        attestation: Vec::new(),
        owner: HumanRef::new(require(args, "owner")?)?,
        zone: ZoneId::new(require(args, "zone")?)?,
        declared: declared(args)?,
        mode: mode(args),
    };

    // A surface handed in on the command line (CI already has it) or fetched with
    // a real MCP handshake. Either way stage 2 must succeed: nothing is pinned on
    // trust.
    let inline;
    let http;
    let source: &dyn SurfaceSource = match args.get("surface") {
        Some(path) => {
            inline = InlineSurface::new(SurfaceKind::McpTools, read_json(path)?);
            &inline
        }
        None => {
            http = McpHttpSurface::default();
            &http
        }
    };

    admit_and_record(args, &request, source)
}

fn register_agent(args: &Args) -> Result<()> {
    let card_path = require(args, "card")?;
    let card = read_json(card_path)?;
    let request = AdmissionRequest {
        kind: Kind::Agent,
        id: match args.get("id") {
            Some(id) => Some(EntityId::new(id)?),
            None => Some(EntityId::new(derive_urn(card_path))?),
        },
        card: Some(card.clone()),
        endpoint: args.get("endpoint").map(str::to_string),
        attestation: Vec::new(),
        owner: HumanRef::new(require(args, "owner")?)?,
        zone: ZoneId::new(require(args, "zone")?)?,
        declared: declared(args)?,
        mode: mode(args),
    };
    let source = InlineSurface::new(SurfaceKind::A2aCard, card);
    admit_and_record(args, &request, &source)
}

/// Load a set of trusted public keys from repeated `KID=PATH[:ALG]` arguments.
///
/// Empty is returned as empty rather than as an error: the caller decides whether
/// an unconfigured trust set means "skip this stage" or "refuse". What is never
/// allowed is a key that fails to load being quietly dropped.
fn key_set(args: &Args, flag: &str) -> Result<IssuerKeys> {
    let mut keys = IssuerKeys::new();
    for spec in args.list(flag) {
        let (kid, rest) = spec.split_once('=').ok_or_else(|| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("--{flag} expects KID=PATH[:ALG], got {spec:?}"),
            )
        })?;
        // Split the algorithm off the right, so a Windows-style path or a colon in
        // a directory name cannot be mistaken for one.
        let (path, alg) = match rest.rsplit_once(':') {
            Some((p, a)) if matches!(a, "ES256" | "ES384" | "EdDSA" | "Ed25519") => (p, a),
            _ => (rest, "ES256"),
        };
        let pem = std::fs::read(path).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
        })?;
        match alg {
            "ES256" => keys.add_ec_pem(kid, &pem, Algorithm::ES256)?,
            "ES384" => keys.add_ec_pem(kid, &pem, Algorithm::ES384)?,
            "EdDSA" | "Ed25519" => keys.add_ed_pem(kid, &pem)?,
            other => {
                return Err(WcError::with_detail(
                    Code::ALG_NOT_ASYMMETRIC,
                    format!("{other:?} is not an accepted algorithm"),
                ))
            }
        }
    }
    Ok(keys)
}

/// Read the DSSE envelopes named by `--attest`.
fn attestation_envelopes(args: &Args) -> Result<Vec<serde_json::Value>> {
    args.list("attest").iter().map(|p| read_json(p)).collect()
}

/// Tool names already registered in this estate, keyed to their owner.
///
/// This is what makes S2's collision half and S6's cross-entity half real at
/// admission: without it a typosquat on another server's tool name cannot be
/// detected, because there is nothing to collide with. Built from the pins the
/// registry already holds, so it costs one projection read.
fn estate_names(args: &Args) -> Result<screen::NameIndex> {
    let mut index = screen::NameIndex::empty();
    let store = match open_store(args) {
        Ok(s) => s,
        // A first registration into an empty root has no estate to compare
        // against. That is not an error, but the screening report must say the
        // collision half did not run — which it does, from an empty index.
        Err(_) => return Ok(index),
    };
    for (id, entity) in &store.projection.entities {
        for tool in entity.pin.items.keys() {
            index.insert(tool, id.clone());
        }
    }
    Ok(index)
}

/// Run admission, write the entity, and record what happened — including every
/// stage that was skipped.
fn admit_and_record(
    args: &Args,
    request: &AdmissionRequest,
    source: &dyn SurfaceSource,
) -> Result<()> {
    let ts = now();

    // Screening is on by default with the built-in ruleset. It ships
    // uncalibrated, so it cannot block anything — but the alternative is that
    // most registrations are never screened at all, and a control that is
    // available rather than active protects nobody.
    let rules = match args.get("screen-rules") {
        Some(p) => screen::ScreenRules::load(std::path::Path::new(p))?,
        None => screen::ScreenRules::default(),
    };
    let acceptances = match args.get("acceptances") {
        Some(p) => screen::Acceptances::load(std::path::Path::new(p))?,
        None => screen::Acceptances::default(),
    };
    let names = estate_names(args)?;
    let screener = screen::RulesetScreener {
        rules: &rules,
        acceptances: &acceptances,
        names: &names,
        mode: screen::ScreenMode::parse(args.get("screen-mode").unwrap_or("flag"))?,
        limits: Limits::default(),
    };

    let mut ctx = admission::observe_ctx(source, ts);
    ctx.screener = &screener;

    // --- stages 1, 3 and 4: real verifiers when material is supplied ---------
    //
    // Each stage stays on its P0 stand-in unless the operator supplied what it
    // needs. The stand-ins report `Skipped`, which keeps the party
    // `Unattested` — so an unconfigured stage is visible in `connect posture`
    // rather than passing by omission.

    let trust_keys = key_set(args, "trust-key")?;
    let card_keys = key_set(args, "card-key")?;
    let prov_keys = key_set(args, "prov-key")?;
    let envelopes = attestation_envelopes(args)?;

    let svid_identity = match args.get("svid") {
        Some(path) => {
            let token = std::fs::read_to_string(path)
                .map_err(|e| {
                    WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}"))
                        .with_source(e)
                })?
                .trim()
                .to_string();
            Some(attest::JwtSvidIdentity {
                keys: &trust_keys,
                // No default: an unset audience would make the check vacuous, so
                // the verifier refuses rather than accepting a token minted for
                // anyone.
                audience: args.get("aud").unwrap_or_default().to_string(),
                token,
                leeway: args.number("leeway").unwrap_or(60),
                // The same instant the rest of admission is judged at, not the wall
                // clock. `ctx.now` is what a replay would supply, and a validity
                // window checked against a different clock than the stages around it
                // is a window checked against nothing in particular.
                now: ctx.now,
            })
        }
        None => None,
    };
    if let Some(v) = &svid_identity {
        ctx.identity = v;
    }

    let card_verifier = if card_keys.is_empty() {
        None
    } else {
        Some(attest::JwksCardVerifier {
            keys: &card_keys,
            require_signature: args.has("require-card-signature"),
        })
    };
    if let Some(v) = &card_verifier {
        ctx.card = v;
    }

    // Provenance is bound to something concrete or it is not provenance. Either
    // the operator names the artifact digest, or `--bind-surface` binds it to the
    // surface manifest being pinned — which is the honest option for a party with
    // no container digest to hand.
    let artifact_digest = match args.get("artifact-digest") {
        Some(d) => Some(d.to_string()),
        None if args.has("bind-surface") => {
            let fetched = source.fetch_surface(request)?;
            let subject = request.id.clone().unwrap_or_else(|| {
                EntityId::new(screen::SCREENING_SUBJECT).unwrap_or_else(|_| unreachable!())
            });
            Some(attest::surface_artifact_digest(
                fetched.kind,
                &subject,
                &fetched.raw,
            )?)
        }
        None => None,
    };
    let prov_verifier = if envelopes.is_empty() && prov_keys.is_empty() {
        None
    } else {
        Some(attest::DsseProvenanceVerifier {
            keys: &prov_keys,
            envelopes,
            artifact_digest,
            allowed_builders: args.list("builder").into_iter().collect(),
        })
    };
    if let Some(v) = &prov_verifier {
        ctx.provenance = v;
    }
    let outcome = match admission::admit(request, &ctx) {
        Ok(o) => o,
        Err(e) => {
            // A refusal is evidence too: an estate that only records successes
            // cannot show what it turned away.
            let mut evidence = open_evidence(args)?;
            let _ = evidence.record(
                &LifecycleEvent::new(EventKind::AdmissionDenied, actor_id(args))
                    .with_reason(e.to_string())
                    .with_detail(json!({"mode": format!("{:?}", request.mode)})),
                ts,
            );
            return Err(e);
        }
    };

    let mut store = open_store(args)?;
    let entity = store
        .registry(actor(args)?, ts)
        .put(outcome.entity.clone())?;

    let mut evidence = open_evidence(args)?;
    let recorded = evidence.record(
        &LifecycleEvent::new(EventKind::Register, actor_id(args))
            .with_entities([entity.id.as_str()])
            .with_reason(outcome.tier_rationale.clone())
            .with_detail(json!({
                "kind": format!("{:?}", entity.kind),
                "zone": entity.zone.as_str(),
                "tier": entity.tier.as_u8(),
                "posture": format!("{:?}", entity.posture),
                "pin": entity.pin.manifest,
                "items": entity.pin.items.len(),
                "stages": outcome.stages.iter().map(|s| json!({
                    "stage": format!("{:?}", s.stage),
                    "verdict": format!("{:?}", s.verdict),
                })).collect::<Vec<_>>(),
                // Findings belong in the record, not only on the terminal: an
                // admission that raised a screening hit and stored no trace of it
                // cannot be reviewed later.
                "findings": outcome.findings.iter().map(|f| json!({
                    "code": f.code.to_string(),
                    "severity": format!("{:?}", f.severity),
                    "detail": f.detail,
                })).collect::<Vec<_>>(),
            })),
        ts,
    )?;

    for warning in &recorded.warnings {
        eprintln!("connect: warning: {warning}");
    }

    if args.has("json") {
        println!("{}", pretty(&entity_json(&entity))?);
        return Ok(());
    }

    println!("registered {}", entity.id);
    println!("  kind      {:?}", entity.kind);
    println!("  owner     {}", entity.owner);
    println!(
        "  zone      {}  ({:?})",
        entity.zone,
        entity.zone.trust_level()
    );
    println!("  tier      {}", entity.tier);
    println!("  posture   {:?}", entity.posture);
    println!("  pin       {}", entity.pin.manifest);
    println!("  items     {}", entity.pin.items.len());
    println!(
        "  lifecycle {:?}  (registration is not connectivity)",
        entity.lifecycle
    );
    println!("  why       {}", outcome.tier_rationale);

    // A finding that nobody is shown is a control nobody has. Screening runs on
    // every registration, so if this is silent the whole stage may as well not
    // exist.
    if !outcome.findings.is_empty() {
        println!("\n  findings");
        for f in &outcome.findings {
            println!(
                "    {:<9} {:<8} {}",
                f.code.to_string(),
                format!("{:?}", f.severity),
                f.detail
            );
        }
    }

    let skipped = outcome.skipped();
    if !skipped.is_empty() {
        println!("\n  not verified: {skipped:?}");
        println!(
            "  posture is {:?} until these are configured",
            entity.posture
        );
    }
    println!(
        "\nevidence seq {} ({})",
        recorded.seq,
        &recorded.row_hash[..16]
    );
    Ok(())
}

fn actor_id(args: &Args) -> String {
    args.get("by")
        .map(str::to_string)
        .or_else(|| std::env::var("WARDEN_CONNECT_ACTOR").ok())
        .unwrap_or_else(|| "service:cli".to_string())
}

/// A stable urn for a party whose identity was not supplied. Content-addressed so
/// re-registering the same endpoint resolves to the same entity.
fn derive_urn(seed: &str) -> String {
    format!("urn:wc:{}", &wc_core::util::sha256_hex(seed)[..24])
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

fn activate(args: &Args) -> Result<()> {
    let id = EntityId::new(positional_or_flag(args, "id")?)?;
    let ts = now();
    let mut store = open_store(args)?;
    store.registry(actor(args)?, ts).transition(
        &id,
        Lifecycle::Active,
        args.get("why").unwrap_or("admitted"),
    )?;

    let mut evidence = open_evidence(args)?;
    let recorded = evidence.record(
        &LifecycleEvent::new(EventKind::Admit, actor_id(args))
            .with_entities([id.as_str()])
            .with_reason(args.get("why").unwrap_or("admitted").to_string()),
        ts,
    )?;
    println!("{id} is now active (evidence seq {})", recorded.seq);
    Ok(())
}

fn quarantine(args: &Args) -> Result<()> {
    let id = EntityId::new(positional_or_flag(args, "id")?)?;
    let reason = require(args, "reason")?.to_string();
    let reason_for_feed = reason.clone();
    let approvers: Vec<HumanRef> = args
        .list("approver")
        .into_iter()
        .map(HumanRef::new)
        .collect::<Result<Vec<_>>>()?;

    let ts = now();
    let mut store = open_store(args)?;
    let outcome = store
        .registry(actor(args)?, ts)
        .quarantine(&id, &reason, &approvers)?;

    let mut evidence = open_evidence(args)?;
    let recorded = evidence.record(
        &LifecycleEvent::new(EventKind::Quarantine, actor_id(args))
            .with_entities([id.as_str()])
            .with_reason(reason)
            .with_detail(json!({
                "revoked": outcome.revoked.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                "impacted_services": outcome.impacted_services,
                "approvers": approvers.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
            })),
        ts,
    )?;

    // --- reach the data plane, and refuse to overstate how far it got ------
    //
    // The registry transition above is the control plane's own state. The party
    // keeps working until every mediator holding one of its contracts stops
    // honouring it, so the interesting output is which mediators have confirmed.
    let mediator_set = match args.get("mediators") {
        Some(path) => contain::MediatorSet::load(std::path::Path::new(path))?,
        None => contain::MediatorSet::default(),
    };
    let containment = match args.get("revocation-key") {
        Some(key_path) => {
            let key = load_issuer_key(key_path, require(args, "kid")?, args.get("alg"))?;
            let p = paths(args);
            let mut feed = contain::RevocationFeed::open(&p.revocations)?;
            let mut ledger = contain::AckLedger::open(&p.acks)?;
            let push: Box<dyn contain::Push> = match args.get("push-token") {
                Some(token) => Box::new(contain::HttpPush {
                    token: token.to_string(),
                    ..contain::HttpPush::default()
                }),
                // No token means pull-only, which is slower to confirm and exactly
                // as safe. It is never silently treated as a successful push.
                None => Box::new(contain::NoPush),
            };
            let deadline = args
                .number("ack-deadline")
                .unwrap_or(u64::from(contain::DEFAULT_ACK_DEADLINE))
                .min(u64::from(u32::MAX)) as u32;
            let report = {
                let mut ctx = contain::ContainCtx {
                    feed: &mut feed,
                    ledger: &mut ledger,
                    mediators: &mediator_set,
                    push: push.as_ref(),
                    key: &key,
                    ack_deadline: deadline,
                };
                contain::contain(
                    contain::Revoked::Party { id: id.clone() },
                    &outcome.revoked,
                    &reason_for_feed,
                    &actor_id(args),
                    ts,
                    &mut ctx,
                )?
            };
            ledger.save(&p.acks)?;
            Some(report)
        }
        None => None,
    };

    println!("quarantined {}", outcome.party);
    println!("  contracts revoked  {}", outcome.revoked.len());
    for cid in &outcome.revoked {
        println!("    {cid}");
    }
    if outcome.impacted_services.is_empty() {
        println!("  impacted services  none recorded");
    } else {
        // The cost of containment, surfaced before it is discovered (UC-07 A2).
        println!(
            "  impacted services  {}",
            outcome.impacted_services.join(", ")
        );
    }
    println!("  evidence seq       {}", recorded.seq);

    match &containment {
        None => {
            // Never phrase an unenforced cut as containment.
            println!();
            println!("  NOT PROPAGATED — no --revocation-key, so no signed revocation was");
            println!("  written and no mediator has been told. The registry says quarantined;");
            println!("  the data plane has not been asked.");
        }
        Some(report) => {
            println!();
            println!("  feed seq           {}", report.feed_seq);
            println!("  {}", report.summary());
            for m in &report.mediators {
                let ack = match &m.ack {
                    contain::AckState::Confirmed { confirmation } => {
                        format!(
                            "confirmed seq {} ({} aborted)",
                            confirmation.feed_seq, confirmation.aborted
                        )
                    }
                    contain::AckState::Waiting { seconds_left } => {
                        format!("waiting, {seconds_left}s to deadline")
                    }
                    contain::AckState::Overdue { seconds_late, .. } => {
                        format!("OVERDUE by {seconds_late}s")
                    }
                };
                let push = match &m.push {
                    contain::PushOutcome::Accepted => "pushed".to_string(),
                    contain::PushOutcome::PullOnly => "pull-only".to_string(),
                    contain::PushOutcome::Failed { attempts, detail } => {
                        format!("push failed after {attempts}: {detail}")
                    }
                };
                println!(
                    "    {:<34} {:<12} {}  (bound {}s)",
                    m.mediator, push, ack, m.bounded_by
                );
            }
            if !report.fully_confirmed() {
                println!();
                println!("  Unconfirmed is not contained. Run `connect mediators` to chase it;");
                println!("  each unconfirmed mediator applies the cut within its own poll");
                println!("  interval regardless, which is the bound printed above.");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// mediators — who has confirmed, and who has not (§8.7.7)
// ---------------------------------------------------------------------------

/// Report outstanding containment orders and which mediators still owe a
/// confirmation.
///
/// This is the command that keeps "never assumed contained" true after the
/// incident call ends: an order nobody confirmed stays listed until somebody
/// does, however old it gets.
fn mediators_cmd(args: &Args) -> Result<()> {
    let p = paths(args);
    let ts = now();
    let ledger = contain::AckLedger::open(&p.acks)?;
    let feed = contain::RevocationFeed::open(&p.revocations)?;

    // Verifying the feed here is the point: an order an operator cannot verify is
    // an order that may not have been authorised.
    let verified = match (args.get("revocation-pub"), args.get("kid")) {
        (Some(path), Some(kid)) => {
            let mut keys = IssuerKeys::new();
            let pem = std::fs::read(path).map_err(|e| {
                WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}"))
                    .with_source(e)
            })?;
            match args.get("alg").unwrap_or("ES256") {
                "ES256" => keys.add_ec_pem(kid, &pem, Algorithm::ES256)?,
                "ES384" => keys.add_ec_pem(kid, &pem, Algorithm::ES384)?,
                "EdDSA" | "Ed25519" => keys.add_ed_pem(kid, &pem)?,
                other => {
                    return Err(WcError::with_detail(
                        Code::ALG_NOT_ASYMMETRIC,
                        format!("{other:?} is not an accepted algorithm"),
                    ))
                }
            }
            Some(feed.verify(&keys)?)
        }
        _ => None,
    };

    let outstanding = ledger.outstanding(ts);

    if args.has("json") {
        let rows: Vec<Value> = outstanding
            .iter()
            .map(|(order, states)| {
                json!({
                    "feed_seq": order.feed_seq,
                    "target": order.target,
                    "at": order.at,
                    "deadline_at": order.deadline_at,
                    "mediators": states.iter().map(|(m, st)| json!({
                        "mediator": m,
                        "confirmed": st.is_confirmed(),
                        "state": match st {
                            contain::AckState::Confirmed { .. } => "confirmed",
                            contain::AckState::Waiting { .. } => "waiting",
                            contain::AckState::Overdue { .. } => "overdue",
                        },
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            pretty(&json!({
                "feed_events": feed.len(),
                "feed_head": feed.next_seq() - 1,
                "feed_verified": verified,
                "outstanding": rows,
            }))?
        );
        return Ok(());
    }

    println!(
        "feed        {} event(s), head seq {}",
        feed.len(),
        feed.next_seq() - 1
    );
    match verified {
        Some(n) => println!("signatures  {n} verified"),
        None => println!("signatures  not checked (pass --revocation-pub and --kid)"),
    }

    if outstanding.is_empty() {
        println!("outstanding none");
        return Ok(());
    }
    println!("outstanding {} order(s)", outstanding.len());
    for (order, states) in &outstanding {
        println!(
            "\n  seq {} · {} · ordered at {}",
            order.feed_seq, order.target, order.at
        );
        for (mediator, state) in states.iter() {
            let text = match state {
                contain::AckState::Confirmed { confirmation } => {
                    format!("confirmed seq {}", confirmation.feed_seq)
                }
                contain::AckState::Waiting { seconds_left } => {
                    format!("waiting ({seconds_left}s left)")
                }
                contain::AckState::Overdue {
                    seconds_late,
                    last_seq,
                } => format!(
                    "OVERDUE by {seconds_late}s (last confirmed {})",
                    last_seq.map_or_else(|| "never".to_string(), |s| s.to_string())
                ),
            };
            println!("    {mediator:<34} {text}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// reads
// ---------------------------------------------------------------------------

fn entity_json(e: &Entity) -> Value {
    json!({
        "id": e.id.as_str(),
        "kind": format!("{:?}", e.kind),
        "owner": e.owner.as_str(),
        "service": e.service,
        "tier": e.tier.as_u8(),
        "zone": e.zone.as_str(),
        "trust_level": format!("{:?}", e.zone.trust_level()),
        "posture": format!("{:?}", e.posture),
        "posture_score": e.posture_score,
        "lifecycle": format!("{:?}", e.lifecycle),
        "data_classes": e.data_classes,
        "jurisdictions": e.jurisdictions,
        "endpoint": e.endpoint,
        "pin": { "alg": e.pin.alg, "manifest": e.pin.manifest, "items": e.pin.items },
        "reattest_every": e.reattest_every,
        "reattested_at": e.reattested_at,
        "created_at": e.created_at,
        "updated_at": e.updated_at,
    })
}

fn entities(args: &Args) -> Result<()> {
    let mut store = open_store(args)?;
    let reg = store.registry(actor(args)?, now());
    let all = reg.enumerate_for_operator();

    if args.has("json") {
        let rows = Value::Array(all.iter().map(|e| entity_json(e)).collect());
        println!("{}", pretty(&rows)?);
        return Ok(());
    }

    if all.is_empty() {
        println!("no entities registered");
        return Ok(());
    }
    println!(
        "{:<44} {:<11} {:<6} {:<22} {:<12} LIFECYCLE",
        "ID", "KIND", "TIER", "ZONE", "POSTURE"
    );
    for e in all {
        println!(
            "{:<44} {:<11} {:<6} {:<22} {:<12} {:?}",
            truncate(e.id.as_str(), 44),
            format!("{:?}", e.kind),
            e.tier.as_u8(),
            truncate(e.zone.as_str(), 22),
            format!("{:?}", e.posture),
            e.lifecycle
        );
    }
    Ok(())
}

fn show(args: &Args) -> Result<()> {
    let id = EntityId::new(positional_or_flag(args, "id")?)?;
    let mut store = open_store(args)?;
    let reg = store.registry(actor(args)?, now());
    let entity = reg.require(&id)?;

    if args.has("json") {
        println!("{}", pretty(&entity_json(entity))?);
        return Ok(());
    }
    println!("{}", entity.id);
    println!("  kind        {:?}", entity.kind);
    println!("  owner       {}", entity.owner);
    println!("  service     {}", entity.service.as_deref().unwrap_or("-"));
    println!("  tier        {}", entity.tier);
    println!(
        "  zone        {} ({:?})",
        entity.zone,
        entity.zone.trust_level()
    );
    println!(
        "  posture     {:?} ({})",
        entity.posture, entity.posture_score
    );
    println!("  lifecycle   {:?}", entity.lifecycle);
    println!(
        "  endpoint    {}",
        entity.endpoint.as_deref().unwrap_or("-")
    );
    println!("  pin         {}", entity.pin.manifest);
    for (name, hash) in &entity.pin.items {
        println!("    {name:<32} {}", &hash[..23.min(hash.len())]);
    }
    Ok(())
}

fn posture(args: &Args) -> Result<()> {
    let mut store = open_store(args)?;
    let ts = now();
    let reg = store.registry(actor(args)?, ts);
    let all = reg.enumerate_for_operator();

    let unattested: Vec<&Entity> = all
        .iter()
        .copied()
        .filter(|e| e.posture == Posture::Unattested)
        .collect();
    let degraded: Vec<&Entity> = all
        .iter()
        .copied()
        .filter(|e| e.posture == Posture::Degraded)
        .collect();
    let quarantined: Vec<&Entity> = all
        .iter()
        .copied()
        .filter(|e| e.posture == Posture::Quarantined)
        .collect();
    let overdue = reg.reattest_due(ts);

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "total": all.len(),
                "unattested": unattested.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
                "degraded": degraded.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
                "quarantined": quarantined.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
                "reattest_overdue": overdue.iter().map(|i| i.as_str()).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }

    println!("estate           {} entities", all.len());
    println!("unattested       {}", unattested.len());
    println!("degraded         {}", degraded.len());
    println!("quarantined      {}", quarantined.len());
    println!("reattest overdue {}", overdue.len());

    if args.has("score") {
        // The score is shown with its deductions, never on its own. A number
        // nobody can explain gets argued with rather than acted on.
        let cfg = assurance::AssuranceCfg::default();
        println!();
        for e in &all {
            let signals = observed_signals(e, ts);
            let scored = assurance::score(e, &signals, &cfg);
            println!(
                "  {:<48} {:>3}  {:<11} {}",
                e.id,
                scored.score,
                format!("{:?}", scored.state),
                scored.rationale()
            );
        }
        println!();
        println!("note: identity and provenance signals are read from the stored");
        println!("      posture, so a party that was never attested scores as such.");
        println!("      Degradation is automatic; quarantine is never.");
    }

    if args.has("unattested") {
        println!();
        for e in &unattested {
            println!("  {} ({:?})", e.id, e.lifecycle);
        }
    }
    if args.has("expiring") {
        println!();
        for id in &overdue {
            println!("  {id}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// discover — mediated capability discovery (§8.5.6, UC-03)
// ---------------------------------------------------------------------------

/// Find who offers a capability, without handing out a catalogue.
///
/// The asker is named with `--as` and must itself be registered and active: this
/// is a mediated directory, not a public one. A result names an entity and its
/// owner and nothing that would let you reach it — the contract still does that.
fn discover_cmd(args: &Args) -> Result<()> {
    let capability = positional_or_flag(args, "capability")?.to_string();
    let asker = EntityId::new(require(args, "as")?)?;
    let policy = load_policy(args)?;
    let store = open_store(args)?;
    let ts = now();

    let limits = broker::DiscoveryLimits {
        max_matches: args
            .number("limit")
            .unwrap_or(broker::DiscoveryLimits::default().max_matches as u64)
            .min(1_000) as usize,
        ..broker::DiscoveryLimits::default()
    };
    limits.validate()?;

    let standing = standing_state(&store);
    let query = broker::Query {
        capability: capability.clone(),
        jurisdiction: args.get("jurisdiction").map(str::to_string),
        data_class: args.get("data-class").map(str::to_string),
    };

    // Padding is applied around the whole answer so an empty result is not
    // measurably faster than a full one. It is necessary, not sufficient — see
    // `broker::Padding` for what a floor cannot cover.
    let padding = broker::Padding::new(limits.latency_floor_ms);
    let started = std::time::Instant::now();
    let result = broker::discover(
        &query,
        &asker,
        &mut broker::Throttle::new(),
        &broker::BrokerCtx {
            projection: &store.projection,
            policy: &policy,
            standing: &standing,
            limits: &limits,
            now: ts,
        },
    );
    padding.apply(started.elapsed());
    let result = result?;

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "capability": capability,
                "normalised": broker::CapKey::normalise(&capability).as_str(),
                "matches": result.matches,
                "truncated": result.truncated,
            }))?
        );
        return Ok(());
    }

    println!(
        "query      {:?}  →  {}",
        capability,
        broker::CapKey::normalise(&capability)
    );
    if result.matches.is_empty() {
        // Deliberately the same wording whether nothing matched, everything was
        // filtered out, or the asker is over budget.
        println!("matches    none");
        if result.truncated {
            println!("           (the answer was cut short)");
        }
        return Ok(());
    }

    println!("matches    {}", result.matches.len());
    println!();
    println!(
        "  {:<44} {:<18} {:<5} {:<22} LIKELY",
        "ENTITY", "CAPABILITY", "TIER", "OWNER"
    );
    for m in &result.matches {
        println!(
            "  {:<44} {:<18} {:<5} {:<22} {}",
            m.entity, m.capability, m.tier, m.owner, m.likely_decision
        );
    }
    if result.truncated {
        println!();
        println!("  the answer was cut short; narrow the capability to see more");
    }
    println!();
    println!("  No endpoint is returned. Reaching one of these needs a contract:");
    println!("    connect request --from {asker} --to <ENTITY> --tools … --justify …");
    Ok(())
}

// ---------------------------------------------------------------------------
// assurance — posture signals and blast radius (§8.7.6, §8.7.8)
// ---------------------------------------------------------------------------

/// The signals this deployment can actually observe today.
///
/// Everything not yet collected stays `None` or zero, which reads as *absent*
/// rather than *healthy* — the scoring function treats `None` identity as
/// "never verified" and deducts for it. Filling these in is what later phases do;
/// pretending they are satisfied is what this must never do.
fn observed_signals(entity: &Entity, now: u64) -> assurance::Signals {
    let attested = entity.posture == Posture::Attested;
    // `reattested_at == 0` means never attested, not "overdue since the epoch".
    // Counting that as overdue double-charges the party for the same fact and
    // makes the rationale say the wrong thing — the reason is "never verified",
    // which the identity and provenance signals already carry.
    let intervals = if entity.reattest_every == 0 || entity.reattested_at == 0 {
        0
    } else {
        (now.saturating_sub(entity.reattested_at) / u64::from(entity.reattest_every))
            .saturating_sub(1)
            .min(u64::from(u32::MAX)) as u32
    };
    assurance::Signals {
        // Admission recorded the outcome as a posture, which is the only identity
        // and provenance evidence the registry holds between re-attestations.
        identity_ok: if attested { Some(true) } else { None },
        provenance_ok: if attested { Some(true) } else { None },
        intervals_overdue: intervals,
        // Not yet collected: drift history, owner directory, credential expiry,
        // denied-action feedback, open screening findings.
        ..assurance::Signals::default()
    }
}

/// What stops if this party is cut.
fn blast_radius_cmd(args: &Args) -> Result<()> {
    let raw = positional_or_flag(args, "id")?;
    let subject = EntityId::new(raw)?;
    let depth = args
        .number("depth")
        .unwrap_or(u64::from(assurance::DEFAULT_BLAST_DEPTH))
        .min(255) as u8;

    let store = open_store(args)?;
    if !store.projection.entities.contains_key(&subject) {
        return Err(WcError::with_detail(
            Code::ENTITY_NOT_FOUND,
            format!("{subject} is not registered"),
        ));
    }
    let report = assurance::blast_radius(&subject, depth, &store.projection);

    if args.has("json") {
        let value = serde_json::to_value(&report).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, "cannot serialise the report").with_source(e)
        })?;
        println!("{}", pretty(&value)?);
    } else if args.has("services") {
        // What the change manager asks for. "These 3 business services stop" beats
        // a list of 400 entity ids.
        for s in &report.impacted_services {
            println!("{s}");
        }
    } else {
        println!("subject   {}", report.subject);
        println!("depth     {}", report.max_depth);
        println!("summary   {}", report.summary());
        if !report.impacted_services.is_empty() {
            println!("services  {}", report.impacted_services.join(", "));
        }
        // `forward` is who this party can reach; `reverse` is who reaches it.
        // Labelling these the wrong way round tells an operator deciding a cut the
        // opposite of the truth about which direction the dependency runs.
        for (label, nodes) in [
            ("reaches", &report.forward),
            ("reached by", &report.reverse),
        ] {
            if nodes.is_empty() {
                continue;
            }
            println!("\n{label}");
            for n in nodes {
                println!(
                    "  d{} tier{} {:<44} {:<20} {}",
                    n.depth,
                    n.tier,
                    n.id,
                    n.service.as_deref().unwrap_or("-"),
                    n.owner
                );
            }
        }
        if !report.cut_set.is_empty() {
            println!("\ncut set   {}", report.cut_set.join(" "));
        }
        if !report.dangling.is_empty() {
            // The edge is real, so the radius is real. Never silently omitted.
            println!("\ndangling  {}", report.dangling.join(" "));
            println!("          named by a contract but absent from the registry");
        }
    }

    if report.truncated {
        return Err(WcError::with_detail(
            Code::BLAST_DEPTH_TRUNCATED,
            format!(
                "traversal stopped at depth {}; the real radius is wider",
                report.max_depth
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// caep — ingest a shared-signals token (§8.9.4)
// ---------------------------------------------------------------------------

/// Verify a Security Event Token and report what it asks this estate to do.
///
/// Prints rather than applies. Ingest is a remote-triggered path, so an operator
/// gets to see what a stream asked for before anything acts on it — and a
/// verified signature is only half the check: the transmitter's declared
/// authority is the other half.
fn caep_ingest(args: &Args) -> Result<()> {
    let path = positional_or_flag(args, "file")?;
    let token = std::fs::read_to_string(path)
        .map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
        })?
        .trim()
        .to_string();

    let streams = wc_control::caep::TransmitterSet::load(std::path::Path::new(require(
        args,
        "transmitters",
    )?))?;
    let ts = args.number("now").unwrap_or_else(now);

    // Replay state is per-invocation here; a running control plane keeps it for
    // the freshness window. The CLI exists to inspect one token, and saying so
    // beats implying a durable store it does not have.
    let mut seen = wc_control::caep::SeenTokens::default();
    let out = wc_control::caep::ingest(&token, &streams, &mut seen, ts)?;

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "issuer": out.issuer,
                "jti": out.jti,
                "subject": out.subject,
                "effects": out.effects.iter().map(|e| json!({
                    "kind": e.kind(),
                    "detail": format!("{e:?}"),
                })).collect::<Vec<_>>(),
                "unhandled": out.unhandled.iter().map(|(uri, why)| json!({
                    "event": uri, "reason": why
                })).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }

    println!("issuer    {}", out.issuer);
    println!("token     {}", out.jti);
    println!("subject   {}", out.subject);
    if out.effects.is_empty() {
        println!("effects   none");
    } else {
        println!("effects   {}", out.effects.len());
        for effect in &out.effects {
            println!("  {:<20} {effect:?}", effect.kind());
        }
    }
    if !out.unhandled.is_empty() {
        // A stream sending events we silently drop is a partner who believes they
        // have told us something.
        println!();
        println!("not acted on");
        for (uri, why) in &out.unhandled {
            println!("  {uri}");
            println!("    {why}");
        }
    }
    println!();
    println!("  Nothing on this path can quarantine the estate. An external input that");
    println!("  can cut connections is a denial-of-service primitive; the strongest");
    println!("  outcome here is revoking one connection its sender is a party to.");
    Ok(())
}

// ---------------------------------------------------------------------------
// bundle — air-gapped contract delivery (§8.9.4)
// ---------------------------------------------------------------------------

/// Cut a signed bundle for one mediator.
fn bundle_export(args: &Args) -> Result<()> {
    let mediator = require(args, "mediator")?.to_string();
    let key = load_issuer_key(
        require(args, "signing-key")?,
        require(args, "kid")?,
        args.get("alg"),
    )?;
    let ttl = args
        .get("ttl")
        .and_then(cpolicy::parse_duration)
        .unwrap_or(7 * 86_400);

    let p = paths(args);
    let store = open_store(args)?;
    let ts = now();

    // Every live contract addressed to this mediator, read from the artifacts the
    // issuer persisted — the same bytes a pulling mediator would receive.
    let mut contracts: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for record in store.projection.contracts.values() {
        if !record.is_live(ts) || !record.aud.iter().any(|a| a == &mediator) {
            continue;
        }
        match store.read_artifact(record.cid.as_str(), &mediator) {
            Some(jws) => contracts.push(jws),
            // Named, never silently omitted: a bundle short one contract is an
            // agent that stops working in an air-gapped site with no way to ask why.
            None => missing.push(record.cid.as_str().to_string()),
        }
    }

    let jwks =
        match args.get("keyring") {
            Some(path) => wc_control::keys::Keyring::load(std::path::Path::new(path))?.jwks()?,
            None => return Err(WcError::with_detail(
                Code::EXPORT_FAILED,
                "--keyring is required: a bundle must carry the JWKS its contracts verify against",
            )),
        };

    let feed = wc_control::contain::RevocationFeed::open(&p.revocations)?;
    let revocations: Vec<Value> = feed
        .all()
        .iter()
        .map(|e| json!({ "event": e.event, "jws": e.jws, "kid": e.kid }))
        .collect();

    let bundle = wc_control::bundle::export(
        &wc_control::bundle::ExportRequest {
            mediator_id: mediator.clone(),
            contracts,
            jwks,
            revocations,
            revocation_head: feed.head_digest(),
            ttl_secs: ttl,
        },
        ts,
        &key,
    )?;
    let text = wc_control::bundle::to_bytes(&bundle)?;

    match args.get("out") {
        Some(path) => {
            std::fs::write(path, &text).map_err(|e| {
                WcError::with_detail(Code::EXPORT_FAILED, format!("cannot write {path}"))
                    .with_source(e)
            })?;
            println!("wrote {path}");
        }
        None => print!("{text}"),
    }

    eprintln!(
        "bundle for {mediator}: {} contract(s), {} revocation(s), expires {} (in {})",
        bundle.body.contracts.len(),
        bundle.body.revocations.len(),
        bundle.body.exp,
        human_duration(ttl)
    );
    if !missing.is_empty() {
        eprintln!(
            "connect: warning: {} live contract(s) had no stored artifact and are NOT in this \
             bundle: {}",
            missing.len(),
            missing.join(" ")
        );
    }
    eprintln!(
        "connect: the whole bundle stops working at its expiry, whatever the contracts inside say"
    );
    Ok(())
}

/// Verify a bundle as a mediator would.
fn bundle_verify(args: &Args) -> Result<()> {
    let path = positional_or_flag(args, "file")?;
    let mediator = require(args, "mediator")?;
    let kid = require(args, "kid")?;

    let mut envelope = IssuerKeys::new();
    let pem = std::fs::read(require(args, "envelope-pub")?).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, "cannot read --envelope-pub").with_source(e)
    })?;
    envelope.add_ec_pem(kid, &pem, Algorithm::ES256)?;

    // The contracts' issuer is a separate trust decision from the courier's
    // envelope key, so it is loaded separately — falling back to the envelope key
    // only when the operator says they are the same.
    let contract_keys = {
        let path = args
            .get("issuer-pub")
            .unwrap_or(require(args, "envelope-pub")?);
        let pem = std::fs::read(path).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
        })?;
        let mut keys = IssuerKeys::new();
        keys.add_ec_pem(kid, &pem, Algorithm::ES256)?;
        keys
    };

    let ts = args.number("now").unwrap_or_else(now);
    let imported = wc_control::bundle::import_file(
        std::path::Path::new(path),
        &envelope,
        &contract_keys,
        mediator,
        ts,
    )?;

    println!("bundle      {path}");
    println!("mediator    {}", imported.mediator_id);
    println!(
        "expires     {} (in {})",
        imported.exp,
        human_duration(imported.remaining)
    );
    println!("contracts   {} verified", imported.contracts.len());
    if !imported.rejected.is_empty() {
        println!(
            "            {} rejected: {}",
            imported.rejected.len(),
            imported
                .rejected
                .iter()
                .map(|(i, c)| format!("#{i} {c}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!(
        "revocations {} (feed head {})",
        imported.revocations, imported.revocation_head
    );
    if !imported.is_clean() {
        return Err(WcError::with_detail(
            Code::SIGNATURE_INVALID,
            format!(
                "{} contract(s) in the bundle did not verify",
                imported.rejected.len()
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bench — the performance gates (§8.10.3)
// ---------------------------------------------------------------------------

/// Run the CI performance gates.
///
/// A latency claim in a design document that is not asserted by a test is a
/// marketing claim. Exits non-zero on regression.
fn bench_cmd(args: &Args) -> Result<()> {
    use wc_control::bench::{measure, thresholds, Report};

    let iterations = args.number("iterations").unwrap_or(500).min(100_000) as usize;
    let scale = args.number("scale").unwrap_or(100_000).min(1_000_000) as usize;
    let only = args.get("gate");
    let wanted = |name: &str| only.is_none_or(|g| name.contains(g));

    let mut report = Report::default();
    let ts = now();

    // --- the §8.10.3 gates -------------------------------------------------
    //
    // `gate::verify` and `contract::mint` need a signing key, because there is no
    // honest way to benchmark signing without one. Absent, they are recorded as
    // *not deliberate* skips, which fails the run — a CI job that quietly measured
    // three of six gates and exited green is the failure this harness exists to
    // prevent.
    let signer = match (args.get("signing-key"), args.get("kid")) {
        (Some(path), Some(kid)) => Some(load_issuer_key(path, kid, args.get("alg"))?),
        _ => None,
    };

    for name in [
        "contract::mint",
        "contract::mint overhead",
        "gate::verify warm",
        "gate::verify cold",
    ] {
        if !wanted(name) {
            report.skip(name, "not selected by --gate", true);
        } else if signer.is_none() {
            report.skip(
                name,
                "needs --signing-key PEM --kid KID; signing cannot be benchmarked without a key",
                false,
            );
        }
    }

    if let Some(key) = &signer {
        let payload = bench_payload(ts)?;

        if wanted("contract::mint") {
            report.gates.push(measure(
                "contract::mint",
                "one artifact, ES256",
                thresholds::MINT,
                iterations.min(200),
                5,
                || {
                    let _ = contract::mint(&payload, key);
                },
            ));
        }

        // Mint through a signer that returns a fixed, correctly-shaped signature: the
        // difference between this and `contract::mint` is what the signature costs,
        // and this figure is the part an operator can hold us to once the key is in a
        // token (`docs/key-custody.md`).
        if wanted("contract::mint overhead") {
            let free = IssuerKey::external(
                args.get("kid").unwrap_or("k1"),
                Algorithm::ES256,
                Box::new(FreeSigner),
            )?;
            report.gates.push(measure(
                "contract::mint overhead",
                "everything except the signature",
                thresholds::MINT_OVERHEAD,
                iterations.min(200),
                5,
                || {
                    let _ = contract::mint(&payload, &free);
                },
            ));
        }

        let jws = contract::mint(&payload, key)?;
        // Verification needs the public half, and asking for it beats deriving it:
        // `IssuerKeys` takes an SPKI PEM, and quietly handing it a private key
        // would skip the gate for a reason that reads like a bug.
        let pem = match args.get("verify-pub") {
            Some(path) => Some(std::fs::read(path).map_err(|e| {
                WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}"))
                    .with_source(e)
            })?),
            None => None,
        };

        if wanted("gate::verify warm") {
            let mut keys = IssuerKeys::new();
            let ok = pem.as_ref().is_some_and(|pem| {
                keys.add_ec_pem(args.get("kid").unwrap_or("k1"), pem, Algorithm::ES256)
                    .is_ok()
            });
            if !ok {
                report.skip(
                    "gate::verify warm",
                    "needs --verify-pub PEM: verification takes the public half",
                    false,
                );
            } else {
                let opts = contract::VerifyOpts::new(&keys, MEDIATOR_FOR_BENCH, ts);
                report.gates.push(measure(
                    "gate::verify warm",
                    "steady state, key already parsed",
                    thresholds::VERIFY_WARM,
                    iterations,
                    20,
                    || {
                        let _ = contract::verify_artifact(&jws, &opts);
                    },
                ));
            }
        }

        if wanted("gate::verify cold") {
            let kid = args.get("kid").unwrap_or("k1").to_string();
            let mut probe = IssuerKeys::new();
            let ok = pem
                .as_ref()
                .is_some_and(|pem| probe.add_ec_pem(&kid, pem, Algorithm::ES256).is_ok());
            if !ok {
                report.skip(
                    "gate::verify cold",
                    "needs --verify-pub PEM: verification takes the public half",
                    false,
                );
            } else {
                let pem = pem.clone().unwrap_or_default();
                // Cold means the key set is rebuilt each time, which is what a
                // mediator pays on its first verification after a refresh.
                report.gates.push(measure(
                    "gate::verify cold",
                    "key set rebuilt per verification",
                    thresholds::VERIFY_COLD,
                    iterations.min(200),
                    5,
                    || {
                        let mut keys = IssuerKeys::new();
                        if keys.add_ec_pem(&kid, &pem, Algorithm::ES256).is_ok() {
                            let opts = contract::VerifyOpts::new(&keys, MEDIATOR_FOR_BENCH, ts);
                            let _ = contract::verify_artifact(&jws, &opts);
                        }
                    },
                ));
            }
        }
    }

    // Blast radius at the NFR scale, not a token one.
    if wanted("assurance::blast_radius") {
        let projection = bench_estate(scale)?;
        let subject = EntityId::new("urn:wc:bench:n0")?;
        report.gates.push(measure(
            "assurance::blast_radius",
            &format!("{scale} contracts, depth 3"),
            thresholds::BLAST_RADIUS,
            iterations.min(50),
            2,
            || {
                let _ = assurance::blast_radius(&subject, 3, &projection);
            },
        ));
    } else {
        report.skip("assurance::blast_radius", "not selected by --gate", true);
    }

    // wcs1 canonicalisation of a 256-tool surface — the pin path.
    if wanted("canon::wcs1") {
        let tools: Vec<Value> = (0..256)
            .map(|i| {
                json!({
                    "name": format!("tool_{i:03}"),
                    "description": format!("Operation {i} on the ledger, returning a record."),
                    "inputSchema": { "type": "object", "properties": { "id": { "type": "string" } } }
                })
            })
            .collect();
        let raw = json!({ "tools": tools });
        let entity = EntityId::new("urn:wc:bench")?;
        report.gates.push(measure(
            "canon::wcs1 (256 tools)",
            "canonicalise + pin",
            thresholds::CANON_256,
            iterations.min(200),
            5,
            || {
                let _ =
                    canon::canonicalise(SurfaceKind::McpTools, &entity, &raw, &Limits::default());
            },
        ));
    } else {
        report.skip("canon::wcs1 (256 tools)", "not selected by --gate", true);
    }

    // Screening the same surface — the admission path.
    if wanted("screen") {
        let tools: Vec<Value> = (0..256)
            .map(|i| {
                json!({
                    "name": format!("tool_{i:03}"),
                    "description": format!("Operation {i}. Returns a ledger record for an account."),
                })
            })
            .collect();
        let entity = EntityId::new("urn:wc:bench")?;
        let surface = canon::canonicalise(
            SurfaceKind::McpTools,
            &entity,
            &json!({ "tools": tools }),
            &Limits::default(),
        )?;
        let rules = screen::ScreenRules::default();
        let acceptances = screen::Acceptances::default();
        let names = screen::NameIndex::empty();
        let ctx = screen::ScreenCtx {
            rules: &rules,
            acceptances: &acceptances,
            names: &names,
            entity: &entity,
            mode: screen::ScreenMode::Flag,
        };
        report.gates.push(measure(
            "screen (256 tools)",
            "S1-S8 over a full surface",
            thresholds::SCREEN_256,
            iterations.min(100),
            3,
            || {
                let _ = screen::screen(&surface, Tier::THREE, &ctx);
            },
        ));
    } else {
        report.skip("screen (256 tools)", "not selected by --gate", true);
    }

    // Projection::rebuild at 10⁵ contracts — the startup path. A control plane that
    // takes a minute to become answerable after a restart is one an operator reboots
    // during an incident and then waits on.
    if wanted("store::rebuild") {
        match bench_rebuild(scale) {
            Ok(gate) => report.gates.push(gate),
            Err(e) => report.skip(
                "store::rebuild",
                &format!("could not build the fixture: {}", e.detail()),
                // Not deliberate: a gate that could not run because writing a
                // temporary log failed is an incomplete job reporting green.
                false,
            ),
        }
    } else {
        report.skip("store::rebuild", "not selected by --gate", true);
    }

    // The one gate this binary cannot run, stated rather than omitted: measuring
    // it needs `wc-mediator`, and the CLI deliberately does not link it (§8.3) so
    // that a control-plane-only deployment never pulls in Warden core.
    report.skip(
        "filter_tools_list (256 tools)",
        &format!(
            "lives in wc-mediator, which the CLI does not link by design; run `{}`",
            thresholds::FILTER_GATE_COMMAND
        ),
        true,
    );

    if args.has("json") {
        println!(
            "{}",
            pretty(&serde_json::to_value(&report).map_err(|e| {
                WcError::with_detail(Code::EXPORT_FAILED, "cannot serialise the report")
                    .with_source(e)
            })?)?
        );
    } else {
        println!("gates    {} · {iterations} iterations", report.gates.len());
        println!();
        for gate in &report.gates {
            println!("  {}", gate.line());
        }
        if !report.skipped.is_empty() {
            println!();
            for skip in &report.skipped {
                println!(
                    "  {:<28} {}  ({})",
                    skip.name,
                    if skip.deliberate {
                        "skipped"
                    } else {
                        "NOT RUN"
                    },
                    skip.reason
                );
            }
        }
        if !report.marginal().is_empty() {
            println!();
            println!("  marginal gates hold today and are the ones that start failing for");
            println!("  reasons nobody changed. Investigate before they become a flaky build.");
        }
    }

    if !report.passed() {
        return Err(WcError::with_detail(
            Code::EXPORT_FAILED,
            if report.gates.is_empty() {
                // A run that measured nothing must not exit zero.
                "no gates ran; `--gate` matched nothing".to_string()
            } else if !report.incomplete().is_empty() {
                format!(
                    "{} gate(s) could not run: {}",
                    report.incomplete().len(),
                    report
                        .incomplete()
                        .iter()
                        .map(|s| s.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                format!(
                    "{} gate(s) regressed: {}",
                    report.failed().len(),
                    report
                        .failed()
                        .iter()
                        .map(|g| g.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
        ));
    }
    Ok(())
}

/// The mediator id the benchmark artifacts are addressed to.
const MEDIATOR_FOR_BENCH: &str = "warden:mediator:bench";

/// A contract payload for the mint and verify gates.
fn bench_payload(now: u64) -> Result<contract::ContractPayload> {
    use wc_core::contract::Party;
    use wc_core::model::{Cid, Jti};

    let party = |name: &str| -> Result<Party> {
        Ok(Party {
            id: EntityId::new(format!("urn:wc:bench:{name}"))?,
            zone: ZoneId::new("internal.bench")?,
            tier: Tier::THREE,
            card: None,
            manifest: Some("sha256:m".to_string()),
            surface_digest: Some("sha256:s".to_string()),
        })
    };
    let mut payload = contract::ContractPayload::new(
        Cid::new("conn_beac0001")?,
        Jti::new("jti_beac000000000001")?,
        "https://connect.bench",
        MEDIATOR_FOR_BENCH,
        party("caller")?,
        party("callee")?,
    );
    payload.iat = now;
    payload.nbf = now;
    payload.exp = now + 86_400;
    payload.surface = Surface {
        tools: (0..8).map(|i| format!("tool_{i}")).collect(),
        ..Default::default()
    };
    Ok(payload)
}

/// An estate of `contracts` edges for the blast-radius gate.
///
/// Built as a wide star rather than a chain: a chain of 10⁵ would exceed the depth
/// bound after three hops and measure almost nothing, which is a benchmark that
/// passes by not doing the work.
fn bench_estate(contracts: usize) -> Result<wc_control::store::Projection> {
    use wc_control::store::Projection;
    use wc_core::contract::{ApprovalRef, ContractRecord, ContractStatus, Terms, CONTRACT_SCHEMA};
    use wc_core::model::{Cid, Entity, HumanRef, Jti, Kind, Lifecycle};

    let mut projection = Projection::default();
    let owner = HumanRef::new("human:bench")?;
    let zone = ZoneId::new("internal.bench")?;

    // A hub, a middle ring, and leaves — three hops, so depth 3 traverses all of
    // it and the gate measures the traversal rather than the bound.
    let ring = (contracts / 100).max(2);
    let parties = ring + contracts / ring + 2;
    for i in 0..parties {
        let id = EntityId::new(format!("urn:wc:bench:n{i}"))?;
        let mut e = Entity::pending(
            id.clone(),
            Kind::McpServer,
            owner.clone(),
            zone.clone(),
            Tier::THREE,
            0,
        );
        e.lifecycle = Lifecycle::Active;
        e.service = Some(format!("svc-{}", i % 20));
        projection.entities.insert(id, e);
    }

    for i in 0..contracts {
        let caller = if i < ring { 0 } else { 1 + (i % ring) };
        let callee = (i % (parties - 1)) + 1;
        if caller == callee {
            continue;
        }
        let cid = Cid::new(format!("conn_{i:08x}"))?;
        let record = ContractRecord {
            cid: cid.clone(),
            jti: Jti::new("jti_beac000000000001")?,
            caller: EntityId::new(format!("urn:wc:bench:n{caller}"))?,
            callee: EntityId::new(format!("urn:wc:bench:n{callee}"))?,
            caller_zone: zone.clone(),
            callee_zone: zone.clone(),
            callee_tier: Tier::THREE,
            callee_manifest: "sha256:m".to_string(),
            surface_digest: "sha256:s".to_string(),
            surface: Surface::default(),
            terms: Terms::default(),
            aud: vec![MEDIATOR_FOR_BENCH.to_string()],
            jws_sha256: "sha256:a".to_string(),
            status: ContractStatus::Active,
            approval: ApprovalRef::standing(),
            policy_version: "bench@v1".to_string(),
            iat: 0,
            exp: u64::MAX,
            schema: CONTRACT_SCHEMA,
        };
        projection
            .by_caller
            .entry(record.caller.clone())
            .or_default()
            .insert(cid.clone());
        projection
            .by_callee
            .entry(record.callee.clone())
            .or_default()
            .insert(cid.clone());
        projection.contracts.insert(cid, record);
    }
    Ok(projection)
}

// ---------------------------------------------------------------------------
// keys — the issuer keyring and its rotation lifecycle (§8.12.1)
// ---------------------------------------------------------------------------

fn keyring_path(args: &Args) -> PathBuf {
    PathBuf::from(args.get("keyring").unwrap_or("keys.toml"))
}

fn load_keyring(args: &Args) -> Result<wc_control::keys::Keyring> {
    let path = keyring_path(args);
    if path.exists() {
        wc_control::keys::Keyring::load(&path)
    } else {
        Ok(wc_control::keys::Keyring::default())
    }
}

fn keys_list(args: &Args) -> Result<()> {
    let ring = load_keyring(args)?;
    let ts = now();

    if args.has("json") {
        println!(
            "{}",
            pretty(&serde_json::to_value(&ring).map_err(|e| {
                WcError::with_detail(Code::CONFIG_INVALID, "cannot serialise the keyring")
                    .with_source(e)
            })?)?
        );
        return Ok(());
    }

    if ring.keys.is_empty() {
        println!("keyring {} is empty", keyring_path(args).display());
        println!("  connect keys new --kid $(date +%Y-%m)");
        return Ok(());
    }

    println!("keyring  {}", keyring_path(args).display());
    println!(
        "rotate   every {}{}",
        human_duration(ring.rotate_every),
        if ring.rotation_due(ts) {
            "   ROTATION OVERDUE"
        } else {
            ""
        }
    );
    println!();
    println!(
        "  {:<24} {:<9} {:<7} {:<22} RETIRABLE",
        "KID", "STATE", "ALG", "SIGNED THROUGH"
    );
    for key in &ring.keys {
        let through = key
            .last_contract_exp
            .map_or_else(|| "unknown".to_string(), |e| e.to_string());
        let retirable = match key.state {
            wc_control::keys::KeyState::Active => "-- active --".to_string(),
            wc_control::keys::KeyState::Retired => "retired".to_string(),
            wc_control::keys::KeyState::Retiring => match key.safe_to_retire_at() {
                None => "unknown — nothing recorded".to_string(),
                Some(at) if ts >= at => "now".to_string(),
                Some(at) => format!("in {}", human_duration(at - ts)),
            },
        };
        println!(
            "  {:<24} {:<9} {:<7} {:<22} {}",
            key.kid,
            key.state.as_str(),
            key.alg,
            through,
            retirable
        );
    }
    Ok(())
}

/// Print the commands that produce a key this ring accepts.
///
/// Deliberately not a keygen. Rolling one into a control plane means owning an
/// entropy and PKCS#8 bug surface for no gain, and PKCS#11 or a KMS URI is the
/// production answer anyway.
fn keys_new(args: &Args) -> Result<()> {
    let kid = require(args, "kid")?;
    let alg = args.get("alg").unwrap_or("ES256");
    let dir = args.get("out").unwrap_or(".");
    let private = format!("{dir}/{kid}.key");
    let public = format!("{dir}/{kid}.pub");

    println!("# generate the key pair for kid {kid:?}:");
    for cmd in wc_control::keys::generation_command(alg, &private, &public) {
        println!("{cmd}");
    }
    println!();
    println!("# then register the public half:");
    println!("connect keys add --kid {kid} --alg {alg} --public {public} --private-ref {private}");
    println!();
    println!("# warden-connect does not generate keys. A PKCS#11 or KMS URI is the");
    println!("# production answer, and --private-ref records wherever it lives.");
    Ok(())
}

fn keys_add(args: &Args) -> Result<()> {
    let kid = require(args, "kid")?.to_string();
    let public_path = require(args, "public")?;
    let public_pem = std::fs::read_to_string(public_path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {public_path}"))
            .with_source(e)
    })?;

    let mut ring = load_keyring(args)?;
    let first = ring.keys.is_empty();
    let entry = wc_control::keys::KeyEntry {
        kid: kid.clone(),
        alg: args.get("alg").unwrap_or("ES256").to_string(),
        public_pem,
        private_ref: args.get("private-ref").map(str::to_string),
        // The first key in an empty ring becomes active; any later one is added
        // inactive and must be rotated to explicitly, so adding a key never
        // silently changes what signs.
        state: if first {
            wc_control::keys::KeyState::Active
        } else {
            wc_control::keys::KeyState::Retiring
        },
        activated_at: if first { now() } else { 0 },
        retiring_at: None,
        last_contract_exp: None,
        retired_at: None,
    };
    // Rendering the JWK now surfaces a malformed PEM here rather than at the
    // first mediator that fetches the JWKS.
    wc_control::keys::jwk_from_pem(&entry.kid, &entry.alg, &entry.public_pem)?;

    ring.add(entry)?;
    ring.save(&keyring_path(args))?;

    println!("added {kid}");
    if first {
        println!("  active — this is the first key in the ring, so it signs immediately");
    } else {
        println!("  not signing yet; `connect keys rotate --kid {kid}` promotes it");
    }
    Ok(())
}

fn keys_rotate(args: &Args) -> Result<()> {
    let kid = require(args, "kid")?;
    let mut ring = load_keyring(args)?;
    let rotation = ring.rotate_to(kid, now())?;
    ring.save(&keyring_path(args))?;

    println!("active   {}", rotation.now_active);
    match rotation.now_retiring {
        Some(previous) => {
            println!("retiring {previous}");
            println!();
            println!("  {previous} still verifies, and every contract it signed keeps working.");
            println!("  Retire it only once those have expired:");
            println!("    connect keys retire --kid {previous}");
            println!("  Distribute the new JWKS before minting:  connect keys jwks");
        }
        None => println!("  (no key was previously active)"),
    }
    Ok(())
}

fn keys_retire(args: &Args) -> Result<()> {
    let kid = require(args, "kid")?;
    let mut ring = load_keyring(args)?;
    ring.retire(kid, now())?;
    ring.save(&keyring_path(args))?;
    println!("retired {kid}");
    println!("  removed from the JWKS; anything it signed no longer verifies");
    Ok(())
}

/// Record the latest contract expiry a key signed.
///
/// The number the retirement guard depends on. Monotonic — a later note can only
/// push the date out — so recording a short contract after a long one cannot
/// shorten a key's required life.
fn keys_note(args: &Args) -> Result<()> {
    let kid = require(args, "kid")?;
    let exp = args.number("exp").ok_or_else(|| {
        WcError::with_detail(
            Code::CONFIG_INVALID,
            "--exp is required: the unix time of the latest contract this key signed",
        )
    })?;
    let mut ring = load_keyring(args)?;
    if ring.get(kid).is_none() {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("kid {kid:?} is not in the ring"),
        ));
    }
    ring.note_signed(kid, exp);
    ring.save(&keyring_path(args))?;

    let recorded = ring
        .get(kid)
        .and_then(|k| k.last_contract_exp)
        .unwrap_or(exp);
    println!("{kid} signed through {recorded}");
    if recorded > exp {
        println!("  (kept the later date already on record; this only ever moves outward)");
    }
    if let Some(at) = ring
        .get(kid)
        .and_then(wc_control::keys::KeyEntry::safe_to_retire_at)
    {
        println!("  retirable at {at}");
    }
    Ok(())
}

fn keys_jwks(args: &Args) -> Result<()> {
    let ring = load_keyring(args)?;
    let jwks = ring.jwks()?;
    match args.get("out") {
        Some(path) => {
            std::fs::write(path, &jwks).map_err(|e| {
                WcError::with_detail(Code::CONFIG_INVALID, format!("cannot write {path}"))
                    .with_source(e)
            })?;
            println!("wrote {path} ({} verifying key(s))", ring.verifying().len());
        }
        None => println!("{jwks}"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// tenants — what this root holds, and what is declared
// ---------------------------------------------------------------------------

/// List tenants: those declared in the registry, and those present on disk.
///
/// Reported separately on purpose. A directory with no declaration is state
/// nobody is administering; a declaration with no directory is a tenant that has
/// never been used. Both are worth seeing, and merging them into one list hides
/// which is which.
fn tenants_cmd(args: &Args) -> Result<()> {
    let root = args
        .get("root")
        .map(PathBuf::from)
        .or_else(|| std::env::var("WARDEN_CONNECT_ROOT").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT));

    let declared = match args.get("registry") {
        Some(path) => wc_control::tenant::TenantRegistry::load(std::path::Path::new(path))?,
        None => wc_control::tenant::TenantRegistry::default(),
    };

    // What is actually on disk. An unparseable directory name is listed as such
    // rather than skipped: it is state under this root either way.
    let mut on_disk: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root.join("tenants")) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                on_disk.push(entry.file_name().to_string_lossy().to_string());
            }
        }
    }
    on_disk.sort();

    let declared_ids: Vec<String> = declared.ids().iter().map(|t| t.to_string()).collect();
    let undeclared: Vec<&String> = on_disk
        .iter()
        .filter(|d| !declared_ids.contains(d))
        .collect();
    let unused: Vec<&String> = declared_ids
        .iter()
        .filter(|d| !on_disk.contains(d))
        .collect();

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "root": root.display().to_string(),
                "declared": declared.tenants.iter().map(|t| json!({
                    "id": t.id.as_str(),
                    "name": t.name,
                    "mode": t.mode,
                    "suspended": t.suspended,
                    "has_own_issuer_key": t.issuer_key.is_some(),
                })).collect::<Vec<_>>(),
                "on_disk": on_disk,
                "undeclared": undeclared,
                "unused": unused,
            }))?
        );
        return Ok(());
    }

    println!("root      {}", root.display());
    if declared.is_empty() {
        println!("declared  none (pass --registry to load tenants.toml)");
    } else {
        println!("declared  {}", declared.len());
        println!();
        println!("  {:<20} {:<9} {:<10} NAME", "TENANT", "MODE", "OWN KEY");
        for t in &declared.tenants {
            println!(
                "  {:<20} {:<9} {:<10} {}{}",
                t.id,
                t.mode,
                if t.issuer_key.is_some() {
                    "yes"
                } else {
                    "shared"
                },
                t.name,
                if t.suspended { "  (suspended)" } else { "" }
            );
        }
    }
    println!();
    println!("on disk   {}", on_disk.len());
    if !undeclared.is_empty() {
        println!();
        println!("  UNDECLARED — state under this root that no registry entry administers:");
        for d in &undeclared {
            println!("    {d}");
        }
    }
    if !unused.is_empty() {
        println!();
        println!(
            "  declared but never used: {}",
            unused
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// federate — resolve a partner trust chain (UC-05)
// ---------------------------------------------------------------------------

/// Verify a federation trust chain against the configured anchors.
///
/// The chain file is a JSON array of compact JWS strings, **leaf first**. Exit 4
/// on any verification failure, so this works as a CI gate on a partner
/// onboarding bundle before anybody registers anything.
fn federate_cmd(args: &Args) -> Result<()> {
    let chain_path = positional_or_flag(args, "chain")?;
    let raw = read_json(chain_path)?;
    let chain: Vec<String> = serde_json::from_value(raw).map_err(|e| {
        WcError::with_detail(
            Code::FEDERATION_CHAIN_INVALID,
            format!("{chain_path}: expected a JSON array of compact JWS strings, leaf first"),
        )
        .with_source(e)
    })?;

    let anchors = federate::AnchorSet::load(std::path::Path::new(require(args, "anchors")?))?;
    let at = args.number("now").unwrap_or_else(now);
    let leeway = args.number("leeway").unwrap_or(60);

    let resolved = federate::resolve(&chain, &anchors, at, leeway)?;
    let terms = resolved.partner_terms();

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "subject": resolved.subject,
                "anchor": resolved.anchor,
                "chain_len": resolved.chain_len,
                "expires_at": resolved.expires_at,
                "anchor_stale": resolved.anchor_stale,
                "may_issue": resolved.may_issue(at),
                "keys": resolved.jwks.keys().collect::<Vec<_>>(),
                "zone": terms.zone.as_str(),
                "max_ttl_secs": terms.max_ttl_secs,
                "max_delegation_depth": terms.max_delegation_depth,
                "jurisdictions": terms.jurisdictions,
                "data_classes": terms.data_classes,
                "capabilities": resolved.metadata.capabilities,
            }))?
        );
        return Ok(());
    }

    println!("resolved   {}", resolved.subject);
    println!("anchor     {}", resolved.anchor);
    println!("chain      {} statement(s)", resolved.chain_len);
    println!(
        "keys       {}",
        resolved.jwks.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    println!(
        "expires    {} (in {})",
        resolved.expires_at,
        human_duration(resolved.expires_at.saturating_sub(at))
    );
    println!();
    println!(
        "  zone            {}  ({:?})",
        terms.zone,
        terms.zone.trust_level()
    );
    println!(
        "  ttl ceiling     {}",
        terms
            .max_ttl_secs
            .map_or_else(|| "-".to_string(), human_duration)
    );
    println!(
        "  delegation      max depth {}",
        terms
            .max_delegation_depth
            .map_or_else(|| "-".to_string(), |d| d.to_string())
    );
    println!("  jurisdictions   {}", terms.jurisdictions.join(", "));
    println!("  data classes    {}", terms.data_classes.join(", "));
    println!(
        "  capabilities    {}",
        resolved
            .metadata
            .capabilities
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );

    if resolved.anchor_stale {
        // UC-05 A2: a degrade, not a refusal.
        println!();
        println!("  ANCHOR STALE — this anchor is overdue for out-of-band re-verification.");
        println!("  Existing contracts run to their expiry; no new ones may be issued until");
        println!("  the anchor is re-confirmed and `verified_at` updated.");
        return Err(WcError::with_detail(
            Code::FEDERATION_ANCHOR_STALE,
            format!("anchor {} is overdue for re-verification", resolved.anchor),
        ));
    }
    println!();
    println!("  Federation sets a ceiling. It never names a tool — that is still the");
    println!("  contract's job, and local policy applies its own bar on top.");
    Ok(())
}

// ---------------------------------------------------------------------------
// evidence
// ---------------------------------------------------------------------------

fn audit_verify(args: &Args) -> Result<()> {
    let p = paths(args);
    let anchor_pub = match args.get("anchor-pub") {
        Some(path) => Some(std::fs::read(path).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
        })?),
        None => None,
    };
    let report = Evidence::verify(&p.evidence, anchor_pub.as_deref())?;

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "entries": report.entries,
                "head_seq": report.head_seq,
                "head_hash": report.head_hash,
                "intact": report.is_intact(),
                "broken_at": report.broken_at,
                "anchors_verified": report.anchors_verified,
                "anchor_mismatches": report.anchor_mismatches,
                "problems": report.problems,
            }))?
        );
    } else {
        println!("entries          {}", report.entries);
        println!(
            "head             seq {} {}",
            report.head_seq, report.head_hash
        );
        if anchor_pub.is_some() {
            println!("anchors verified {}", report.anchors_verified);
            if report.anchors_verified == 0 && report.entries > 0 {
                println!("                 (nothing signed: register with --anchor-key to anchor)");
            }
        } else {
            // Chain-only verification cannot detect a wholesale rewrite, and
            // saying so is more useful than a bare "ok".
            println!("anchors          not checked (pass --anchor-pub to verify signatures)");
        }
        for problem in &report.problems {
            println!("  problem: {problem}");
        }
        println!(
            "\n{}",
            if report.is_intact() {
                "chain is intact"
            } else {
                "CHAIN IS BROKEN"
            }
        );
    }

    if report.is_intact() {
        Ok(())
    } else {
        Err(WcError::with_detail(
            Code::CHAIN_BROKEN,
            format!(
                "verification failed with {} problem(s)",
                report.problems.len()
            ),
        ))
    }
}

fn export(args: &Args) -> Result<()> {
    let format = args.get("format").unwrap_or("csv");
    let p = paths(args);
    let as_of = args.number("as-of").unwrap_or_else(now);

    // An export references the chain head, so it is verifiable rather than merely
    // asserted (§8.5.9). The anchor key is optional and its absence is reported in
    // the export itself, never quietly.
    let anchor_pem = match args.get("anchor-pub") {
        Some(path) => Some(std::fs::read(path).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
        })?),
        None => None,
    };
    let head = Evidence::verify(&p.evidence, anchor_pem.as_deref())?;

    // Point-in-time: replay the log to `as_of` rather than reading the live
    // projection, so "as of 30 June" means what it says.
    let (projection, replay) =
        wc_control::store::Projection::as_of(&p.state, wc_control::store::STATE_LOG_NAME, as_of)?;
    let provenance = export::Provenance {
        as_of,
        chain_head_seq: head.head_seq,
        chain_head_hash: head.head_hash.clone(),
        // Only a checkpoint that actually verified counts as one.
        anchor_ref: (head.anchors_verified > 0 && head.anchor_mismatches.is_empty())
            .then(|| format!("anchor:{}:{}", head.anchors_verified, head.head_seq)),
        replay_complete: replay.is_clean() && head.broken_at.is_none(),
    };

    let rendered = match format {
        "dora" => render_register(
            args,
            &export::dora_register(&projection, provenance.clone())?,
        )?,
        "cps230" => render_register(
            args,
            &export::cps230_register(&projection, provenance.clone())?,
        )?,
        "oscal" => pretty(&export::oscal_component(&projection, &provenance)?)?,
        "bom" => {
            let raw = positional_or_flag(args, "id")?;
            let id = EntityId::new(raw)?;
            let entity = projection.entities.get(&id).ok_or_else(|| {
                WcError::with_detail(
                    Code::ENTITY_NOT_FOUND,
                    format!("{id} is not registered as of {as_of}"),
                )
            })?;
            pretty(&export::cyclonedx_bom(entity, as_of)?)?
        }
        "csv" | "json" => legacy_export(args, format, &projection, &provenance)?,
        other => {
            return Err(WcError::with_detail(
                Code::EXPORT_FAILED,
                format!(
                    "unknown export format {other:?}; try csv, json, dora, cps230, oscal or bom"
                ),
            ))
        }
    };

    match args.get("out") {
        Some(path) => {
            std::fs::write(path, &rendered).map_err(|e| {
                WcError::with_detail(Code::EXPORT_FAILED, format!("cannot write {path}"))
                    .with_source(e)
            })?;
            println!("wrote {} ({} bytes)", path, rendered.len());
        }
        None => print!("{rendered}"),
    }

    // The caveat goes to stderr as well as into the document, because the one
    // place it must not be missable is the terminal of the person about to file it.
    if !provenance.is_verifiable() {
        eprintln!("connect: warning: {}", provenance.caveat());
    }
    Ok(())
}

/// A regulatory register, as CSV or as JSON.
fn render_register(args: &Args, register: &export::Register) -> Result<String> {
    if args.has("json") {
        let value = serde_json::to_value(register).map_err(|e| {
            WcError::with_detail(Code::EXPORT_FAILED, "cannot serialise the register")
                .with_source(e)
        })?;
        Ok(format!("{}\n", pretty(&value)?))
    } else {
        Ok(register.to_csv())
    }
}

/// The original flat entity dump, kept because CI pipelines consume it.
fn legacy_export(
    args: &Args,
    format: &str,
    projection: &wc_control::store::Projection,
    provenance: &export::Provenance,
) -> Result<String> {
    let mut all: Vec<&Entity> = projection.entities.values().collect();
    all.sort_by_key(|e| e.id.as_str());

    if format == "csv" {
        let mut out = String::new();
        out.push_str(&format!(
            "# as_of={} chain_head_seq={} chain_head_hash={}\n# {}\n",
            provenance.as_of,
            provenance.chain_head_seq,
            provenance.chain_head_hash,
            provenance.caveat()
        ));
        out.push_str(
            "id,kind,owner,service,tier,zone,trust_level,posture,lifecycle,data_classes,jurisdictions,pin\n",
        );
        for e in &all {
            out.push_str(&format!(
                "{},{:?},{},{},{},{},{:?},{:?},{:?},{},{},{}\n",
                e.id,
                e.kind,
                e.owner,
                e.service.as_deref().unwrap_or(""),
                e.tier.as_u8(),
                e.zone,
                e.zone.trust_level(),
                e.posture,
                e.lifecycle,
                e.data_classes.join("|"),
                e.jurisdictions.join("|"),
                e.pin.manifest
            ));
        }
        return Ok(out);
    }

    let _ = args;
    Ok(format!(
        "{}\n",
        pretty(&json!({
            "as_of": provenance.as_of,
            "chain_head_seq": provenance.chain_head_seq,
            "chain_head_hash": provenance.chain_head_hash,
            "anchor_ref": provenance.anchor_ref,
            "verifiable": provenance.is_verifiable(),
            "caveat": provenance.caveat(),
            "entities": all.iter().map(|e| entity_json(e)).collect::<Vec<_>>(),
            // Gaps are declared, never silently omitted (UC-10 A1).
            "exceptions": export::gaps(projection, provenance.as_of),
        }))?
    ))
}

// ---------------------------------------------------------------------------
// canon
// ---------------------------------------------------------------------------

/// Parse a surface-kind name.
fn surface_kind(name: &str) -> Result<SurfaceKind> {
    match name {
        "mcp" | "mcp_tools" => Ok(SurfaceKind::McpTools),
        "a2a" | "a2a_card" => Ok(SurfaceKind::A2aCard),
        other => Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("unknown surface kind {other:?}; try mcp or a2a"),
        )),
    }
}

fn canon_cmd(args: &Args) -> Result<()> {
    let path = positional_or_flag(args, "file")?;
    let raw = read_json(path)?;
    let kind = surface_kind(args.get("kind").unwrap_or("mcp"))?;
    let entity = EntityId::new(args.get("entity").unwrap_or("urn:wc:canon"))?;
    let surface = canon::canonicalise(kind, &entity, &raw, &Limits::default())?;
    let pin = surface.to_pin(now());

    if args.has("document") {
        println!("{}", surface.document);
        return Ok(());
    }
    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "alg": pin.alg,
                "manifest": pin.manifest,
                "items": pin.items,
                "document": surface.document,
            }))?
        );
        return Ok(());
    }
    println!("alg      {}", pin.alg);
    println!("manifest {}", pin.manifest);
    for (name, hash) in &pin.items {
        println!("  {name:<32} {hash}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// screen — declared-surface injection screening (§8.7.4)
// ---------------------------------------------------------------------------

/// Screen a declared surface and report what the detectors found.
///
/// Exit 5 on a block, so this is usable as a CI gate on a vendored tool
/// manifest: a supplier who changes a description into an exfiltration
/// instruction fails the build rather than reaching admission.
///
/// The report always prints which detectors ran and which did not. A screening
/// pass that says "clean" without saying what executed is indistinguishable from
/// no screening at all.
fn screen_cmd(args: &Args) -> Result<()> {
    let path = positional_or_flag(args, "file")?;
    let raw = read_json(path)?;
    let kind = surface_kind(args.get("kind").unwrap_or("mcp"))?;
    let entity = EntityId::new(args.get("entity").unwrap_or(screen::SCREENING_SUBJECT))?;

    let rules = match args.get("rules") {
        Some(p) => screen::ScreenRules::load(std::path::Path::new(p))?,
        None => screen::ScreenRules::default(),
    };
    let acceptances = match args.get("acceptances") {
        Some(p) => screen::Acceptances::load(std::path::Path::new(p))?,
        None => screen::Acceptances::default(),
    };
    let mode = screen::ScreenMode::parse(args.get("mode").unwrap_or("flag"))?;
    let tier = match args.get("tier") {
        Some(t) => Tier::new(t.parse::<u8>().map_err(|e| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("tier must be 1..=4, got {t:?}"),
            )
            .with_source(e)
        })?)?,
        None => Tier::FOUR,
    };

    // The estate's other tool names, for S2's collision half and S6. Without
    // them those halves cannot fire, and the report says so rather than
    // reporting a clean surface.
    let mut names = screen::NameIndex::empty();
    if let Some(estate) = args.get("estate") {
        let doc = read_json(estate)?;
        let map = doc.as_object().ok_or_else(|| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                "estate file must be an object of tool-name -> entity-id",
            )
        })?;
        for (tool, owner) in map {
            let owner = owner.as_str().ok_or_else(|| {
                WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("estate entry {tool:?} must map to an entity id string"),
                )
            })?;
            names.insert(tool, EntityId::new(owner)?);
        }
    }

    let surface = canon::canonicalise(kind, &entity, &raw, &Limits::default())?;
    let ctx = screen::ScreenCtx {
        rules: &rules,
        acceptances: &acceptances,
        names: &names,
        entity: &entity,
        mode,
    };
    let report = screen::screen(&surface, tier, &ctx);

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "ruleset": report.ruleset,
                "mode": report.mode.as_str(),
                "calibrated": report.calibrated,
                "verdict": report.verdict.as_str(),
                "score": report.score,
                "max_item_score": report.max_item_score,
                "softened": report.softened,
                "ran": report.ran.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
                "skipped": report.skipped.iter()
                    .map(|(d, why)| json!({ "detector": d.as_str(), "reason": why }))
                    .collect::<Vec<_>>(),
                "item_scores": report.item_scores,
                "hits": report.hits.iter().map(|h| json!({
                    "detector": h.detector.as_str(),
                    "class": if h.detector.is_blocking() { "block" } else { "flag" },
                    "item": h.item,
                    "field": h.field,
                    "detail": h.detail,
                    "accepted": h.accepted,
                })).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!("ruleset  {}", report.ruleset);
        println!(
            "mode     {}{}",
            report.mode.as_str(),
            if report.calibrated {
                ""
            } else {
                "  (ruleset uncalibrated: blocking detectors report only)"
            }
        );
        println!(
            "verdict  {}   score {} (max item {})",
            report.verdict.as_str(),
            report.score,
            report.max_item_score
        );
        if let Some(why) = &report.softened {
            println!("softened {why}");
        }
        println!(
            "ran      {}",
            report
                .ran
                .iter()
                .map(|d| d.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );
        for (d, why) in &report.skipped {
            println!("not run  {} — {}", d.as_str(), why);
        }
        if report.hits.is_empty() {
            println!("\nno findings");
        } else {
            println!();
            for h in &report.hits {
                println!(
                    "{:<3} {:<6} {:<24} {:<28} {}{}",
                    h.detector.as_str(),
                    if h.detector.is_blocking() {
                        "block"
                    } else {
                        "flag"
                    },
                    h.item,
                    h.field,
                    h.detail,
                    if h.accepted { "  (accepted)" } else { "" }
                );
            }
        }
    }

    if report.blocked() {
        return Err(WcError::with_detail(
            Code::SCREENING_BLOCKED,
            format!(
                "{} blocking finding(s) under ruleset {}",
                report.blocking_hits().len(),
                report.ruleset
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// verify — the conformance ground truth (§7.4)
// ---------------------------------------------------------------------------

/// Check a `warden-connection+jws` against a trusted issuer key.
///
/// This is what makes the artifact a candidate standard rather than a product
/// format: any implementation may mint a contract, and a contract is valid iff
/// this accepts it. Only the artifact checks (1–5) run here — the context checks
/// need an authenticated peer and a presented surface, which a command-line tool
/// does not have. The exit code is the verdict.
fn verify_cmd(args: &Args) -> Result<()> {
    let path = positional_or_flag(args, "file")?;
    let jws = std::fs::read_to_string(path)
        .map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
        })?
        .trim()
        .to_string();

    // Trust comes from one PEM, or from a key set. A third-party implementer checking
    // their minter against this has a JWKS far more often than a PEM — it is what an
    // OIDC issuer and a SPIRE server both publish — and requiring them to convert it by
    // hand made the conformance entry point harder to reach than the specification.
    let keys = match (args.get("jwks"), args.get("issuer-pub")) {
        (Some(_), Some(_)) => {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "--jwks and --issuer-pub both name the issuer's trust; pass one",
            ))
        }
        (Some(path), None) => {
            let document = std::fs::read_to_string(path).map_err(|e| {
                WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}"))
                    .with_source(e)
            })?;
            let mut keys = IssuerKeys::new();
            let report = keys.add_jwks(&document)?;
            if !report.is_complete() {
                // On stderr, so `--json` on stdout stays machine-readable. Said at all
                // because "the key I expected was skipped" is otherwise indistinguishable
                // from "the contract names a kid nobody has heard of".
                eprintln!(
                    "connect verify: {} key(s) skipped: {}",
                    report.skipped.len(),
                    report.skipped.join("; ")
                );
            }
            keys
        }
        (None, _) => {
            let key_path = require(args, "issuer-pub")?;
            let pem = std::fs::read(key_path).map_err(|e| {
                WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {key_path}"))
                    .with_source(e)
            })?;
            let kid = require(args, "kid")?;

            let mut keys = IssuerKeys::new();
            match args.get("alg").unwrap_or("ES256") {
                "ES256" => keys.add_ec_pem(kid, &pem, Algorithm::ES256)?,
                "ES384" => keys.add_ec_pem(kid, &pem, Algorithm::ES384)?,
                "EdDSA" | "Ed25519" => keys.add_ed_pem(kid, &pem)?,
                other => {
                    return Err(WcError::with_detail(
                        Code::ALG_NOT_ASYMMETRIC,
                        format!("{other:?} is not an accepted contract algorithm"),
                    ))
                }
            }
            keys
        }
    };

    let mediator = require(args, "mediator-id")?;
    let at = args.number("now").unwrap_or_else(now);
    let mut opts = VerifyOpts::new(&keys, mediator, at);
    opts.leeway = args.number("leeway").unwrap_or(0);

    let verified = contract::verify_artifact(&jws, &opts)?;
    let p = &verified.payload;

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "verdict": "valid",
                "cid": p.cid.as_str(),
                "jti": p.jti.as_str(),
                "iss": p.iss,
                "aud": p.aud,
                "caller": p.caller.id.as_str(),
                "callee": p.callee.id.as_str(),
                "surface": { "tools": p.surface.tools, "skills": p.surface.skills,
                             "resources": p.surface.resources },
                "surface_digest": p.callee.surface_digest,
                "exp": p.exp,
                "remaining_secs": p.exp.saturating_sub(at),
                "posture": format!("{:?}", p.assurance.posture),
                "policy_version": p.policy_version,
                "checked": ["size", "alg", "signature", "schema", "typ", "nbf", "exp", "aud", "revocation"],
                "not_checked": ["peer identity", "presented surface digest", "zone policy",
                                "token binding"],
            }))?
        );
        return Ok(());
    }

    println!("valid  {}", p.cid);
    println!("  issuer     {}", p.iss);
    println!("  audience   {}", p.aud);
    println!(
        "  caller     {} ({}, tier {})",
        p.caller.id,
        p.caller.zone,
        p.caller.tier.as_u8()
    );
    println!(
        "  callee     {} ({}, tier {})",
        p.callee.id,
        p.callee.zone,
        p.callee.tier.as_u8()
    );
    println!("  surface    {}", p.surface.items().join(", "));
    if !p.surface.resources.is_empty() {
        println!("  resources  {}", p.surface.resources.join(", "));
    }
    println!(
        "  digest     {}",
        p.callee.surface_digest.as_deref().unwrap_or("-")
    );
    println!(
        "  expires    {} ({}s remaining)",
        p.exp,
        p.exp.saturating_sub(at)
    );
    println!("  posture    {:?}", p.assurance.posture);
    println!("  policy     {}", p.policy_version);
    // Saying what was *not* checked matters: a verdict that overstates its scope
    // is worse than no verdict.
    println!("\n  checked: size, alg, signature, schema, typ, nbf/exp, aud, revocation");
    println!("  not checked here: peer identity, presented surface, zone policy, token binding");
    Ok(())
}

// ---------------------------------------------------------------------------
// issuance — the core loop (UC-04)
// ---------------------------------------------------------------------------

/// The accountable human behind a request.
fn requesting_human(args: &Args) -> Result<HumanRef> {
    let raw = args
        .get("by")
        .map(str::to_string)
        .or_else(|| std::env::var("WARDEN_CONNECT_ACTOR").ok())
        .ok_or_else(|| {
            WcError::with_detail(
                Code::OWNER_UNRESOLVABLE,
                "a request needs an accountable human: pass --by human:you or set \
                 WARDEN_CONNECT_ACTOR",
            )
        })?;
    HumanRef::new(raw)
}

/// A signing key from a PEM path and a `kid`.
///
/// Used for the revocation key, which is deliberately separate from the issuer key
/// (§8.12.1): an operator who can mint contracts should not thereby be able to cut
/// connections, and vice versa.
fn load_issuer_key(path: &str, kid: &str, alg: Option<&str>) -> Result<IssuerKey> {
    let pem = std::fs::read(path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
    })?;
    match alg.unwrap_or("ES256") {
        "ES256" => IssuerKey::ec_pem(kid, &pem, Algorithm::ES256),
        "ES384" => IssuerKey::ec_pem(kid, &pem, Algorithm::ES384),
        "EdDSA" | "Ed25519" => IssuerKey::ed_pem(kid, &pem),
        other => Err(WcError::with_detail(
            Code::ALG_NOT_ASYMMETRIC,
            format!("{other:?} is not an accepted algorithm"),
        )),
    }
}

/// The issuer signing key, and the `kid` stamped into every artifact.
/// Whether this estate forbids signing keys on local disk.
///
/// The posture that makes "KMS, no local copy" a control rather than a wiki page.
/// Enforced at construction, so a run that would have signed with a PEM does not
/// start — the alternative is discovering it in the evidence chain afterwards, which
/// [`Custody`] makes possible but which is a worse place to find out.
fn external_signing_required(args: &Args) -> bool {
    args.has("require-external-signing")
        || std::env::var("WARDEN_CONNECT_REQUIRE_EXTERNAL_SIGNING")
            .is_ok_and(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
}

fn issuer_key(args: &Args) -> Result<IssuerKey> {
    let kid = require(args, "kid")?;

    // `--signer` is the custody choice: the private key lives in an HSM, a
    // smartcard or a KMS and this process never sees it (`docs/key-custody.md`).
    // Checked before `--issuer-key` so that supplying both is an error rather than a
    // silent preference — an operator who believes their key is in a token and finds
    // a PEM was used instead has the worst possible outcome here.
    match (args.get("signer"), args.get("issuer-key")) {
        (Some(_), Some(_)) => Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            "--signer and --issuer-key both given; one names a key held elsewhere \
             and the other a key on this disk, so which is in force must not be a guess",
        )),
        (Some(command), None) => {
            CommandSigner::parse(command)?.into_issuer_key(kid, Algorithm::ES256)
        }
        (None, Some(path)) => {
            if external_signing_required(args) {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!(
                        "--require-external-signing is set and --issuer-key {path} is a key on \
                         this disk; use --signer COMMAND"
                    ),
                ));
            }
            let pem = std::fs::read(path).map_err(|e| {
                WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}"))
                    .with_source(e)
            })?;
            IssuerKey::ec_pem(kid, &pem, Algorithm::ES256)
        }
        (None, None) => Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            "--issuer-key PEM or --signer COMMAND is required",
        )),
    }
}

/// Where artifacts are written. One file per mediator, because one contract is
/// addressed to one mediator.
fn write_artifacts(args: &Args, issued: &Issued) -> Result<Vec<String>> {
    let dir = args.get("out").unwrap_or(".");
    std::fs::create_dir_all(dir).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot create {dir}")).with_source(e)
    })?;

    let mut written = Vec::new();
    for (aud, jws) in &issued.artifacts {
        let safe: String = aud
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = std::path::Path::new(dir).join(format!("{}.{safe}.jws", issued.record.cid));
        std::fs::write(&path, format!("{jws}\n")).map_err(|e| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("cannot write {}", path.display()),
            )
            .with_source(e)
        })?;
        written.push(path.display().to_string());
    }
    Ok(written)
}

fn print_issued(args: &Args, issued: &Issued, paths: &[String]) -> Result<()> {
    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "cid": issued.record.cid.as_str(),
                "jti": issued.record.jti.as_str(),
                "caller": issued.record.caller.as_str(),
                "callee": issued.record.callee.as_str(),
                "surface": issued.record.surface.items(),
                "surface_digest": issued.record.surface_digest,
                "aud": issued.record.aud,
                "exp": issued.record.exp,
                "approval_mode": format!("{:?}", issued.record.approval.mode),
                "policy_version": issued.record.policy_version,
                "evidence_seq": issued.evidence_seq,
                "artifacts": paths,
            }))?
        );
        return Ok(());
    }

    let r = &issued.record;
    println!("issued {}", r.cid);
    println!("  caller     {}", r.caller);
    println!("  callee     {} (tier {})", r.callee, r.callee_tier.as_u8());
    println!("  surface    {}", r.surface.items().join(", "));
    println!("  digest     {}", r.surface_digest);
    println!(
        "  expires    {} (in {})",
        r.exp,
        human_duration(r.exp.saturating_sub(r.iat))
    );
    println!("  approval   {:?}", r.approval.mode);
    if let Some(by) = &r.approval.by {
        println!("  approved   {by}");
    }
    if let Some(second) = &r.approval.second {
        println!("  second     {second}");
    }
    if let Some(ticket) = &r.approval.ticket {
        println!("  ticket     {ticket}");
    }
    println!("  policy     {}", r.policy_version);
    println!("  evidence   seq {}", issued.evidence_seq);
    for path in paths {
        println!("  artifact   {path}");
    }
    Ok(())
}

/// Build the issuance context: store, chain, policy and signing key together.
fn with_issuer<T>(args: &Args, f: impl FnOnce(&mut Issuer<'_>) -> Result<T>) -> Result<T> {
    let policy = load_policy(args)?;
    let key = issuer_key(args)?;
    let mut store = open_store(args)?;
    let mut evidence = open_evidence(args)?;
    let iss = args
        .get("iss")
        .unwrap_or("https://connect.internal")
        .to_string();

    let mut issuer = Issuer::new(
        &mut store,
        &mut evidence,
        &policy,
        &key,
        &iss,
        now(),
        actor(args)?,
    );
    // Observe unless told otherwise, the same default `register` uses: P0 is a
    // visibility wedge, and an estate with no attestation verifiers configured must
    // still be able to issue and record contracts.
    issuer.mode = mode(args);
    f(&mut issuer)
}

fn request_cmd(args: &Args) -> Result<()> {
    let input = RequestInput {
        caller: EntityId::new(require(args, "from")?)?,
        callee: EntityId::new(require(args, "to")?)?,
        surface: Surface {
            tools: args.list("tools"),
            skills: args.list("skills"),
            resources: args.list("resources"),
        },
        terms: Terms {
            data_classes: args.list("data-classes"),
            jurisdictions: args.list("jurisdictions"),
            ..Default::default()
        },
        ttl_secs: args
            .get("ttl")
            .and_then(cpolicy::parse_duration)
            .unwrap_or(30 * 86_400),
        justification: require(args, "justify")?.to_string(),
        // A request needs an accountable human, full stop. Falling back to an
        // anonymous placeholder is exactly what invariant 1 exists to prevent.
        requester: requesting_human(args)?,
        mediators: {
            let m = args.list("mediator");
            if m.is_empty() {
                vec!["warden:mediator:default".to_string()]
            } else {
                m
            }
        },
    };

    let outcome = with_issuer(args, |issuer| issuer.request(&input))?;

    match outcome {
        Outcome::Issued(issued) => {
            let paths = write_artifacts(args, &issued)?;
            print_issued(args, &issued, &paths)
        }
        Outcome::AwaitingApproval(pending) => {
            if args.has("json") {
                println!(
                    "{}",
                    pretty(&json!({
                        "request": pending.id,
                        "status": "awaiting_approval",
                        "digest": pending.digest(),
                        "approver_role": pending.approver_role,
                        "dual_control": pending.dual_control,
                        "expires_at": pending.expires_at,
                        "ttl_secs": pending.ttl_secs,
                        "policy_version": pending.policy_version,
                        "reason": pending.policy_reason,
                        "trace": pending.policy_trace,
                    }))?
                );
            } else {
                println!("awaiting approval  {}", pending.id);
                println!("  surface     {}", pending.surface.items().join(", "));
                println!("  ttl         {}", human_duration(pending.ttl_secs));
                println!(
                    "  approver    {}{}",
                    pending.approver_role.as_deref().unwrap_or("any"),
                    if pending.dual_control {
                        " (two distinct approvers)"
                    } else {
                        ""
                    }
                );
                println!("  digest      {}", pending.digest());
                println!("  lapses at   {}", pending.expires_at);
                println!("  why         {}", pending.policy_reason);
                println!("  trace       {}", pending.policy_trace);
            }
            // Exit 6: approval required and not granted. CI can act on this.
            Err(WcError::with_detail(
                Code::APPROVER_ROLE_MISSING,
                format!("request {} needs a human", pending.id),
            ))
        }
        Outcome::Denied { reason, trace } => {
            println!("denied");
            println!("  why    {reason}");
            println!("  trace  {trace}");
            Err(WcError::with_detail(Code::POLICY_DENIED, reason))
        }
    }
}

/// Approve a pending request: sign as the approver, verify, then mint.
///
/// In production the signing happens in the approver's own client and only the
/// signature reaches the control plane. Doing both here keeps the demo honest —
/// the same verification runs either way.
fn approve_cmd(args: &Args) -> Result<()> {
    let request_id = positional_or_flag(args, "id")?.to_string();
    let registry = load_approvers(args)?;

    let approver = HumanRef::new(require(args, "by")?)?;
    let key_path = require(args, "approver-key")?;
    let signing = approver_signing_key(&approver, key_path)?;

    let second = match (args.get("second"), args.get("second-key")) {
        (Some(id), Some(path)) => {
            let who = HumanRef::new(id)?;
            Some((approver_signing_key(&who, path)?, who))
        }
        (None, None) => None,
        _ => {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "--second and --second-key must be given together",
            ))
        }
    };
    let ticket = args.get("ticket").map(str::to_string);

    let issued = with_issuer(args, move |issuer| {
        let pending = issuer.pending_request(&request_id)?;
        let mut proofs = vec![ApprovalProof {
            by: approver.clone(),
            jws: issuance::sign_approval(&pending, &signing, ticket.as_deref(), issuer.now)?,
        }];
        if let Some((key, who)) = &second {
            proofs.push(ApprovalProof {
                by: who.clone(),
                jws: issuance::sign_approval(&pending, key, ticket.as_deref(), issuer.now)?,
            });
        }
        issuer.approve(&request_id, &proofs, &registry)
    })?;

    let paths = write_artifacts(args, &issued)?;
    print_issued(args, &issued, &paths)
}

/// Issue a time-boxed emergency contract (T6.6).
///
/// Two distinct approvers are mandatory and the TTL is bounded. What this command
/// cannot check is key custody: it verifies two registered identities with valid
/// signatures over the same digest, not that two people were present. That is an
/// envelope-and-safe control, and the runbook has to carry it.
fn breakglass_cmd(args: &Args) -> Result<()> {
    let registry = load_approvers(args)?;

    let first = HumanRef::new(require(args, "by")?)?;
    let first_key = approver_signing_key(&first, require(args, "approver-key")?)?;
    let second = HumanRef::new(require(args, "second")?)?;
    let second_key = approver_signing_key(&second, require(args, "second-key")?)?;
    if first == second {
        // Caught here as well as in the issuer, so the operator hears it before
        // typing a second passphrase.
        return Err(WcError::with_detail(
            Code::DUAL_CONTROL_MISSING,
            "break-glass needs two distinct approvers",
        ));
    }

    let limits = issuance::BreakGlassLimits {
        max_ttl_secs: args
            .get("max-ttl")
            .and_then(cpolicy::parse_duration)
            .unwrap_or(issuance::BreakGlassLimits::default().max_ttl_secs),
        max_per_window: args
            .number("budget")
            .unwrap_or(u64::from(
                issuance::BreakGlassLimits::default().max_per_window,
            ))
            .min(u64::from(u32::MAX)) as u32,
        window_secs: args
            .get("window")
            .and_then(cpolicy::parse_duration)
            .unwrap_or(issuance::BreakGlassLimits::default().window_secs),
    };
    limits.validate()?;

    let input = issuance::BreakGlassInput {
        caller: EntityId::new(require(args, "from")?)?,
        callee: EntityId::new(require(args, "to")?)?,
        surface: Surface {
            tools: args.list("tools"),
            skills: args.list("skills"),
            resources: args.list("resources"),
        },
        terms: Terms::default(),
        // Default 15 minutes: long enough to triage, short enough that nobody
        // builds a process on it.
        ttl_secs: args
            .get("ttl")
            .and_then(cpolicy::parse_duration)
            .unwrap_or(900),
        incident: require(args, "incident")?.to_string(),
        justification: require(args, "justify")?.to_string(),
        requester: requesting_human(args)?,
        mediators: {
            let m = args.list("mediator");
            if m.is_empty() {
                vec!["warden:mediator:default".to_string()]
            } else {
                m
            }
        },
    };

    let issued = with_issuer(args, move |issuer| {
        let pending = issuer.breakglass_pending(&input);
        let proofs = vec![
            ApprovalProof {
                by: first.clone(),
                jws: issuance::sign_approval(&pending, &first_key, None, issuer.now)?,
            },
            ApprovalProof {
                by: second.clone(),
                jws: issuance::sign_approval(&pending, &second_key, None, issuer.now)?,
            },
        ];
        issuer.breakglass(&input, &proofs, &registry, &limits)
    })?;

    let paths = write_artifacts(args, &issued)?;
    print_issued(args, &issued, &paths)?;
    if !args.has("json") {
        // The two things an operator must leave this command knowing.
        println!();
        println!(
            "  BREAK-GLASS — expires at {} and cannot be renewed. Extending it means",
            issued.record.exp
        );
        println!("  a fresh request under policy. Recorded as contract.breakglass with both");
        println!("  approvers, the incident, and every override it used.");
    }
    Ok(())
}

/// A duration a human can read at a glance.
///
/// Integer days is wrong for anything short: a 15-minute break-glass contract
/// rendered as `0d` tells an operator nothing during the incident it was issued
/// for, which is the only time they will read it.
fn human_duration(secs: u64) -> String {
    match secs {
        0 => "0s".to_string(),
        s if s < 60 => format!("{s}s"),
        s if s < 3_600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h{}m", s / 3_600, (s % 3_600) / 60),
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s => format!("{}d{}h", s / 86_400, (s % 86_400) / 3_600),
    }
}

fn deny_cmd(args: &Args) -> Result<()> {
    let request_id = positional_or_flag(args, "id")?.to_string();
    let reason = require(args, "reason")?.to_string();
    with_issuer(args, |issuer| issuer.deny(&request_id, &reason))?;
    println!("denied {request_id}");
    Ok(())
}

fn requests_cmd(args: &Args) -> Result<()> {
    let mut store = open_store(args)?;
    let show_all = args.has("all");
    let mut rows: Vec<&PendingRequest> = store
        .projection
        .requests
        .values()
        .filter(|r| show_all || r.status == RequestStatus::Pending)
        .collect();
    rows.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));

    if args.has("json") {
        let out: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "id": r.id, "status": format!("{:?}", r.status),
                    "caller": r.caller.as_str(), "callee": r.callee.as_str(),
                    "surface": r.surface.items(), "ttl_secs": r.ttl_secs,
                    "approver_role": r.approver_role, "dual_control": r.dual_control,
                    "expires_at": r.expires_at, "digest": r.digest(),
                })
            })
            .collect();
        println!("{}", pretty(&Value::Array(out))?);
        return Ok(());
    }

    if rows.is_empty() {
        println!(
            "{}",
            if show_all {
                "no requests"
            } else {
                "no pending requests"
            }
        );
        return Ok(());
    }
    println!(
        "{:<18} {:<10} {:<28} {:<22} SURFACE",
        "REQUEST", "STATUS", "CALLER", "CALLEE"
    );
    for r in rows {
        println!(
            "{:<18} {:<10} {:<28} {:<22} {}",
            r.id,
            format!("{:?}", r.status),
            truncate(r.caller.as_str(), 28),
            truncate(r.callee.as_str(), 22),
            r.surface.items().join(", ")
        );
    }
    let _ = &mut store;
    Ok(())
}

fn contracts_cmd(args: &Args) -> Result<()> {
    let store = open_store(args)?;

    if let Some(cid) = args
        .get("cid")
        .or_else(|| args.verbs.get(1).map(String::as_str))
    {
        let record = store
            .projection
            .contracts
            .values()
            .find(|c| c.cid.as_str() == cid)
            .ok_or_else(|| {
                WcError::with_detail(Code::CONTRACT_NOT_FOUND, format!("no contract {cid}"))
            })?;
        if args.has("json") {
            println!(
                "{}",
                pretty(&serde_json::to_value(record).unwrap_or_default())?
            );
        } else {
            println!("{}", record.cid);
            println!("  status     {:?}", record.status);
            println!("  caller     {}", record.caller);
            println!(
                "  callee     {} (tier {})",
                record.callee,
                record.callee_tier.as_u8()
            );
            println!("  surface    {}", record.surface.items().join(", "));
            println!("  digest     {}", record.surface_digest);
            println!("  aud        {}", record.aud.join(", "));
            println!("  expires    {}", record.exp);
            println!("  approval   {:?}", record.approval.mode);
            println!("  policy     {}", record.policy_version);
        }
        return Ok(());
    }

    let mut rows: Vec<_> = store.projection.contracts.values().collect();
    rows.sort_by(|a, b| a.cid.as_str().cmp(b.cid.as_str()));
    if rows.is_empty() {
        println!("no contracts");
        return Ok(());
    }
    println!(
        "{:<18} {:<10} {:<28} {:<22} EXPIRES",
        "CID", "STATUS", "CALLER", "CALLEE"
    );
    for r in rows {
        println!(
            "{:<18} {:<10} {:<28} {:<22} {}",
            r.cid,
            format!("{:?}", r.status),
            truncate(r.caller.as_str(), 28),
            truncate(r.callee.as_str(), 22),
            r.exp
        );
    }
    Ok(())
}

/// Load the approver registry from TOML.
fn load_approvers(args: &Args) -> Result<ApproverRegistry> {
    #[derive(serde::Deserialize)]
    struct Entry {
        id: String,
        #[serde(default)]
        roles: Vec<String>,
        key: String,
    }
    #[derive(serde::Deserialize)]
    struct File {
        #[serde(default)]
        approver: Vec<Entry>,
    }

    let path = args.get("approvers").unwrap_or("approvers.toml");
    let text = std::fs::read_to_string(path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
    })?;
    let parsed: File = toml_from_str(&text, path)?;

    let mut registry = ApproverRegistry::new();
    for entry in parsed.approver {
        let id = HumanRef::new(&entry.id)?;
        let pem = std::fs::read(&entry.key).map_err(|e| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("cannot read approver key {}", entry.key),
            )
            .with_source(e)
        })?;
        let roles: Vec<&str> = entry.roles.iter().map(String::as_str).collect();
        registry.add_ec(&id, &pem, Algorithm::ES256, &roles)?;
    }
    if registry.is_empty() {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("{path} registers no approvers"),
        ));
    }
    Ok(registry)
}

fn toml_from_str<T: serde::de::DeserializeOwned>(text: &str, path: &str) -> Result<T> {
    toml::from_str(text).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot parse {path}: {e}"))
    })
}

/// An approver's private key, for signing in this process.
fn approver_signing_key(who: &HumanRef, path: &str) -> Result<IssuerKey> {
    let pem = std::fs::read(path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
    })?;
    IssuerKey::ec_pem(who.as_str(), &pem, Algorithm::ES256)
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

/// Run the control-plane HTTP surface.
///
/// The store holds an exclusive writer lock for the process lifetime, so `serve`
/// and the other subcommands cannot run against the same tenant at once — by
/// design (§8.5.2). Use the API while it is up.
fn serve_cmd(args: &Args) -> Result<()> {
    let listen = args.get("listen").unwrap_or("127.0.0.1:8787").to_string();
    let policy = load_policy(args)?;
    let report = policy.lint();
    if !report.is_usable() {
        // Refuse to start rather than serve under a policy that will not load
        // (§8.13): a control plane that boots with a broken policy believes it is
        // enforcing something it is not.
        for e in &report.errors {
            eprintln!("connect: policy error: {e}");
        }
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!(
                "policy has {} error(s); refusing to start",
                report.errors.len()
            ),
        ));
    }
    for w in &report.warnings {
        eprintln!("connect: policy warning: {w}");
    }

    let signer = issuer_key(args)?;
    let store = open_store(args)?;
    let evidence = open_evidence(args)?;
    let iss = args
        .get("iss")
        .unwrap_or("https://connect.internal")
        .to_string();

    let transport = transport_policy(args, &listen)?;
    let mut cp = ControlPlane::new(store, evidence, policy, signer, &iss, now)
        .with_mode(mode(args))
        .with_transport(transport.clone());

    if let Some(path) = args.get("jwks") {
        let text = std::fs::read_to_string(path).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
        })?;
        cp = cp.with_jwks(&text);
    }
    if args.get("approvers").is_some() || std::path::Path::new("approvers.toml").exists() {
        cp = cp.with_approvers(load_approvers(args)?);
    }

    let tokens = load_tokens(args)?;
    for (token, token_roles) in &tokens {
        let as_refs: Vec<&str> = token_roles.iter().map(String::as_str).collect();
        cp = cp.with_token(token, &as_refs);
    }

    let api = Arc::new(Api(Arc::new(cp)));
    let shutdown = Arc::new(Shutdown::default());

    println!("connect serve  {listen}");
    println!("  tenant   {}", args.get("tenant").unwrap_or("default"));
    println!("  policy   {}", load_policy(args)?.version);
    println!("  mode     {:?}", mode(args));
    println!("  tokens   {}", tokens.len());
    println!("  transport {}", transport.describe());
    println!("\n  GET  /healthz /readyz /metrics /v1/jwks.json");
    println!("  GET  /v1/entities /v1/posture /v1/connections /v1/requests /v1/mediators");
    println!("  POST /v1/connections /v1/requests/<id>/approve|deny /v1/quarantine");
    println!("  GET  /v1/mediators/<id>/contracts    POST /v1/mediators/<id>/ack");

    http::serve(&listen, api, shutdown, |addr| {
        if listen.ends_with(":0") {
            println!("  bound    {addr}");
        }
    })
    .map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot serve on {listen}"))
            .with_source(e)
    })
}

/// Bearer tokens and their roles.
///
/// A file rather than flags, so a token never lands in a shell history or a process
/// listing.
fn load_tokens(args: &Args) -> Result<Vec<(String, Vec<String>)>> {
    #[derive(serde::Deserialize)]
    struct Entry {
        token: String,
        #[serde(default)]
        roles: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct File {
        #[serde(default)]
        client: Vec<Entry>,
    }

    let path = args.get("tokens").unwrap_or("tokens.toml");
    let text = std::fs::read_to_string(path).map_err(|e| {
        WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("cannot read {path}; the api needs at least one client token"),
        )
        .with_source(e)
    })?;
    let parsed: File = toml_from_str(&text, path)?;
    if parsed.client.is_empty() {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("{path} registers no clients, so nothing could authenticate"),
        ));
    }
    Ok(parsed
        .client
        .into_iter()
        .map(|c| (c.token, c.roles))
        .collect())
}

// ---------------------------------------------------------------------------
// policy
// ---------------------------------------------------------------------------

/// The default policy file name, alongside the binary's working directory.
const DEFAULT_POLICY: &str = "connect-policy.toml";

fn load_policy(args: &Args) -> Result<ConnectPolicy> {
    ConnectPolicy::load(args.get("policy").unwrap_or(DEFAULT_POLICY))
}

/// Static checks. Exits 3 on an error, 0 with warnings — a warning is advice, an
/// error means the policy would not load.
fn policy_lint(args: &Args) -> Result<()> {
    let policy = load_policy(args)?;
    let report = policy.lint();

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "version": policy.version,
                "usable": report.is_usable(),
                "errors": report.errors,
                "warnings": report.warnings,
            }))?
        );
    } else {
        println!(
            "policy   {}",
            if policy.version.trim().is_empty() {
                "(unset)"
            } else {
                &policy.version
            }
        );
        println!("zones    {}", policy.zones.len());
        println!("rules    {}", policy.rules.len());
        println!("default  {}", policy.default.as_str());
        println!(
            "crossings {} declared, lattice {}",
            policy.crossings.len(),
            if policy.strict_crossings {
                "ENFORCED"
            } else {
                "advisory (strict_crossings = false)"
            }
        );
        if !report.errors.is_empty() || !report.warnings.is_empty() {
            println!();
        }
        // The bridge between the two mechanisms: an estate about to turn on
        // strict_crossings needs to know which stanzas to write first, and
        // deriving them from the rules already in the file beats discovering them
        // from denied traffic.
        let lattice = policy.lattice()?;
        for problem in lattice.lint() {
            println!("  warning zone lattice: {problem}");
        }
        let implied = policy.implied_crossings();
        if !implied.is_empty() && !policy.strict_crossings {
            println!();
            println!("  these rules cross a trust boundary. To enforce the lattice, set");
            println!("  strict_crossings = true and declare them:");
            for (crossing, from, to) in &implied {
                let already = policy.crossings.iter().any(|c| {
                    c.crossing == crossing.as_str()
                        && c.from.as_deref() == Some(from.as_str())
                        && c.to.as_deref() == Some(to.as_str())
                });
                println!(
                    "    [[crossing]] crossing = {:?}, from = {from:?}, to = {to:?}{}",
                    crossing.as_str(),
                    if already { "   # already declared" } else { "" }
                );
            }
        }

        for e in &report.errors {
            println!("  error   {e}");
        }
        for w in &report.warnings {
            println!("  warning {w}");
        }
        println!(
            "\n{}",
            if report.is_usable() {
                format!("usable · {} warning(s)", report.warnings.len())
            } else {
                format!("NOT USABLE · {} error(s)", report.errors.len())
            }
        );
    }

    if report.is_usable() {
        Ok(())
    } else {
        Err(WcError::with_detail(
            Code::POLICY_INVALID,
            format!("{} error(s)", report.errors.len()),
        ))
    }
}

/// Replay every live contract against a candidate policy.
///
/// A policy change is the likeliest cause of a self-inflicted outage, so this
/// answers "what breaks if I ship this" before it ships.
fn policy_dry_run(args: &Args) -> Result<()> {
    let policy = load_policy(args)?;
    let store = open_store(args)?;
    let ts = args.number("now").unwrap_or_else(now);

    let standing = standing_state(&store);
    let report = policy.dry_run(&store.projection, &standing, ts);

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "policy": policy.version,
                "evaluated": report.rows.len(),
                "neutral": report.is_neutral(),
                "would_deny": report.would_deny,
                "would_escalate": report.would_escalate,
                "unevaluable": report.unevaluable.iter()
                    .map(|(cid, why)| json!({"cid": cid, "why": why}))
                    .collect::<Vec<_>>(),
                "rows": report.rows.iter().map(|r| json!({
                    "cid": r.cid, "decision": r.decision,
                    "still_issuable": r.still_issuable, "reason": r.reason,
                })).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }

    println!("candidate  {}", policy.version);
    println!("evaluated  {} live contract(s)", report.rows.len());
    if report.rows.is_empty() && report.unevaluable.is_empty() {
        println!("\nno live contracts to re-evaluate");
        return Ok(());
    }

    println!();
    println!("{:<18} {:<18} WHY", "CID", "WOULD BE");
    for row in &report.rows {
        println!(
            "{:<18} {:<18} {}",
            truncate(&row.cid, 18),
            row.decision,
            row.reason
        );
    }

    if !report.unevaluable.is_empty() {
        // Never silently omitted: an answer that leaves out part of the estate is
        // worse than no answer.
        println!("\nunevaluable:");
        for (cid, why) in &report.unevaluable {
            println!("  {cid}  {why}");
        }
    }

    println!(
        "\n{}",
        if report.is_neutral() {
            "no live contract changes decision".to_string()
        } else {
            format!(
                "{} would be denied · {} would need a human",
                report.would_deny.len(),
                report.would_escalate.len()
            )
        }
    );
    Ok(())
}

/// Print the resolved zone bars — what a rule actually inherits, rather than what
/// the file literally says.
fn policy_show(args: &Args) -> Result<()> {
    let policy = load_policy(args)?;

    if args.has("json") {
        let zones: Vec<Value> = policy
            .zones
            .iter()
            .map(|z| {
                let bar = ZoneId::new(&z.id).ok().map(|id| policy.bar_for(&id));
                json!({
                    "id": z.id,
                    "trust": format!("{:?}", z.trust).to_lowercase(),
                    "resolved": bar.map(|b| json!({
                        "identity": format!("{:?}", b.identity).to_lowercase(),
                        "provenance": format!("{:?}", b.provenance).to_lowercase(),
                        "approval": format!("{:?}", b.approval).to_lowercase(),
                        "oversight": format!("{:?}", b.oversight).to_lowercase(),
                        "ttl_secs": b.ttl_secs(),
                        "max_delegation_depth": b.max_delegation_depth,
                    })),
                })
            })
            .collect();
        println!("{}", pretty(&Value::Array(zones))?);
        return Ok(());
    }

    println!("policy   {}", policy.version);
    println!("default  {}", policy.default.as_str());
    println!("\nresolved zone bars (declaration combined with the trust-level floor):");
    println!(
        "\n{:<24} {:<9} {:<10} {:<12} {:<10} DEPTH",
        "ZONE", "TRUST", "IDENTITY", "APPROVAL", "TTL"
    );
    for zone in &policy.zones {
        let Ok(id) = ZoneId::new(&zone.id) else {
            continue;
        };
        let bar = policy.bar_for(&id);
        println!(
            "{:<24} {:<9} {:<10} {:<12} {:<10} {}",
            truncate(&zone.id, 24),
            format!("{:?}", zone.trust).to_lowercase(),
            format!("{:?}", bar.identity).to_lowercase(),
            format!("{:?}", bar.approval).to_lowercase(),
            bar.ttl_secs()
                .map_or_else(|| "-".to_string(), human_duration),
            bar.max_delegation_depth
                .map_or("-".to_string(), |d| d.to_string())
        );
    }

    println!("\nstanding policy:");
    let s = &policy.standing;
    println!("  max share          {:.0}%", s.max_share * 100.0);
    println!("  max per window     {} per {}", s.max_per_window, s.window);
    println!("  min callee tier    {}", s.min_callee_tier);
    println!("  write allowed      {}", s.allow_write);
    println!("  max items          {}", s.max_tools);
    println!(
        "  reviewed           {}",
        if s.reviewed_at == 0 {
            "never — every request escalates to a human".to_string()
        } else {
            format!("at {} (every {})", s.reviewed_at, s.review_every)
        }
    );
    Ok(())
}

/// Standing-issuance counters as of now, from the projection.
fn standing_state(store: &Store) -> StandingState {
    let active: Vec<_> = store
        .projection
        .contracts
        .values()
        .filter(|c| c.status == wc_core::contract::ContractStatus::Active)
        .collect();
    let standing = active
        .iter()
        .filter(|c| c.approval.mode == ApprovalMode::StandingPolicy)
        .count();
    StandingState {
        active_contracts: active.len(),
        standing_contracts: standing,
        // Windowed issuance needs the state log; until the issuance workflow lands
        // this is the conservative zero rather than a guess.
        issued_in_window: 0,
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Accept either `connect show <id>` or `connect show --id <id>`.
/// The subject of a command, from a positional, a trailing verb, or a flag.
///
/// `verbs` holds everything before the first flag, so for a one-word command the
/// subject is `verbs[1]` and for a two-word one it is `verbs[2]`. Reading a fixed
/// index makes `bundle verify estate.wcb` resolve its own subcommand name as the
/// filename — found by running exactly that.
fn positional_or_flag<'a>(args: &'a Args, flag: &str) -> Result<&'a str> {
    if let Some(v) = args.positional.first() {
        return Ok(v);
    }
    let skip = if TWO_WORD.contains(&args.verb_prefix(2).as_str()) {
        2
    } else {
        1
    };
    if let Some(v) = args.verbs.get(skip) {
        return Ok(v);
    }
    require(args, flag)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("…{}", &s[s.len() - (max - 1)..])
    }
}

fn usage() -> String {
    let exe = "connect";
    format!(
        "\
warden-connect — the connection control plane for AI agents

USAGE
  {exe} <command> [flags]

REGISTER
  register server --endpoint URL --owner human:x --zone internal.y
                  [--surface FILE] [--tier N] [--service S]
                  [--data-classes a,b] [--jurisdictions SG,AU] [--enforce]
  register agent  --card FILE --owner human:x --zone internal.y [--id ID]

  ATTESTATION (any subset; each stage stays skipped without its material)
    --svid FILE --trust-key KID=PEM[:ALG] --aud NAME [--leeway N]   stage 1
    --card-key KID=PEM[:ALG] [--require-card-signature]             stage 3
    --attest FILE --prov-key KID=PEM[:ALG] --builder ID             stage 4
      and one of --artifact-digest sha256:... | --bind-surface
    --screen-rules FILE --screen-mode observe|flag|enforce          stage 5

CONNECT  (the core loop)
  request --from ID --to ID --tools a,b --justify TEXT [--ttl 30d]
          [--mediator ID] [--data-classes a,b] [--jurisdictions SG,AU]
          --issuer-key PEM --kid KID [--out DIR]
  approve <req-id> --by human:x --approver-key PEM [--second human:y --second-key PEM]
          [--ticket RISK-1] --issuer-key PEM --kid KID [--out DIR]
  deny    <req-id> --reason TEXT
  breakglass --from ID --to ID --tools a,b --incident SOC-1 --justify TEXT
             --ttl 15m --by human:a --approver-key PEM
             --second human:b --second-key PEM --issuer-key PEM --kid KID
             [--max-ttl 1h] [--budget 3] [--window 24h]
  requests [--all]
  contracts [<cid>]

ESTATE
  activate <id> [--why REASON]
  entities [--json]
  show <id> [--json]
  discover --capability payments.balance.read --as ID
           [--jurisdiction SG] [--data-class financial] [--limit N] [--json]
  posture [--unattested] [--expiring] [--score] [--json]
  blast-radius <id> [--depth 3] [--services] [--json]   exit 1 if truncated
  quarantine <id> --reason R [--approver human:a --approver human:b]
                  [--revocation-key PEM --kid KID] [--mediators FILE]
                  [--ack-deadline 60] [--push-token TOKEN]
  mediators       [--mediators FILE] [--revocation-pub PEM --kid KID] [--json]
  tenants         [--registry tenants.toml] [--json]   what exists on this root

KEYS  (--keyring keys.toml, default: keys.toml)
  keys list       [--json]                        state, and what may be retired
  keys new        --kid KID [--alg ES256] [--out DIR]   prints the openssl command
  keys add        --kid KID --public PEM [--private-ref REF]
  keys rotate     --kid KID                       promote; the old key keeps verifying
  keys retire     --kid KID                       refuses while its contracts are live
  keys note       --kid KID --exp TS              record what a key signed
  keys jwks       [--out FILE]                    what mediators verify against

AIR-GAPPED
  bundle export   --mediator ID --signing-key PEM --kid KID [--ttl 7d] [--out FILE]
  bundle verify   <bundle.wcb> --envelope-pub PEM --kid KID --mediator ID
                  [--issuer-pub PEM]              exit 4 if it does not verify

SHARED SIGNALS
  caep ingest     <token.jwt> --transmitters streams.toml [--now TS] [--json]
                  verify a Security Event Token and print what it asks for

CI
  bench           [--iterations N] [--gate NAME] [--scale N] [--json]
                  --signing-key PEM --verify-pub PEM --kid KID
                                                needed by the mint/verify gates
                  exit 1 on regression, or on a gate that could not run
  federate <chain.json> --anchors anchors.toml [--now TS] [--json]
                  resolve a partner trust chain
                  exit 4 if it does not verify · 3 if the anchor is stale

EVIDENCE
  audit verify [--anchor-pub PEM] [--json]
  export --format csv|json|dora|cps230|oscal|bom [--as-of TS]
         [--anchor-pub PEM] [--id ID for bom] [--out FILE]

POLICY
  policy lint    [--policy FILE] [--json]
  policy show    [--policy FILE] [--json]      resolved zone bars + standing caps
  policy dry-run [--policy FILE] [--json]      what a change does to live contracts

TOOLS
  canon <surface.json> [--kind mcp|a2a] [--entity ID] [--document] [--json]
  screen <surface.json> [--kind mcp|a2a] [--mode observe|flag|enforce] [--tier N]
                        [--rules screen-rules.toml] [--acceptances FILE]
                        [--estate names.json] [--json]      exit 5 on block
  verify <contract.jws> (--issuer-pub PEM --kid KID | --jwks FILE) --mediator-id ID
                        [--alg ES256|ES384|EdDSA] [--now TS] [--leeway N] [--json]
                        --jwks takes an issuer key set — what an OIDC issuer or a
                        SPIRE server publishes — instead of a converted PEM
  version

SERVE
  serve [--listen 127.0.0.1:8787] --issuer-key PEM --kid KID
        [--behind-tls-proxy [--trusted-proxy ADDR]...] | [--insecure-plaintext]
        [--tokens tokens.toml] [--approvers approvers.toml] [--jwks FILE]

TRANSPORT  (serve speaks plain HTTP; TLS is terminated in front of it)
  A non-loopback listener refuses to start rather than accept bearer tokens in
  clear. That is the whole control: the deployment contract was documented and
  unenforced, so a pod bound to 0.0.0.0 shipped approval tokens in plaintext and
  nothing objected.

  --behind-tls-proxy    TLS is terminated in front. Every authenticated request
                        must then carry `x-forwarded-proto: https`, so a request
                        that reaches the port directly — bypassing the ingress —
                        is refused rather than trusted
  --trusted-proxy ADDR  believe that header only from this address. Repeatable.
                        Omitted means any source, which is correct only if nothing
                        else can reach the port
  --insecure-plaintext  accept tokens over plaintext from anywhere. Named so it is
                        visible in the process list and in the startup banner

KEY CUSTODY  (docs/key-custody.md)
  Every signing flag has a PEM form and a delegated form. The delegated form runs
  a command you supply, so the private key can live in an HSM, a smartcard or a
  KMS and never reach this process. Giving both forms is an error, never a
  preference: believing a key is in a token while a file was used is the worst
  outcome available here.

  --issuer-key PEM      the contract signing key, on this disk
  --signer COMMAND      ...or delegated. stdin: base64url signing input,
                        stdout: base64url signature. JWS ECDSA is raw R‖S, and
                        every KMS returns DER — convert in the wrapper
  --anchor-key PEM      the evidence checkpoint key, on this disk
  --anchor-signer CMD   ...or delegated. Move this one first: a checkpoint signed
                        by a key this host holds proves only that the host agrees
                        with itself
  --require-external-signing
                        refuse to start if any signing key would be read from this
                        disk (env WARDEN_CONNECT_REQUIRE_EXTERNAL_SIGNING). Every
                        mint also records which kid signed and where it lives, so a
                        local signature after the move is answerable from the
                        evidence chain, not only from configuration

GLOBAL
  --root PATH        state and evidence root (env WARDEN_CONNECT_ROOT, default {DEFAULT_ROOT})
  --tenant NAME      tenant (default: default)
  --by human:x       the accountable operator (env WARDEN_CONNECT_ACTOR)
  --anchor-interval N checkpoint every N appends (default 100)
  --approvers FILE   approver registry (default: approvers.toml)
  --json             machine-readable output

EXIT CODES
  0 ok · 1 operational · 2 usage · 3 denied · 4 verification failed
  5 screening/drift · 6 approval required
"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::path::Path;

    #[test]
    fn exit_codes_separate_the_cases() {
        // A failed trust chain is an untrustworthy artifact, not an I/O problem.
        assert_eq!(exit_code(Code::FEDERATION_ANCHOR_UNKNOWN), 4);
        assert_eq!(exit_code(Code::FEDERATION_CHAIN_INVALID), 4);
        assert_eq!(exit_code(Code::FEDERATION_METADATA_WIDENED), 4);
        // A stale anchor is a valid chain we decline to issue against.
        assert_eq!(exit_code(Code::FEDERATION_ANCHOR_STALE), 3);
        assert_eq!(exit_code(Code::SCREENING_BLOCKED), 5);
        assert_eq!(exit_code(Code::DRIFT_MATERIAL), 5);
        assert_eq!(exit_code(Code::QUARANTINE_DUAL_CONTROL_MISSING), 6);
        assert_eq!(exit_code(Code::CHAIN_BROKEN), 4);
        assert_eq!(exit_code(Code::IDENTITY_UNVERIFIABLE), 4);
        // The whole verification block is one verdict class.
        for code in [
            Code::ALG_NOT_ASYMMETRIC,
            Code::SIGNATURE_INVALID,
            Code::CONTRACT_EXPIRED,
            Code::AUDIENCE_MISMATCH,
            Code::CONTRACT_REVOKED,
            Code::CALLER_PEER_MISMATCH,
            Code::PIN_MISMATCH,
            Code::POSTURE_NOT_ATTESTED,
            Code::ZONE_PAIR_FORBIDDEN,
            Code::TOKEN_BINDING_MISMATCH,
            Code::SCHEMA_UNKNOWN,
            Code::CONTRACT_OVERSIZE,
        ] {
            assert_eq!(
                exit_code(code),
                4,
                "{code} should be a verification failure"
            );
        }
        assert_eq!(exit_code(Code::POLICY_DENIED), 3);
        assert_eq!(exit_code(Code::ENTITY_QUARANTINED), 3);
        // A contract-lifecycle refusal is a decision, not a malfunction.
        assert_eq!(exit_code(Code::SURFACE_NOT_SUBSET), 3);
        // Everything else is operational.
        assert_eq!(exit_code(Code::STORE_LOCKED), 1);
        assert_eq!(exit_code(Code::ENTITY_NOT_FOUND), 1);
    }

    #[test]
    fn derived_urns_are_stable_and_valid() {
        let a = derive_urn("https://payments-mcp.internal/mcp");
        let b = derive_urn("https://payments-mcp.internal/mcp");
        assert_eq!(a, b, "re-registering the same endpoint must resolve equal");
        assert_ne!(a, derive_urn("https://other.internal/mcp"));
        assert!(EntityId::new(&a).is_ok());
    }

    #[test]
    fn truncate_keeps_the_distinctive_tail() {
        // Identifiers differ at the end, so the tail is what an operator needs.
        assert_eq!(truncate("short", 10), "short");
        let long = truncate("spiffe://org/ns/agents/sa/recon-bot-7", 12);
        assert_eq!(long.chars().count(), 12);
        assert!(long.ends_with("recon-bot-7"));
    }

    #[test]
    fn paths_are_tenant_scoped() {
        let args = Args::parse(
            ["--root", "/tmp/r", "--tenant", "apac"]
                .iter()
                .map(|s| (*s).to_string()),
        );
        let p = paths(&args);
        assert_eq!(p.state, Path::new("/tmp/r/tenants/apac/state"));
        assert_eq!(p.evidence, Path::new("/tmp/r/tenants/apac/evidence"));
    }

    #[test]
    fn mode_defaults_to_observe() {
        assert_eq!(mode(&Args::default()), Mode::Observe);
        let enforcing = Args::parse(["--enforce"].iter().map(|s| (*s).to_string()));
        assert_eq!(mode(&enforcing), Mode::Enforce);
    }

    #[test]
    fn an_unknown_flag_is_a_usage_error() {
        // The failure this prevents: a mistyped --anchor-key silently disabling
        // anchoring, so the operator believes the chain is externally proven.
        let typo = Args::parse(
            ["--anchor-ky", "/keys/a.pem"]
                .iter()
                .map(|s| (*s).to_string()),
        );
        assert!(check_flags("activate", &typo).is_err());

        let ok = Args::parse(
            ["--anchor-key", "/keys/a.pem", "--why", "admitted"]
                .iter()
                .map(|s| (*s).to_string()),
        );
        assert!(check_flags("activate", &ok).is_ok());
    }

    #[test]
    fn a_flag_valid_elsewhere_is_still_rejected_here() {
        let wrong_command = Args::parse(["--reason", "SOC-1"].iter().map(|s| (*s).to_string()));
        assert!(check_flags("quarantine", &wrong_command).is_ok());
        assert!(check_flags("activate", &wrong_command).is_err());
    }

    #[test]
    fn screening_flags_are_checked_on_screen_and_register() {
        let typo = Args::parse(["--screen-mod", "enforce"].iter().map(|s| (*s).to_string()));
        assert!(check_flags("screen", &typo).is_err());
        assert!(check_flags("register server", &typo).is_err());

        let ok = Args::parse(
            [
                "--mode",
                "enforce",
                "--rules",
                "screen-rules.toml",
                "--tier",
                "2",
            ]
            .iter()
            .map(|s| (*s).to_string()),
        );
        assert!(check_flags("screen", &ok).is_ok());

        // Registration takes the ruleset under a namespaced flag, because `--mode`
        // there would collide with the admission mode.
        let reg = Args::parse(
            [
                "--screen-rules",
                "screen-rules.toml",
                "--screen-mode",
                "flag",
            ]
            .iter()
            .map(|s| (*s).to_string()),
        );
        assert!(check_flags("register server", &reg).is_ok());
        assert!(check_flags("register agent", &reg).is_ok());
        assert!(check_flags("screen", &reg).is_err());
    }

    #[test]
    fn the_shipped_screen_ruleset_parses_and_is_uncalibrated() {
        // The file operators are handed must load, and must not claim a
        // calibration nobody performed.
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../screen-rules.toml"),
        )
        .expect("screen-rules.toml is readable");
        let rules = screen::ScreenRules::parse(&text).expect("shipped ruleset parses");
        assert!(
            !rules.calibrated,
            "the shipped ruleset must not claim calibration"
        );
        assert!(rules.disabled.is_empty());
        assert_eq!(rules.escalate_at, 60);
    }

    #[test]
    fn a_never_attested_party_is_not_also_counted_as_overdue() {
        // Found by running `posture --score` on a fresh registration: the
        // rationale claimed "overdue by more than three intervals" for a party
        // that had simply never been attested, charging it twice for one fact and
        // naming the wrong reason.
        let mut e = Entity::pending(
            EntityId::new("spiffe://org/ns/x/sa/fresh").unwrap(),
            wc_core::model::Kind::McpServer,
            HumanRef::new("human:priya@org").unwrap(),
            ZoneId::new("internal.apac-ops").unwrap(),
            wc_core::model::Tier::THREE,
            1_000,
        );
        assert_eq!(e.reattested_at, 0);
        let s = observed_signals(&e, 2_000_000_000);
        assert_eq!(s.intervals_overdue, 0);
        assert_eq!(s.identity_ok, None, "the real reason is carried here");

        // Once attested, overdue means what it says.
        e.posture = Posture::Attested;
        e.reattested_at = 1_000;
        e.reattest_every = 3_600;
        let s = observed_signals(&e, 1_000 + 4 * 3_600);
        assert_eq!(s.intervals_overdue, 3);
        assert_eq!(s.identity_ok, Some(true));
    }

    #[test]
    fn durations_read_correctly_at_every_scale() {
        // A 15-minute break-glass contract rendered as "0d" is the only reading an
        // operator gets during the incident it was issued for.
        assert_eq!(human_duration(0), "0s");
        assert_eq!(human_duration(45), "45s");
        assert_eq!(human_duration(900), "15m");
        assert_eq!(human_duration(3_600), "1h0m");
        assert_eq!(human_duration(5_400), "1h30m");
        assert_eq!(human_duration(86_400), "1d");
        assert_eq!(human_duration(30 * 86_400), "30d");
        assert_eq!(human_duration(90_000), "1d1h");
    }

    #[test]
    fn a_two_word_command_takes_its_subject_after_the_second_word() {
        // `bundle verify estate.wcb` resolved its own subcommand name as the
        // filename, because the subject was read from a fixed index.
        let two = Args::parse(
            ["bundle", "verify", "estate.wcb"]
                .iter()
                .map(|s| (*s).to_string()),
        );
        assert_eq!(positional_or_flag(&two, "file").unwrap(), "estate.wcb");

        // One-word commands are unchanged.
        let one = Args::parse(["canon", "surface.json"].iter().map(|s| (*s).to_string()));
        assert_eq!(positional_or_flag(&one, "file").unwrap(), "surface.json");

        // And a flag still works when no positional was given.
        let flagged = Args::parse(
            ["bundle", "verify", "--file", "x.wcb"]
                .iter()
                .map(|s| (*s).to_string()),
        );
        assert_eq!(positional_or_flag(&flagged, "file").unwrap(), "x.wcb");
    }

    #[test]
    fn every_two_word_command_is_dispatchable_as_two_words() {
        // Adding `keys list` to COMMANDS without adding it to TWO_WORD made every
        // `keys` verb resolve to the one-word `keys`, which is not a command —
        // found by running the binary, because both lists looked right in isolation.
        for command in COMMANDS {
            if let Some((head, _)) = command.split_once(' ') {
                assert!(
                    TWO_WORD.contains(command),
                    "{command} is two words but is not in TWO_WORD, so it dispatches as `{head}`"
                );
            }
        }
        // And nothing in TWO_WORD is missing from COMMANDS.
        for command in TWO_WORD {
            assert!(COMMANDS.contains(command), "{command} is not dispatchable");
        }
    }

    // -----------------------------------------------------------------------
    // Key custody (docs/key-custody.md)
    // -----------------------------------------------------------------------

    fn argv(tokens: &[&str]) -> Args {
        Args::parse(tokens.iter().map(|t| (*t).to_string()))
    }

    /// Tests run with the crate directory as cwd, so fixture paths must be absolute.
    fn fixture_key() -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/keys/test_issuer_es256_priv.pem")
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn every_command_that_takes_an_issuer_key_also_takes_a_delegated_signer() {
        // The gap this closes: custody reachable from the library and not from the
        // tool would be custody nobody uses. Any command that can sign with a PEM
        // must be able to sign with a token.
        for command in COMMANDS {
            let flags = accepted_flags(command);
            if flags.contains(&"issuer-key") {
                assert!(
                    flags.contains(&"signer"),
                    "`{command}` accepts --issuer-key but not --signer"
                );
            }
        }
    }

    #[test]
    fn supplying_both_key_forms_is_an_error_rather_than_a_preference() {
        // Silently preferring one would leave an operator believing their key is in a
        // token while a file on disk did the signing — the one outcome worse than
        // refusing to start.
        let args = argv(&[
            "request",
            "--issuer-key",
            "k.pem",
            "--signer",
            "/usr/local/bin/wc-sign",
            "--kid",
            "k1",
        ]);
        let err = issuer_key(&args).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(
            err.detail().contains("must not be a guess"),
            "{}",
            err.detail()
        );

        // And neither form is also an error, with both named.
        let neither = argv(&["request", "--kid", "k1"]);
        let err = issuer_key(&neither).unwrap_err();
        assert!(err.detail().contains("--signer"), "{}", err.detail());
    }

    #[test]
    fn the_anchor_refuses_two_custody_choices_too() {
        let args = argv(&[
            "entities",
            "--anchor-key",
            "a.pem",
            "--anchor-signer",
            "/usr/local/bin/wc-anchor",
        ]);
        let err = open_evidence(&args).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(
            err.detail().contains("must not be a guess"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn require_external_signing_refuses_a_key_on_this_disk() {
        // What makes "KMS, no local copy" a control rather than a wiki page. Refused
        // at construction, so a run that would have signed with a PEM never starts.
        let args = argv(&[
            "request",
            "--issuer-key",
            &fixture_key(),
            "--kid",
            "k1",
            "--require-external-signing",
        ]);
        let err = issuer_key(&args).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(
            err.detail().contains("--signer COMMAND"),
            "{}",
            err.detail()
        );

        // The same posture applies to the anchor: a checkpoint key on disk defeats
        // the anchor's whole purpose, so it cannot be the one exception.
        let anchored = argv(&[
            "entities",
            "--anchor-key",
            &fixture_key(),
            "--require-external-signing",
        ]);
        let err = open_evidence(&anchored).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(err.detail().contains("--anchor-signer"), "{}", err.detail());
    }

    #[test]
    fn require_external_signing_permits_a_delegated_key() {
        // The posture must not be a way to refuse everything: a delegated key is the
        // point of it, so it has to be accepted.
        let args = argv(&[
            "request",
            "--signer",
            "/usr/local/bin/wc-sign",
            "--kid",
            "k1",
            "--require-external-signing",
        ]);
        let key = issuer_key(&args).expect("a delegated key must be accepted");
        assert_eq!(key.custody(), wc_core::contract::Custody::Delegated);
        assert_eq!(key.kid(), "k1");
    }

    #[test]
    fn custody_is_recorded_on_the_key_it_describes() {
        let local = argv(&["request", "--issuer-key", &fixture_key(), "--kid", "k1"]);
        assert_eq!(
            issuer_key(&local).unwrap().custody(),
            wc_core::contract::Custody::Local
        );
    }

    #[test]
    fn a_non_loopback_listener_will_not_accept_credentials_in_clear() {
        // The control this whole item is about. Nothing stopped it before, and the
        // failure was silent: the pod came up, served, and shipped approval tokens in
        // plaintext.
        for listen in ["0.0.0.0:8787", "10.0.0.5:8787", "[::]:8787"] {
            let err = transport_policy(&argv(&["serve"]), listen).unwrap_err();
            assert_eq!(err.code(), Code::CONFIG_INVALID, "{listen}");
            assert!(
                err.detail().contains("--behind-tls-proxy"),
                "{listen}: {}",
                err.detail()
            );
        }
        // Loopback is fine without any assertion, in both families.
        for listen in ["127.0.0.1:8787", "[::1]:8787"] {
            assert_eq!(
                transport_policy(&argv(&["serve"]), listen).unwrap(),
                wc_control::api::Transport::Loopback,
                "{listen}"
            );
        }
    }

    #[test]
    fn a_hostname_that_merely_starts_with_127_is_not_loopback() {
        // The bug this codebase already fixed once in `wc_mediator::peer`:
        // `starts_with("127.")` accepts `127.0.0.1.evil.example`. Parsed and asked
        // `is_loopback` instead, so an unparseable host is not loopback either.
        for listen in ["127.0.0.1.evil.example:8787", "localhost:8787", "notanip:1"] {
            assert!(
                transport_policy(&argv(&["serve"]), listen).is_err(),
                "{listen} must not be taken for loopback"
            );
        }
    }

    #[test]
    fn a_trusted_proxy_that_is_trusted_for_nothing_is_a_typo() {
        let err = transport_policy(
            &argv(&["serve", "--trusted-proxy", "10.0.0.1"]),
            "127.0.0.1:8787",
        )
        .unwrap_err();
        assert!(err.detail().contains("only meaningful"), "{}", err.detail());

        let bad = transport_policy(
            &argv(&[
                "serve",
                "--behind-tls-proxy",
                "--trusted-proxy",
                "not-an-ip",
            ]),
            "0.0.0.0:8787",
        )
        .unwrap_err();
        assert!(
            bad.detail().contains("is not an IP address"),
            "{}",
            bad.detail()
        );
    }

    #[test]
    fn asserting_a_proxy_permits_a_non_loopback_bind() {
        let t = transport_policy(
            &argv(&["serve", "--behind-tls-proxy", "--trusted-proxy", "10.0.0.1"]),
            "0.0.0.0:8787",
        )
        .unwrap();
        assert_eq!(
            t,
            wc_control::api::Transport::TlsProxy {
                trusted: vec!["10.0.0.1".parse().unwrap()]
            }
        );
        // And the escape hatch, which has to exist or an operator reaches for worse.
        assert_eq!(
            transport_policy(&argv(&["serve", "--insecure-plaintext"]), "0.0.0.0:8787").unwrap(),
            wc_control::api::Transport::Insecure
        );
    }

    #[test]
    fn the_transport_flags_are_documented() {
        let text = usage();
        for flag in [
            "--behind-tls-proxy",
            "--trusted-proxy ADDR",
            "--insecure-plaintext",
        ] {
            assert!(text.contains(flag), "usage does not mention {flag}");
        }
        assert!(
            text.contains("x-forwarded-proto"),
            "the per-request requirement has to be in the help, not only the source"
        );
    }

    #[test]
    fn the_custody_flags_are_documented() {
        // A flag the tool accepts and never mentions is a flag nobody uses.
        let text = usage();
        for flag in ["--signer COMMAND", "--anchor-signer CMD"] {
            assert!(text.contains(flag), "usage does not mention {flag}");
        }
        // And the trap has to be in the help, not only in the source.
        assert!(
            text.contains("DER"),
            "usage does not warn about DER signatures"
        );
    }

    #[test]
    fn usage_lists_every_dispatchable_command() {
        // Keeps the help text honest as commands are added.
        let text = usage();
        for command in COMMANDS {
            assert!(text.contains(command), "usage does not mention {command}");
        }
    }

    #[test]
    fn every_command_declares_its_flags() {
        // A command with no entry would silently accept anything, which is the
        // failure `check_flags` exists to prevent. Only these two legitimately take
        // nothing beyond the global flags.
        const NO_OWN_FLAGS: &[&str] = &["entities", "version"];
        for command in COMMANDS {
            let declared = accepted_flags(command);
            assert_eq!(
                declared.is_empty(),
                NO_OWN_FLAGS.contains(command),
                "{command} flag list looks wrong"
            );
        }
    }
}

/// A signer that returns a correctly-shaped signature at no cost.
///
/// Only for the `contract::mint overhead` gate: subtracting this from
/// `contract::mint` is what the signature costs, which is the figure that makes a
/// slow delegated mint attributable to the token rather than to this code.
#[derive(Debug)]
struct FreeSigner;

impl wc_core::contract::Signer for FreeSigner {
    fn sign(&self, _signing_input: &[u8]) -> Result<Vec<u8>> {
        // 64 bytes, because ES256 needs exactly that and `IssuerKey` checks.
        Ok(vec![0u8; 64])
    }
}

/// Measure `Projection::rebuild` over a log of `contracts` contracts (§8.10.3).
///
/// The fixture is written once and replayed several times, because what the gate is
/// about is *startup*: the cost of turning a log on disk back into an answerable
/// projection. Building the log is not part of the measurement — an estate does not
/// write its history on every boot.
fn bench_rebuild(contracts: usize) -> Result<wc_control::bench::Gate> {
    use wc_control::bench::{measure, thresholds};
    use wc_control::store::{Durability, Event, Projection, Store, STATE_LOG_NAME};

    let dir = std::env::temp_dir().join(format!("wc-bench-rebuild-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, "cannot create a scratch dir").with_source(e)
    })?;

    // Removed on the way out however this returns, including on the error paths
    // below — a benchmark that leaves a 100 MB log in the temp directory is a
    // benchmark somebody disables.
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _scratch = Scratch(dir.clone());

    let projection = bench_estate(contracts)?;
    let actor = Actor::Service {
        id: "bench".to_string(),
    };
    {
        let (mut store, _) = Store::open(&dir)?;
        // Batched, not Durable. `fsync` per record would make the fixture take
        // minutes and would measure the disk rather than the replay; durability of a
        // throwaway fixture buys nothing.
        for entity in projection.entities.values() {
            store.commit(
                Event::EntityPut {
                    entity: Box::new(entity.clone()),
                    actor: actor.clone(),
                },
                0,
                Durability::Batched,
            )?;
        }
        for record in projection.contracts.values() {
            store.commit(
                Event::ContractMint {
                    record: Box::new(record.clone()),
                },
                0,
                Durability::Batched,
            )?;
        }
    }

    // Replay once outside the measurement, and assert it rebuilt what was written. A
    // gate that timed a rebuild producing an empty projection would report a very
    // good number for doing nothing.
    let (rebuilt, report) = Projection::rebuild(&dir, STATE_LOG_NAME)?;
    if rebuilt.contracts.len() != projection.contracts.len() || !report.is_clean() {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!(
                "fixture replayed {} of {} contracts ({} unknown, {} inconsistent)",
                rebuilt.contracts.len(),
                projection.contracts.len(),
                report.unknown,
                report.inconsistent.len()
            ),
        ));
    }

    Ok(measure(
        "store::rebuild",
        &format!(
            "{} contracts, {} parties",
            projection.contracts.len(),
            projection.entities.len()
        ),
        thresholds::REBUILD,
        5,
        1,
        || {
            let _ = Projection::rebuild(&dir, STATE_LOG_NAME);
        },
    ))
}
