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
mod config;

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
use wc_control::custody;
use wc_control::evidence::{EventKind, Evidence, LifecycleEvent};
use wc_control::export;
use wc_control::federate;
use wc_control::http::{self, Shutdown};
use wc_control::issuance::{
    self as issuance, ApprovalProof, ApproverRegistry, Issued, Issuer, Outcome, PendingRequest,
    RequestInput, RequestStatus,
};
use wc_control::rekor;
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

/// The config file read when `--config` is not given, if it happens to exist.
const DEFAULT_CONFIG: &str = "connect.toml";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() || argv[0] == "--help" || argv[0] == "-h" || argv[0] == "help" {
        print!("{}", usage());
        return ExitCode::from(if argv.is_empty() { 2 } else { 0 });
    }

    let mut args = Args::parse(argv);
    match dispatch(&mut args) {
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
    "attest verify",
    "attest surface",
    "offer publish",
    "offer show",
    "need check",
    "need apply",
    "scm probe",
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
    "attest verify",
    "attest surface",
    "offer publish",
    "offer show",
    "need check",
    "need apply",
    "scm probe",
    "blast-radius",
    "quarantine",
    "unquarantine",
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
    "backup",
    "restore",
    "retention",
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
    "config",
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
            "oidc-token",
            "oidc-issuer",
            "oidc-label",
            "oidc-subject-claim",
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
            "oidc-token",
            "oidc-issuer",
            "oidc-label",
            "oidc-subject-claim",
        ],
        "attest surface" => &["surface", "card-key", "out", "kid"],
        "offer publish" => &[
            "surface",
            "terms",
            "kind",
            "repo",
            "sha",
            "version",
            "shim",
            "shim-label",
            "git-ref",
        ],
        "offer show" => &["asset"],
        "need check" => &["manifest", "repo", "sha"],
        "need apply" => &[
            "manifest",
            "repo",
            "sha",
            "git-ref",
            "shim",
            "shim-label",
            "mediator",
            "issuer-key",
            "signer",
            "kid",
            "alg",
            "out",
        ],
        "scm probe" => &[
            "shim",
            "label",
            "repo",
            "sha",
            "timeout",
            "expect-ref",
            "expect-protected",
            "expect-approver",
            "expect-file",
        ],
        "attest verify" => &[
            "file",
            "prov-key",
            "builder",
            "artifact-digest",
            "artifact",
            "rekor-proof",
            "rekor-body",
        ],
        "activate" => &["id", "why"],
        "unquarantine" => &["id", "approver", "why"],
        "quarantine" => &[
            "id",
            "reason",
            "approver",
            "revocation-key",
            "revocation-signer",
            "revocation-kid",
            "break-glass-kid",
            "break-glass",
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
            "envelope-signer",
            "kid",
            "ttl",
            "out",
            "contracts",
        ],
        "bundle verify" => &[
            "file",
            "envelope-pub",
            "issuer-pub",
            "issuer-id",
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
        "backup" => &["out", "anchor-pub", "now"],
        "restore" => &["from", "into"],
        "retention" => &["contracts", "discovery", "now", "retire", "anchor-pub"],
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
            "scenario",
            "enforce",
            "file",
            "issuer-pub",
            "jwks",
            "kid",
            "alg",
            "mediator-id",
            "issuer-id",
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
            "alg",
            "iss",
            "out",
        ],
        "approve" => &[
            "enforce",
            "id",
            "approvers",
            "approver-key",
            "approver-signer",
            "second-key",
            "second-signer",
            "second",
            "ticket",
            "policy",
            "issuer-key",
            "signer",
            "kid",
            "alg",
            "iss",
            "out",
        ],
        "deny" => &["id", "reason", "policy"],
        "serve" => &[
            "listen",
            "standby",
            "standby-timeout",
            "behind-tls-proxy",
            "trusted-proxy",
            "proxy-secret-file",
            "insecure-plaintext",
            "policy",
            "issuer-key",
            "signer",
            "kid",
            "alg",
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
            "approver-signer",
            "second",
            "second-key",
            "second-signer",
            "issuer-key",
            "signer",
            "kid",
            "alg",
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

fn dispatch(args: &mut Args) -> std::result::Result<(), Failure> {
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
    // --- the config layer (§8.13, P1 #12) ---------------------------------
    //
    // Resolved here, after the command is known and before flags are checked, because
    // which keys apply depends on the command. `--config FILE` is explicit; otherwise
    // `connect.toml` beside the process is used if it exists. Absent is fine; present
    // and broken is a startup failure, because a file that exists was written on purpose.
    {
        let mut known: Vec<&str> = accepted_flags(command).to_vec();
        known.extend_from_slice(GLOBAL_FLAGS);
        let loaded = match args.get("config") {
            Some(path) => Some(config::Config::load(path).map_err(Failure::Wc)?),
            None => config::Config::load_default(DEFAULT_CONFIG).map_err(Failure::Wc)?,
        };
        config::apply(args, loaded.as_ref(), &known);
    }

    let args = &*args;
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
        "unquarantine" => unquarantine(args)?,
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
        "attest verify" => attest_verify_cmd(args)?,
        "attest surface" => attest_surface_cmd(args)?,
        "offer publish" => offer_publish_cmd(args)?,
        "offer show" => offer_show_cmd(args)?,
        "need check" => need_check_cmd(args)?,
        "need apply" => need_apply_cmd(args)?,
        "scm probe" => scm_probe_cmd(args)?,
        "audit verify" => audit_verify(args)?,
        "backup" => backup_cmd(args)?,
        "restore" => restore_cmd(args)?,
        "retention" => retention_cmd(args)?,
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
    warn_if_unclean(&report);
    Ok(store)
}

/// Open the store, standing by for the active writer if `--standby` was given (P1 #10).
///
/// Only `serve` offers this. A one-shot command competing with a running control plane
/// should fail immediately and say the estate is busy; a *second control plane* should
/// wait, because that is what active/standby means (§8.5.2).
///
/// Note what does **not** happen while standing by: no listener is bound. A standby that
/// bound the port and answered `/readyz` with "not ready" would be relying on every
/// load balancer in front of it to read that correctly. Not being there at all is the same
/// signal with no room for a health-check misconfiguration, and it also makes the port
/// available to the active writer on the same host.
fn open_store_or_stand_by(args: &Args) -> Result<Store> {
    if !args.has("standby") {
        return open_store(args);
    }
    let p = paths(args);
    let timeout = std::time::Duration::from_secs(args.number("standby-timeout").unwrap_or(3_600));
    eprintln!(
        "connect: standing by for the active writer on {} (up to {}s); no listener is \
         bound until this process is active",
        p.state.display(),
        timeout.as_secs()
    );
    let (store, report, election) = Store::open_waiting(
        &p.state,
        timeout,
        std::time::Duration::from_millis(250),
        |secs| eprintln!("connect: still standing by after {secs}s"),
    )?;
    eprintln!("connect: {}", election.describe());
    warn_if_unclean(&report);
    Ok(store)
}

fn warn_if_unclean(report: &wc_control::store::RebuildReport) {
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

    // An address or a CIDR block. Blocks matter because an AWS ALB answers from many
    // addresses and a Kubernetes Ingress pod gets a new one on every restart, so exact
    // matching made the strong configuration unusable in two of the four documented
    // topologies — and the fallback is `--trusted-proxy` omitted, which believes the header
    // from anywhere.
    let trusted: Vec<wc_control::api::TrustedSource> = args
        .list("trusted-proxy")
        .iter()
        .map(|raw| wc_control::api::TrustedSource::parse(raw))
        .collect::<Result<_>>()?;

    // The secret closes the address check's honest limit: a process sharing a trusted
    // address can forge `x-forwarded-proto`, and no CIDR is narrow enough to stop it
    // because the forger shares the address. Read from a file rather than taken inline,
    // because a secret on a command line is in the process list and in shell history.
    let secret = match args.get("proxy-secret-file") {
        Some(path) => {
            let raw = std::fs::read_to_string(path).map_err(|e| {
                WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}"))
                    .with_source(e)
            })?;
            Some(wc_control::api::ProxySecret::new(raw.trim())?)
        }
        None => None,
    };

    if args.has("behind-tls-proxy") {
        return Ok(wc_control::api::Transport::TlsProxy { trusted, secret });
    }
    if secret.is_some() {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            "--proxy-secret-file is only meaningful with --behind-tls-proxy; on a loopback \
             listener there is no forwarding hop to share a secret with, and accepting it \
             here would suggest a protection that is not in play",
        ));
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

    // Stage 1 for an estate with no SPIRE, which is most of them: a Kubernetes projected
    // service-account token, IRSA, Azure workload identity, a GCP service account or a
    // Vault identity token. All are JWTs with a published JWKS and a subject that is not a
    // SPIFFE URI, so `--svid` could never accept one and the party stayed Unattested
    // forever — which made enforce mode unreachable and `--observe` the only option.
    //
    // `--oidc-token` selects this path. It is mutually exclusive with `--svid`: two
    // identity verifiers would mean whichever ran last decided who the party is, and a
    // precedence rule between two authentications is not something an operator should have
    // to know.
    let oidc_identity = match args.get("oidc-token") {
        Some(path) => {
            if args.get("svid").is_some() {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    "--svid and --oidc-token are two different stage-1 verifiers; pass one. \
                     A precedence rule between two authentications is not a thing to guess",
                ));
            }
            let token = std::fs::read_to_string(path)
                .map_err(|e| {
                    WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}"))
                        .with_source(e)
                })?
                .trim()
                .to_string();
            Some(attest::OidcIdentity {
                keys: &trust_keys,
                // Every one of these is refused when unset rather than defaulted — see
                // `OidcIdentity::check_config` for what each vacuous default would admit.
                issuer: args.get("oidc-issuer").unwrap_or_default().to_string(),
                label: args.get("oidc-label").unwrap_or_default().to_string(),
                audience: args.get("aud").unwrap_or_default().to_string(),
                subject_claim: args.get("oidc-subject-claim").unwrap_or("sub").to_string(),
                token,
                leeway: args.number("leeway").unwrap_or(60),
                now: ctx.now,
            })
        }
        None => None,
    };
    if let Some(v) = &oidc_identity {
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

/// The revocation key for a containment, with its declared role.
#[derive(Debug)]
struct RevocationSigning {
    kid: String,
    role: custody::Role,
    key: IssuerKey,
}

/// Resolve the revocation key and which of the two roles it is signing in (P0 #5c).
///
/// Two keys, not two copies of one: `revoke-online` lives in the KMS and does the routine
/// work, `revoke-offline` is non-exportable on a hardware token with its PIN split M-of-N
/// and exists so containment still works when the KMS or this control plane does not.
///
/// The verification side already supported both — a feed entry carries its own `kid` and
/// resolves it against an `IssuerKeys` map, so a mediator can trust two at once. What was
/// missing was on this side: **nothing knew which `kid` was the break-glass one**, so
/// nothing could refuse to reach for it out of habit, and nothing could escalate when it
/// was used.
///
/// Returns `None` when no revocation key was given at all, which is the control-plane-only
/// topology: the registry records the quarantine and no fan-out is attempted. That is a
/// supported deployment, and it is reported rather than mistaken for a successful push.
fn resolve_revocation_custody(args: &Args) -> Result<Option<RevocationSigning>> {
    let declared =
        custody::RevocationCustody::new(args.get("revocation-kid"), args.get("break-glass-kid"))?;

    if args.get("revocation-key").is_none() && args.get("revocation-signer").is_none() {
        return Ok(None);
    }

    // `--break-glass` selects the emergency key; it does not merely permit it. One flag
    // flipping to the offline key is the shape a runbook can be followed under pressure —
    // an operator at 03:00 should not have to type the same kid into two flags and get
    // the pairing right.
    let kid = if args.has("break-glass") {
        declared.offline_kid.clone().ok_or_else(|| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                "--break-glass needs --break-glass-kid KID to name the offline key; \
                     without it there is nothing to switch to",
            )
        })?
    } else {
        args.get("revocation-kid")
            .or_else(|| args.get("kid"))
            .ok_or_else(|| {
                WcError::with_detail(
                    Code::CONFIG_INVALID,
                    "--kid or --revocation-kid names the key signing the revocation feed",
                )
            })?
            .to_string()
    };

    // Still authorised rather than assumed. `--break-glass` implies consent, but an
    // operator who names the offline kid directly in `--revocation-kid` has not consented
    // to anything, and that is the reach-for-it-out-of-habit case the guard is for.
    let role = declared.authorise(&kid, args.has("break-glass"))?;
    let key = custody_key(args, role, &kid, args.get("alg"))?;
    Ok(Some(RevocationSigning { kid, role, key }))
}

/// Lift a quarantine, returning the party to `Pending` so the full admission pipeline has
/// to run again (UC-07 A3).
///
/// This had no command and no API route. `Registry::clear_quarantine` existed,
/// dual-controlled and tested, and nothing could reach it — so **quarantine was a one-way
/// door in the shipped product**: a false positive permanently bricked a party, and the
/// only recovery was hand-editing a hash-linked state log, which breaks every row after
/// the edit. Found while wiring `wc_quarantine_duration_seconds`, whose whole input is a
/// clearing that could not happen.
///
/// Dual-controlled like the order it lifts, and for a sharper reason: an attacker who can
/// quarantine causes an outage somebody will notice, while one who can *un*-quarantine
/// restores a party the estate decided to cut. Clearing is the more dangerous direction.
///
/// Contracts stay revoked. Clearing restores the party's ability to be re-admitted, never
/// its former authority — [`wc_core::model::Entity::clear_quarantine`] enforces that and
/// this command says it out loud, because "cleared" reads like "back to normal".
fn unquarantine(args: &Args) -> Result<()> {
    let id = EntityId::new(positional_or_flag(args, "id")?)?;
    let approvers: Vec<HumanRef> = args
        .list("approver")
        .into_iter()
        .map(HumanRef::new)
        .collect::<Result<Vec<_>>>()?;
    let why = args.get("why").unwrap_or("quarantine lifted").to_string();

    let ts = now();
    let mut store = open_store(args)?;
    let held_for = store
        .registry(actor(args)?, ts)
        .clear_quarantine(&id, &approvers)?;

    let mut evidence = open_evidence(args)?;
    let recorded = evidence.record(
        &LifecycleEvent::new(EventKind::QuarantineCleared, actor_id(args))
            .with_entities([id.as_str()])
            .with_reason(why.clone())
            .with_detail(json!({
                "approvers": approvers.iter().map(HumanRef::as_str).collect::<Vec<_>>(),
                "held_for_seconds": held_for,
                "contracts_restored": false,
            })),
        ts,
    )?;

    println!("quarantine lifted for {id}");
    println!("  posture            Unattested (re-admission required)");
    println!("  lifecycle          Pending");
    match held_for {
        Some(seconds) => println!("  held for           {}", human_duration(seconds)),
        None => println!("  held for           unknown (quarantined before this was recorded)"),
    }
    println!(
        "  approvers          {}",
        approvers
            .iter()
            .map(HumanRef::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  evidence seq       {}", recorded.seq);
    println!();
    println!("Contracts stay revoked. This party can be admitted again; it has not");
    println!("regained the authority it held, and nothing it used to hold is live.");
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

    // --- revocation custody, before anything is written (P0 #5c) ----------
    //
    // Resolved here rather than at the fan-out below, because the registry transition
    // is a state write: a misdeclared key would otherwise quarantine the party in the
    // control plane, fail, and leave the mediators never told — a half-applied
    // containment that reads in the register as done. Same reasoning as `open_evidence`
    // refusing on posture before it locks the chain.
    let revocation = resolve_revocation_custody(args)?;

    let ts = now();
    let mut store = open_store(args)?;
    let outcome = store
        .registry(actor(args)?, ts)
        .quarantine(&id, &reason, &approvers)?;

    let mut evidence = open_evidence(args)?;
    let recorded = evidence.record(
        &LifecycleEvent::new(EventKind::Quarantine, actor_id(args))
            .with_entities([id.as_str()])
            .with_reason(reason.clone())
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
    let containment = if let Some(revocation) = &revocation {
        {
            let (kid, signing_role, key) = (&revocation.kid, revocation.role, &revocation.key);
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
                    key,
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

            // Break-glass use is itself the event. It happens approximately never, so
            // one use is a page — and recorded at `Critical` rather than left to whoever
            // reads the feed to notice which `kid` signed. `Severity` and the blocking
            // sinks already carried this; nothing was raising it.
            //
            // Written through the chain handle already open above, not through a second
            // `open_evidence`. The chain is single-writer by design (§8.5.2), so opening
            // it twice fails with `WC-8003` — and it would have failed *only* on the
            // break-glass path, which is the one path that must not have a bug in it. The
            // first version of this did exactly that.
            if signing_role == custody::Role::RevokeOffline {
                evidence.record(
                    &LifecycleEvent::new(EventKind::BreakGlassKeyUsed, actor_id(args))
                        .with_entities([id.as_str()])
                        .with_reason(format!(
                            "break-glass revocation key {kid} was used: {reason}"
                        ))
                        .with_detail(json!({
                            "break_glass": true,
                            "kid": kid,
                            "key_custody": key.custody().as_str(),
                            "why_this_is_loud": "the offline revocation key is for when the \
                                KMS or the control plane is unavailable; its use is expected \
                                approximately never",
                        })),
                    ts,
                )?;
                eprintln!(
                    "connect: BREAK-GLASS revocation signed with {kid} — recorded at Critical"
                );
            }
            Some(report)
        }
    } else {
        None
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
/// Verify a DSSE / in-toto SLSA provenance envelope on its own.
///
/// `DsseProvenanceVerifier` existed only inside `register --attest`, which means the one
/// thing this repository could do that nobody else's tooling does — check a SLSA envelope
/// against a **named builder and a bound subject digest**, offline, with no network and no
/// Sigstore client — was reachable only as a side effect of registering a party.
///
/// It is the piece `docs/releasing.md` needs to close its own loop: this repository verifies
/// other people's provenance and produces none of its own, and the shortest honest path is to
/// attest releases in the format this component already accepts and then verify our own
/// artifacts with our own code. `scripts/verify-release.sh` is that, and this is what it
/// calls.
///
/// Three bindings, all required, because a signature alone vouches for nothing in
/// particular: signed by a trusted key, `subject[].digest.sha256` equal to the artifact in
/// front of you, and `builder.id` in an allowlist you wrote. A verifier that reported the
/// first as success would tell you a stranger's valid attestation about a different file was
/// your build.
/// `offer publish` — record a provider's terms of availability (W6).
///
/// The provider's pipeline runs this on merge. Nothing here signs anything: the offer's
/// authority is the review on the commit it names, and verifying *that* is W5's job
/// (`ApprovalAuthority`). Until then `--by` names the actor, which is honest — the record says
/// who asserted it rather than pretending it was verified.
fn offer_publish_cmd(args: &Args) -> Result<()> {
    let surface_path = require(args, "surface")?;
    let terms_path = require(args, "terms")?;
    let repo = require(args, "repo")?.to_string();
    let sha = require(args, "sha")?.to_string();
    let kind = surface_kind(args.get("kind").unwrap_or("mcp"))?;

    let surface_raw = std::fs::read(surface_path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {surface_path}"))
            .with_source(e)
    })?;
    let document: serde_json::Value = serde_json::from_slice(&surface_raw).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("{surface_path} is not JSON"))
            .with_source(e)
    })?;
    let terms_text = std::fs::read_to_string(terms_path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {terms_path}"))
            .with_source(e)
    })?;

    let manifest = wc_control::offer::OfferManifest::parse(&terms_text)?;
    let asset = EntityId::new(&manifest.asset)?;

    // The declared items come from canonicalising the surface, not from the manifest: a term may
    // only offer what the callee actually declares, and the canonicaliser is the one thing that
    // decides what "declares" means.
    let pin =
        wc_core::canon::canonicalise(kind, &asset, &document, &wc_core::canon::Limits::default())?;
    let declared: std::collections::BTreeSet<String> = pin.items.keys().cloned().collect();
    let surface_digest = pin.manifest_hash();

    let mut store = open_store(args)?;
    let held = store.projection.offers.get(&asset).map(|o| o.version);
    let version = match args.number("version") {
        Some(v) => {
            if held.is_some_and(|h| v <= h) {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!(
                        "--version {v} is not higher than the held version {}; the projection \
                         keeps the highest, so this would be recorded and then ignored",
                        held.unwrap_or(0)
                    ),
                ));
            }
            v
        }
        None => held.map_or(1, |h| h + 1),
    };

    let mut offer = manifest.into_offer(
        &declared,
        kind,
        &surface_digest,
        version,
        wc_control::offer::OfferSource {
            repo: repo.clone(),
            sha: sha.clone(),
            manifest_digest: format!("sha256:{}", wc_core::util::sha256_hex(&terms_text)),
        },
    )?;

    // The provider's half of a bilateral contract. Without a shim the offer is recorded on the
    // publisher's word alone — fine for a catalogue, and `need apply` refuses to mint against it,
    // because one side's word is not an agreement.
    if let Some(command) = args.get("shim") {
        let label = args.get("shim-label").unwrap_or("scm");
        let git_ref = args.get("git-ref").unwrap_or("refs/heads/main");
        let shim = wc_control::scm::ScmShim::parse(label, command)?;
        let authority = wc_control::authority::ScmMerge { shim: &shim };
        let asserted = wc_control::pipeline::Asserted {
            repo: repo.clone(),
            git_ref: git_ref.to_string(),
            sha: sha.clone(),
        };
        let consent = wc_control::authority::ApprovalAuthority::consent(
            &authority,
            wc_core::contract::Side::Target,
            &asserted,
            &wc_control::authority::ManifestBinding::of(terms_path, &terms_text),
        )?;
        println!(
            "consent    {} approved by {} via {}",
            consent.request_id,
            consent.approvers.join(", "),
            consent.via
        );
        offer = offer.with_consent(consent);
    } else {
        println!("consent    NONE — no --shim given, so `need apply` will refuse to mint");
    }

    let items = offer.offered_items();
    store.commit(
        wc_control::store::Event::OfferPublished {
            offer: Box::new(offer),
            actor: actor(args)?,
        },
        now(),
        wc_control::store::Durability::Durable,
    )?;

    println!("published  {asset}");
    println!(
        "  version  {version}{}",
        held.map_or(String::new(), |h| format!(" (was {h})"))
    );
    println!("  surface  {surface_digest}");
    println!(
        "  offers   {}",
        items.iter().cloned().collect::<Vec<_>>().join(", ")
    );
    println!("  from     {repo}@{sha}");
    Ok(())
}

/// `scm probe` — exercise a source-host shim and say exactly what it returned (W4).
///
/// The counterpart to the advice `signer.rs` gives about signing wrappers ("verify any wrapper
/// before trusting it"), and more necessary, because a wrong answer here is not caught by
/// cryptography.
fn scm_probe_cmd(args: &Args) -> Result<()> {
    let command = require(args, "shim")?;
    let label = require(args, "label")?;
    let repo = require(args, "repo")?;
    let sha = require(args, "sha")?;

    let mut shim = wc_control::scm::ScmShim::parse(label, command)?;
    if let Some(secs) = args.number("timeout") {
        shim = shim.with_timeout(std::time::Duration::from_secs(secs));
    }

    println!("probing    {label}  ({command})");
    println!("  repo     {repo}");
    println!("  sha      {sha}");

    let evidence = shim.merge_evidence(repo, sha)?;
    println!();
    println!("merge evidence");
    println!("  merged     {}", evidence.merged);
    println!("  ref        {}", evidence.git_ref);
    println!("  protected  {}", evidence.protected);
    println!("  request    {}", evidence.request_id);
    println!("  author     {}", evidence.author);
    println!("  approvers  {}", evidence.approvers.join(", "));
    println!(
        "  verdict    {}",
        if evidence.is_reviewed_merge() {
            "a reviewed merge".to_string()
        } else {
            format!("NOT a reviewed merge — {}", evidence.why_not_reviewed())
        }
    );

    // Every mismatch is collected rather than returned on the first one: probing a shim one
    // wrong field per run is the slow loop this command exists to avoid.
    let mut wrong: Vec<String> = Vec::new();
    if let Some(want) = args.get("expect-ref") {
        if evidence.git_ref != want {
            wrong.push(format!("expected ref {want:?}, got {:?}", evidence.git_ref));
        }
    }
    if args.has("expect-protected") && !evidence.protected {
        wrong.push("expected a protected ref, and the shim says it is not".to_string());
    }
    for who in args.list("expect-approver") {
        if !evidence.approvers.iter().any(|a| a == &who) {
            wrong.push(format!(
                "expected {who:?} among the approvers, got [{}]",
                evidence.approvers.join(", ")
            ));
        }
    }

    if let Some(path) = args.get("expect-file") {
        match shim.file(repo, sha, path) {
            Ok(bytes) => {
                println!();
                println!("file       {path}");
                println!("  bytes    {}", bytes.len());
                println!(
                    "  sha256   sha256:{}",
                    wc_core::util::sha256_hex(&String::from_utf8_lossy(&bytes))
                );
                if bytes.is_empty() {
                    wrong.push(format!("{path} came back empty"));
                }
            }
            Err(e) => wrong.push(format!("the `file` verb failed: {}", e.detail())),
        }
    }

    println!();
    if wrong.is_empty() {
        println!("PROBE OK — this shim answered as expected. Record that it has been probed.");
        return Ok(());
    }
    for w in &wrong {
        println!("  MISMATCH  {w}");
    }
    Err(WcError::with_detail(
        Code::CONFIG_INVALID,
        format!(
            "{} expectation(s) not met; do not trust this shim until it answers correctly",
            wrong.len()
        ),
    ))
}

/// `need apply` — mint what a consumer's manifest asks for, on the strength of two merges (W5).
///
/// The verb `need check` could not be. It reports; this issues.
fn need_apply_cmd(args: &Args) -> Result<()> {
    let manifest_path = require(args, "manifest")?;
    let repo = require(args, "repo")?.to_string();
    let sha = require(args, "sha")?.to_string();
    let mediator = require(args, "mediator")?.to_string();
    let git_ref = args.get("git-ref").unwrap_or("refs/heads/main").to_string();
    let shim_cmd = require(args, "shim")?;
    let shim_label = args.get("shim-label").unwrap_or("scm");

    let text = std::fs::read_to_string(manifest_path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {manifest_path}"))
            .with_source(e)
    })?;
    let manifest = wc_control::need::NeedManifest::parse(&text)?;

    // The consumer's consent is verified once for the manifest, not once per need: one merge
    // carried the whole file, and asking the source host the same question per entry would be a
    // slower way to get the same answer.
    let shim = wc_control::scm::ScmShim::parse(shim_label, shim_cmd)?;
    let authority = wc_control::authority::ScmMerge { shim: &shim };
    let asserted = wc_control::pipeline::Asserted {
        repo: repo.clone(),
        git_ref,
        sha: sha.clone(),
    };
    let consumer_consent = wc_control::authority::ApprovalAuthority::consent(
        &authority,
        wc_core::contract::Side::Source,
        &asserted,
        &wc_control::authority::ManifestBinding::of(manifest_path, &text),
    )?;
    println!(
        "consumer   {} approved by {} via {}",
        consumer_consent.request_id,
        consumer_consent.approvers.join(", "),
        consumer_consent.via
    );

    // Two phases, because the issuer borrows the store mutably and the matching needs to read
    // it. Phase one decides everything and writes nothing; phase two mints.
    let ts = now();
    struct Planned {
        matched: wc_control::need::Matched,
        approval: wc_core::contract::ApprovalRef,
        consumer: wc_core::model::Entity,
        provider: wc_core::model::Entity,
        input: wc_control::issuance::RequestInput,
    }
    let mut plan: Vec<Planned> = Vec::new();
    let mut noop = 0usize;

    {
        let mut store = open_store(args)?;
        for entry in &manifest.needs {
            let need = manifest.resolve(entry)?;

            let Some(offer) = store.projection.offers.get(&need.provider).cloned() else {
                return Err(WcError::with_detail(
                    Code::NO_CONTRACT,
                    format!(
                        "no offer is held for {}. There is no central fallback by design, so \
                         provider consent is never implied",
                        need.provider
                    ),
                ));
            };
            let Some(provider_consent) = offer.consent.clone() else {
                return Err(WcError::with_detail(
                    Code::APPROVAL_SIGNATURE_INVALID,
                    format!(
                        "the offer for {} carries no verified consent — it was published without \
                         a shim, so only the publisher's word says its terms were reviewed. \
                         Republish with `offer publish --shim` before contracting against it",
                        need.provider
                    ),
                ));
            };

            let (consumer, provider) = {
                let reg = store.registry(actor(args)?, ts);
                (
                    reg.require(&need.consumer)?.clone(),
                    reg.require(&need.provider)?.clone(),
                )
            };

            let matched =
                wc_control::need::match_need(&need, &offer, consumer.zone.as_str(), consumer.tier)
                    .map_err(|refusals| wc_control::need::refusal_error(&need, &refusals))?;

            println!();
            println!("{} -> {}", need.consumer, need.provider);

            // Idempotency before anything is written, so an unchanged re-run appends no request
            // row either: "no duplicate contract" and "no duplicate audit noise" are both part of
            // the claim.
            if store
                .projection
                .contracts
                .get(&matched.cid)
                .is_some_and(|c| c.jti == matched.jti)
            {
                println!("  already current  {} ({})", matched.cid, matched.jti);
                noop += 1;
                continue;
            }

            let approval = wc_core::contract::ApprovalRef::reviewed_merge(vec![
                consumer_consent.clone(),
                provider_consent,
            ])?;
            let input = wc_control::issuance::RequestInput {
                caller: need.consumer.clone(),
                callee: need.provider.clone(),
                surface: wc_core::contract::Surface {
                    tools: matched.items.iter().cloned().collect(),
                    ..Default::default()
                },
                terms: wc_core::contract::Terms::default(),
                ttl_secs: matched.ttl,
                justification: need.justify.clone(),
                requester: requester_of(&consumer_consent)?,
                mediators: vec![mediator.clone()],
            };
            plan.push(Planned {
                matched,
                approval,
                consumer,
                provider,
                input,
            });
        }
    }

    let mut minted = 0usize;
    if !plan.is_empty() {
        with_issuer(args, |issuer| {
            for p in &plan {
                // Routed through `request` so connect-policy is evaluated exactly as it is for a
                // human request. The offer is the provider's ceiling; it is not a way past the
                // estate's policy.
                let pending = match issuer.request(&p.input)? {
                    Outcome::Denied { reason, .. } => {
                        return Err(WcError::with_detail(
                            Code::POLICY_DENIED,
                            format!("connection policy refused this need: {reason}"),
                        ))
                    }
                    Outcome::Issued(issued) => {
                        println!("  issued by standing policy  {}", issued.record.cid);
                        minted += 1;
                        continue;
                    }
                    Outcome::AwaitingApproval(pending) => pending,
                };

                let issued = issuer.mint_with_identity(
                    &pending,
                    p.approval.clone(),
                    &p.consumer,
                    &p.provider,
                    p.matched.cid.clone(),
                    p.matched.jti.clone(),
                )?;
                println!("  minted     {} ({})", issued.record.cid, issued.record.jti);
                println!(
                    "  items      {}",
                    p.matched
                        .items
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!("  ttl        {}s", p.matched.ttl);
                if let Some(dir) = args.get("out") {
                    for (name, jws) in &issued.artifacts {
                        let path = std::path::Path::new(dir).join(name);
                        std::fs::write(&path, format!("{jws}\n")).map_err(|e| {
                            WcError::with_detail(
                                Code::CONFIG_INVALID,
                                format!("cannot write {}", path.display()),
                            )
                            .with_source(e)
                        })?;
                        println!("  artifact   {name}");
                    }
                }
                minted += 1;
            }
            Ok(())
        })?;
    }

    println!();
    println!("{minted} minted · {noop} already current");
    Ok(())
}

/// The requester recorded on a pipeline-driven request.
///
/// The change's author, not the pipeline: a contract's justification is written by a person and
/// the record should name the person who wrote it. Falls back to the approver when a host reports
/// no author, because a request with no accountable human is worse than an imprecise one.
fn requester_of(consent: &wc_core::contract::MergeApproval) -> Result<HumanRef> {
    let who = if consent.author.is_empty() {
        consent.approvers.first().map(String::as_str).unwrap_or("")
    } else {
        consent.author.as_str()
    };
    if who.is_empty() {
        return Err(WcError::with_detail(
            Code::APPROVAL_SIGNATURE_INVALID,
            "the merge names neither an author nor an approver, so no human can be recorded",
        ));
    }
    HumanRef::new(format!("human:{who}"))
}

/// `need check` — does any provider's offer permit what this consumer asks for? (W6)
///
/// The consumer's pipeline runs this on merge. It is deliberately read-only: see the usage text
/// for why it cannot mint yet.
fn need_check_cmd(args: &Args) -> Result<()> {
    let manifest_path = require(args, "manifest")?;
    let text = std::fs::read_to_string(manifest_path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {manifest_path}"))
            .with_source(e)
    })?;
    let manifest = wc_control::need::NeedManifest::parse(&text)?;

    let mut store = open_store(args)?;
    let ts = now();
    let mut refused = 0usize;
    let mut ok = 0usize;

    for entry in &manifest.needs {
        let need = manifest.resolve(entry)?;

        // The consumer's zone and tier come from the registry, never from the manifest: a party
        // that could assert its own zone could write itself into any provider's audience.
        let consumer = {
            let reg = store.registry(actor(args)?, ts);
            reg.require(&need.consumer)?.clone()
        };

        let Some(offer) = store.projection.offers.get(&need.provider).cloned() else {
            println!("REFUSED  {} -> {}", need.consumer, need.provider);
            println!(
                "  no offer is held for {}. There is no central fallback by design, so provider \
                 consent is never implied — ask its owner to publish one.",
                need.provider
            );
            refused += 1;
            continue;
        };

        match wc_control::need::match_need(&need, &offer, consumer.zone.as_str(), consumer.tier) {
            Ok(m) => {
                ok += 1;
                println!("OK       {} -> {}", need.consumer, need.provider);
                println!("  cid    {}", m.cid);
                println!("  jti    {}", m.jti);
                println!(
                    "  items  {}",
                    m.items.iter().cloned().collect::<Vec<_>>().join(", ")
                );
                println!(
                    "  ttl    {}s{}",
                    m.ttl,
                    if m.ttl < need.ttl_requested {
                        format!(" (asked {}s, capped by the offer)", need.ttl_requested)
                    } else {
                        String::new()
                    }
                );
                println!("  offer  version {}", m.offer_version);
            }
            Err(refusals) => {
                refused += 1;
                println!("REFUSED  {} -> {}", need.consumer, need.provider);
                for r in &refusals {
                    if r.item.is_empty() {
                        println!("  {}", r.why);
                    } else {
                        println!("  {}: {}", r.item, r.why);
                    }
                }
            }
        }
    }

    println!();
    println!("{ok} contractable · {refused} refused");
    if refused > 0 {
        // Non-zero, so a consumer's pipeline fails on a need no provider offers. A check that
        // reported a refusal and exited 0 would be a check nobody notices.
        return Err(WcError::with_detail(
            Code::POLICY_DENIED,
            format!("{refused} need(s) are not permitted by the offers currently held"),
        ));
    }
    Ok(())
}

/// `offer show` — the terms currently held for a provider.
fn offer_show_cmd(args: &Args) -> Result<()> {
    let asset = EntityId::new(positional_or_flag(args, "asset")?)?;
    let store = open_store(args)?;
    let offer = store
        .projection
        .offers
        .get(&asset)
        .cloned()
        .ok_or_else(|| {
            WcError::with_detail(
                Code::NO_CONTRACT,
                format!(
                "no offer is held for {asset}. Without one nothing can be contracted against it \
                 — there is no central fallback by design, so provider consent is never implied"
            ),
            )
        })?;

    if args.has("json") {
        println!(
            "{}",
            pretty(&serde_json::to_value(&offer).unwrap_or_default())?
        );
        return Ok(());
    }
    println!("{}", offer.asset);
    println!("  version  {}", offer.version);
    println!(
        "  surface  {} ({})",
        offer.surface_digest,
        offer.surface_kind.as_str()
    );
    println!("  from     {}@{}", offer.source.repo, offer.source.sha);
    println!("  manifest {}", offer.source.manifest_digest);
    for (n, term) in offer.terms.iter().enumerate() {
        println!(
            "  term {n}    {:?} · ttl_max {}s · {}",
            term.approval,
            term.ttl_max,
            term.items.join(", ")
        );
    }
    Ok(())
}

/// `attest surface` — sign a declared surface so stage 3 can pass.
///
/// The counterpart to `attest verify`: that one checks somebody else's provenance, this one
/// produces the attestation our own admission pipeline requires. Until this existed
/// `wc_control::offer::attest_surface` had no caller outside its tests — the same shape as
/// `drain`, which had nine tests and no flag.
fn attest_surface_cmd(args: &Args) -> Result<()> {
    let surface_path = require(args, "surface")?;
    let out_path = require(args, "out")?;
    let (kid, key) = card_key(args)?;

    let raw = std::fs::read(surface_path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {surface_path}"))
            .with_source(e)
    })?;
    let document: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| {
        WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("{surface_path} is not JSON; a surface is the document the callee declares"),
        )
        .with_source(e)
    })?;

    let signed = wc_control::offer::attest_surface(&document, &key)?;
    let rendered = serde_json::to_string_pretty(&signed).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, "cannot render the signed surface")
            .with_source(e)
    })?;
    std::fs::write(out_path, format!("{rendered}\n")).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot write {out_path}"))
            .with_source(e)
    })?;

    println!("attested   {out_path}");
    println!("  kid      {kid}");
    println!("  covers   the canonical document with `signatures` removed");
    println!(
        "  next     register the party with --card {out_path} --card-key {kid}=<pub.pem>, and \
         supply stage 1 and stage 4 material too — all three legs are required for Attested"
    );
    Ok(())
}

/// The card-signing key for `attest surface`, through the custody rules like every other role.
fn card_key(args: &Args) -> Result<(String, IssuerKey)> {
    let spec = require(args, "card-key")?;
    let (kid, path) = spec.split_once('=').ok_or_else(|| {
        WcError::with_detail(
            Code::CONFIG_INVALID,
            "--card-key takes KID=PEM, so the key id in the JWS header is the one you named",
        )
    })?;
    let pem = std::fs::read(path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
    })?;
    let key = IssuerKey::ec_pem(kid, &pem, Algorithm::ES256)?;
    Ok((kid.to_string(), key))
}

fn attest_verify_cmd(args: &Args) -> Result<()> {
    let path = positional_or_flag(args, "file")?;
    let envelope = read_json(path)?;
    let keys = key_set(args, "prov-key")?;
    if keys.is_empty() {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            "--prov-key KID=PEM is required: with no trusted key there is nothing to verify              the signature against, and an unverified envelope is a text file",
        ));
    }

    // The digest, either given or computed from the artifact in front of you. Computing it
    // is the safer default to offer: a digest retyped from a release page is a digest that
    // can be retyped from the attacker's release page.
    let digest = match (args.get("artifact-digest"), args.get("artifact")) {
        (Some(_), Some(_)) => {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "--artifact-digest and --artifact both name the subject; pass one",
            ))
        }
        (Some(d), None) => Some(normalise_digest(d)),
        (None, Some(file)) => {
            let bytes = std::fs::read(file).map_err(|e| {
                WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {file}"))
                    .with_source(e)
            })?;
            Some(wc_core::util::sha256_prefixed(&bytes))
        }
        (None, None) => None,
    };

    let builders: std::collections::BTreeSet<String> = args.list("builder").into_iter().collect();

    let verifier = attest::DsseProvenanceVerifier {
        keys: &keys,
        envelopes: vec![envelope.clone()],
        artifact_digest: digest.clone(),
        allowed_builders: builders.clone(),
    };
    let (bindings, refs, method) = verifier.verify_envelope(&envelope)?;

    // Transparency-log inclusion, when a proof is supplied. `bindings.log_checked` was
    // permanently false and the method string said so — honest, and now it can be true.
    //
    // The leaf is the log entry's *body*, not the envelope: Rekor hashes what it stored, and
    // hashing the artifact or the envelope here would produce a leaf that matches nothing and
    // fail for a reason nobody could diagnose.
    let inclusion = match args.get("rekor-proof") {
        None => None,
        Some(proof_path) => {
            let raw = read_json(proof_path)?;
            // Accept a whole entry response or just the proof object, because the two are
            // what an operator actually has to hand.
            let proof_value = raw
                .get("verification")
                .and_then(|v| v.get("inclusionProof"))
                .or_else(|| raw.get("inclusionProof"))
                .cloned()
                .unwrap_or_else(|| raw.clone());
            let proof: rekor::InclusionProof =
                serde_json::from_value(proof_value).map_err(|e| {
                    WcError::with_detail(
                        Code::CONFIG_INVALID,
                        format!("{proof_path} is not a Rekor inclusion proof"),
                    )
                    .with_source(e)
                })?;

            let body_b64 = match args.get("rekor-body") {
                Some(p) => std::fs::read_to_string(p)
                    .map_err(|e| {
                        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {p}"))
                            .with_source(e)
                    })?
                    .trim()
                    .to_string(),
                None => raw
                    .get("body")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        WcError::with_detail(
                            Code::CONFIG_INVALID,
                            "the proof file carries no `body`, so pass --rekor-body FILE with                              the log entry's base64 body: the leaf is a hash of what the log                              stored, not of the artifact",
                        )
                    })?
                    .to_string(),
            };
            let body = wc_core::util::base64_decode(&body_b64).ok_or_else(|| {
                WcError::with_detail(Code::CONFIG_INVALID, "the Rekor entry body is not base64")
            })?;
            Some(rekor::verify(&rekor::leaf_hash(&body), &proof)?)
        }
    };

    // Every binding is reported, and a missing one is a refusal rather than a footnote.
    // `verify_envelope` returns the bindings even when one did not hold, so this command
    // owes the decision — silently printing "verified" beside `subject_matched: false` is
    // exactly the shape of defect this codebase keeps producing.
    let mut missing: Vec<&str> = Vec::new();
    if digest.is_none() {
        missing.push("no artifact digest supplied, so the statement is bound to nothing");
    } else if !bindings.subject_matched {
        missing.push("the statement's subject digest is not this artifact");
    }
    if builders.is_empty() {
        missing.push("no --builder allowlist, so any builder would have been accepted");
    } else if !bindings.builder_allowed {
        missing.push("the statement's builder is not in the allowlist");
    }
    // Not in `missing`: inclusion is additional assurance, and its absence is the documented
    // default rather than a broken binding. Saying nothing at all would be the mistake.

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "verdict": if missing.is_empty() { "verified" } else { "unbound" },
                "method": method,
                "subject_digest": bindings.subject_digest,
                "builder": bindings.builder,
                "subject_matched": bindings.subject_matched,
                "builder_allowed": bindings.builder_allowed,
                "rekor_inclusion_checked": inclusion.is_some(),
                "rekor": inclusion.as_ref().map(|i| json!({
                    "leaf_hash": i.leaf_hash,
                    "root": i.computed_root,
                    "tree_size": i.tree_size,
                    "checkpoint_agrees": i.checkpoint_agrees,
                    "origin": i.origin,
                    "root_trust": i.root_trust,
                })),
                "missing": missing,
                "refs": refs.len(),
            }))?
        );
    } else {
        println!("signature  {method}");
        println!(
            "  subject    {}",
            bindings.subject_digest.as_deref().unwrap_or("none stated")
        );
        println!(
            "  builder    {}",
            bindings.builder.as_deref().unwrap_or("none stated")
        );
        println!(
            "  bound      subject {} · builder {}",
            bindings.subject_matched, bindings.builder_allowed
        );
        match &inclusion {
            None => println!("  rekor      inclusion NOT checked (pass --rekor-proof)"),
            Some(i) => {
                println!(
                    "  rekor      included in a tree of {} leaves, root {}…",
                    i.tree_size,
                    &i.computed_root[..16]
                );
                match &i.origin {
                    Some(o) => println!("             checkpoint {o}"),
                    None => println!("             no checkpoint"),
                }
                println!("             {}", i.root_trust);
            }
        }
        for m in &missing {
            println!("  UNBOUND    {m}");
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(WcError::with_detail(
            Code::PROVENANCE_UNVERIFIABLE,
            format!(
                "the signature verified and the attestation is not bound: {}",
                missing.join("; ")
            ),
        ))
    }
}

/// Accept a digest with or without the `sha256:` prefix, since release pages print both.
fn normalise_digest(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("sha256:") {
        trimmed.to_string()
    } else {
        format!("sha256:{trimmed}")
    }
}

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
    // 5e: the envelope key follows the issuer key's custody, so it goes through the same
    // resolution and honours `--require-external-signing`. It did not before: an estate
    // with the posture set could export a bundle signed by a PEM on this disk, which is
    // the artifact most likely to be carried physically into somewhere the KMS is not.
    let key = custody_key(
        args,
        custody::Role::Envelope,
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
    // Required here for the same reason the mediator requires it: a bundle is a contract set
    // that travelled as a file, so the plane it came from is the one thing the courier's
    // envelope cannot vouch for.
    let trust = wc_core::contract::Trust {
        keys: &contract_keys,
        mediator_id: mediator,
        issuer: require(args, "issuer-id")?,
    };
    let imported =
        wc_control::bundle::import_file(std::path::Path::new(path), &envelope, &trust, ts)?;

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

    // --- the §8.16 acceptance criteria (P1 #9) ----------------------------
    //
    // Stated as phase exit gates and never run. They are here rather than in a separate
    // harness because `connect bench` is already the thing CI invokes, and a criterion in
    // a second place nobody calls is the same as a criterion nobody measured.

    // P4: a DORA register at 10⁵ contracts, which §8.16 bounds at one hour.
    if wanted("export::dora") {
        let projection = bench_estate(scale)?;
        let provenance = export::Provenance {
            as_of: ts,
            chain_head_seq: 0,
            chain_head_hash: String::new(),
            anchor_ref: None,
            replay_complete: true,
        };
        // Two iterations, not five hundred: at this scale one run is seconds, and the
        // question is "does it complete", not "what is the jitter". The register is
        // asserted non-empty, because an export that produced nothing would post an
        // excellent number for doing no work — the same defect the rebuild gate had.
        let mut rows = 0usize;
        report.gates.push(measure(
            "export::dora",
            &format!("{scale} contracts"),
            thresholds::DORA_100K,
            2,
            0,
            || {
                if let Ok(register) = export::dora_register(&projection, provenance.clone()) {
                    rows = register.tables.iter().map(|t| t.rows.len()).sum();
                }
            },
        ));
        if rows == 0 {
            report.skip(
                "export::dora",
                "the register came back empty, so the timing above measured nothing",
                false,
            );
        }
    } else {
        report.skip("export::dora", "not selected by --gate", true);
    }

    // P0: 10⁴ entities registered. Against a real store on a real filesystem, because the
    // cost is durability rather than computation and an in-memory projection would measure
    // the wrong thing entirely.
    if wanted("registry::register") {
        let dir = std::env::temp_dir().join(format!("wc-bench-register-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut registered = 0usize;
        report.gates.push(measure(
            "registry::register",
            "10,000 entities, appended and fsynced",
            thresholds::REGISTER_10K,
            1,
            0,
            || {
                let _ = std::fs::remove_dir_all(&dir);
                registered = bench_register(&dir, 10_000).unwrap_or(0);
            },
        ));
        let _ = std::fs::remove_dir_all(&dir);
        if registered < 10_000 {
            report.skip(
                "registry::register",
                "fewer than 10,000 entities landed, so the timing measured a partial run",
                false,
            );
        }
    } else {
        report.skip("registry::register", "not selected by --gate", true);
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
/// Register `count` entities into a fresh store, returning how many landed.
///
/// A real `Store` on a real filesystem: every registration is an append plus an `fsync`, so
/// an in-memory version would measure the wrong thing and pass while the durable path
/// regressed.
fn bench_register(dir: &std::path::Path, count: usize) -> Result<usize> {
    use wc_control::store::Store;
    use wc_core::model::{Entity, HumanRef, Kind};

    std::fs::create_dir_all(dir).map_err(|e| {
        WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("cannot create {}", dir.display()),
        )
        .with_source(e)
    })?;
    let (mut store, _) = Store::open(dir)?;
    let owner = HumanRef::new("human:bench")?;
    let zone = ZoneId::new("internal.bench")?;
    let actor = wc_control::store::Actor::Human { id: owner.clone() };
    let ts = now();

    for i in 0..count {
        let id = EntityId::new(format!("urn:wc:bench:reg{i}"))?;
        let entity = Entity::pending(
            id,
            Kind::McpServer,
            owner.clone(),
            zone.clone(),
            Tier::THREE,
            0,
        );
        store.registry(actor.clone(), ts).put(entity)?;
    }
    Ok(store.projection.entities.len())
}

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

/// `connect backup --out DIR` — a verified snapshot of this tenant's system of record.
///
/// Verifies the chain before writing a manifest, so a snapshot of an already-corrupt root
/// is refused rather than labelled a backup. See [`wc_control::backup`] for why that
/// refusal is the whole point.
fn backup_cmd(args: &Args) -> Result<()> {
    let p = paths(args);
    let out = require(args, "out")?;
    let anchor_pub = read_optional(args, "anchor-pub")?;
    let ts = args.number("now").unwrap_or_else(now);
    let tenant = tenant_id(args)?;

    let report = wc_control::backup::snapshot(
        &p.state,
        &p.evidence,
        std::path::Path::new(out),
        tenant.as_str(),
        anchor_pub.as_deref(),
        ts,
    )?;

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "out": out,
                "tenant": report.manifest.tenant,
                "state_seq": report.manifest.state_seq,
                "chain_seq": report.manifest.chain_seq,
                "chain_head": report.manifest.chain_head,
                "files": report.manifest.files.len(),
                "bytes": report.bytes,
                "torn_tail": report.torn_tail,
            }))?
        );
        return Ok(());
    }

    println!("backed up {} to {out}", report.manifest.tenant);
    println!("  state seq   {}", report.manifest.state_seq);
    println!("  chain seq   {}", report.manifest.chain_seq);
    println!(
        "  chain head  {}",
        report
            .manifest
            .chain_head
            .chars()
            .take(20)
            .collect::<String>()
    );
    println!(
        "  files       {} ({} bytes)",
        report.manifest.files.len(),
        report.bytes
    );
    println!("  verified    the chain was intact before this manifest was written");
    if report.torn_tail {
        // Said loudly because it is the difference between a cold and a hot copy, and an
        // operator restoring this later needs to know one record may be missing.
        println!(
            "  NOTE        a log ended mid-record: this was a hot copy, so the last \
             append may be absent from the restore"
        );
    }
    println!();
    println!("Ship this offsite, to WORM storage if the retention clock matters.");
    println!("Restore it into an empty root with `connect restore --from {out} --into ROOT`.");
    Ok(())
}

/// `connect restore --from DIR --into ROOT` — place a verified snapshot into an empty root.
fn restore_cmd(args: &Args) -> Result<()> {
    let from = require(args, "from")?;
    let into = require(args, "into")?;
    let tenant = tenant_id(args)?;
    let base = std::path::Path::new(into)
        .join("tenants")
        .join(tenant.as_str());

    let report = wc_control::backup::restore(
        std::path::Path::new(from),
        &base.join("state"),
        &base.join("evidence"),
    )?;

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "into": base.display().to_string(),
                "placed": report.placed,
                "state_seq": report.manifest.state_seq,
                "chain_seq": report.manifest.chain_seq,
                "chain_head": report.chain_head,
                "taken_at": report.manifest.at,
            }))?
        );
        return Ok(());
    }

    println!("restored {} file(s) into {}", report.placed, base.display());
    println!("  taken at    {}", report.manifest.at);
    println!("  state seq   {}", report.manifest.state_seq);
    println!("  chain seq   {}", report.manifest.chain_seq);
    println!("  chain head  matches the manifest");
    println!();
    // The number an incident actually turns on.
    println!(
        "Anything committed after state seq {} is not in this restore. Run \
         `connect audit verify` against the new root before serving from it.",
        report.manifest.state_seq
    );
    Ok(())
}

/// `connect retention` — the window of evidence this root actually holds.
fn retention_cmd(args: &Args) -> Result<()> {
    let p = paths(args);
    let ts = args.number("now").unwrap_or_else(now);
    let mut policy = wc_control::backup::Retention::default();
    if let Some(v) = args.get("contracts").and_then(cpolicy::parse_duration) {
        policy.contracts = v;
    }
    if let Some(v) = args.get("discovery").and_then(cpolicy::parse_duration) {
        policy.discovery = v;
    }
    // `--retire N` is the half that acts. Everything above still runs first, because an
    // operator should be able to see the window before moving any of it — and the report is
    // what tells them which N to pass.
    if let Some(upto) = args.number("retire") {
        let anchor_pub = read_optional(args, "anchor-pub")?.ok_or_else(|| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                "--retire needs --anchor-pub: retiring rows the anchor key never attested is                  indistinguishable from truncating them, so the key is not optional here",
            )
        })?;
        let horizon = ts.saturating_sub(policy.contracts);
        let out = wc_control::chain::retire_segment(&p.evidence, upto, horizon, &anchor_pub, ts)?;
        let r = &out.retirement;
        println!("retired seq {}..{} ({} rows)", r.from, r.to, r.count);
        println!("  archive        {}", out.segment_path.display());
        println!("  digest         {}", r.segment_digest);
        println!("  attested by    checkpoint at seq {}", r.anchor_seq);
        println!(
            "  live chain     {} rows, starting at seq {}",
            out.remaining,
            r.to + 1
        );
        println!("  newest retired {}", r.newest_retired_ts);
        println!();
        println!("The rows were MOVED, not deleted. Ship the archive to WORM storage and");
        println!("delete it yourself — a control plane that can erase its own evidence is a");
        println!("control plane whose evidence is worth less. `connect audit verify` still");
        println!("passes; the archive is checkable with the digest above.");
        return Ok(());
    }

    let report = wc_control::backup::retention_report(&p.evidence, &policy, ts)?;

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "contracts_secs": policy.contracts,
                "discovery_secs": policy.discovery,
                "retained": report.retained,
                "expired": report.expired,
                "oldest": report.oldest,
                "deletes": false,
                "note": report.note,
            }))?
        );
        return Ok(());
    }

    println!(
        "retention  contracts {}s · discovery {}s",
        policy.contracts, policy.discovery
    );
    println!("  rows retained  {}", report.retained);
    println!("  rows expired   {}", report.expired);
    match report.oldest {
        Some(at) => println!(
            "  oldest row     {at} ({}s of history)",
            ts.saturating_sub(at)
        ),
        None => println!("  oldest row     none — this chain is empty"),
    }
    println!();
    println!("Nothing was deleted — {}.", report.note);
    Ok(())
}

/// A PEM named by an optional flag.
fn read_optional(args: &Args, flag: &str) -> Result<Option<Vec<u8>>> {
    match args.get(flag) {
        None => Ok(None),
        Some(path) => Ok(Some(std::fs::read(path).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
        })?)),
    }
}

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
                // Linking proves nothing about rows that are gone. A consumer that
                // reads only `intact` would treat a truncated chain as healthy, so
                // both facts are emitted and named differently.
                "retired_through": report.retired_through,
                "anchors_retired": report.anchors_retired,
                "truncation_checked": report.truncation_was_checked(),
                "complete_to_seq": report.highest_checkpoint_seq,
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
        if report.retired_through > 0 {
            // Without this, "entries 4 / head seq 8" reads as four missing rows. The
            // boundary is the difference between a retired chain and a truncated one.
            println!(
                "retired          seq 1..{} moved to retired/ ({} checkpoint(s) attest rows \
                 no longer here)",
                report.retired_through, report.anchors_retired
            );
        }
        println!("completeness     {}", report.completeness());
        for problem in &report.problems {
            println!("  problem: {problem}");
        }
        // Never a bare "intact". Linking every row and *having* every row are two
        // claims, and this command used to print one word for both — so a chain with
        // its most recent evidence deleted verified green, which is the single edit
        // somebody who just used break-glass would make.
        println!(
            "\n{}",
            match (report.is_intact(), report.truncation_was_checked()) {
                (false, _) => "CHAIN IS BROKEN".to_string(),
                (true, true) => format!(
                    "chain is intact and complete to seq {}",
                    report.highest_checkpoint_seq
                ),
                (true, false) =>
                    "chain links are intact · COMPLETENESS UNVERIFIED (no checkpoint to \
                     compare against — see `completeness` above)"
                        .to_string(),
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

/// A mediator scenario: the context the artifact stage does not carry.
///
/// One file rather than a dozen flags, because the set is open — a mediator conformance
/// scenario needs peers, a presented surface, a feed and zone policy today, and whatever the
/// next context check needs after that. A positional-argument convention would have to break
/// to add one.
#[derive(serde::Deserialize)]
struct Scenario {
    /// Authenticated caller, as the peer layer resolved it.
    caller: String,
    /// Authenticated callee.
    callee: String,
    /// The surface the callee presented at `initialize`, as an MCP tools document or an
    /// A2A card. Absent means "exactly what the contract pinned", which is the ordinary
    /// case and keeps a scenario that is only testing zones from needing a surface file.
    #[serde(default)]
    presented_surface: Option<String>,
    /// `mcp` or `a2a`, for the presented surface.
    #[serde(default)]
    presented_kind: Option<String>,
    /// Revoked artifact ids.
    #[serde(default)]
    revoked_jtis: Vec<String>,
    /// Revoked connection ids.
    #[serde(default)]
    revoked_cids: Vec<String>,
    /// Revoked or quarantined parties.
    #[serde(default)]
    revoked_parties: Vec<String>,
    /// Zone pairs local policy permits, `[caller, callee]`. Absent means the default
    /// same-trust-level rule, which is what a mediator ships with.
    #[serde(default)]
    permitted_zone_pairs: Option<Vec<Vec<String>>>,
    /// `wcid` from the session token, when there is one.
    #[serde(default)]
    token_wcid: Option<String>,
    /// The control plane the mediator obeys, when the scenario is testing that boundary.
    ///
    /// Absent means `iss` is not checked, which is right for every other scenario: they are
    /// about a mediator's context, and the plane is configuration. Present, it is LLD check
    /// 4b — the one check a command-line verifier cannot reach on its own, because an artifact
    /// carries its issuer and nothing in the artifact says which issuer was expected.
    #[serde(default)]
    expected_iss: Option<String>,
}

/// Revocations from a scenario file.
struct ScenarioRevocations {
    jtis: std::collections::BTreeSet<String>,
    cids: std::collections::BTreeSet<String>,
    parties: std::collections::BTreeSet<String>,
}

impl contract::RevocationView for ScenarioRevocations {
    fn jti_revoked(&self, jti: &str) -> bool {
        self.jtis.contains(jti)
    }
    fn cid_revoked(&self, cid: &str) -> bool {
        self.cids.contains(cid)
    }
    fn party_revoked(&self, party: &str) -> bool {
        self.parties.contains(party)
    }
}

/// Zone policy from a scenario file.
///
/// An explicit pair list rather than a policy file, so a vector can state "this crossing is
/// not permitted" without also needing a whole `connect-policy.toml` to be interpreted the
/// same way by a third party.
struct ScenarioZones(Option<Vec<(String, String)>>);

impl contract::ZoneRule for ScenarioZones {
    fn permits(&self, caller: &wc_core::model::ZoneId, callee: &wc_core::model::ZoneId) -> bool {
        match &self.0 {
            None => contract::SameTrustLevel.permits(caller, callee),
            Some(pairs) => pairs
                .iter()
                .any(|(a, b)| a == caller.as_str() && b == callee.as_str()),
        }
    }
}

fn verify_with_scenario(
    args: &Args,
    jws: &str,
    keys: &IssuerKeys,
    mediator: &str,
    at: u64,
    leeway: u64,
    path: &str,
) -> Result<()> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
    })?;
    let scenario: Scenario = serde_json::from_str(&text).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("{path} is not a scenario"))
            .with_source(e)
    })?;

    let revocations = ScenarioRevocations {
        jtis: scenario.revoked_jtis.iter().cloned().collect(),
        cids: scenario.revoked_cids.iter().cloned().collect(),
        parties: scenario.revoked_parties.iter().cloned().collect(),
    };
    let mut opts = VerifyOpts::new(keys, mediator, at);
    opts.leeway = leeway;
    opts.revoked = &revocations;
    opts.expected_iss = scenario.expected_iss.as_deref();

    // The artifact stage first, with the feed attached — revocation is an artifact-stage
    // check that needs a context input, which is exactly why `revoked-jti` was deferred.
    let verified = contract::verify_artifact(jws, &opts)?;

    // The presented surface, when the scenario supplies one. Check 8 needs the real
    // document — `Pin::surface_digest` hashes each item's own digest, so a pin cannot be
    // fabricated from the contract's digest alone. A scenario testing zone policy therefore
    // does not have to restate a surface, and **check 8 is then not run**, which is said out
    // loud below rather than left for the reader to infer from a passing exit code.
    let presented = match (&scenario.presented_surface, &scenario.presented_kind) {
        (Some(surface_path), kind) => {
            // Relative to the scenario file, not the working directory. A scenario
            // references its own neighbours, and a kit that only worked when run from one
            // directory is a kit a third party cannot use.
            let resolved = std::path::Path::new(path).parent().map_or_else(
                || std::path::PathBuf::from(surface_path),
                |d| d.join(surface_path),
            );
            let raw = read_json(&resolved.to_string_lossy())?;
            let entity = EntityId::new(&scenario.callee)?;
            let kind = match kind.as_deref().unwrap_or("mcp") {
                "mcp" => SurfaceKind::McpTools,
                "a2a" => SurfaceKind::A2aCard,
                other => {
                    return Err(WcError::with_detail(
                        Code::CONFIG_INVALID,
                        format!("presented_kind must be mcp or a2a, got {other:?}"),
                    ))
                }
            };
            Some(wc_core::canon::pin(
                kind,
                &entity,
                &raw,
                &wc_core::canon::Limits::default(),
                at,
            )?)
        }
        (None, _) => None,
    };

    let peer = contract::PeerIdentity {
        caller: EntityId::new(&scenario.caller)?,
        callee: EntityId::new(&scenario.callee)?,
    };
    let zones = ScenarioZones(scenario.permitted_zone_pairs.as_ref().map(|pairs| {
        pairs
            .iter()
            .filter_map(|p| match p.as_slice() {
                [a, b] => Some((a.clone(), b.clone())),
                _ => None,
            })
            .collect()
    }));

    // `Pin::empty` stands in when no surface is supplied and is never read: the `None` arm
    // calls `admit_context`, which does not touch it. Built here so the borrow lives as long
    // as the context does.
    let empty = wc_core::model::Pin::empty(at);
    let ctx = contract::AdmitCtx {
        peer: &peer,
        presented: presented.as_ref().unwrap_or(&empty),
        token_wcid: scenario.token_wcid.as_deref(),
        zones: &zones,
        mode: mode(args),
    };
    let (admitted, pin_checked) = match presented.is_some() {
        true => (verified.admit(&ctx)?, true),
        // `admit_context` is checks 6, 7, 9, 10 and 11. Its own doc comment says a caller
        // using it **owes a `check_pin`**, and this is the one place that debt is acceptable:
        // the scenario declared it has no surface to present. It is reported, not assumed.
        false => (verified.admit_context(&ctx)?, false),
    };

    if args.has("json") {
        println!(
            "{}",
            pretty(&json!({
                "verdict": "admitted",
                "cid": admitted.cid.as_str(),
                "jti": admitted.jti.as_str(),
                "items": admitted.items.iter().collect::<Vec<_>>(),
                "exp": admitted.exp,
                "findings": admitted.findings.iter()
                    .map(|(c, d)| json!({"code": c.to_string(), "detail": d}))
                    .collect::<Vec<_>>(),
                "pin_checked": pin_checked,
                "checked": ["artifact stage", "revocation", "peer identity",
                            "zone policy", "token binding", "posture"],
                "not_checked": if pin_checked { Vec::<&str>::new() }
                               else { vec!["presented surface digest"] },
            }))?
        );
        return Ok(());
    }

    println!("admitted  {}", admitted.cid);
    println!(
        "  surface    {}",
        admitted
            .items
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  expires    {}", admitted.exp);
    for (code, detail) in &admitted.findings {
        println!("  finding    {code} {detail}");
    }
    println!();
    if pin_checked {
        println!("Every check ran, including the ones a bare `connect verify` cannot reach:");
        println!("peer identity, the presented surface digest, zone policy and posture.");
    } else {
        println!("Checks 6, 7, 9, 10 and 11 ran. Check 8 — the presented surface digest —");
        println!("did NOT: this scenario supplies no surface. A mediator owes that check");
        println!("before forwarding a call, so a scenario without a surface is testing the");
        println!("other five and is not evidence that drift would be caught.");
    }
    Ok(())
}

/// Check a `warden-connection+jws` against a trusted issuer key.
///
/// This is what makes the artifact a candidate standard rather than a product format: any
/// implementation may mint a contract, and a contract is valid iff this accepts it.
///
/// Without `--scenario` only the artifact checks run, because the context checks need an
/// authenticated peer, a presented surface, a revocation feed and zone policy — none of which
/// a command-line tool has. **With** `--scenario` all eleven run: that is the mediator's view,
/// and it is what makes the four context vectors checkable rather than deferred.
///
/// The exit code is the verdict.
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
    // Optional here and required at the mediator, deliberately: this command exists partly to
    // inspect an artifact somebody handed you, where the plane it came from is the question
    // rather than a setting. When it is not given, the report says `iss` was not checked
    // instead of leaving a printed `issuer` line to imply that it was.
    opts.expected_iss = args.get("issuer-id");
    opts.leeway = args.number("leeway").unwrap_or(0);

    // `--scenario` supplies what the artifact stage deliberately does not have: an
    // authenticated peer pair, the surface the callee actually presented, a revocation feed
    // and local zone policy. Without it this command checks the artifact in isolation and
    // **admits** the context vectors, which is correct for a command-line verifier and is
    // why four of the nineteen were reported as deferred rather than as passes.
    //
    // With it, this is the mediator's view of the same artifact, and those four become
    // checkable by any implementation — which is what a conformance kit for a *mediator*
    // needs and what the kit did not have.
    if let Some(path) = args.get("scenario") {
        return verify_with_scenario(args, &jws, &keys, mediator, at, opts.leeway, path);
    }

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
                "surface": { "tools": p.surface.tools(), "skills": p.surface.skills(),
                             "resources": p.surface.resources() },
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
    if !p.surface.resources().is_empty() {
        println!("  resources  {}", p.surface.resources().join(", "));
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
    let iss_checked = args.get("issuer-id").is_some();
    println!(
        "\n  checked: size, alg, signature, schema, typ, nbf/exp, aud{}, revocation",
        if iss_checked { ", iss" } else { "" }
    );
    println!(
        "  not checked here: {}peer identity, presented surface, zone policy, token binding",
        if iss_checked {
            ""
        } else {
            "iss (pass --issuer-id), "
        }
    );
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

/// What an operator supplied for a signing role, as `custody` wants it.
fn custody_request<'a>(args: &'a Args, role: custody::Role) -> custody::Request<'a> {
    let (pem_flag, signer_flag) = role.flags();
    custody::Request {
        pem_path: args.get(pem_flag.trim_start_matches('-')),
        signer_command: args.get(signer_flag.trim_start_matches('-')),
    }
}

/// Load a signing key for a role, with the custody posture applied.
///
/// Every signing site goes through here rather than through `load_issuer_key`, which is
/// what makes `--require-external-signing` mean what it says. It used to be checked in
/// exactly two places out of six.
fn custody_key(
    args: &Args,
    role: custody::Role,
    kid: &str,
    alg: Option<&str>,
) -> Result<IssuerKey> {
    let alg = match alg.unwrap_or("ES256") {
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "EdDSA" | "Ed25519" => Algorithm::EdDSA,
        other => {
            return Err(WcError::with_detail(
                Code::ALG_NOT_ASYMMETRIC,
                format!("{other:?} is not an accepted algorithm"),
            ))
        }
    };
    custody::resolve(
        role,
        custody_request(args, role),
        kid,
        alg,
        external_signing_required(args),
    )
}

/// The issuer signing key, from a PEM on disk or a key held elsewhere.
///
/// This used to be a second implementation of [`custody::resolve`] — same three refusals,
/// re-written — and the copy had drifted: it hard-coded `Algorithm::ES256` and never read
/// `--alg`. Everything downstream of it accepted three algorithms (`IssuerKeys` verifies
/// ES256, ES384 and Ed25519; `connect verify` takes `--alg`; the mediator's `--alg` selects
/// among all three), so an estate mandated onto P-384 — which is not unusual where the issuer
/// key sits in a bank's KMS — could verify contracts it had no way to mint. With `--signer`
/// the failure was at least loud, because a 96-byte signature fails the length check; with a
/// PEM it was `ec_pem` refusing a key that was perfectly good.
fn issuer_key(args: &Args) -> Result<IssuerKey> {
    let kid = require(args, "kid")?;
    custody_key(args, custody::Role::Issuer, kid, args.get("alg"))
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
    // The service's keys first, so an approver key that is one of them is refused before
    // anything signs (P0 #5d).
    let mut sep = service_key_separation(args)?;
    let signing = approver_signing_key(args, &approver, "approver-key", &mut sep)?;

    let second = match (
        args.get("second"),
        args.get("second-key").or_else(|| args.get("second-signer")),
    ) {
        (Some(id), Some(_)) => {
            let who = HumanRef::new(id)?;
            Some((
                approver_signing_key(args, &who, "second-key", &mut sep)?,
                who,
            ))
        }
        (None, None) => None,
        _ => {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "--second and --second-key (or --second-signer) must be given together",
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
    let mut sep = service_key_separation(args)?;
    let first_key = approver_signing_key(args, &first, "approver-key", &mut sep)?;
    let second = HumanRef::new(require(args, "second")?)?;
    let second_key = approver_signing_key(args, &second, "second-key", &mut sep)?;
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
            // Who signed, on the durable view an auditor reads — not only on the
            // transient `approve` output. Dual control's whole product is
            // attributability, and a two-controller contract printed identically to a
            // one-controller contract is that product missing from the place it is
            // looked for.
            if let Some(by) = &record.approval.by {
                println!("  approved   {by}");
            }
            if let Some(second) = &record.approval.second {
                println!("  second     {second}");
            }
            if let Some(ticket) = &record.approval.ticket {
                println!("  ticket     {ticket}");
            }
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
/// An approver's signing key, with the separation rule applied (P0 #5d).
///
/// `sep` carries what the service's own keys fingerprint to, so an approver key that is
/// the same material is refused here rather than producing a valid approval proof that
/// nobody can later distinguish from real dual control.
///
/// `which` is `approver-key` or `second-key`, so the two holders in dual control resolve
/// their own flags and can each be delegated independently — an approver's key belongs on
/// their own hardware token, which is the whole point of the role.
fn approver_signing_key(
    args: &Args,
    who: &HumanRef,
    which: &str,
    sep: &mut custody::Separation,
) -> Result<IssuerKey> {
    let request = custody::Request {
        pem_path: args.get(which),
        signer_command: args.get(match which {
            "second-key" => "second-signer",
            _ => "approver-signer",
        }),
    };
    sep.observe_request(custody::Role::Approver, who.as_str(), request)?;
    custody::resolve(
        custody::Role::Approver,
        request,
        who.as_str(),
        Algorithm::ES256,
        external_signing_required(args),
    )
}

/// The service's own signing keys, fingerprinted, so an approver key cannot be one.
///
/// Fingerprinting does not load or use the key, so this is safe to call on a command that
/// may not sign anything itself.
fn service_key_separation(args: &Args) -> Result<custody::Separation> {
    let mut sep = custody::Separation::new();
    for (role, label) in [
        (custody::Role::Issuer, "control-plane"),
        (custody::Role::Anchor, "evidence-anchor"),
    ] {
        sep.observe_request(role, label, custody_request(args, role))?;
    }
    Ok(sep)
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
    let store = open_store_or_stand_by(args)?;
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
  register server --endpoint URL --owner human:x --zone internal.y [--id ID]
                  [--surface FILE] [--tier N] [--service S]
                  [--data-classes a,b] [--jurisdictions SG,AU] [--enforce]
  register agent  --card FILE --owner human:x --zone internal.y [--id ID]

  --id matters more than it looks. Omit it and the id is derived (`urn:wc:...`),
  which no JWT-SVID can ever name — a SPIFFE `sub` must be a spiffe:// URI, so
  stage 1 can never pass and the party stays Unattested forever. Pass the
  workload's real SPIFFE id and stage 1 works.

  ATTESTATION (any subset; each stage stays skipped without its material)
    --svid FILE --trust-key KID=PEM[:ALG] --aud NAME [--leeway N]   stage 1
    ...or stage 1 WITHOUT SPIRE, for a Kubernetes projected service-account
    token, IRSA, Azure workload identity, a GCP service account or a Vault
    identity token — all JWTs with a published JWKS and a subject that is not
    a spiffe:// URI, which --svid cannot accept:
    --oidc-token FILE --oidc-issuer URL --oidc-label NAME
      [--oidc-subject-claim sub] --trust-key KID=PEM --aud NAME
      The entity id is DERIVED, not asserted:
          urn:wc:oidc:<label>:<subject>
      Register the party under exactly that. --oidc-label is your short name
      for the issuer and is folded in, because two clusters both mint
      `system:serviceaccount:default:default` and they are not one party. A
      label containing ':' is refused: it would make the derivation ambiguous.
      --oidc-issuer is required — without it any key in the trust set would
      authenticate a token from whichever issuer holds that key.
    --card-key KID=PEM[:ALG] [--require-card-signature]             stage 3
    --attest FILE --prov-key KID=PEM[:ALG] --builder ID             stage 4
      and one of --artifact-digest sha256:... | --bind-surface
    --screen-rules FILE --screen-mode observe|flag|enforce          stage 5

  REACHING `Attested` (what the mediator's check 9 demands in enforce mode)
    Stages 1, 3 and 4 must all pass. Stage 3 signs a *document*, and for an MCP
    server that document is its tool list, not an agent card: sign the --surface
    file and give it a `signatures` array of {{protected, signature}} over the
    wcs1-canonical document with `signatures` removed. Without this an MCP server
    stays Unattested, every mediated call fails WC-3109, and the estate looks
    broken rather than unconfigured.

    `register` names the stage that failed, in its own output — that is where to
    look. `connect show <id>` reports the resulting posture but NOT which leg is
    missing: the per-stage verdicts are computed at admission and not persisted
    on the entity, so after the fact only the outcome survives. Re-register with
    the material to see the reason.

    `scripts/attest-drill.sh` does all of this end to end and then runs a mediator
    in enforce mode, which is the only thing that proves the path works.

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
  unquarantine <id> --approver human:a --approver human:b [--why REASON]
                  lift a quarantine: posture returns to Unattested and lifecycle to
                  Pending, so full admission runs again. Contracts STAY revoked.
                  Dual-controlled — clearing containment is the more dangerous
                  direction, because it restores a party the estate decided to cut
  quarantine <id> --reason R [--approver human:a --approver human:b]
                  [--revocation-key PEM | --revocation-signer CMD] [--kid KID]
                  [--revocation-kid KID] [--break-glass-kid KID] [--break-glass]
                  [--mediators FILE] [--ack-deadline 60] [--push-token TOKEN]
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
  bundle export   --mediator ID (--signing-key PEM | --envelope-signer CMD) --kid KID
                  [--ttl 7d] [--out FILE]
  bundle verify   <bundle.wcb> --envelope-pub PEM --kid KID --mediator ID
                  --issuer-id URL [--issuer-pub PEM]
                  exit 4 if it does not verify. --issuer-id is required: a bundle
                  is a contract set that travelled as a file, so the plane it came
                  from is the one thing the courier envelope cannot vouch for

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
  backup    --out DIR [--anchor-pub PEM] [--json]
            a verified snapshot of this tenant's state and evidence. Refuses if
            the chain does not verify: a snapshot of a corrupt root looks like
            insurance and launders the corruption into every copy
  restore   --from DIR --into ROOT [--json]
            place a snapshot into an empty root. Verifies every digest before
            writing anything, refuses to merge into an occupied root, and holds
            the writer lock while it places
  retention [--contracts 7y] [--discovery 90d] [--json]
            the window of evidence this root holds
  retention --retire SEQ --anchor-pub PEM [--contracts 7y]
            retire sequences 1..SEQ out of the live chain. A row delete would break
            every row after it, so whole ranges move to retired/segment-*.jsonl and
            a verifiable tombstone takes their place — `audit verify` keeps passing
            and reports where the chain now starts. Four refusals: a chain that does
            not verify, a row still inside its retention window, a range no SIGNED
            checkpoint covers (without one, retiring and truncating are the same
            operation), and retiring the head. Nothing is deleted: ship the archive
            to WORM storage and remove it at your own hand
  export --format csv|json|dora|cps230|oscal|bom [--as-of TS]
         [--anchor-pub PEM] [--id ID for bom] [--out FILE]

POLICY
  policy lint    [--policy FILE] [--json]
  policy show    [--policy FILE] [--json]      resolved zone bars + standing caps
  policy dry-run [--policy FILE] [--json]      what a change does to live contracts

TOOLS
  offer publish --surface FILE --terms FILE [--kind mcp|a2a]
                --repo NAME --sha SHA [--version N]
                publish a provider's terms of availability, from the provider's
                own pipeline. The offer is the callee's half of a bilateral
                contract: it says which items may be contracted, by which
                consumers, for how long — and it is held until a consumer's need
                arrives, so neither party reviews the other's pull request.

                --repo and --sha are recorded, never parsed: Azure Repos is
                org/project/repo, GitLab nests arbitrarily and Bitbucket
                addresses by UUID. They make a contract auditable back to a
                reviewed commit.

                --version defaults to the held version plus one. An explicit
                version that is not higher than what is held is refused: the
                projection keeps the highest, so a stale republish would be
                silently ignored rather than applied.

  scm probe --shim COMMAND --label NAME --repo NAME --sha SHA
            [--expect-ref REF] [--expect-protected] [--expect-approver WHO]
            [--expect-file PATH] [--timeout N]
                exercise a source-host shim against a commit whose answer you
                already know, and print what it returned.

                Run this before trusting a shim with anything. The wrappers in
                scripts/scm/ are written from vendor API documentation and have
                NEVER been run against a real tenant — the same position that
                produced four wrong SPIRE commands in these docs. A shim nobody
                has probed is a shim nobody has run.

                It matters more here than for a signing helper. A signing shim
                cannot lie: cryptography catches it. An SCM shim's answer is just
                JSON, so one that simply reports a merge happened mints a contract
                on fabricated evidence and nothing downstream can tell. That is
                why a shim is a trusted component and why this command exists.

                The --expect flags turn a print into an assertion, and exit
                non-zero when the answer disagrees.

  need apply --manifest FILE --repo NAME --sha SHA --mediator ID
             --shim COMMAND [--shim-label NAME] [--git-ref REF]
             (--issuer-key PEM | --signer COMMAND) --kid KID [--out DIR]
                mint the contracts a consumer's manifest asks for, from the
                consumer's pipeline on merge.

                Both consents must already be evidenced. The provider's came from
                `offer publish --shim` and is recorded on the offer; the consumer's
                is verified here, from the merge that carried this manifest. An
                offer with no consent is refused: one side's word is not an
                agreement.

                Idempotent by construction. The artifact id is derived from the
                inputs, so re-running an unchanged build finds the contract already
                current and does nothing — no duplicate, and no request row.

                Policy still applies. This routes through the same evaluation
                `request` does, so an org policy that denies a zone pair denies it
                here too; the offer is the provider's ceiling, not a way past the
                estate's.

  need check --manifest FILE [--repo NAME --sha SHA]
                check a consumer's declared needs against the providers' offers.
                Run from the consumer's pipeline on merge: it fails the build when
                a manifest asks for something no provider has offered, which is
                the point at which that is cheap to fix.

                Reports what WOULD be contracted — the derived cid and jti, and
                the TTL after the offer's ceiling is applied. It does NOT mint.
                Minting needs a contract approval, and the only modes that exist
                are Human, StandingPolicy and BreakGlass; an approval evidenced by
                two reviewed merges is not expressible yet and belongs with the
                approval-authority work. The verb is `check` rather than `apply`
                for that reason — it does not apply anything.

  offer show <asset>
                the terms currently held for a provider, and where they came
                from.

  attest surface --surface FILE --card-key KID=PEM --out FILE
                sign a declared surface so it can be registered as an attested
                card, satisfying §8.7.1 stage 3.

                Why this exists: `Posture::Attested` needs identity, card AND
                provenance verified, and an unsigned surface reports
                card.verified = false. So a server registered from a plain
                surface.json is permanently Unattested, WC-3109 is
                ClosedUnlessObserve, and ENFORCE MODE REFUSES EVERY CALL. MCP
                has no convention for signing a tools/list result, so nothing
                produced the input the verifier wanted.

                The signature is appended, not replaced, so a provider's own
                signature survives a counter-signature. One trusted signature
                is the whole claim.

  attest verify <provenance.dsse.json> --prov-key KID=PEM
                (--artifact FILE | --artifact-digest sha256:...) --builder ID
                verify a DSSE / in-toto SLSA envelope on its own — offline, no
                Sigstore client, no network. Three bindings, ALL required: signed
                by a key you trust, the statement's subject digest equal to the
                artifact, and builder.id in your allowlist. A signature alone
                vouches for nothing in particular. Prefer --artifact: it computes
                the digest from the bytes, where a digest retyped from a release
                page is one the page's owner chose. Reports rekor inclusion as NOT
                checked, because it does not check it. exit 4 if unverified/unbound
  canon <surface.json> [--kind mcp|a2a] [--entity ID] [--document] [--json]
  screen <surface.json> [--kind mcp|a2a] [--mode observe|flag|enforce] [--tier N]
                        [--rules screen-rules.toml] [--acceptances FILE]
                        [--estate names.json] [--json]      exit 5 on block
  verify <contract.jws> (--issuer-pub PEM --kid KID | --jwks FILE) --mediator-id ID
                        [--issuer-id URL] [--alg ES256|ES384|EdDSA] [--now TS]
                        [--leeway N] [--json]
                        --jwks takes an issuer key set — what an OIDC issuer or a
                        SPIRE server publishes — instead of a converted PEM.
                        --issuer-id pins the control plane, as a mediator must; it
                        is optional here because this command also exists to inspect
                        an artifact somebody handed you. Omit it and the report says
                        iss was not checked rather than implying it was
  version

SERVE
  serve [--listen 127.0.0.1:8787] --issuer-key PEM --kid KID
        [--behind-tls-proxy [--trusted-proxy ADDR]...] | [--insecure-plaintext]
        [--tokens tokens.toml] [--approvers approvers.toml] [--jwks FILE]
        [--standby [--standby-timeout 3600]]

HIGH AVAILABILITY  (§8.5.2, docs/production-readiness.md P1 #10)
  The state log and the evidence chain are single-writer by construction: two
  writers would fork a hash chain. HA is therefore active/standby, with the
  writer lock as the election primitive — not two active replicas.

  --standby           wait for the active writer to release, then take over. No
                      listener is bound while waiting, so a load balancer sees
                      nothing rather than something answering \"not ready\" — the
                      same signal with no room for a health-check to be wrong
  --standby-timeout N give up after N seconds (default 3600) and exit non-zero.
                      A standby that started anyway would be a second writer,
                      which would look exactly like a successful failover

  The lock is released by a crash as well as a clean exit, because it belongs to
  the file descriptor and the kernel closes it. There is no lease to expire and
  no heartbeat to tune. What this does NOT give you is fencing against a
  partitioned active: flock is advisory and node-local, so a shared filesystem
  must guarantee single attachment (ReadWriteOnce, one EBS volume, one LUN) —
  that guarantee is what actually fences.

TRANSPORT  (serve speaks plain HTTP; TLS is terminated in front of it)
  A non-loopback listener refuses to start rather than accept bearer tokens in
  clear. That is the whole control: the deployment contract was documented and
  unenforced, so a pod bound to 0.0.0.0 shipped approval tokens in plaintext and
  nothing objected.

  --behind-tls-proxy    TLS is terminated in front. Every authenticated request
                        must then carry `x-forwarded-proto: https`, so a request
                        that reaches the port directly — bypassing the ingress —
                        is refused rather than trusted
  --trusted-proxy ADDR  believe that header only from this address or CIDR block
                        (10.0.1.5 or 10.0.1.0/24). Repeatable. Omitted means any
                        source, which is correct only if nothing else can reach
                        the port. A /0 is refused: it reads as a restriction and
                        matches everything, so omit the flag instead and let the
                        banner say so
  --proxy-secret-file F a secret the proxy sets in x-warden-proxy-secret and this
                        listener requires. Closes the address check's real limit:
                        a process SHARING a trusted address can forge the header,
                        and no CIDR fixes that because the forger shares the
                        address — which is the ordinary shape when the proxy is a
                        localhost sidecar. With a secret, forging costs the secret
                        instead of the position. From a file, not a flag value, so
                        it stays out of the process list; >= 32 chars, checked in
                        constant time, and narrowing only — the address check still
                        applies. `openssl rand -hex 32 > proxy.secret`
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
  --revocation-key PEM  the containment key, on this disk
  --revocation-signer   ...or delegated. Two revocation keys are supported and
                        wanted: --revocation-kid names the routine one (KMS), and
                        --break-glass-kid names the offline one (hardware token,
                        PIN split M-of-N) for when the KMS or this control plane
                        is unavailable. Signing with the break-glass kid needs
                        --break-glass and is recorded at Critical, because it is
                        expected approximately never
  --approver-signer CMD an approver's key, delegated. --second-signer for the
                        second holder. An approver key belongs on that person's
                        own token, and it may never be key material this service
                        holds — if the control plane can sign its own approvals,
                        dual control is theatre and the evidence chain cannot tell
                        the difference afterwards. Refused structurally, on key
                        material rather than on filenames
  --envelope-signer CMD the air-gapped bundle envelope, delegated

  --require-external-signing
                        refuse to start if any signing key would be read from this
                        disk (env WARDEN_CONNECT_REQUIRE_EXTERNAL_SIGNING). Covers
                        every role that signs — issuer, anchor, both revocation
                        keys, approvers and the bundle envelope. `connect bench` is
                        the one exemption and says so: it measures the cost of
                        signing and discards the signature. Every mint also records
                        which kid signed and where it lives, so a local signature
                        after the move is answerable from the evidence chain, not
                        only from configuration

GLOBAL
  --config FILE      flag defaults from a TOML file (default: {DEFAULT_CONFIG} if it
                     exists). Precedence is flag over file over env (§8.13); every
                     flag also reads WARDEN_CONNECT_<FLAG>, derived not hand-wired.
                     A key that maps to nothing is refused, not ignored — a config
                     file is reviewed by somebody who believes it took effect
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

    /// Every `connect …` line in every Markdown file names a real command with real flags.
    ///
    /// Standing up a SPIRE server turned up **four wrong commands in this repository's own
    /// documented procedure** — a `brew` formula that does not exist, two subcommands SPIRE
    /// does not have, and a `sed` that would have written an empty file. Every one had been
    /// written, reviewed and left alone, because a fenced block in a `.md` is not executable
    /// and therefore not checkable. `limitations.md` recorded the general form: *nothing
    /// checks the commands in these documents.*
    ///
    /// This checks ours. It lives here rather than in a script because `COMMANDS` and
    /// `accepted_flags` are in scope — a shell checker would need its own copy of both
    /// tables, and two copies of a table is how they drift.
    ///
    /// Synopsis notation (`[optional]`, `a|b`, `<placeholder>`) is stripped rather than
    /// skipped, so a usage line claiming `[--export FILE]` still has `--export` checked
    /// against the command it is claimed for.
    #[test]
    fn every_documented_command_exists_with_the_flags_it_claims() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut checked = 0usize;
        let mut problems: Vec<String> = Vec::new();

        for file in markdown_files(&root) {
            let text = match std::fs::read_to_string(&file) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let shown = file
                .strip_prefix(&root)
                .unwrap_or(&file)
                .display()
                .to_string();

            for line in shell_lines(&text) {
                let Some(rest) = strip_invocation(&line) else {
                    continue;
                };
                let cleaned = strip_synopsis(&rest);
                let tokens: Vec<&str> = cleaned.split_whitespace().collect();
                if tokens.is_empty() {
                    continue;
                }

                // Two-word commands first, or `audit verify` resolves to `audit`.
                let two = if tokens.len() >= 2 {
                    format!("{} {}", tokens[0], tokens[1])
                } else {
                    String::new()
                };
                let (command, flag_start) = if TWO_WORD.contains(&two.as_str()) {
                    (two, 2)
                } else {
                    (tokens[0].to_string(), 1)
                };

                if !COMMANDS.contains(&command.as_str()) {
                    problems.push(format!(
                        "{shown}: `connect {command}` is not a command\n      line: {line}"
                    ));
                    continue;
                }
                checked += 1;

                let accepted = accepted_flags(&command);
                for token in &tokens[flag_start.min(tokens.len())..] {
                    let Some(flag) = token.strip_prefix("--") else {
                        continue;
                    };
                    // `--flag=value` and a trailing comma from prose.
                    let flag = flag.split('=').next().unwrap_or(flag).trim_end_matches(',');
                    if flag.is_empty() {
                        continue;
                    }
                    if !accepted.contains(&flag) && !GLOBAL_FLAGS.contains(&flag) {
                        problems.push(format!(
                            "{shown}: `connect {command}` does not accept --{flag}\n      line: {line}"
                        ));
                    }
                }
            }
        }

        assert!(
            checked >= 40,
            "only {checked} documented commands were checked; the extractor has stopped \
             finding them, which would make this test pass by looking at nothing"
        );
        assert!(
            problems.is_empty(),
            "{} documented command(s) do not exist as written:\n  {}",
            problems.len(),
            problems.join("\n  ")
        );
    }

    /// Every `scripts/…` path named in the docs exists and is executable.
    #[test]
    fn every_documented_script_exists() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut checked = 0usize;
        let mut missing: Vec<String> = Vec::new();

        for file in markdown_files(&root) {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            let shown = file
                .strip_prefix(&root)
                .unwrap_or(&file)
                .display()
                .to_string();
            for line in shell_lines(&text) {
                for token in line.split_whitespace() {
                    let candidate = token
                        .trim_start_matches("./")
                        .trim_end_matches(&[',', '`'][..]);
                    if !candidate.starts_with("scripts/") {
                        continue;
                    }
                    if candidate.contains('*') || candidate.contains('<') {
                        continue;
                    }
                    checked += 1;
                    let path = root.join(candidate);
                    if !path.is_file() {
                        missing.push(format!("{shown}: {candidate} does not exist"));
                    }
                }
            }
        }
        assert!(checked >= 5, "only {checked} script references found");
        assert!(missing.is_empty(), "{}", missing.join("\n  "));
    }

    /// Every Markdown file in the repository, skipping build output and vendored trees.
    fn markdown_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if path.is_dir() {
                    // `explainer` holds film scripts, not procedures.
                    if matches!(
                        name.as_str(),
                        "target" | ".git" | "node_modules" | "explainer"
                    ) {
                        continue;
                    }
                    stack.push(path);
                } else if name.ends_with(".md") {
                    out.push(path);
                }
            }
        }
        out.sort();
        out
    }

    /// Lines inside fenced shell blocks, with `\`-continuations joined.
    fn shell_lines(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut in_block = false;
        let mut pending = String::new();
        for raw in text.lines() {
            let trimmed = raw.trim();
            if trimmed.starts_with("```") {
                // A fence closes any half-built continuation rather than letting it
                // swallow prose from beyond the block.
                if !pending.is_empty() {
                    out.push(std::mem::take(&mut pending));
                }
                in_block = matches!(
                    trimmed.trim_start_matches('`'),
                    "sh" | "bash" | "console" | "shell"
                );
                continue;
            }
            if !in_block {
                continue;
            }
            let line = trimmed.trim_start_matches("$ ").trim();
            if let Some(head) = line.strip_suffix('\\') {
                pending.push_str(head.trim_end());
                pending.push(' ');
                continue;
            }
            if pending.is_empty() {
                out.push(line.to_string());
            } else {
                pending.push_str(line);
                out.push(std::mem::take(&mut pending));
            }
        }
        if !pending.is_empty() {
            out.push(pending);
        }
        out
    }

    /// The part after `connect`, for a line that invokes it. `None` for anything else.
    fn strip_invocation(line: &str) -> Option<String> {
        let line = line.trim();
        for prefix in [
            "connect ",
            "./connect ",
            "./target/release/connect ",
            "./target/debug/connect ",
            "$CONNECT ",
            "\"$CONNECT\" ",
        ] {
            if let Some(rest) = line.strip_prefix(prefix) {
                // `connect-mediate` is a different binary with its own flags.
                if prefix == "connect " && line.starts_with("connect-mediate") {
                    return None;
                }
                return Some(rest.to_string());
            }
        }
        None
    }

    /// Remove synopsis notation so a usage line can still be checked for real flags.
    fn strip_synopsis(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut depth = 0usize;
        for ch in s.chars() {
            match ch {
                '<' => depth += 1,
                '>' if depth > 0 => depth -= 1,
                '[' | ']' | '|' | '`' => out.push(' '),
                // A comment ends the command.
                '#' => break,
                c if depth == 0 => out.push(c),
                _ => {}
            }
        }
        out
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
    fn every_config_mapping_points_at_a_flag_some_command_accepts() {
        // The mapping table promises `server.listen` fills `--listen`. If no command
        // accepted `--listen`, the key would parse, validate, pass the unknown-key check
        // and then be filtered out as not-for-this-command — silently, on every command.
        // That is the same failure the module exists to prevent, one level up.
        let mut all: Vec<&str> = GLOBAL_FLAGS.to_vec();
        for command in COMMANDS {
            all.extend_from_slice(accepted_flags(command));
        }
        for flag in config::mapped_flags() {
            assert!(
                all.contains(&flag),
                "connect.toml maps to --{flag}, which no command accepts"
            );
        }
    }

    #[test]
    fn the_config_file_is_read_and_a_flag_still_wins() {
        // End to end through `dispatch`'s own layering rather than through `config::apply`
        // alone, because the wiring is what was missing — the rule was never in doubt.
        let dir = std::env::temp_dir().join(format!("wc-cfg-{}", std::process::id()));
        // Clear first: `create_dir_all` on an EXISTING directory succeeds and leaves its
        // contents, and these paths repeat across runs because a pid gets reused and the
        // counter restarts at 0. `Drop` does not run when a test aborts or a run is killed,
        // so leftovers accumulate — 2,956 of them were sitting in /tmp when this was found.
        // A stale log underneath a durability test can fail it, and can also make it PASS
        // for the wrong reason, which is the worse half.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("connect.toml");
        std::fs::write(&path, "[server]\ntenant = \"from-file\"\n").unwrap();

        let loaded = config::Config::load(path.to_str().unwrap()).unwrap();
        let mut args = argv(&["entities"]);
        config::apply(&mut args, Some(&loaded), &["tenant"]);
        assert_eq!(
            tenant_id(&args).unwrap().as_str(),
            "from-file",
            "the file layer must reach the code that uses it, not just the parser"
        );

        let mut overridden = argv(&["entities", "--tenant", "from-flag"]);
        config::apply(&mut overridden, Some(&loaded), &["tenant"]);
        assert_eq!(tenant_id(&overridden).unwrap().as_str(), "from-flag");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_key_flag_has_a_delegated_partner_on_every_command_that_takes_it() {
        // The generalisation of the test above, and the one that would have caught
        // P0 #5c–5e. `--issuer-key` had `--signer` from the start; `--revocation-key`,
        // `--signing-key`, `--approver-key` and `--second-key` had nothing, so four of
        // the six signing operations could only ever use a key on local disk. Custody
        // that is reachable for one role and not the others is custody an estate cannot
        // actually adopt.
        let pairs = [
            ("issuer-key", "signer"),
            ("anchor-key", "anchor-signer"),
            ("revocation-key", "revocation-signer"),
            ("signing-key", "envelope-signer"),
            ("approver-key", "approver-signer"),
            ("second-key", "second-signer"),
        ];
        for command in COMMANDS {
            let flags = accepted_flags(command);
            for (pem, delegated) in pairs {
                // `bench` signs synthetically and is exempt by `Role::Benchmark`; it
                // takes `--signing-key` for a key it throws away.
                if *command == "bench" {
                    continue;
                }
                if flags.contains(&pem) {
                    assert!(
                        flags.contains(&delegated) || GLOBAL_FLAGS.contains(&delegated),
                        "`{command}` accepts --{pem} but not --{delegated}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_external_signing_posture_reaches_every_role_from_the_command_line() {
        // Asserted through the CLI's own resolution, not only through `custody::resolve`,
        // because the defect was never in the rule — it was that four call sites did not
        // ask. A regression here looks like somebody reaching for `load_issuer_key`.
        for (role, expect_flag) in [
            (custody::Role::RevokeOnline, "--revocation-signer"),
            (custody::Role::RevokeOffline, "--revocation-signer"),
            (custody::Role::Envelope, "--envelope-signer"),
            (custody::Role::Approver, "--approver-signer"),
        ] {
            let (pem_flag, _) = role.flags();
            let args = argv(&[
                "quarantine",
                pem_flag,
                &fixture_key(),
                "--require-external-signing",
            ]);
            let err = custody_key(&args, role, "k1", None).unwrap_err();
            assert_eq!(err.code(), Code::CONFIG_INVALID, "{role:?}");
            assert!(
                err.detail().contains(expect_flag),
                "{role:?}: {}",
                err.detail()
            );
        }
    }

    #[test]
    fn break_glass_selects_the_offline_key_and_refuses_to_be_reached_by_accident() {
        // Three behaviours the runbook depends on, and each was absent: nothing knew
        // which kid was break-glass, so nothing could switch to it deliberately, refuse
        // it casually, or record that it happened.
        let base = |extra: &[&str]| {
            let mut v = vec![
                "quarantine",
                "--revocation-key",
                "K",
                "--kid",
                "revoke-online",
            ];
            v.extend_from_slice(extra);
            argv(&v)
        };

        // 1 · `--break-glass` switches the signing kid, so the operator types one flag.
        let args = base(&["--break-glass", "--break-glass-kid", "revoke-offline"]);
        let declared = custody::RevocationCustody::new(
            args.get("revocation-kid"),
            args.get("break-glass-kid"),
        )
        .unwrap();
        assert_eq!(declared.offline_kid.as_deref(), Some("revoke-offline"));
        assert!(declared.is_break_glass("revoke-offline"));

        // 2 · naming the offline kid without consenting is refused — the habit case.
        let habit = base(&["--break-glass-kid", "revoke-online"]);
        let declared = custody::RevocationCustody::new(None, habit.get("break-glass-kid")).unwrap();
        let err = declared.authorise("revoke-online", false).unwrap_err();
        assert!(err.detail().contains("--break-glass"), "{}", err.detail());

        // 3 · `--break-glass` with nothing declared to switch to is refused rather than
        //     quietly signing with the routine key, which would be the worst outcome:
        //     an operator believing they used the offline path when they did not.
        let empty = base(&["--break-glass"]);
        let err = resolve_revocation_custody(&empty).unwrap_err();
        assert!(
            err.detail().contains("nothing to switch to"),
            "{}",
            err.detail()
        );
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
                trusted: vec!["10.0.0.1".parse().unwrap()],
                secret: None,
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
