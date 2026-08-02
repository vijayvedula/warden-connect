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

use wc_control::admission::{
    self, AdmissionRequest, Declared, InlineSurface, McpHttpSurface, SurfaceSource,
};
use wc_control::chain::ANCHOR_FILE;
use wc_control::cpolicy::{ConnectPolicy, StandingState};
use wc_control::evidence::{EventKind, Evidence, LifecycleEvent};
use wc_control::store::{Actor, Store};
use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::contract::{self, Algorithm, ApprovalMode, IssuerKeys, VerifyOpts};
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
];

/// Every dispatchable command.
const COMMANDS: &[&str] = &[
    "register server",
    "register agent",
    "activate",
    "entities",
    "show",
    "posture",
    "quarantine",
    "audit verify",
    "canon",
    "export",
    "verify",
    "policy lint",
    "policy dry-run",
    "policy show",
    "version",
];

/// Flags accepted by every command.
const GLOBAL_FLAGS: &[&str] = &[
    "root",
    "tenant",
    "by",
    "json",
    "anchor-key",
    "anchor-interval",
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
        ],
        "activate" => &["id", "why"],
        "quarantine" => &["id", "reason", "approver"],
        "show" => &["id"],
        "entities" => &[],
        "posture" => &["unattested", "expiring", "drift"],
        "audit verify" => &["anchor-pub"],
        "export" => &["format", "as-of"],
        "canon" => &["file", "kind", "entity", "document"],
        "verify" => &[
            "file",
            "issuer-pub",
            "kid",
            "alg",
            "mediator-id",
            "now",
            "leeway",
        ],
        "policy lint" | "policy show" => &["policy"],
        "policy dry-run" => &["policy", "now"],
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
            other => format!("unknown command {other:?}"),
        }));
    }
    check_flags(command, args)?;

    match command {
        "register server" => register_server(args)?,
        "register agent" => register_agent(args)?,
        "activate" => activate(args)?,
        "entities" => entities(args)?,
        "show" => show(args)?,
        "posture" => posture(args)?,
        "quarantine" => quarantine(args)?,
        "audit verify" => audit_verify(args)?,
        "canon" => canon_cmd(args)?,
        "verify" => verify_cmd(args)?,
        "policy lint" => policy_lint(args)?,
        "policy dry-run" => policy_dry_run(args)?,
        "policy show" => policy_show(args)?,
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
}

fn paths(args: &Args) -> Paths {
    let root = args
        .get("root")
        .map(PathBuf::from)
        .or_else(|| std::env::var("WARDEN_CONNECT_ROOT").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT));
    let tenant = args.get("tenant").map(str::to_string).unwrap_or_else(|| {
        std::env::var("WARDEN_CONNECT_TENANT").unwrap_or_else(|_| "default".to_string())
    });
    let base = root.join("tenants").join(tenant);
    Paths {
        state: base.join("state"),
        evidence: base.join("evidence"),
    }
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

/// The evidence chain, with an anchor key when one is configured.
fn open_evidence(args: &Args) -> Result<Evidence> {
    let p = paths(args);
    let evidence = Evidence::open(&p.evidence)?;
    match args.get("anchor-key") {
        Some(key_path) => {
            let key = std::fs::read(key_path).map_err(|e| {
                WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("cannot read anchor key {key_path}"),
                )
                .with_source(e)
            })?;
            let interval = args.number("anchor-interval").unwrap_or(100);
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

/// Run admission, write the entity, and record what happened — including every
/// stage that was skipped.
fn admit_and_record(
    args: &Args,
    request: &AdmissionRequest,
    source: &dyn SurfaceSource,
) -> Result<()> {
    let ts = now();
    let ctx = admission::observe_ctx(source, ts);
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
    let mut store = open_store(args)?;
    let reg = store.registry(actor(args)?, now());
    let all = reg.enumerate_for_operator();

    // An export references the chain head, so it is verifiable rather than merely
    // asserted (§8.5.9).
    let head = Evidence::verify(&p.evidence, None)?;

    match format {
        "csv" => {
            println!(
                "id,kind,owner,service,tier,zone,trust_level,posture,lifecycle,data_classes,jurisdictions,pin"
            );
            for e in &all {
                println!(
                    "{},{:?},{},{},{},{},{:?},{:?},{:?},{},{},{}",
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
                );
            }
            eprintln!(
                "# as_of chain head seq {} hash {}",
                head.head_seq, head.head_hash
            );
        }
        "json" => {
            // Gaps are declared, never silently omitted (UC-10 A1).
            let exceptions: Vec<Value> = all
                .iter()
                .filter(|e| e.posture != Posture::Attested)
                .map(|e| {
                    json!({"id": e.id.as_str(), "posture": format!("{:?}", e.posture),
                           "why": "not fully attested; see registration stages"})
                })
                .collect();
            println!(
                "{}",
                pretty(&json!({
                    "as_of": now(),
                    "chain_head_seq": head.head_seq,
                    "chain_head_hash": head.head_hash,
                    "entities": all.iter().map(|e| entity_json(e)).collect::<Vec<_>>(),
                    "exceptions": exceptions,
                }))?
            );
        }
        other => {
            return Err(WcError::with_detail(
                Code::EXPORT_FAILED,
                format!("unknown export format {other:?}; try csv or json"),
            ))
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// canon
// ---------------------------------------------------------------------------

fn canon_cmd(args: &Args) -> Result<()> {
    let path = positional_or_flag(args, "file")?;
    let raw = read_json(path)?;
    let kind = match args.get("kind").unwrap_or("mcp") {
        "mcp" | "mcp_tools" => SurfaceKind::McpTools,
        "a2a" | "a2a_card" => SurfaceKind::A2aCard,
        other => {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("unknown surface kind {other:?}; try mcp or a2a"),
            ))
        }
    };
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

    let key_path = require(args, "issuer-pub")?;
    let pem = std::fs::read(key_path).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {key_path}")).with_source(e)
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
        if !report.errors.is_empty() || !report.warnings.is_empty() {
            println!();
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
                .map_or("-".to_string(), |s| format!("{}d", s / 86_400)),
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
fn positional_or_flag<'a>(args: &'a Args, flag: &str) -> Result<&'a str> {
    if let Some(v) = args.positional.first() {
        return Ok(v);
    }
    if let Some(v) = args.verbs.get(1) {
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

ESTATE
  activate <id> [--why REASON]
  entities [--json]
  show <id> [--json]
  posture [--unattested] [--expiring] [--json]
  quarantine <id> --reason R [--approver human:a --approver human:b]

EVIDENCE
  audit verify [--anchor-pub PEM] [--json]
  export --format csv|json

POLICY
  policy lint    [--policy FILE] [--json]
  policy show    [--policy FILE] [--json]      resolved zone bars + standing caps
  policy dry-run [--policy FILE] [--json]      what a change does to live contracts

TOOLS
  canon <surface.json> [--kind mcp|a2a] [--entity ID] [--document] [--json]
  verify <contract.jws> --issuer-pub PEM --kid KID --mediator-id ID
                        [--alg ES256|ES384|EdDSA] [--now TS] [--leeway N] [--json]
  version

GLOBAL
  --root PATH        state and evidence root (env WARDEN_CONNECT_ROOT, default {DEFAULT_ROOT})
  --tenant NAME      tenant (default: default)
  --by human:x       the accountable operator (env WARDEN_CONNECT_ACTOR)
  --anchor-key PEM   sign evidence checkpoints as they are written
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
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::path::Path;

    #[test]
    fn exit_codes_separate_the_cases() {
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
