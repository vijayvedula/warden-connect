//! Continuous assurance: re-attestation scheduling, drift classification,
//! posture scoring and blast radius (`docs/08-lld.md` §8.5.7, §8.7.5, §8.7.6,
//! §8.7.8).
//!
//! Admission decides whether a party may be trusted *once*. This module is the
//! answer to the harder question: what happens when that decision goes stale
//! without anybody touching it.
//!
//! Four pieces, in the order they matter:
//!
//! 1. **The schedule** — every active party is re-attested on its tier's
//!    interval, jittered so an estate admitted by one CI run does not re-attest
//!    in one second, and rate-limited per endpoint so assurance cannot become a
//!    denial-of-service against the tool server it is protecting.
//! 2. **Drift** (A5) — the newly fetched surface compared to the pin, classified
//!    against what is actually *contracted*. Per-item pins make this mostly
//!    structural, which is what keeps it quiet enough to leave switched on.
//! 3. **Posture** (A6) — a 0–100 score with a per-signal breakdown, because a
//!    score nobody can explain gets argued with rather than acted on.
//! 4. **Blast radius** (A8) — what stops if this party is cut.
//!
//! # Degradation is automatic; containment is authorised
//!
//! A low score never triggers quarantine. Auto-quarantine on a computed score
//! would hand anyone who can nudge the inputs — a burst of denied actions, a few
//! noisy benign drifts — an estate-wide denial-of-service primitive. So this
//! module can move a party to `Degraded`, which stops renewal and new contracts
//! while existing ones run to `exp`. Cutting is a human or signed-CAEP decision,
//! and lives elsewhere.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use wc_core::contract::ContractRecord;
use wc_core::error::{Code, Result, WcError};
use wc_core::model::{Entity, EntityId, Lifecycle, Pin, PinDiff, Posture, Tier};
use wc_core::util::sha256_bytes;

use crate::store::Projection;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Assurance-loop configuration (`[assurance]` in `connect.toml`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceCfg {
    /// Worker count for the caller's pool. Recorded here so a tick report can say
    /// what parallelism it assumed.
    #[serde(default = "default_workers")]
    pub workers: usize,
    /// Re-attestation interval override per tier, in seconds. Absent entries fall
    /// back to the tier's own interval.
    #[serde(default)]
    pub reattest_every: BTreeMap<u8, u32>,
    /// Jitter as a fraction of the interval, applied deterministically per entity.
    #[serde(default = "default_jitter")]
    pub jitter: f64,
    /// Maximum re-attestations started per endpoint per minute.
    #[serde(default = "default_per_endpoint_per_minute")]
    pub per_endpoint_per_minute: u32,
    /// Benign drifts within [`AssuranceCfg::benign_window`] that make a party
    /// "restless": the interval halves and the posture takes a penalty.
    #[serde(default = "default_benign_burst")]
    pub benign_burst: u32,
    /// Window for counting benign drifts, in seconds.
    #[serde(default = "default_benign_window")]
    pub benign_window: u32,
    /// How far ahead of expiry an owner is warned, in seconds, soonest last.
    #[serde(default = "default_expiry_warnings")]
    pub expiry_warnings: Vec<u32>,
    /// Score at or above which a party is [`Posture::Attested`].
    #[serde(default = "default_attested_at")]
    pub attested_at: u8,
}

fn default_workers() -> usize {
    8
}
fn default_jitter() -> f64 {
    0.10
}
fn default_per_endpoint_per_minute() -> u32 {
    4
}
fn default_benign_burst() -> u32 {
    3
}
fn default_benign_window() -> u32 {
    7 * 86_400
}
fn default_expiry_warnings() -> Vec<u32> {
    vec![30 * 86_400, 7 * 86_400, 86_400]
}
fn default_attested_at() -> u8 {
    85
}

impl Default for AssuranceCfg {
    fn default() -> Self {
        AssuranceCfg {
            workers: default_workers(),
            reattest_every: BTreeMap::new(),
            jitter: default_jitter(),
            per_endpoint_per_minute: default_per_endpoint_per_minute(),
            benign_burst: default_benign_burst(),
            benign_window: default_benign_window(),
            expiry_warnings: default_expiry_warnings(),
            attested_at: default_attested_at(),
        }
    }
}

impl AssuranceCfg {
    /// Validate. Called at load, because a configuration that quietly disables the
    /// loop is worse than one that refuses to parse.
    pub fn validate(&self) -> Result<()> {
        if self.workers == 0 {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "assurance.workers = 0 would stop every scheduled check",
            ));
        }
        if !(0.0..0.5).contains(&self.jitter) {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("assurance.jitter must be in 0.0..0.5, got {}", self.jitter),
            ));
        }
        if self.per_endpoint_per_minute == 0 {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "assurance.per_endpoint_per_minute = 0 would defer every re-attestation forever",
            ));
        }
        if self.attested_at == 0 {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "assurance.attested_at = 0 would make every party attested regardless of signals",
            ));
        }
        for (tier, secs) in &self.reattest_every {
            Tier::new(*tier)?;
            if *secs == 0 {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("assurance.reattest_every[{tier}] = 0"),
                ));
            }
        }
        Ok(())
    }

    /// The base interval for a tier, before jitter and before any restlessness
    /// penalty.
    #[must_use]
    pub fn base_interval(&self, tier: Tier) -> u32 {
        self.reattest_every
            .get(&tier.as_u8())
            .copied()
            .unwrap_or_else(|| tier.reattest_interval_secs())
    }

    /// The interval this party should actually be re-attested on.
    ///
    /// A party that keeps changing shape is a party to watch, even when each
    /// individual change is harmless — so repeated benign drift halves the
    /// interval.
    #[must_use]
    pub fn interval_for(&self, tier: Tier, benign_drifts_in_window: u32) -> u32 {
        let base = self.base_interval(tier);
        if benign_drifts_in_window > self.benign_burst {
            // Never below a minute, whatever the config says: a tight loop against
            // someone else's endpoint is the failure mode the rate limiter exists
            // to prevent, and halving should not be able to reach it.
            (base / 2).max(60)
        } else {
            base
        }
    }
}

/// Deterministic jitter in `-fraction..=+fraction` of `interval`, seeded from the
/// entity id.
///
/// Deterministic rather than random for two reasons: a restart must not reshuffle
/// the whole estate into one bucket again, and a test must be able to assert the
/// spread.
#[must_use]
pub fn jitter_offset(id: &EntityId, interval: u32, fraction: f64) -> i64 {
    if interval == 0 || fraction <= 0.0 {
        return 0;
    }
    let digest = sha256_bytes(id.as_str().as_bytes());
    // 16 bits is plenty of spread for a window that is at most 10% of an interval,
    // and keeps the arithmetic exact in i64.
    let raw = u32::from(digest[0]) << 8 | u32::from(digest[1]);
    let span = (f64::from(interval) * fraction).round() as i64;
    if span == 0 {
        return 0;
    }
    // Map 0..=65535 onto -span..=+span.
    let scaled = i64::from(raw) * (2 * span) / 65_535;
    scaled - span
}

// ---------------------------------------------------------------------------
// The schedule
// ---------------------------------------------------------------------------

/// What a scheduled task does.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    /// Re-fetch the declared surface and re-run the attestation stages.
    Reattest,
    /// Warn the owner that a contract expires in this many seconds.
    ExpiryWarn(u32),
    /// A credential or certificate is approaching expiry.
    CredExpiry,
    /// Recompute the posture score from current signals.
    PostureRescore,
    /// Refresh a federation trust chain.
    FederationRefresh,
}

impl TaskKind {
    /// Label for logs and reports.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskKind::Reattest => "reattest",
            TaskKind::ExpiryWarn(_) => "expiry-warn",
            TaskKind::CredExpiry => "cred-expiry",
            TaskKind::PostureRescore => "posture-rescore",
            TaskKind::FederationRefresh => "federation-refresh",
        }
    }
}

/// One scheduled unit of work.
///
/// Ordering is by `due_at` first, so a `BinaryHeap<Reverse<Task>>` is a due-time
/// queue. The remaining fields break ties deterministically — two tasks due in
/// the same second must come out in the same order on every run, or a tick report
/// is not reproducible.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Task {
    /// When this becomes due.
    pub due_at: u64,
    /// What to do.
    pub kind: TaskKind,
    /// Which party.
    pub target: EntityId,
    /// Endpoint to rate-limit against, where the task talks to one.
    pub endpoint: Option<String>,
}

/// Why a due task was not run in this tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deferral {
    /// The per-endpoint rate limit was already spent.
    EndpointRateLimited {
        /// The endpoint.
        endpoint: String,
        /// Tasks already started against it in this window.
        started: u32,
    },
    /// The tick's own budget was exhausted.
    TickBudget,
}

/// A due task that was not run, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferred {
    /// The task.
    pub task: Task,
    /// Why it was held back.
    pub reason: Deferral,
}

/// What one tick decided.
///
/// The deferred list is not an implementation detail. A scheduler that drops
/// rate-limited work and reports only what it ran looks healthy while an
/// endpoint's parties go unchecked indefinitely — so deferrals are returned,
/// re-queued, and countable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Tasks to execute now, in due order.
    pub due: Vec<Task>,
    /// Due tasks held back, with the reason. Still in the queue.
    pub deferred: Vec<Deferred>,
    /// Tasks still in the queue that are not yet due.
    pub pending: usize,
    /// Worker count assumed.
    pub workers: usize,
}

impl TickReport {
    /// Whether every due task was released.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.deferred.is_empty()
    }
}

/// The due-time queue and its rate limiter.
#[derive(Debug)]
pub struct Scheduler {
    cfg: AssuranceCfg,
    queue: BinaryHeap<Reverse<Task>>,
    /// endpoint → (window start, started in window)
    windows: HashMap<String, (u64, u32)>,
}

impl Scheduler {
    /// Build a scheduler. The configuration is validated here rather than trusted.
    pub fn new(cfg: AssuranceCfg) -> Result<Scheduler> {
        cfg.validate()?;
        Ok(Scheduler {
            cfg,
            queue: BinaryHeap::new(),
            windows: HashMap::new(),
        })
    }

    /// The configuration in force.
    #[must_use]
    pub fn cfg(&self) -> &AssuranceCfg {
        &self.cfg
    }

    /// How many tasks are queued.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether nothing is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Queue a task.
    pub fn push(&mut self, task: Task) {
        self.queue.push(Reverse(task));
    }

    /// Queue the next re-attestation for a party.
    pub fn schedule_reattest(&mut self, entity: &Entity, benign_drifts: u32, now: u64) {
        let interval = self.cfg.interval_for(entity.tier, benign_drifts);
        let offset = jitter_offset(&entity.id, interval, self.cfg.jitter);
        let base = entity.reattested_at.max(now);
        let due_at = base
            .saturating_add(u64::from(interval))
            .saturating_add_signed(offset);
        self.push(Task {
            due_at,
            kind: TaskKind::Reattest,
            target: entity.id.clone(),
            endpoint: entity.endpoint.clone(),
        });
    }

    /// Enqueue every active party that is overdue, plus its expiry warnings.
    ///
    /// Overdue parties are queued at `now` rather than at their computed next due
    /// time: something already late must not be pushed a further interval away.
    pub fn enqueue_due(&mut self, proj: &Projection, now: u64) -> usize {
        let mut queued = 0;
        for entity in proj.entities.values() {
            if entity.lifecycle != Lifecycle::Active {
                continue;
            }
            if entity.reattest_overdue(now) {
                self.push(Task {
                    due_at: now,
                    kind: TaskKind::Reattest,
                    target: entity.id.clone(),
                    endpoint: entity.endpoint.clone(),
                });
                queued += 1;
            }
        }
        queued
    }

    /// Pull the tasks that are due, honouring the per-endpoint rate limit.
    ///
    /// `budget` bounds how much work one tick releases. Deferred tasks are put
    /// back, so nothing is lost — and they are also reported, so a permanently
    /// throttled endpoint is visible rather than merely quiet.
    pub fn tick(&mut self, now: u64, budget: usize) -> TickReport {
        let mut report = TickReport {
            workers: self.cfg.workers,
            ..TickReport::default()
        };
        let mut held: Vec<Task> = Vec::new();

        while let Some(Reverse(task)) = self.queue.pop() {
            if task.due_at > now {
                // The heap is ordered by due time, so the first future task means
                // there are no more due ones.
                self.queue.push(Reverse(task));
                break;
            }
            if report.due.len() >= budget {
                report.deferred.push(Deferred {
                    task: task.clone(),
                    reason: Deferral::TickBudget,
                });
                held.push(task);
                continue;
            }
            match self.take_slot(task.endpoint.as_deref(), now) {
                Ok(()) => report.due.push(task),
                Err(started) => {
                    let endpoint = task.endpoint.clone().unwrap_or_default();
                    report.deferred.push(Deferred {
                        task: task.clone(),
                        reason: Deferral::EndpointRateLimited { endpoint, started },
                    });
                    held.push(task);
                }
            }
        }

        for task in held {
            self.queue.push(Reverse(task));
        }
        report.pending = self.queue.len() - report.deferred.len();
        report
    }

    /// Consume one rate-limit slot for an endpoint, or report how many are spent.
    fn take_slot(&mut self, endpoint: Option<&str>, now: u64) -> std::result::Result<(), u32> {
        let Some(endpoint) = endpoint else {
            // No endpoint means no third party to protect.
            return Ok(());
        };
        let window = now / 60;
        let entry = self.windows.entry(endpoint.to_string()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= self.cfg.per_endpoint_per_minute {
            return Err(entry.1);
        }
        entry.1 += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// A5 · drift classification
// ---------------------------------------------------------------------------

/// What is contracted on the surface being compared.
///
/// The distinction is load-bearing. "Nothing is contracted" and "we could not
/// resolve what is contracted" must not produce the same verdict, because the
/// first makes every change benign and the second makes every change unknown —
/// and an unknown change to a surface somebody may be depending on is material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Contracted {
    /// The contracted item set, resolved from live contracts.
    Known(BTreeSet<String>),
    /// The contract set could not be resolved. Fails closed.
    Unknown,
}

impl Contracted {
    /// Resolve from contract records.
    #[must_use]
    pub fn from_contracts(contracts: &[ContractRecord]) -> Contracted {
        Contracted::Known(
            contracts
                .iter()
                .flat_map(|c| c.surface.items())
                .collect::<BTreeSet<String>>(),
        )
    }

    fn contains(&self, item: &str) -> bool {
        match self {
            Contracted::Known(set) => set.contains(item),
            // Unknown: treat everything as possibly contracted.
            Contracted::Unknown => true,
        }
    }
}

/// Everything drift classification needs beyond the two pins.
#[derive(Debug, Clone)]
pub struct DriftInputs<'a> {
    /// The pin on record.
    pub old: &'a Pin,
    /// The surface as just fetched.
    pub new: &'a Pin,
    /// What is contracted on this party.
    pub contracted: &'a Contracted,
    /// Whether the endpoint or transport changed since the pin was taken.
    pub endpoint_changed: bool,
    /// Whether identity still verifies. `None` means the stage did not run.
    pub identity_ok: Option<bool>,
    /// Whether the card signature still verifies. `None` means not checked.
    pub card_ok: Option<bool>,
    /// Whether provenance still verifies. `None` means not checked.
    pub provenance_ok: Option<bool>,
    /// Whether re-screening the new or changed text produced a block-class
    /// finding.
    pub screening_blocked: bool,
}

/// How serious a drift is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftClass {
    /// The surface is byte-identical under `wcs1`.
    None,
    /// Something moved, but nothing anybody contracted for.
    Benign,
    /// A contracted tool vanished or changed, the endpoint moved, an attestation
    /// stopped verifying, or the new text screens as poisoned.
    Material,
}

impl DriftClass {
    /// Label for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DriftClass::None => "none",
            DriftClass::Benign => "benign",
            DriftClass::Material => "material",
        }
    }
}

/// The result of classifying a drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftVerdict {
    /// The classification.
    pub class: DriftClass,
    /// The structural difference.
    pub diff: PinDiff,
    /// Contracted items that disappeared.
    pub contracted_removed: Vec<String>,
    /// Contracted items whose canonical text moved.
    pub contracted_changed: Vec<String>,
    /// Every reason the verdict is what it is, in the order they were found.
    pub reasons: Vec<String>,
    /// Whether the new pin may be adopted automatically.
    pub auto_repin: bool,
}

impl DriftVerdict {
    /// Whether contracts pinned to the old manifest must be suspended.
    #[must_use]
    pub fn suspends(&self) -> bool {
        self.class == DriftClass::Material
    }
}

/// Classify a drift (A5).
#[must_use]
pub fn classify_drift(input: &DriftInputs<'_>) -> DriftVerdict {
    let diff = input.old.diff(input.new);
    let mut reasons: Vec<String> = Vec::new();

    let contracted_removed: Vec<String> = diff
        .removed
        .iter()
        .filter(|k| input.contracted.contains(k))
        .cloned()
        .collect();
    let contracted_changed: Vec<String> = diff
        .changed
        .iter()
        .filter(|k| input.contracted.contains(k))
        .cloned()
        .collect();

    if !contracted_removed.is_empty() {
        reasons.push(format!(
            "contracted item(s) removed: {}",
            contracted_removed.join(", ")
        ));
    }
    if !contracted_changed.is_empty() {
        reasons.push(format!(
            "contracted item(s) changed: {}",
            contracted_changed.join(", ")
        ));
    }
    if input.endpoint_changed {
        reasons.push("endpoint or transport changed".to_string());
    }
    if input.identity_ok == Some(false) {
        reasons.push("identity no longer verifies".to_string());
    }
    if input.card_ok == Some(false) {
        reasons.push("card signature no longer verifies".to_string());
    }
    if input.provenance_ok == Some(false) {
        reasons.push("provenance no longer verifies".to_string());
    }
    if input.screening_blocked {
        reasons.push("re-screening the new text produced a block-class finding".to_string());
    }
    if matches!(input.contracted, Contracted::Unknown) && !diff.is_empty() {
        reasons.push(
            "the contracted item set could not be resolved, so the change cannot be shown to be safe"
                .to_string(),
        );
    }

    let class = if !reasons.is_empty() {
        DriftClass::Material
    } else if diff.is_empty() && input.old.manifest == input.new.manifest {
        DriftClass::None
    } else if diff.is_empty() {
        // Same items, same per-item hashes, different manifest: the difference is
        // entirely in fields the manifest covers and the items do not — metadata,
        // or a canonicalisation algorithm upgrade. Safe to adopt.
        reasons.push("manifest-only difference; per-item pins unchanged".to_string());
        DriftClass::Benign
    } else {
        let mut what: Vec<String> = Vec::new();
        if !diff.added.is_empty() {
            what.push(format!("added {}", diff.added.join(", ")));
        }
        if !diff.removed.is_empty() {
            what.push(format!("removed {}", diff.removed.join(", ")));
        }
        if !diff.changed.is_empty() {
            what.push(format!("changed {}", diff.changed.join(", ")));
        }
        reasons.push(format!("uncontracted {}", what.join("; ")));
        DriftClass::Benign
    };

    DriftVerdict {
        class,
        diff,
        contracted_removed,
        contracted_changed,
        reasons,
        auto_repin: class != DriftClass::Material,
    }
}

/// Contracts that a material drift on this manifest must suspend.
///
/// One index lookup, not a scan — which is why `by_pin` exists.
#[must_use]
pub fn contracts_to_suspend(manifest: &str, proj: &Projection) -> Vec<wc_core::model::Cid> {
    let mut cids: Vec<wc_core::model::Cid> = proj
        .by_pin
        .get(manifest)
        .map(|set| set.iter().cloned().collect())
        .unwrap_or_default();
    cids.sort();
    cids
}

// ---------------------------------------------------------------------------
// A6 · posture score
// ---------------------------------------------------------------------------

/// The inputs to a posture score.
///
/// Every field is something the estate can observe. Nothing here is inferred from
/// another field, so a signal that is not being collected reads as absent rather
/// than as healthy — the `Option`s are the difference between "verified" and
/// "never checked".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signals {
    /// Identity verified at the last re-attestation. `None` means not checked.
    pub identity_ok: Option<bool>,
    /// Provenance verified at the last re-attestation. `None` means not checked.
    pub provenance_ok: Option<bool>,
    /// An unresolved material-drift finding is open.
    pub open_material_drift: bool,
    /// Benign drifts inside the configured window.
    pub benign_drifts_in_window: u32,
    /// How many whole re-attestation intervals overdue, 0 if current.
    pub intervals_overdue: u32,
    /// The owner no longer resolves in the IdP and has not been reassigned.
    pub owner_orphaned: bool,
    /// Seconds until a credential or certificate expires; negative if expired.
    pub credential_expires_in: Option<i64>,
    /// The party's denied-action rate, as a percentile 0..=100, fed back from
    /// Warden core.
    pub denied_action_percentile: Option<u8>,
    /// Open flag-class screening findings.
    pub open_screening_flags: u32,
}

/// One deduction, so the score can be explained rather than asserted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deduction {
    /// What was deducted.
    pub points: u8,
    /// Why.
    pub reason: String,
}

/// A posture score with its working shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureScore {
    /// 0..=100.
    pub score: u8,
    /// The resulting state.
    pub state: Posture,
    /// Every deduction applied.
    pub deductions: Vec<Deduction>,
    /// Whether identity or provenance is unverified, which forces `Unattested`
    /// regardless of score.
    pub unattested: bool,
}

impl PostureScore {
    /// A one-line explanation, for `connect posture` and for the approver.
    #[must_use]
    pub fn rationale(&self) -> String {
        if self.deductions.is_empty() {
            return format!("{} — no deductions", self.score);
        }
        format!(
            "{} — {}",
            self.score,
            self.deductions
                .iter()
                .map(|d| format!("-{} {}", d.points, d.reason))
                .collect::<Vec<_>>()
                .join("; ")
        )
    }
}

/// Compute a posture score (A6).
///
/// Note what this does **not** do: it never returns [`Posture::Quarantined`]
/// unless the party is already quarantined. Auto-quarantine on a computed score
/// would let anyone who can move the inputs cut the estate.
#[must_use]
pub fn score(entity: &Entity, signals: &Signals, cfg: &AssuranceCfg) -> PostureScore {
    let mut deductions: Vec<Deduction> = Vec::new();
    let mut deduct = |points: u8, reason: &str| {
        if points > 0 {
            deductions.push(Deduction {
                points,
                reason: reason.to_string(),
            });
        }
    };

    if signals.identity_ok != Some(true) {
        deduct(
            30,
            if signals.identity_ok.is_none() {
                "identity never verified"
            } else {
                "identity unverifiable at last re-attestation"
            },
        );
    }
    if signals.provenance_ok != Some(true) {
        deduct(
            25,
            if signals.provenance_ok.is_none() {
                "provenance never verified"
            } else {
                "provenance no longer verifies"
            },
        );
    }
    if signals.open_material_drift {
        deduct(20, "open material-drift finding");
    }
    if signals.benign_drifts_in_window > 0 {
        let raw = 8u32.saturating_mul(signals.benign_drifts_in_window);
        let capped = raw.min(24) as u8;
        deduct(
            capped,
            &format!(
                "{} benign drift(s) in the window",
                signals.benign_drifts_in_window
            ),
        );
        if signals.benign_drifts_in_window > cfg.benign_burst {
            deduct(10, "restless: benign drift burst exceeded");
        }
    }
    match signals.intervals_overdue {
        0 => {}
        1..=3 => deduct(15, "re-attestation overdue by more than one interval"),
        _ => deduct(30, "re-attestation overdue by more than three intervals"),
    }
    if signals.owner_orphaned {
        deduct(20, "owner orphaned");
    }
    if let Some(secs) = signals.credential_expires_in {
        if secs <= 0 {
            deduct(25, "credential expired");
        } else if secs <= 7 * 86_400 {
            deduct(10, "credential expires within 7 days");
        }
    }
    if let Some(p) = signals.denied_action_percentile {
        let points = (2 * u32::from(p) / 10).min(20) as u8;
        deduct(points, &format!("denied-action rate at p{p}"));
    }
    if signals.open_screening_flags > 0 {
        let capped = (5u32.saturating_mul(signals.open_screening_flags)).min(15) as u8;
        deduct(
            capped,
            &format!("{} open screening flag(s)", signals.open_screening_flags),
        );
    }

    let total: u32 = deductions.iter().map(|d| u32::from(d.points)).sum();
    let score = 100u32.saturating_sub(total).min(100) as u8;

    let unattested = signals.identity_ok != Some(true) || signals.provenance_ok != Some(true);
    let state = if entity.posture == Posture::Quarantined {
        // Terminal until a full re-admission. No score reopens it.
        Posture::Quarantined
    } else if unattested {
        Posture::Unattested
    } else if score >= cfg.attested_at {
        Posture::Attested
    } else {
        Posture::Degraded
    };

    PostureScore {
        score,
        state,
        deductions,
        unattested,
    }
}

// ---------------------------------------------------------------------------
// A8 · blast radius
// ---------------------------------------------------------------------------

/// One party reachable from the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlastNode {
    /// The party.
    pub id: EntityId,
    /// Hops from the subject.
    pub depth: u8,
    /// Risk tier.
    pub tier: u8,
    /// Trust zone.
    pub zone: String,
    /// Accountable human.
    pub owner: String,
    /// Business service, where declared.
    pub service: Option<String>,
    /// Data classes it touches.
    pub data_classes: Vec<String>,
}

/// What stops if a party is cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlastReport {
    /// The subject.
    pub subject: EntityId,
    /// Depth limit applied.
    pub max_depth: u8,
    /// Parties reachable by following contracts outward from the subject.
    pub forward: Vec<BlastNode>,
    /// Parties that reach the subject.
    pub reverse: Vec<BlastNode>,
    /// Contracts that would be revoked, sorted.
    pub cut_set: Vec<String>,
    /// Business services with a party in the radius, sorted. This is what a change
    /// manager asks for; the entity list is what an engineer asks for.
    pub impacted_services: Vec<String>,
    /// Whether the traversal hit the depth limit and stopped early.
    pub truncated: bool,
    /// Parties named by a contract but absent from the registry.
    ///
    /// Reported rather than skipped: a dangling reference means the radius is
    /// wider than it looks, and silently omitting it understates the impact of a
    /// cut.
    pub dangling: Vec<String>,
}

impl BlastReport {
    /// Every distinct party in the radius, excluding the subject.
    #[must_use]
    pub fn nodes(&self) -> Vec<&BlastNode> {
        let mut seen: HashSet<&EntityId> = HashSet::new();
        self.forward
            .iter()
            .chain(self.reverse.iter())
            .filter(|n| seen.insert(&n.id))
            .collect()
    }

    /// A one-line summary for an operator about to act.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} contract(s) cut · {} part{} reached · {} service(s) impacted{}",
            self.cut_set.len(),
            self.nodes().len(),
            if self.nodes().len() == 1 { "y" } else { "ies" },
            self.impacted_services.len(),
            if self.truncated {
                " · TRUNCATED at the depth limit"
            } else {
                ""
            }
        )
    }
}

/// Default traversal depth.
pub const DEFAULT_BLAST_DEPTH: u8 = 3;

/// Compute a blast radius (A8).
///
/// Returns the report even when truncated, with `truncated: true` — and the
/// caller is expected to surface [`Code::BLAST_DEPTH_TRUNCATED`]. A truncated
/// radius presented as complete is how an operator concludes a cut is safe when
/// it is not.
#[must_use]
pub fn blast_radius(subject: &EntityId, max_depth: u8, proj: &Projection) -> BlastReport {
    // A depth of 0 explores nothing and would report an empty radius for a party
    // with fifty contracts. One hop is the floor.
    let max_depth = max_depth.max(1);
    let mut forward = Vec::new();
    let mut reverse = Vec::new();
    let mut cut: BTreeSet<String> = BTreeSet::new();
    let mut services: BTreeSet<String> = BTreeSet::new();
    let mut dangling: BTreeSet<String> = BTreeSet::new();
    let mut truncated = false;

    // Forward: who this party can reach.
    traverse(
        subject,
        max_depth,
        proj,
        true,
        &mut forward,
        &mut cut,
        &mut services,
        &mut dangling,
        &mut truncated,
    );
    // Reverse: who reaches this party.
    traverse(
        subject,
        max_depth,
        proj,
        false,
        &mut reverse,
        &mut cut,
        &mut services,
        &mut dangling,
        &mut truncated,
    );

    // The subject's own service is impacted by definition.
    if let Some(e) = proj.entities.get(subject) {
        if let Some(s) = &e.service {
            services.insert(s.clone());
        }
    }

    BlastReport {
        subject: subject.clone(),
        max_depth,
        forward,
        reverse,
        cut_set: cut.into_iter().collect(),
        impacted_services: services.into_iter().collect(),
        truncated,
        dangling: dangling.into_iter().collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn traverse(
    subject: &EntityId,
    max_depth: u8,
    proj: &Projection,
    outward: bool,
    out: &mut Vec<BlastNode>,
    cut: &mut BTreeSet<String>,
    services: &mut BTreeSet<String>,
    dangling: &mut BTreeSet<String>,
    truncated: &mut bool,
) {
    let mut seen: HashSet<EntityId> = HashSet::new();
    seen.insert(subject.clone());
    let mut queue: VecDeque<(EntityId, u8)> = VecDeque::new();
    queue.push_back((subject.clone(), 0));

    while let Some((current, depth)) = queue.pop_front() {
        let index = if outward {
            proj.by_caller.get(&current)
        } else {
            proj.by_callee.get(&current)
        };
        let Some(cids) = index else { continue };

        for cid in cids {
            let Some(record) = proj.contracts.get(cid) else {
                dangling.insert(cid.to_string());
                continue;
            };
            cut.insert(record.cid.to_string());
            let next = if outward {
                &record.callee
            } else {
                &record.caller
            };
            let next_depth = depth + 1;
            if next_depth > max_depth {
                // Beyond the limit: do not emit it, and say the radius is wider
                // than what follows. Emitting a node past the bound would make a
                // depth-limited report look like it explored one hop further than
                // it did.
                *truncated = true;
                continue;
            }
            if !seen.insert(next.clone()) {
                continue;
            }
            match proj.entities.get(next) {
                Some(entity) => {
                    if let Some(s) = &entity.service {
                        services.insert(s.clone());
                    }
                    out.push(BlastNode {
                        id: next.clone(),
                        depth: next_depth,
                        tier: entity.tier.as_u8(),
                        zone: entity.zone.as_str().to_string(),
                        owner: entity.owner.as_str().to_string(),
                        service: entity.service.clone(),
                        data_classes: entity.data_classes.clone(),
                    });
                }
                // A contract names a party the registry does not hold. The edge is
                // real, so the radius is real; say so.
                None => {
                    dangling.insert(next.to_string());
                }
            }
            if next_depth < max_depth {
                queue.push_back((next.clone(), next_depth));
            } else if has_further_edges(next, proj, outward) {
                *truncated = true;
            }
        }
    }

    out.sort_by(|a, b| (a.depth, a.id.as_str()).cmp(&(b.depth, b.id.as_str())));
}

fn has_further_edges(id: &EntityId, proj: &Projection, outward: bool) -> bool {
    let index = if outward {
        proj.by_caller.get(id)
    } else {
        proj.by_callee.get(id)
    };
    index.is_some_and(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use wc_core::contract::{Surface, Terms};
    use wc_core::model::{Cid, HumanRef, Jti, Kind, ZoneId};

    // --- fixtures ----------------------------------------------------------

    fn id(name: &str) -> EntityId {
        EntityId::new(format!("spiffe://org/ns/x/sa/{name}")).unwrap()
    }

    fn entity(name: &str, tier: u8) -> Entity {
        let mut e = Entity::pending(
            id(name),
            Kind::McpServer,
            HumanRef::new("human:priya@org").unwrap(),
            ZoneId::new("internal.apac-ops").unwrap(),
            Tier::new(tier).unwrap(),
            1_000,
        );
        e.lifecycle = Lifecycle::Active;
        e.service = Some(format!("svc-{name}"));
        e
    }

    fn pin(items: &[(&str, &str)], manifest: &str) -> Pin {
        Pin {
            alg: "wcs1".to_string(),
            manifest: manifest.to_string(),
            items: items
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            pinned_at: 1_000,
        }
    }

    /// A `cid` of the shape the type actually accepts: at least 8 hex digits.
    fn cid(n: u32) -> String {
        format!("conn_{n:08x}")
    }

    fn contract(n: u32, caller: &str, callee: &str, tools: &[&str], manifest: &str) -> ContractRecord {
        ContractRecord {
            cid: Cid::new(cid(n)).unwrap(),
            jti: Jti::new("jti_0123456789abcdef").unwrap(),
            caller: id(caller),
            callee: id(callee),
            caller_zone: ZoneId::new("internal.apac-ops").unwrap(),
            callee_zone: ZoneId::new("internal.apac-ops").unwrap(),
            callee_tier: Tier::THREE,
            callee_manifest: manifest.to_string(),
            surface_digest: "sha256:deadbeef".to_string(),
            surface: Surface {
                tools: tools.iter().map(|t| (*t).to_string()).collect(),
                ..Surface::default()
            },
            terms: Terms::default(),
            aud: vec!["warden:mediator:1".to_string()],
            jws_sha256: "sha256:aa".to_string(),
            status: wc_core::contract::ContractStatus::Active,
            approval: wc_core::contract::ApprovalRef::standing(),
            policy_version: "connect-policy@v1".to_string(),
            iat: 1_000,
            exp: 1_000_000,
            schema: wc_core::contract::CONTRACT_SCHEMA,
        }
    }

    fn projection(entities: Vec<Entity>, contracts: Vec<ContractRecord>) -> Projection {
        let mut p = Projection::default();
        for e in entities {
            p.entities.insert(e.id.clone(), e);
        }
        for c in contracts {
            p.by_caller
                .entry(c.caller.clone())
                .or_default()
                .insert(c.cid.clone());
            p.by_callee
                .entry(c.callee.clone())
                .or_default()
                .insert(c.cid.clone());
            p.by_pin
                .entry(c.callee_manifest.clone())
                .or_default()
                .insert(c.cid.clone());
            p.contracts.insert(c.cid.clone(), c);
        }
        p
    }

    // --- config ------------------------------------------------------------

    #[test]
    fn a_config_that_would_disable_the_loop_is_rejected() {
        // Each of these parses fine and silently stops the thing from working,
        // which is the bug class this crate keeps producing.
        for (bad, what) in [
            (
                AssuranceCfg {
                    workers: 0,
                    ..Default::default()
                },
                "zero workers",
            ),
            (
                AssuranceCfg {
                    per_endpoint_per_minute: 0,
                    ..Default::default()
                },
                "zero rate limit defers forever",
            ),
            (
                AssuranceCfg {
                    attested_at: 0,
                    ..Default::default()
                },
                "everything attested",
            ),
            (
                AssuranceCfg {
                    jitter: 0.9,
                    ..Default::default()
                },
                "jitter wider than the interval",
            ),
        ] {
            assert_eq!(
                bad.validate().unwrap_err().code(),
                Code::CONFIG_INVALID,
                "should reject: {what}"
            );
        }
        assert!(AssuranceCfg::default().validate().is_ok());
    }

    #[test]
    fn intervals_come_from_the_tier_unless_overridden() {
        let mut cfg = AssuranceCfg::default();
        assert_eq!(cfg.base_interval(Tier::ONE), 3_600);
        assert_eq!(cfg.base_interval(Tier::FOUR), 604_800);
        cfg.reattest_every.insert(1, 900);
        assert_eq!(cfg.base_interval(Tier::ONE), 900);
    }

    #[test]
    fn repeated_benign_drift_halves_the_interval_but_never_below_a_minute() {
        let cfg = AssuranceCfg::default();
        assert_eq!(cfg.interval_for(Tier::ONE, 0), 3_600);
        assert_eq!(cfg.interval_for(Tier::ONE, 3), 3_600, "at the burst, not over");
        assert_eq!(cfg.interval_for(Tier::ONE, 4), 1_800);

        let tight = AssuranceCfg {
            reattest_every: [(1u8, 90u32)].into_iter().collect(),
            ..Default::default()
        };
        assert_eq!(tight.interval_for(Tier::ONE, 9), 60, "floored, not 45");
    }

    // --- jitter ------------------------------------------------------------

    #[test]
    fn jitter_is_deterministic_bounded_and_spread() {
        let interval = 3_600;
        let span = 360; // 10%
        let mut offsets = Vec::new();
        for i in 0..200 {
            let e = id(&format!("agent-{i}"));
            let o = jitter_offset(&e, interval, 0.10);
            assert!((-span..=span).contains(&o), "out of range: {o}");
            assert_eq!(o, jitter_offset(&e, interval, 0.10), "must be stable");
            offsets.push(o);
        }
        // The point of the jitter: an estate admitted together must not land in one
        // second. Assert real spread rather than merely "it varies".
        let distinct: BTreeSet<i64> = offsets.iter().copied().collect();
        assert!(distinct.len() > 150, "only {} distinct offsets", distinct.len());
        let negatives = offsets.iter().filter(|o| **o < 0).count();
        assert!((60..140).contains(&negatives), "lopsided: {negatives}/200 negative");
    }

    #[test]
    fn jitter_is_zero_when_disabled() {
        assert_eq!(jitter_offset(&id("a"), 3_600, 0.0), 0);
        assert_eq!(jitter_offset(&id("a"), 0, 0.10), 0);
    }

    // --- scheduler ---------------------------------------------------------

    fn task(due: u64, name: &str, endpoint: Option<&str>) -> Task {
        Task {
            due_at: due,
            kind: TaskKind::Reattest,
            target: id(name),
            endpoint: endpoint.map(str::to_string),
        }
    }

    #[test]
    fn a_tick_releases_due_tasks_in_due_order_and_leaves_the_rest() {
        let mut s = Scheduler::new(AssuranceCfg::default()).unwrap();
        s.push(task(300, "c", None));
        s.push(task(100, "a", None));
        s.push(task(200, "b", None));

        let r = s.tick(250, 100);
        assert_eq!(
            r.due.iter().map(|t| t.due_at).collect::<Vec<_>>(),
            vec![100, 200]
        );
        assert_eq!(r.pending, 1);
        assert!(r.is_clean());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn the_rate_limit_defers_rather_than_drops() {
        // A scheduler that silently discards throttled work looks healthy while an
        // endpoint's parties go unchecked indefinitely.
        let cfg = AssuranceCfg {
            per_endpoint_per_minute: 2,
            ..Default::default()
        };
        let mut s = Scheduler::new(cfg).unwrap();
        for i in 0..5 {
            s.push(task(100, &format!("a{i}"), Some("https://payments.internal")));
        }

        let r = s.tick(100, 100);
        assert_eq!(r.due.len(), 2, "the limit is honoured");
        assert_eq!(r.deferred.len(), 3, "and the rest are reported");
        assert!(!r.is_clean());
        assert!(matches!(
            r.deferred[0].reason,
            Deferral::EndpointRateLimited { .. }
        ));
        assert_eq!(s.len(), 3, "still queued, not lost");

        // A minute later the window resets.
        let r2 = s.tick(160, 100);
        assert_eq!(r2.due.len(), 2);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn separate_endpoints_do_not_share_a_rate_limit() {
        let cfg = AssuranceCfg {
            per_endpoint_per_minute: 1,
            ..Default::default()
        };
        let mut s = Scheduler::new(cfg).unwrap();
        s.push(task(100, "a", Some("https://one.internal")));
        s.push(task(100, "b", Some("https://two.internal")));
        let r = s.tick(100, 100);
        assert_eq!(r.due.len(), 2);
        assert!(r.is_clean());
    }

    #[test]
    fn tasks_without_an_endpoint_are_not_rate_limited() {
        // There is no third party to protect from a posture rescore.
        let cfg = AssuranceCfg {
            per_endpoint_per_minute: 1,
            ..Default::default()
        };
        let mut s = Scheduler::new(cfg).unwrap();
        for i in 0..5 {
            s.push(Task {
                due_at: 100,
                kind: TaskKind::PostureRescore,
                target: id(&format!("a{i}")),
                endpoint: None,
            });
        }
        assert_eq!(s.tick(100, 100).due.len(), 5);
    }

    #[test]
    fn a_tick_budget_defers_the_overflow() {
        let mut s = Scheduler::new(AssuranceCfg::default()).unwrap();
        for i in 0..10 {
            s.push(task(100, &format!("a{i}"), None));
        }
        let r = s.tick(100, 4);
        assert_eq!(r.due.len(), 4);
        assert_eq!(r.deferred.len(), 6);
        assert!(r.deferred.iter().all(|d| d.reason == Deferral::TickBudget));
        assert_eq!(s.len(), 6);
    }

    #[test]
    fn overdue_parties_are_queued_at_now_not_an_interval_later() {
        // Something already late must not be pushed further away.
        let mut e = entity("payments", 3);
        e.reattested_at = 1_000;
        e.reattest_every = 3_600;
        e.endpoint = Some("https://payments.internal/mcp".to_string());
        let proj = projection(vec![e], vec![]);

        let mut s = Scheduler::new(AssuranceCfg::default()).unwrap();
        let now = 100_000;
        assert_eq!(s.enqueue_due(&proj, now), 1);
        let r = s.tick(now, 100);
        assert_eq!(r.due.len(), 1);
        assert_eq!(r.due[0].due_at, now);
    }

    #[test]
    fn inactive_parties_are_not_scheduled() {
        let mut e = entity("payments", 3);
        e.lifecycle = Lifecycle::Pending;
        e.reattested_at = 0;
        let proj = projection(vec![e], vec![]);
        let mut s = Scheduler::new(AssuranceCfg::default()).unwrap();
        assert_eq!(s.enqueue_due(&proj, 100_000), 0);
    }

    #[test]
    fn scheduling_the_next_reattest_lands_inside_the_jitter_window() {
        let mut e = entity("payments", 1);
        e.reattested_at = 10_000;
        let cfg = AssuranceCfg::default();
        let mut s = Scheduler::new(cfg.clone()).unwrap();
        s.schedule_reattest(&e, 0, 10_000);
        let r = s.tick(10_000 + 3_600 + 400, 10);
        assert_eq!(r.due.len(), 1);
        let due = r.due[0].due_at;
        assert!(
            (10_000 + 3_600 - 360..=10_000 + 3_600 + 360).contains(&due),
            "due_at {due} outside the window"
        );
    }

    // --- A5 drift ----------------------------------------------------------

    fn inputs<'a>(old: &'a Pin, new: &'a Pin, contracted: &'a Contracted) -> DriftInputs<'a> {
        DriftInputs {
            old,
            new,
            contracted,
            endpoint_changed: false,
            identity_ok: Some(true),
            card_ok: Some(true),
            provenance_ok: Some(true),
            screening_blocked: false,
        }
    }

    #[test]
    fn an_identical_surface_is_no_drift() {
        let p = pin(&[("get_balance", "sha256:a")], "sha256:m1");
        let c = Contracted::Known(["get_balance".to_string()].into_iter().collect());
        let v = classify_drift(&inputs(&p, &p, &c));
        assert_eq!(v.class, DriftClass::None);
        assert!(v.reasons.is_empty());
        assert!(!v.suspends());
    }

    #[test]
    fn a_contracted_tool_vanishing_is_material() {
        let old = pin(
            &[("get_balance", "sha256:a"), ("list_txn", "sha256:b")],
            "sha256:m1",
        );
        let new = pin(&[("list_txn", "sha256:b")], "sha256:m2");
        let c = Contracted::Known(["get_balance".to_string()].into_iter().collect());
        let v = classify_drift(&inputs(&old, &new, &c));
        assert_eq!(v.class, DriftClass::Material);
        assert_eq!(v.contracted_removed, vec!["get_balance"]);
        assert!(v.suspends());
        assert!(!v.auto_repin);
    }

    #[test]
    fn a_contracted_tools_description_moving_is_material() {
        // The rug-pull. Same name, same schema, different text — and the text is
        // what the model reads as instruction.
        let old = pin(&[("get_balance", "sha256:a")], "sha256:m1");
        let new = pin(&[("get_balance", "sha256:CHANGED")], "sha256:m2");
        let c = Contracted::Known(["get_balance".to_string()].into_iter().collect());
        let v = classify_drift(&inputs(&old, &new, &c));
        assert_eq!(v.class, DriftClass::Material);
        assert_eq!(v.contracted_changed, vec!["get_balance"]);
    }

    #[test]
    fn an_uncontracted_tool_appearing_is_benign() {
        let old = pin(&[("get_balance", "sha256:a")], "sha256:m1");
        let new = pin(
            &[("get_balance", "sha256:a"), ("new_tool", "sha256:z")],
            "sha256:m2",
        );
        let c = Contracted::Known(["get_balance".to_string()].into_iter().collect());
        let v = classify_drift(&inputs(&old, &new, &c));
        assert_eq!(v.class, DriftClass::Benign);
        assert!(v.auto_repin);
        assert!(!v.suspends());
        assert!(v.reasons[0].contains("added new_tool"), "{:?}", v.reasons);
    }

    #[test]
    fn an_uncontracted_tool_changing_or_vanishing_is_benign() {
        let old = pin(
            &[("get_balance", "sha256:a"), ("debug_dump", "sha256:b")],
            "sha256:m1",
        );
        let new = pin(&[("get_balance", "sha256:a")], "sha256:m2");
        let c = Contracted::Known(["get_balance".to_string()].into_iter().collect());
        let v = classify_drift(&inputs(&old, &new, &c));
        assert_eq!(v.class, DriftClass::Benign);
        assert!(v.contracted_removed.is_empty());
    }

    #[test]
    fn an_unresolvable_contract_set_makes_any_change_material() {
        // "Nothing is contracted" and "we do not know what is contracted" must not
        // produce the same verdict. The second one fails closed.
        let old = pin(&[("get_balance", "sha256:a")], "sha256:m1");
        let new = pin(
            &[("get_balance", "sha256:a"), ("new_tool", "sha256:z")],
            "sha256:m2",
        );

        let known_empty = Contracted::Known(BTreeSet::new());
        assert_eq!(
            classify_drift(&inputs(&old, &new, &known_empty)).class,
            DriftClass::Benign
        );

        let unknown = Contracted::Unknown;
        let v = classify_drift(&inputs(&old, &new, &unknown));
        assert_eq!(v.class, DriftClass::Material);
        assert!(v.reasons.iter().any(|r| r.contains("could not be resolved")));
    }

    #[test]
    fn an_unresolvable_contract_set_with_no_change_is_still_no_drift() {
        // Failing closed must not mean crying wolf on a surface that did not move.
        let p = pin(&[("get_balance", "sha256:a")], "sha256:m1");
        let v = classify_drift(&inputs(&p, &p, &Contracted::Unknown));
        assert_eq!(v.class, DriftClass::None);
    }

    #[test]
    fn a_manifest_only_difference_auto_repins() {
        // Same items, same per-item hashes, different manifest: metadata or a
        // canonicalisation upgrade. Safe to adopt without suspending anything.
        let old = pin(&[("get_balance", "sha256:a")], "sha256:m1");
        let new = pin(&[("get_balance", "sha256:a")], "sha256:m2");
        let c = Contracted::Known(["get_balance".to_string()].into_iter().collect());
        let v = classify_drift(&inputs(&old, &new, &c));
        assert_eq!(v.class, DriftClass::Benign);
        assert!(v.auto_repin);
        assert!(v.reasons[0].contains("manifest-only"));
    }

    #[test]
    fn each_non_surface_signal_is_independently_material() {
        let p = pin(&[("get_balance", "sha256:a")], "sha256:m1");
        let c = Contracted::Known(["get_balance".to_string()].into_iter().collect());

        type Mutate = Box<dyn Fn(&mut DriftInputs<'_>)>;
        let cases: Vec<(&str, Mutate)> = vec![
            ("endpoint", Box::new(|i: &mut DriftInputs<'_>| i.endpoint_changed = true)),
            ("identity", Box::new(|i: &mut DriftInputs<'_>| i.identity_ok = Some(false))),
            ("card", Box::new(|i: &mut DriftInputs<'_>| i.card_ok = Some(false))),
            ("provenance", Box::new(|i: &mut DriftInputs<'_>| i.provenance_ok = Some(false))),
            ("screening", Box::new(|i: &mut DriftInputs<'_>| i.screening_blocked = true)),
        ];
        for (what, apply) in cases {
            let mut i = inputs(&p, &p, &c);
            apply(&mut i);
            let v = classify_drift(&i);
            assert_eq!(v.class, DriftClass::Material, "{what} must be material");
            assert!(v.suspends());
        }
    }

    #[test]
    fn a_stage_that_did_not_run_is_not_a_failure() {
        // `None` means not checked. Treating it as a failure would make every
        // observe-mode estate look like it was under attack.
        let p = pin(&[("get_balance", "sha256:a")], "sha256:m1");
        let c = Contracted::Known(["get_balance".to_string()].into_iter().collect());
        let mut i = inputs(&p, &p, &c);
        i.identity_ok = None;
        i.card_ok = None;
        i.provenance_ok = None;
        assert_eq!(classify_drift(&i).class, DriftClass::None);
    }

    #[test]
    fn material_drift_finds_its_contracts_by_pin_lookup() {
        let manifest = "sha256:m1";
        let proj = projection(
            vec![entity("recon", 3), entity("payments", 2)],
            vec![
                contract(1, "recon", "payments", &["get_balance"], manifest),
                contract(2, "recon", "payments", &["list_txn"], manifest),
                contract(3, "recon", "payments", &["other"], "sha256:other"),
            ],
        );
        let cids = contracts_to_suspend(manifest, &proj);
        assert_eq!(
            cids.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
            vec![cid(1), cid(2)]
        );
        assert!(contracts_to_suspend("sha256:absent", &proj).is_empty());
    }

    #[test]
    fn contracted_is_the_union_across_contracts() {
        let c = Contracted::from_contracts(&[
            contract(1, "recon", "payments", &["get_balance"], "m"),
            contract(2, "audit", "payments", &["list_txn"], "m"),
        ]);
        let Contracted::Known(set) = &c else {
            panic!("expected Known")
        };
        assert_eq!(set.len(), 2);
        assert!(set.contains("get_balance") && set.contains("list_txn"));
    }

    // --- A6 posture --------------------------------------------------------

    fn healthy() -> Signals {
        Signals {
            identity_ok: Some(true),
            provenance_ok: Some(true),
            ..Signals::default()
        }
    }

    #[test]
    fn a_fully_verified_party_scores_100_and_is_attested() {
        let e = entity("payments", 3);
        let s = score(&e, &healthy(), &AssuranceCfg::default());
        assert_eq!(s.score, 100);
        assert_eq!(s.state, Posture::Attested);
        assert!(s.deductions.is_empty());
        assert_eq!(s.rationale(), "100 — no deductions");
    }

    #[test]
    fn unverified_identity_or_provenance_forces_unattested_whatever_the_score() {
        let e = entity("payments", 3);
        let cfg = AssuranceCfg::default();

        let mut sig = healthy();
        sig.identity_ok = None;
        let s = score(&e, &sig, &cfg);
        assert_eq!(s.state, Posture::Unattested);
        assert!(s.unattested);
        assert!(s.deductions.iter().any(|d| d.reason.contains("never verified")));

        let mut sig = healthy();
        sig.provenance_ok = Some(false);
        assert_eq!(score(&e, &sig, &cfg).state, Posture::Unattested);
    }

    #[test]
    fn a_verified_party_with_enough_penalties_degrades() {
        let e = entity("payments", 3);
        let cfg = AssuranceCfg::default();
        let sig = Signals {
            open_material_drift: true,
            ..healthy()
        };
        let s = score(&e, &sig, &cfg);
        assert_eq!(s.score, 80);
        assert_eq!(s.state, Posture::Degraded, "80 is below the 85 bar");
        assert!(s.rationale().contains("-20 open material-drift finding"));
    }

    #[test]
    fn benign_drift_deductions_are_capped() {
        let e = entity("payments", 3);
        let cfg = AssuranceCfg::default();
        let with = |n| {
            score(
                &e,
                &Signals {
                    benign_drifts_in_window: n,
                    ..healthy()
                },
                &cfg,
            )
        };
        assert_eq!(with(1).score, 92);
        assert_eq!(with(3).score, 76);
        // 4 drifts: capped at 24, plus the 10-point restlessness penalty.
        assert_eq!(with(4).score, 100 - 24 - 10);
        assert_eq!(with(50).score, 100 - 24 - 10, "the cap holds");
    }

    #[test]
    fn overdue_reattestation_escalates_in_two_steps() {
        let e = entity("payments", 3);
        let cfg = AssuranceCfg::default();
        let with = |n| {
            score(
                &e,
                &Signals {
                    intervals_overdue: n,
                    ..healthy()
                },
                &cfg,
            )
            .score
        };
        assert_eq!(with(0), 100);
        assert_eq!(with(1), 85);
        assert_eq!(with(3), 85);
        assert_eq!(with(4), 70);
    }

    #[test]
    fn credential_expiry_distinguishes_soon_from_expired() {
        let e = entity("payments", 3);
        let cfg = AssuranceCfg::default();
        let with = |secs| {
            score(
                &e,
                &Signals {
                    credential_expires_in: Some(secs),
                    ..healthy()
                },
                &cfg,
            )
            .score
        };
        assert_eq!(with(30 * 86_400), 100);
        assert_eq!(with(6 * 86_400), 90);
        assert_eq!(with(0), 75);
        assert_eq!(with(-1), 75);
    }

    #[test]
    fn screening_flags_and_denied_actions_are_capped() {
        let e = entity("payments", 3);
        let cfg = AssuranceCfg::default();
        let s = score(
            &e,
            &Signals {
                open_screening_flags: 9,
                denied_action_percentile: Some(100),
                ..healthy()
            },
            &cfg,
        );
        // 15 (flag cap) + 20 (denied cap).
        assert_eq!(s.score, 65);
    }

    #[test]
    fn the_score_floors_at_zero_rather_than_wrapping() {
        let e = entity("payments", 3);
        let sig = Signals {
            identity_ok: Some(false),
            provenance_ok: Some(false),
            open_material_drift: true,
            benign_drifts_in_window: 20,
            intervals_overdue: 10,
            owner_orphaned: true,
            credential_expires_in: Some(-1),
            denied_action_percentile: Some(100),
            open_screening_flags: 10,
        };
        let s = score(&e, &sig, &AssuranceCfg::default());
        assert_eq!(s.score, 0);
        assert_eq!(s.state, Posture::Unattested);
    }

    #[test]
    fn a_low_score_never_quarantines() {
        // Auto-quarantine on a computed score would hand anyone who can nudge the
        // inputs an estate-wide denial-of-service primitive.
        let e = entity("payments", 3);
        let sig = Signals {
            identity_ok: Some(false),
            open_material_drift: true,
            intervals_overdue: 99,
            ..Signals::default()
        };
        let s = score(&e, &sig, &AssuranceCfg::default());
        assert_eq!(s.score, 0);
        assert_ne!(s.state, Posture::Quarantined);
    }

    #[test]
    fn quarantine_is_terminal_and_no_score_reopens_it() {
        let mut e = entity("payments", 3);
        e.posture = Posture::Quarantined;
        let s = score(&e, &healthy(), &AssuranceCfg::default());
        assert_eq!(s.score, 100);
        assert_eq!(s.state, Posture::Quarantined);
    }

    #[test]
    fn the_score_is_monotonic_in_every_signal() {
        // Adding a bad signal must never improve the score. Asserted because the
        // caps make it easy to write an accidental non-monotonicity.
        let e = entity("payments", 3);
        let cfg = AssuranceCfg::default();
        let base = score(&e, &healthy(), &cfg).score;

        let worse: Vec<(&str, Signals)> = vec![
            ("material drift", Signals { open_material_drift: true, ..healthy() }),
            ("benign drift", Signals { benign_drifts_in_window: 1, ..healthy() }),
            ("overdue", Signals { intervals_overdue: 1, ..healthy() }),
            ("orphaned", Signals { owner_orphaned: true, ..healthy() }),
            ("cred expiring", Signals { credential_expires_in: Some(1), ..healthy() }),
            ("denials", Signals { denied_action_percentile: Some(50), ..healthy() }),
            ("screening flag", Signals { open_screening_flags: 1, ..healthy() }),
        ];
        for (what, sig) in worse {
            assert!(
                score(&e, &sig, &cfg).score < base,
                "{what} did not lower the score"
            );
        }

        // And monotonic within a signal, including across the cap boundary.
        let mut last = 101;
        for n in 0..8 {
            let s = score(
                &e,
                &Signals {
                    benign_drifts_in_window: n,
                    ..healthy()
                },
                &cfg,
            )
            .score;
            assert!(s <= last, "n={n} raised the score");
            last = s;
        }
    }

    #[test]
    fn the_attested_bar_is_configurable_and_respected() {
        let e = entity("payments", 3);
        let sig = Signals {
            open_material_drift: true,
            ..healthy()
        };
        let strict = AssuranceCfg {
            attested_at: 95,
            ..Default::default()
        };
        let lax = AssuranceCfg {
            attested_at: 70,
            ..Default::default()
        };
        assert_eq!(score(&e, &sig, &strict).state, Posture::Degraded);
        assert_eq!(score(&e, &sig, &lax).state, Posture::Attested);
    }

    // --- A8 blast radius ---------------------------------------------------

    #[test]
    fn a_blast_radius_walks_forward_and_reverse() {
        // orchestrator -> recon -> payments, and audit -> recon.
        let proj = projection(
            vec![
                entity("orchestrator", 3),
                entity("recon", 3),
                entity("payments", 2),
                entity("audit", 4),
            ],
            vec![
                contract(1, "orchestrator", "recon", &["run"], "m1"),
                contract(2, "recon", "payments", &["get_balance"], "m2"),
                contract(3, "audit", "recon", &["read"], "m3"),
            ],
        );
        let r = blast_radius(&id("recon"), DEFAULT_BLAST_DEPTH, &proj);

        assert_eq!(
            r.forward.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(),
            vec!["spiffe://org/ns/x/sa/payments"]
        );
        let mut rev: Vec<&str> = r.reverse.iter().map(|n| n.id.as_str()).collect();
        rev.sort_unstable();
        assert_eq!(
            rev,
            vec!["spiffe://org/ns/x/sa/audit", "spiffe://org/ns/x/sa/orchestrator"]
        );
        assert_eq!(r.cut_set, vec![cid(1), cid(2), cid(3)]);
        assert!(!r.truncated);
        assert!(r.dangling.is_empty());
    }

    #[test]
    fn the_service_summary_is_what_a_change_manager_reads() {
        let proj = projection(
            vec![entity("recon", 3), entity("payments", 2)],
            vec![contract(1, "recon", "payments", &["get_balance"], "m1")],
        );
        let r = blast_radius(&id("recon"), 3, &proj);
        assert_eq!(r.impacted_services, vec!["svc-payments", "svc-recon"]);
        assert_eq!(
            r.summary(),
            "1 contract(s) cut · 1 party reached · 2 service(s) impacted"
        );
    }

    #[test]
    fn depth_truncation_is_reported_not_hidden() {
        // A truncated radius presented as complete is how an operator concludes a
        // cut is safe when it is not.
        let entities: Vec<Entity> = (0..6).map(|i| entity(&format!("n{i}"), 3)).collect();
        let contracts: Vec<ContractRecord> = (0..5)
            .map(|i| {
                contract(
                    i,
                    &format!("n{i}"),
                    &format!("n{}", i + 1),
                    &["x"],
                    &format!("m{i}"),
                )
            })
            .collect();
        let proj = projection(entities, contracts);

        let deep = blast_radius(&id("n0"), 5, &proj);
        assert_eq!(deep.forward.len(), 5);
        assert!(!deep.truncated);

        let shallow = blast_radius(&id("n0"), 2, &proj);
        assert_eq!(shallow.forward.len(), 2);
        assert!(shallow.truncated, "must say it stopped early");
        assert!(shallow.summary().contains("TRUNCATED"));
    }

    #[test]
    fn the_depth_bound_limits_which_nodes_are_emitted() {
        // Found by running `blast-radius --depth 0`: nodes one hop out were still
        // emitted, so a depth-limited report looked like it had explored further
        // than it had.
        let entities: Vec<Entity> = (0..4).map(|i| entity(&format!("n{i}"), 3)).collect();
        let contracts: Vec<ContractRecord> = (0..3)
            .map(|i| {
                contract(
                    i,
                    &format!("n{i}"),
                    &format!("n{}", i + 1),
                    &["x"],
                    &format!("m{i}"),
                )
            })
            .collect();
        let proj = projection(entities, contracts);

        for depth in 1..=3u8 {
            let r = blast_radius(&id("n0"), depth, &proj);
            assert!(
                r.forward.iter().all(|n| n.depth <= depth),
                "depth {depth} emitted a node beyond the bound: {:?}",
                r.forward.iter().map(|n| n.depth).collect::<Vec<_>>()
            );
            assert_eq!(r.forward.len(), usize::from(depth));
            assert_eq!(r.truncated, depth < 3, "depth {depth}");
        }

        // Zero is floored to one rather than reporting an empty radius for a party
        // that has contracts.
        let zero = blast_radius(&id("n0"), 0, &proj);
        assert_eq!(zero.max_depth, 1);
        assert_eq!(zero.forward.len(), 1);
        assert!(zero.truncated);
    }

    #[test]
    fn a_cycle_terminates() {
        let proj = projection(
            vec![entity("a", 3), entity("b", 3)],
            vec![
                contract(1, "a", "b", &["x"], "m1"),
                contract(2, "b", "a", &["y"], "m2"),
            ],
        );
        let r = blast_radius(&id("a"), 10, &proj);
        assert_eq!(r.forward.len(), 1);
        assert_eq!(r.reverse.len(), 1);
        assert_eq!(r.cut_set, vec![cid(1), cid(2)]);
    }

    #[test]
    fn a_party_with_no_contracts_has_an_empty_radius() {
        let proj = projection(vec![entity("lonely", 3)], vec![]);
        let r = blast_radius(&id("lonely"), 3, &proj);
        assert!(r.forward.is_empty() && r.reverse.is_empty());
        assert!(r.cut_set.is_empty());
        assert_eq!(r.impacted_services, vec!["svc-lonely"]);
        assert_eq!(
            r.summary(),
            "0 contract(s) cut · 0 parties reached · 1 service(s) impacted"
        );
    }

    #[test]
    fn a_contract_naming_an_unregistered_party_is_reported_as_dangling() {
        // The edge is real, so the radius is real. Silently dropping it understates
        // the impact of a cut.
        let mut proj = projection(
            vec![entity("recon", 3)],
            vec![contract(1, "recon", "ghost", &["x"], "m1")],
        );
        proj.entities.remove(&id("ghost"));
        let r = blast_radius(&id("recon"), 3, &proj);
        assert!(r.forward.is_empty(), "no node for an absent entity");
        assert_eq!(r.dangling, vec!["spiffe://org/ns/x/sa/ghost"]);
        assert_eq!(r.cut_set, vec![cid(1)], "the contract is still cut");
    }

    #[test]
    fn node_annotations_carry_what_an_operator_needs() {
        let mut payments = entity("payments", 1);
        payments.data_classes = vec!["pii".to_string(), "financial".to_string()];
        let proj = projection(
            vec![entity("recon", 3), payments],
            vec![contract(1, "recon", "payments", &["get_balance"], "m1")],
        );
        let r = blast_radius(&id("recon"), 3, &proj);
        let n = &r.forward[0];
        assert_eq!(n.tier, 1);
        assert_eq!(n.depth, 1);
        assert_eq!(n.zone, "internal.apac-ops");
        assert_eq!(n.owner, "human:priya@org");
        assert_eq!(n.service.as_deref(), Some("svc-payments"));
        assert_eq!(n.data_classes, vec!["pii", "financial"]);
    }
}
