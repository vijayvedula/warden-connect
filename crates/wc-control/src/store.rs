//! Append-only event log with an in-memory projection (`docs/08-lld.md` §8.5.2,
//! §8.8).
//!
//! The registry's current state is a **projection of an event log**, not a
//! mutable table. That buys three things the LLD depends on: point-in-time
//! `as_of` exports (UC-10), a state store that can be rebuilt from scratch, and
//! an append-only write path with the same file discipline Warden core's audit
//! chain already uses.
//!
//! # What is durable versus what is rebuildable
//!
//! This log is **state**: it can be compacted, snapshotted and rebuilt. The
//! evidence chain (`warden::audit`) is **evidence**: it is never compacted and
//! never rewritten. Keeping them separate is what lets state be pragmatic while
//! evidence stays absolute.
//!
//! # Single writer
//!
//! One process holds an exclusive `flock` on `<dir>/<name>.lock` for as long as
//! its [`Log`] is alive. A second writer fails immediately with
//! [`Code::STORE_LOCKED`] rather than interleaving records. High availability is
//! active/standby with that lock as the election primitive.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use wc_core::contract::{ContractRecord, ContractStatus};
use wc_core::error::{Code, Result, WcError};
use wc_core::model::{Cid, Entity, EntityId, HumanRef, Lifecycle, Pin, PinDiff, Posture};

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// A log record: the caller's payload plus the sequence and timestamp the log
/// assigns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Framed<T> {
    /// Monotonic sequence number, unique across all segments.
    pub seq: u64,
    /// Append time, unix seconds.
    pub ts: u64,
    /// The payload.
    pub rec: T,
}

/// How hard to push a record before returning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// `fsync` before returning. For issuance, revocation and quarantine —
    /// anything where losing the record would mean authority exists with no
    /// durable trace of its creation.
    Durable,
    /// Batched: synced every [`SYNC_EVERY`] records or on [`Log::sync`]. For
    /// posture and discovery records, where losing the tail of a crash is
    /// acceptable.
    Batched,
}

/// Records between automatic syncs in [`Durability::Batched`].
pub const SYNC_EVERY: u32 = 64;

/// Default segment size before rotation.
pub const DEFAULT_SEGMENT_BYTES: u64 = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Log
// ---------------------------------------------------------------------------

/// A segmented, append-only JSONL log with a single writer.
#[derive(Debug)]
pub struct Log<T> {
    dir: PathBuf,
    name: String,
    segment: u32,
    file: File,
    last_seq: u64,
    since_sync: u32,
    segment_bytes: u64,
    /// The writer lock, held for the life of the log. `None` means this log was opened for
    /// reading and **appending is refused** — see [`Log::append`]. Optional rather than a
    /// separate read-only type because the read path is identical and a second type would be a
    /// second place for the append guard to be forgotten.
    _lock: Option<crate::lock::LockGuard>,
    // `fn() -> T` rather than `T` so the log stays `Send`/`Sync` whatever `T` is.
    marker: PhantomData<fn() -> T>,
}

impl<T> Log<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Open (or create) the log in `dir`, taking the writer lock.
    ///
    /// Fails with [`Code::STORE_LOCKED`] if another process already holds it.
    pub fn open(dir: impl AsRef<Path>, name: &str) -> Result<Self> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(|e| {
            WcError::with_detail(
                Code::STORE_LOCKED,
                format!("cannot create {}", dir.display()),
            )
            .with_source(e)
        })?;
        let lock = crate::lock::acquire(dir, name)?;
        Log::with_lock(dir, name, lock)
    }

    /// Open a log whose writer lock is already held.
    ///
    /// The standby path needs this (P1 #10): election has to happen **before** the
    /// projection is rebuilt, or the successor rebuilds from a log the outgoing active
    /// writer is still appending to and starts serving a view that is already behind.
    pub fn with_lock(
        dir: impl AsRef<Path>,
        name: &str,
        lock: crate::lock::LockGuard,
    ) -> Result<Self> {
        Log::assemble(dir, name, Some(lock))
    }

    /// Open a log for **reading only**, taking no lock.
    ///
    /// For a process that serves state it does not own — a read-only control plane distributing
    /// contract sets while a pipeline holds the writer lock. `append` refuses, so an unlocked log
    /// cannot corrupt one somebody else is writing even if a route slips past its own guard.
    pub fn open_read_only(dir: impl AsRef<Path>, name: &str) -> Result<Self> {
        Log::assemble(dir, name, None)
    }

    fn assemble(
        dir: impl AsRef<Path>,
        name: &str,
        lock: Option<crate::lock::LockGuard>,
    ) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let segments = segments(&dir, name)?;
        let segment = segments.last().map_or(1, |(n, _)| *n);
        let path = segment_path(&dir, name, segment);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| io_err(Code::CHAIN_APPEND_FAILED, &path, e))?;

        // Sequence numbers are global and monotonic, so the highest lives in the
        // newest non-empty segment. Walk back until one is found; a freshly
        // rotated (empty) tail segment is normal.
        let mut last_seq = 0;
        for (_, seg_path) in segments.iter().rev() {
            if let Some(seq) = last_seq_in(seg_path)? {
                last_seq = seq;
                break;
            }
        }

        Ok(Log {
            dir,
            name: name.to_string(),
            segment,
            file,
            last_seq,
            since_sync: 0,
            segment_bytes: DEFAULT_SEGMENT_BYTES,
            _lock: lock,
            marker: PhantomData,
        })
    }

    /// Override the rotation threshold.
    #[must_use]
    pub fn with_segment_bytes(mut self, bytes: u64) -> Self {
        self.segment_bytes = bytes;
        self
    }

    /// The highest sequence number written.
    #[must_use]
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// The segment currently being appended to.
    #[must_use]
    pub fn segment(&self) -> u32 {
        self.segment
    }

    /// Append a record, returning its sequence number.
    pub fn append(&mut self, rec: &T, now: u64, durability: Durability) -> Result<u64> {
        // The choke point. Every write to every log goes through here, so a read-only process
        // that reached this far — a route that forgot its own guard, a future caller — fails
        // loudly instead of appending to a log another process owns.
        if self._lock.is_none() {
            return Err(WcError::with_detail(
                Code::STORE_LOCKED,
                "this log was opened read-only and holds no writer lock; a process that does not \
                 own the log must not append to it",
            ));
        }
        let framed = Framed {
            seq: self.last_seq + 1,
            ts: now,
            rec,
        };
        let line = serde_json::to_string(&framed).map_err(|e| {
            WcError::with_detail(Code::CHAIN_APPEND_FAILED, "cannot encode record").with_source(e)
        })?;

        // One write call for the whole line: a partial line is a corrupt log, and
        // building the buffer first keeps the window as small as the OS allows.
        let mut buf = line.into_bytes();
        buf.push(b'\n');
        self.file
            .write_all(&buf)
            .map_err(|e| io_err(Code::CHAIN_APPEND_FAILED, &self.current_path(), e))?;

        self.last_seq += 1;
        self.since_sync += 1;

        match durability {
            Durability::Durable => self.sync()?,
            Durability::Batched if self.since_sync >= SYNC_EVERY => self.sync()?,
            Durability::Batched => {}
        }

        self.maybe_rotate()?;
        Ok(self.last_seq)
    }

    /// Flush to disk.
    pub fn sync(&mut self) -> Result<()> {
        self.file
            .sync_data()
            .map_err(|e| io_err(Code::CHAIN_APPEND_FAILED, &self.current_path(), e))?;
        self.since_sync = 0;
        Ok(())
    }

    fn current_path(&self) -> PathBuf {
        segment_path(&self.dir, &self.name, self.segment)
    }

    /// Roll to a new segment when the current one is large enough.
    fn maybe_rotate(&mut self) -> Result<()> {
        let len = self
            .file
            .metadata()
            .map_err(|e| io_err(Code::CHAIN_APPEND_FAILED, &self.current_path(), e))?
            .len();
        if len < self.segment_bytes {
            return Ok(());
        }
        self.sync()?;
        self.segment += 1;
        let path = self.current_path();
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| io_err(Code::CHAIN_APPEND_FAILED, &path, e))?;
        self.since_sync = 0;
        Ok(())
    }

    /// Read every record from every segment, oldest first.
    pub fn replay(dir: impl AsRef<Path>, name: &str) -> Result<Replay<T>> {
        let dir = dir.as_ref();
        let mut out = Replay::default();
        for (_, path) in segments(dir, name)? {
            read_segment(&path, &mut out)?;
        }
        Ok(out)
    }

    /// Read every record appended at or before `ts` — the point-in-time query
    /// that makes an `as_of` export reconstructable rather than asserted.
    pub fn replay_until(dir: impl AsRef<Path>, name: &str, ts: u64) -> Result<Replay<T>> {
        let mut all = Self::replay(dir, name)?;
        all.records.retain(|f| f.ts <= ts);
        Ok(all)
    }
}

/// The outcome of reading a log.
#[derive(Debug)]
pub struct Replay<T> {
    /// Records in sequence order.
    pub records: Vec<Framed<T>>,
    /// True when the final line was incomplete — the normal signature of a crash
    /// mid-append. Tolerated; anything earlier in the file is not.
    pub truncated_tail: bool,
}

impl<T> Default for Replay<T> {
    fn default() -> Self {
        Replay {
            records: Vec::new(),
            truncated_tail: false,
        }
    }
}

/// Read one segment, appending to `out`.
///
/// A malformed line is fatal *unless* it is the last line in the file, which is
/// what a crash mid-append looks like. Tolerating an interior corrupt line would
/// silently drop state.
fn read_segment<T: DeserializeOwned>(path: &Path, out: &mut Replay<T>) -> Result<()> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_err(Code::CHAIN_APPEND_FAILED, path, e)),
    };
    let reader = BufReader::new(file);
    let lines: Vec<std::io::Result<String>> = reader.lines().collect();
    let total = lines.len();

    for (i, line) in lines.into_iter().enumerate() {
        let line = line.map_err(|e| io_err(Code::CHAIN_APPEND_FAILED, path, e))?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Framed<T>>(&line) {
            Ok(framed) => out.records.push(framed),
            Err(_) if i + 1 == total => {
                out.truncated_tail = true;
            }
            Err(e) => {
                return Err(WcError::with_detail(
                    Code::CHAIN_BROKEN,
                    format!(
                        "{}: line {} is corrupt and is not the tail",
                        path.display(),
                        i + 1
                    ),
                )
                .with_source(e));
            }
        }
    }
    Ok(())
}

/// The highest sequence number in one segment, or `None` if it is empty.
fn last_seq_in(path: &Path) -> Result<Option<u64>> {
    let mut out: Replay<SeqOnly> = Replay::default();
    read_segment(path, &mut out)?;
    Ok(out.records.last().map(|f| f.seq))
}

/// A minimal view for scanning sequence numbers without deserialising payloads.
#[derive(Debug, Deserialize, Serialize)]
struct SeqOnly {}

fn segment_path(dir: &Path, name: &str, segment: u32) -> PathBuf {
    dir.join(format!("{name}-{segment:06}.jsonl"))
}

/// Every existing segment, ordered by number.
fn segments(dir: &Path, name: &str) -> Result<Vec<(u32, PathBuf)>> {
    let prefix = format!("{name}-");
    let mut out: Vec<(u32, PathBuf)> = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(io_err(Code::STORE_LOCKED, dir, e)),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(rest) = file_name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(number) = rest.strip_suffix(".jsonl") else {
            continue;
        };
        if let Ok(n) = number.parse::<u32>() {
            out.push((n, path));
        }
    }
    out.sort_by_key(|(n, _)| *n);
    Ok(out)
}

/// A filesystem-safe artifact name. An audience is a `warden:mediator:x` style id,
/// so its colons cannot go straight into a path.
#[must_use]
pub fn artifact_name(cid: &str, audience: &str) -> String {
    let safe: String = audience
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{cid}.{safe}.jws")
}

fn io_err(code: Code, path: &Path, e: std::io::Error) -> WcError {
    WcError::with_detail(code, format!("{}: {}", path.display(), e)).with_source(e)
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Who caused a state change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Actor {
    /// A named human.
    Human {
        /// The accountable party.
        id: HumanRef,
    },
    /// A service principal — CI, a platform automation.
    Service {
        /// Service identifier.
        id: String,
    },
    /// The control plane's own continuous-assurance loop: re-attestation, drift
    /// detection, expiry watch.
    ///
    /// Serialises as `"assurance"`. A stored event log written before the rename
    /// carries `"sentinel"`, so that spelling is still accepted on read — an
    /// append-only log cannot be rewritten, and a rebuild that silently dropped
    /// those rows would lose exactly the automated actions nobody was watching.
    #[serde(alias = "sentinel")]
    Assurance,
}

/// Why a pin was replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepinCause {
    /// First capture, at admission.
    Admission,
    /// Change outside any contracted surface, or metadata only.
    Benign,
    /// Change inside a contracted surface. Suspends contracts.
    Material,
    /// Canonicalisation algorithm upgrade — a silent shadow re-pin (§8.7.1).
    AlgUpgrade,
}

/// Why a contract was suspended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspendCause {
    /// Material surface drift.
    Drift,
    /// Re-attestation failed.
    Reattest,
    /// Owner departed and the connection is orphaned.
    Owner,
    /// A policy change made the connection no longer issuable.
    Policy,
}

/// What a consumer declared, and who may change it.
///
/// Deliberately small. The needs themselves settle into requests and contracts, which are already
/// durable; the one thing that was left with no trace is **who may approve a change to the
/// manifest**. Without this the consumer side has nothing to compare a later `[approval]` against,
/// so an approver set could move there and never be visible — the asymmetry W8.6 left behind on
/// the offer side alone.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NeedRecord {
    /// The consuming party.
    pub asset: EntityId,
    /// `[approval]` as declared, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<crate::authority::ApprovalBlock>,
    /// Where it was read from.
    pub repo: String,
    /// The commit it was read at.
    pub sha: String,
}

impl NeedRecord {
    /// Same reduction as [`crate::offer::Offer::approval_digest`], and deliberately the same rule:
    /// order and notation are not membership.
    #[must_use]
    pub fn approval_digest(&self) -> String {
        crate::offer::approval_digest(self.approval.as_ref())
    }
}

/// A state-log event (§8.8.2).
///
/// `#[serde(other)]` on [`Event::Unknown`] is what makes §8.14.4's
/// forward-compatibility rule true: an older replica replaying a newer log parses
/// unrecognised kinds into `Unknown` and counts them, instead of failing to start
/// or — worse — silently skipping them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Event {
    /// An entity record was written.
    #[serde(rename = "entity.put")]
    EntityPut {
        /// The full record.
        entity: Box<Entity>,
        /// Who wrote it.
        actor: Actor,
    },
    /// A lifecycle transition.
    #[serde(rename = "entity.transition")]
    EntityTransition {
        /// Subject.
        id: EntityId,
        /// New state.
        to: Lifecycle,
        /// Reason, for the operator reading it back.
        why: String,
        /// Who did it.
        actor: Actor,
    },
    /// A new pin was recorded.
    #[serde(rename = "entity.repin")]
    EntityRepin {
        /// Subject.
        id: EntityId,
        /// The new pin.
        pin: Box<Pin>,
        /// Why it changed.
        cause: RepinCause,
        /// What changed.
        diff: PinDiff,
    },
    /// Posture was re-scored.
    #[serde(rename = "entity.posture")]
    EntityPosture {
        /// Subject.
        id: EntityId,
        /// New posture.
        posture: Posture,
        /// New score.
        score: u8,
    },
    /// A connection was requested.
    #[serde(rename = "contract.request")]
    ContractRequest {
        /// The pending request.
        request: Box<crate::issuance::PendingRequest>,
        /// Who asked.
        actor: Actor,
    },
    /// A human approved a request.
    #[serde(rename = "contract.approve")]
    ContractApprove {
        /// Request id.
        request: String,
        /// The distinct approvers.
        approvers: Vec<HumanRef>,
        /// Policy version they approved under.
        policy_version: String,
        /// Who recorded it.
        actor: Actor,
    },
    /// A human refused a request.
    #[serde(rename = "contract.deny")]
    ContractDeny {
        /// Request id.
        request: String,
        /// Why.
        reason: String,
        /// Who refused.
        actor: Actor,
    },
    /// A request ran out of time. Silence terminates; it never approves.
    #[serde(rename = "contract.lapse")]
    ContractLapse {
        /// Request id.
        request: String,
    },
    /// A request produced a contract.
    #[serde(rename = "contract.issued")]
    ContractIssued {
        /// Request id.
        request: String,
        /// The connection it became.
        cid: Cid,
    },
    /// A contract was minted.
    #[serde(rename = "contract.mint")]
    ContractMint {
        /// The record.
        record: Box<ContractRecord>,
    },
    /// A contract was revoked.
    #[serde(rename = "contract.revoke")]
    ContractRevoke {
        /// Subject.
        cid: Cid,
        /// Reason.
        reason: String,
        /// Who did it.
        actor: Actor,
    },
    /// A contract was suspended pending re-approval.
    #[serde(rename = "contract.suspend")]
    ContractSuspend {
        /// Subject.
        cid: Cid,
        /// Why.
        cause: SuspendCause,
    },
    /// A contract was reinstated after suspension.
    #[serde(rename = "contract.reinstate")]
    ContractReinstate {
        /// Subject.
        cid: Cid,
    },
    /// A party was quarantined.
    #[serde(rename = "quarantine.order")]
    QuarantineOrder {
        /// Subject.
        party: EntityId,
        /// Reason, carried into evidence and the blast-radius report.
        reason: String,
        /// Who ordered it.
        actor: Actor,
        /// The approvers, where dual control applied.
        #[serde(default)]
        dual_control: Vec<HumanRef>,
    },
    /// Quarantine was lifted, returning the party to `Pending` so the full
    /// admission pipeline must run again.
    #[serde(rename = "quarantine.cleared")]
    QuarantineCleared {
        /// Subject.
        party: EntityId,
        /// Who lifted it.
        actor: Actor,
        /// The two approvers. Clearing containment is dual-controlled.
        #[serde(default)]
        dual_control: Vec<HumanRef>,
    },
    /// A provider published its terms of availability (W1).
    #[serde(rename = "offer.published")]
    OfferPublished {
        /// The offer, boxed so this variant does not inflate every other one.
        offer: Box<crate::offer::Offer>,
        /// Who published it — a pipeline, so normally `Actor::Service`.
        actor: Actor,
    },
    /// A consumer declared its needs (W2), recorded for the approver set alone.
    #[serde(rename = "need.declared")]
    NeedDeclared {
        /// What was declared.
        need: Box<NeedRecord>,
        /// Who applied it — a pipeline, so normally `Actor::Service`.
        actor: Actor,
    },
    /// An event kind this binary does not know. Counted, never silently dropped.
    #[serde(other)]
    Unknown,
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

/// One mediator's view of the contract set, and the hash it will acknowledge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractSetView {
    /// The hash a mediator echoes back on acknowledgement.
    pub set_hash: String,
    /// Contracts it should be holding, sorted by cid.
    pub active: Vec<Cid>,
    /// Contracts it should drop, named rather than left absent.
    pub removed: Vec<Cid>,
    /// The projection sequence this view was taken at.
    pub seq: u64,
}

/// Everything the control plane knows, rebuilt from the log.
#[derive(Debug, Default)]
pub struct Projection {
    /// Entity records by id.
    pub entities: HashMap<EntityId, Entity>,
    /// Contract records by connection id.
    pub contracts: HashMap<Cid, ContractRecord>,
    /// Caller → its contracts. Forward blast radius.
    pub by_caller: HashMap<EntityId, HashSet<Cid>>,
    /// Callee → its contracts. Reverse blast radius.
    pub by_callee: HashMap<EntityId, HashSet<Cid>>,
    /// Callee manifest hash → contracts pinned to it. Turns material drift into
    /// an O(1) fan-out instead of a scan.
    pub by_pin: HashMap<String, HashSet<Cid>>,
    /// Pending and settled connection requests, by id.
    pub requests: HashMap<String, crate::issuance::PendingRequest>,
    /// Expiry queue, soonest first.
    pub expiring: BinaryHeap<Reverse<(u64, Cid)>>,
    /// The current offer per providing party.
    ///
    /// Highest version wins rather than last-write-wins. An append-only log is ordered, so the
    /// two normally agree — but taking the maximum makes the fold independent of order, which
    /// means a replay cannot land on a different answer and a stale republish cannot roll an
    /// offer backwards to terms the provider has already withdrawn.
    pub offers: HashMap<EntityId, crate::offer::Offer>,
    /// The last declared needs manifest per consuming party, for approver-set comparison.
    ///
    /// Last-write-wins, unlike `offers`: a needs manifest carries no version, and its identity is
    /// the commit it was read at. Replay order is the log's order, which is what the fold follows.
    pub needs: HashMap<EntityId, NeedRecord>,
    /// Highest sequence applied.
    pub seq: u64,
}

/// What happened during a rebuild.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RebuildReport {
    /// Events applied.
    pub applied: u64,
    /// Events whose kind this binary does not know.
    pub unknown: u64,
    /// Events that referenced state that was not there. Reported, not fatal:
    /// aborting startup on one inconsistent historical record would make the
    /// control plane unbootable, but hiding them would mask corruption.
    pub inconsistent: Vec<String>,
    /// Whether the final log line was incomplete.
    pub truncated_tail: bool,
}

impl RebuildReport {
    /// Whether the rebuild was completely clean.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.unknown == 0 && self.inconsistent.is_empty() && !self.truncated_tail
    }
}

impl Projection {
    /// Apply one event. Pure and total: no I/O, no panics, and an unrecognised
    /// or inconsistent event yields a report entry rather than an abort.
    pub fn apply(&mut self, framed: &Framed<Event>, report: &mut RebuildReport) {
        self.seq = self.seq.max(framed.seq);
        match &framed.rec {
            Event::EntityPut { entity, .. } => {
                self.entities.insert(entity.id.clone(), (**entity).clone());
                report.applied += 1;
            }
            Event::NeedDeclared { need, .. } => {
                self.needs.insert(need.asset.clone(), (**need).clone());
                report.applied += 1;
            }
            Event::OfferPublished { offer, .. } => {
                match self.offers.get(&offer.asset) {
                    // A version we already hold or have passed. Not an inconsistency — a
                    // pipeline may retry — but not applied either, and counted so a replay
                    // that quietly discarded half the log would not look clean.
                    Some(held) if held.version >= offer.version => {
                        report.inconsistent.push(format!(
                            "seq {}: offer for {} is version {} but {} is already held",
                            framed.seq, offer.asset, offer.version, held.version
                        ));
                    }
                    _ => {
                        self.offers.insert(offer.asset.clone(), (**offer).clone());
                        report.applied += 1;
                    }
                }
            }
            Event::EntityTransition { id, to, .. } => match self.entities.get_mut(id) {
                Some(entity) => {
                    entity.lifecycle = *to;
                    entity.updated_at = framed.ts;
                    report.applied += 1;
                }
                None => report.inconsistent.push(format!(
                    "seq {}: transition for unknown entity {id}",
                    framed.seq
                )),
            },
            Event::EntityRepin { id, pin, .. } => match self.entities.get_mut(id) {
                Some(entity) => {
                    entity.pin = (**pin).clone();
                    entity.updated_at = framed.ts;
                    report.applied += 1;
                }
                None => report
                    .inconsistent
                    .push(format!("seq {}: repin for unknown entity {id}", framed.seq)),
            },
            Event::EntityPosture { id, posture, score } => match self.entities.get_mut(id) {
                Some(entity) => {
                    entity.posture = *posture;
                    entity.posture_score = *score;
                    entity.updated_at = framed.ts;
                    report.applied += 1;
                }
                None => report.inconsistent.push(format!(
                    "seq {}: posture change for unknown entity {id}",
                    framed.seq
                )),
            },
            Event::ContractRequest { request, .. } => {
                self.requests
                    .insert(request.id.clone(), (**request).clone());
                report.applied += 1;
            }
            Event::ContractApprove { request, .. } | Event::ContractIssued { request, .. } => {
                // Both settle the request; `contract.issued` is what links it to the
                // connection it became.
                match self.requests.get_mut(request) {
                    Some(pending) => {
                        pending.status = crate::issuance::RequestStatus::Minted;
                        report.applied += 1;
                    }
                    None => report.inconsistent.push(format!(
                        "seq {}: decision for unknown request {request}",
                        framed.seq
                    )),
                }
            }
            Event::ContractDeny { request, .. } => {
                self.settle_request(
                    request,
                    crate::issuance::RequestStatus::Denied,
                    framed.seq,
                    report,
                );
            }
            Event::ContractLapse { request } => {
                self.settle_request(
                    request,
                    crate::issuance::RequestStatus::Lapsed,
                    framed.seq,
                    report,
                );
            }
            Event::ContractMint { record } => {
                self.index_contract(record);
                self.contracts
                    .insert(record.cid.clone(), (**record).clone());
                report.applied += 1;
            }
            Event::ContractRevoke { cid, .. } => {
                self.set_status(cid, ContractStatus::Revoked, framed.seq, report);
            }
            Event::ContractSuspend { cid, .. } => {
                self.set_status(cid, ContractStatus::Suspended, framed.seq, report);
            }
            Event::ContractReinstate { cid } => {
                self.set_status(cid, ContractStatus::Active, framed.seq, report);
            }
            Event::QuarantineOrder { party, .. } => {
                match self.entities.get_mut(party) {
                    Some(entity) => entity.quarantine(framed.ts),
                    None => report.inconsistent.push(format!(
                        "seq {}: quarantine for unknown entity {party}",
                        framed.seq
                    )),
                }
                // Containment reaches every contract the party holds, in either
                // direction — not only the ones it initiated.
                for cid in self.contracts_for(party) {
                    if let Some(c) = self.contracts.get_mut(&cid) {
                        c.status = ContractStatus::Revoked;
                    }
                }
                report.applied += 1;
            }
            Event::QuarantineCleared { party, .. } => match self.entities.get_mut(party) {
                Some(entity) => {
                    // Contracts stay revoked: clearing quarantine restores the
                    // party's ability to be re-admitted, never its old authority.
                    // The duration is deliberately dropped here. This runs on every
                    // rebuild, so observing the metric from the projection would
                    // re-observe every historical quarantine each time the log is
                    // replayed. It is observed once, on the live path, in `registry`.
                    match entity.clear_quarantine(framed.ts) {
                        Ok(_) => report.applied += 1,
                        Err(e) => report.inconsistent.push(format!(
                            "seq {}: clear_quarantine on {party}: {e}",
                            framed.seq
                        )),
                    }
                }
                None => report.inconsistent.push(format!(
                    "seq {}: quarantine cleared for unknown entity {party}",
                    framed.seq
                )),
            },
            Event::Unknown => report.unknown += 1,
        }
    }

    fn settle_request(
        &mut self,
        id: &str,
        status: crate::issuance::RequestStatus,
        seq: u64,
        report: &mut RebuildReport,
    ) {
        match self.requests.get_mut(id) {
            Some(pending) => {
                pending.status = status;
                report.applied += 1;
            }
            None => report
                .inconsistent
                .push(format!("seq {seq}: decision for unknown request {id}")),
        }
    }

    fn set_status(
        &mut self,
        cid: &Cid,
        status: ContractStatus,
        seq: u64,
        report: &mut RebuildReport,
    ) {
        match self.contracts.get_mut(cid) {
            Some(contract) => {
                contract.status = status;
                report.applied += 1;
            }
            None => report.inconsistent.push(format!(
                "seq {seq}: status change for unknown contract {cid}"
            )),
        }
    }

    fn index_contract(&mut self, record: &ContractRecord) {
        self.by_caller
            .entry(record.caller.clone())
            .or_default()
            .insert(record.cid.clone());
        self.by_callee
            .entry(record.callee.clone())
            .or_default()
            .insert(record.cid.clone());
        self.by_pin
            .entry(record.callee_manifest.clone())
            .or_default()
            .insert(record.cid.clone());
        self.expiring
            .push(Reverse((record.exp, record.cid.clone())));
    }

    /// Every contract naming this party at either end.
    #[must_use]
    pub fn contracts_for(&self, id: &EntityId) -> Vec<Cid> {
        let mut out: HashSet<Cid> = HashSet::new();
        if let Some(set) = self.by_caller.get(id) {
            out.extend(set.iter().cloned());
        }
        if let Some(set) = self.by_callee.get(id) {
            out.extend(set.iter().cloned());
        }
        let mut out: Vec<Cid> = out.into_iter().collect();
        out.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        out
    }

    /// Every contract pinned to a given manifest hash — the material-drift
    /// fan-out.
    #[must_use]
    pub fn contracts_for_pin(&self, manifest: &str) -> Vec<Cid> {
        let mut out: Vec<Cid> = self
            .by_pin
            .get(manifest)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        out.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        out
    }

    /// Contracts that expire at or before `deadline` and are still active.
    #[must_use]
    pub fn expiring_before(&self, deadline: u64) -> Vec<Cid> {
        let mut out: Vec<Cid> = self
            .contracts
            .values()
            .filter(|c| c.status == ContractStatus::Active && c.exp <= deadline)
            .map(|c| c.cid.clone())
            .collect();
        out.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        out
    }

    /// The contract set a given mediator should be holding, and its hash.
    ///
    /// # Why this is one function
    ///
    /// The hash is what a mediator echoes back when it acknowledges a set, so it is the only
    /// thing that can tell a deploy gate whether distribution has completed. It was computed
    /// inline inside the API's pull handler, which meant anything else wanting to know the
    /// expected value — a gate, a report, a test — had to recompute it. Two implementations of
    /// a digest is the "two copies of a decision" problem §8.3 warns about, and here the failure
    /// mode is specific and bad: a gate that computes it differently never releases, so a
    /// correct deploy blocks forever and the operator is told nothing useful.
    ///
    /// Per mediator, not estate-wide: a contract names one `aud`, so each mediator holds a
    /// different set and confirms a different hash.
    #[must_use]
    pub fn contract_set_for(&self, mediator: &str, now: u64) -> ContractSetView {
        let mut live: Vec<&wc_core::contract::ContractRecord> = self
            .contracts
            .values()
            .filter(|c| c.aud.iter().any(|a| a == mediator))
            .collect();
        // Sorted, because the hash is over a concatenation and a map's iteration order is not a
        // promise. An unsorted digest would change between two identical states.
        live.sort_unstable_by(|a, b| a.cid.as_str().cmp(b.cid.as_str()));

        let mut active = Vec::new();
        let mut removed = Vec::new();
        for c in live {
            if c.status == wc_core::contract::ContractStatus::Active && now < c.exp {
                active.push(c.cid.clone());
            } else {
                // Named explicitly rather than left absent, so a mediator drops it instead of
                // inferring removal from a set it might have fetched partially.
                removed.push(c.cid.clone());
            }
        }

        let mut digest_input = String::new();
        for cid in &active {
            digest_input.push_str(cid.as_str());
            digest_input.push('\n');
        }
        ContractSetView {
            set_hash: format!("sha256:{}", wc_core::util::sha256_hex(&digest_input)),
            active,
            removed,
            seq: self.seq,
        }
    }

    /// Look up one entity.
    ///
    /// These four lookups live here rather than only on [`crate::registry::Registry`] because
    /// `Registry` borrows the store **mutably**, and a mutable borrow is how a reader ends up
    /// taking the single-writer lock. Every read-only CLI verb did — so `connect posture`,
    /// `connect discover`, `connect blast-radius` and the rest all failed with `WC-8003` against
    /// a control plane that was serving, which in production is a control plane that is always
    /// serving. `Registry` delegates to these, so the behaviour and the error message have one
    /// home.
    #[must_use]
    pub fn entity(&self, id: &wc_core::model::EntityId) -> Option<&wc_core::model::Entity> {
        self.entities.get(id)
    }

    /// Look up one entity or fail with [`Code::ENTITY_NOT_FOUND`].
    pub fn require_entity(&self, id: &wc_core::model::EntityId) -> Result<&wc_core::model::Entity> {
        self.entity(id).ok_or_else(|| {
            WcError::with_detail(Code::ENTITY_NOT_FOUND, format!("{id} is not registered"))
        })
    }

    /// A bulk read of the estate, for exports, posture reports and the operator portal.
    ///
    /// Deliberately not called `list`: this is the enumeration an agent principal must never be
    /// able to perform, so every caller should be visibly an operator path.
    #[must_use]
    pub fn enumerate_for_operator(&self) -> Vec<&wc_core::model::Entity> {
        let mut out: Vec<&wc_core::model::Entity> = self.entities.values().collect();
        out.sort_unstable_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        out
    }

    /// Entities whose re-attestation interval has lapsed — the assurance loop's work queue.
    #[must_use]
    pub fn reattest_due(&self, now: u64) -> Vec<wc_core::model::EntityId> {
        let mut out: Vec<wc_core::model::EntityId> = self
            .entities
            .values()
            .filter(|e| e.lifecycle == wc_core::model::Lifecycle::Active && e.reattest_overdue(now))
            .map(|e| e.id.clone())
            .collect();
        out.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        out
    }

    /// Rebuild from the newest snapshot plus the log tail.
    pub fn rebuild(dir: impl AsRef<Path>, name: &str) -> Result<(Projection, RebuildReport)> {
        let dir = dir.as_ref();
        let mut projection = match Snapshot::load_newest(dir)? {
            Some(snapshot) => snapshot.into_projection(),
            None => Projection::default(),
        };
        let from_seq = projection.seq;

        let replay = Log::<Event>::replay(dir, name)?;
        let mut report = RebuildReport {
            truncated_tail: replay.truncated_tail,
            ..Default::default()
        };
        for framed in replay.records.iter().filter(|f| f.seq > from_seq) {
            projection.apply(framed, &mut report);
        }
        Ok((projection, report))
    }

    /// Rebuild the state as it stood at `ts`, from the log alone.
    ///
    /// Snapshots are deliberately not used: a snapshot reflects state *after*
    /// `ts`, and there is no way to unwind it. Full replay is the only honest
    /// answer to a point-in-time question.
    pub fn as_of(
        dir: impl AsRef<Path>,
        name: &str,
        ts: u64,
    ) -> Result<(Projection, RebuildReport)> {
        let replay = Log::<Event>::replay_until(dir, name, ts)?;
        let mut projection = Projection::default();
        let mut report = RebuildReport {
            truncated_tail: replay.truncated_tail,
            ..Default::default()
        };
        for framed in &replay.records {
            projection.apply(framed, &mut report);
        }
        Ok((projection, report))
    }

    /// Write a snapshot so the next rebuild only replays the tail.
    pub fn save_snapshot(&self, dir: impl AsRef<Path>) -> Result<PathBuf> {
        let dir = dir.as_ref();
        let snapshot = Snapshot {
            seq: self.seq,
            entities: self.entities.values().cloned().collect(),
            contracts: self.contracts.values().cloned().collect(),
            requests: self.requests.values().cloned().collect(),
        };
        let path = dir.join(format!("snapshot-{:06}.json", self.seq));
        let text = serde_json::to_string(&snapshot).map_err(|e| {
            WcError::with_detail(Code::CHAIN_APPEND_FAILED, "cannot encode snapshot").with_source(e)
        })?;

        // Write to a temporary file and rename: a snapshot that is half-written
        // when the process dies must not be loadable.
        let tmp = dir.join(format!("snapshot-{:06}.json.tmp", self.seq));
        std::fs::write(&tmp, &text).map_err(|e| io_err(Code::CHAIN_APPEND_FAILED, &tmp, e))?;
        std::fs::rename(&tmp, &path).map_err(|e| io_err(Code::CHAIN_APPEND_FAILED, &path, e))?;
        Ok(path)
    }
}

/// A point-in-time dump of the projection, so a rebuild replays only the tail.
#[derive(Debug, Serialize, Deserialize)]
struct Snapshot {
    seq: u64,
    entities: Vec<Entity>,
    contracts: Vec<ContractRecord>,
    #[serde(default)]
    requests: Vec<crate::issuance::PendingRequest>,
}

impl Snapshot {
    fn load_newest(dir: &Path) -> Result<Option<Snapshot>> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(Code::STORE_LOCKED, dir, e)),
        };
        let mut newest: Option<(u64, PathBuf)> = None;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(rest) = name.strip_prefix("snapshot-") else {
                continue;
            };
            let Some(number) = rest.strip_suffix(".json") else {
                continue;
            };
            if let Ok(seq) = number.parse::<u64>() {
                if newest.as_ref().is_none_or(|(best, _)| seq > *best) {
                    newest = Some((seq, path));
                }
            }
        }

        let Some((_, path)) = newest else {
            return Ok(None);
        };
        let text =
            std::fs::read_to_string(&path).map_err(|e| io_err(Code::CHAIN_BROKEN, &path, e))?;
        let snapshot = serde_json::from_str(&text).map_err(|e| {
            WcError::with_detail(
                Code::CHAIN_BROKEN,
                format!("{}: snapshot is unreadable", path.display()),
            )
            .with_source(e)
        })?;
        Ok(Some(snapshot))
    }

    fn into_projection(self) -> Projection {
        let mut projection = Projection {
            seq: self.seq,
            ..Default::default()
        };
        for entity in self.entities {
            projection.entities.insert(entity.id.clone(), entity);
        }
        for contract in self.contracts {
            projection.index_contract(&contract);
            projection.contracts.insert(contract.cid.clone(), contract);
        }
        for request in self.requests {
            projection.requests.insert(request.id.clone(), request);
        }
        projection
    }
}

/// A convenience alias: the state log is a `Log<Event>`.
pub type StateLog = Log<Event>;

/// The conventional state-log name inside a tenant's `state/` directory.
pub const STATE_LOG_NAME: &str = "events";

/// Read one issued artifact from an artifacts directory, without opening the store.
///
/// A free function because reading an artifact needs a path and nothing else, and routing it
/// through `Store` meant a reader had to take the single-writer lock — which `connect serve`
/// holds for the life of the process.
#[must_use]
pub fn read_artifact_from(dir: &Path, cid: &str, audience: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(artifact_name(cid, audience)))
        .ok()
        .map(|t| t.trim().to_string())
}

/// Sorted entity ids — used by exports, which must be deterministic.
#[must_use]
pub fn sorted_entity_ids(projection: &Projection) -> Vec<EntityId> {
    let mut ids: Vec<EntityId> = projection.entities.keys().cloned().collect();
    ids.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
    ids
}

/// Entity records keyed for a stable dump.
#[must_use]
pub fn entity_map(projection: &Projection) -> BTreeMap<String, &Entity> {
    projection
        .entities
        .iter()
        .map(|(id, e)| (id.as_str().to_string(), e))
        .collect()
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// The state layer's composition root: the log plus its projection, opened
/// together so they cannot drift apart.
///
/// Holding this means holding the writer lock (§8.5.2), so exactly one process
/// per tenant owns a `Store` at a time.
#[derive(Debug)]
pub struct Store {
    /// Current state, rebuilt at open and updated on every commit.
    pub projection: Projection,
    /// The append-only log.
    pub log: StateLog,
    dir: PathBuf,
    artifacts: PathBuf,
    anomalies: Vec<String>,
}

impl Store {
    /// Open the state directory: take the writer lock, **then** rebuild the projection.
    ///
    /// The order is the correctness argument, and it used to be the other way round. A
    /// rebuild performed before election reads a log another process may still be
    /// appending to, so the resulting projection can be behind the log by however many
    /// records landed in between. On the old path that was only wasted work — the
    /// subsequent lock attempt failed and the whole open failed with it — but it is
    /// exactly wrong for a standby, which is *expecting* the log to have grown while it
    /// waited. Lock first and the log is frozen for the duration of the rebuild.
    pub fn open(dir: impl AsRef<Path>) -> Result<(Store, RebuildReport)> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| {
            WcError::with_detail(
                Code::STORE_LOCKED,
                format!("cannot create {}", dir.display()),
            )
            .with_source(e)
        })?;
        let lock = crate::lock::acquire(&dir, STATE_LOG_NAME)?;
        Store::assemble(dir, lock)
    }

    /// Stand by until the active writer releases, then take over (P1 #10).
    ///
    /// §8.5.2 says high availability is "active/standby with that lock as the election
    /// primitive". This is the standby. It returns once the lock is held and the
    /// projection has been rebuilt from everything the outgoing writer committed —
    /// including whatever it wrote while this process was waiting, which is the question
    /// P1 #10 asked and nothing answered.
    ///
    /// The `Election` says whether this process was a successor or the first writer, and
    /// how long the takeover took. Both belong in a startup line: after a failover the
    /// first thing anyone wants to know is whether the new process actually took over or
    /// simply started.
    pub fn open_waiting(
        dir: impl AsRef<Path>,
        timeout: std::time::Duration,
        poll: std::time::Duration,
        on_wait: impl FnMut(u64),
    ) -> Result<(Store, RebuildReport, crate::lock::Election)> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| {
            WcError::with_detail(
                Code::STORE_LOCKED,
                format!("cannot create {}", dir.display()),
            )
            .with_source(e)
        })?;
        let (lock, election) =
            crate::lock::acquire_waiting(&dir, STATE_LOG_NAME, timeout, poll, on_wait)?;
        let (store, report) = Store::assemble(dir, lock)?;
        Ok((store, report, election))
    }

    /// Open the state directory for **reading only**, taking no writer lock.
    ///
    /// For `connect serve --read-only`: a control plane that distributes contract sets to
    /// mediators while a consumer's pipeline holds the writer lock. Without this, `serve` and the
    /// pipeline verbs (`offer publish`, `need apply`) could not both exist in an estate, because
    /// the state log is single-writer and `serve` held that lock for the life of the process.
    ///
    /// The projection is a snapshot as of this call, so a long-lived reader must
    /// [`Store::refresh`] or it will serve an ever-staler set — which for a mediator pulling
    /// contracts means never seeing a newly minted one.
    pub fn open_read_only(dir: impl AsRef<Path>) -> Result<(Store, RebuildReport)> {
        let dir = dir.as_ref().to_path_buf();
        let (projection, report) = Projection::rebuild(&dir, STATE_LOG_NAME)?;
        let log = StateLog::open_read_only(&dir, STATE_LOG_NAME)?;
        Ok((
            Store {
                projection,
                log,
                artifacts: dir.join("contracts"),
                dir,
                anomalies: Vec::new(),
            },
            report,
        ))
    }

    /// Re-read the state from disk, discarding the in-memory projection.
    ///
    /// Only meaningful for a store opened with [`Store::open_read_only`]: a writer's projection is
    /// already current by construction, and re-reading one would throw away uncommitted nothing
    /// while costing a full replay. Returns the rebuild report so a caller can report a log that
    /// did not read back cleanly rather than serving from it silently.
    pub fn refresh(&mut self) -> Result<RebuildReport> {
        let (projection, report) = Projection::rebuild(&self.dir, STATE_LOG_NAME)?;
        self.projection = projection;
        Ok(report)
    }

    fn assemble(dir: PathBuf, lock: crate::lock::LockGuard) -> Result<(Store, RebuildReport)> {
        let (projection, report) = Projection::rebuild(&dir, STATE_LOG_NAME)?;
        let log = StateLog::with_lock(&dir, STATE_LOG_NAME, lock)?;
        let artifacts = dir.join("contracts");
        Ok((
            Store {
                projection,
                log,
                artifacts,
                dir,
                anomalies: Vec::new(),
            },
            report,
        ))
    }

    /// The state directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Put the issued artifacts somewhere other than `<state>/contracts`.
    #[must_use]
    pub fn with_artifacts(mut self, dir: impl Into<PathBuf>) -> Store {
        self.artifacts = dir.into();
        self
    }

    /// Where issued artifacts live.
    #[must_use]
    pub fn artifacts_dir(&self) -> &Path {
        &self.artifacts
    }

    /// Persist an issued artifact (§8.8.1).
    ///
    /// The state log records only `jws_sha256`, to stay compact — so the artifact
    /// itself has to be kept here, or a mediator could never be handed the signed
    /// document it is supposed to verify. One file per audience, because one
    /// contract is addressed to one mediator.
    pub fn write_artifact(&self, cid: &str, audience: &str, jws: &str) -> Result<PathBuf> {
        std::fs::create_dir_all(&self.artifacts)
            .map_err(|e| io_err(Code::CHAIN_APPEND_FAILED, &self.artifacts, e))?;
        let path = self.artifacts.join(artifact_name(cid, audience));
        std::fs::write(&path, format!("{jws}\n"))
            .map_err(|e| io_err(Code::CHAIN_APPEND_FAILED, &path, e))?;
        Ok(path)
    }

    /// Read a persisted artifact back.
    #[must_use]
    pub fn read_artifact(&self, cid: &str, audience: &str) -> Option<String> {
        read_artifact_from(&self.artifacts, cid, audience)
    }

    /// Append an event and apply it to the projection, in that order: if the
    /// append fails, in-memory state is untouched and the caller can retry.
    ///
    /// Callers are expected to have validated the event already (that is what
    /// `registry` is for), so an inconsistency here is a logic bug rather than
    /// bad data. It is recorded in [`Store::anomalies`] instead of being
    /// discarded, because a silent projection divergence is the worst possible
    /// failure of a state store.
    pub fn commit(&mut self, event: Event, now: u64, durability: Durability) -> Result<u64> {
        let seq = self.log.append(&event, now, durability)?;
        let framed = Framed {
            seq,
            ts: now,
            rec: event,
        };
        let mut report = RebuildReport::default();
        self.projection.apply(&framed, &mut report);
        self.anomalies.append(&mut report.inconsistent);
        Ok(seq)
    }

    /// Inconsistencies observed while applying committed events. Empty in normal
    /// operation; non-empty means a validation path was bypassed.
    #[must_use]
    pub fn anomalies(&self) -> &[String] {
        &self.anomalies
    }

    /// Write a snapshot so the next open replays only the tail.
    pub fn snapshot(&self) -> Result<PathBuf> {
        self.projection.save_snapshot(&self.dir)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use wc_core::contract::{ApprovalRef, Surface, Terms, CONTRACT_SCHEMA};
    use wc_core::model::{Jti, Kind, Tier, ZoneId, PIN_ALG};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// A unique temporary directory, removed when the guard drops.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> TmpDir {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("wc-store-{}-{tag}-{n}", std::process::id()));
            // Clear first: `create_dir_all` on an EXISTING directory succeeds and leaves its
            // contents, and these paths repeat across runs because a pid gets reused and the
            // counter restarts at 0. `Drop` does not run when a test aborts or a run is killed,
            // so leftovers accumulate — 2,956 of them were sitting in /tmp when this was found.
            // A stale log underneath a durability test can fail it, and can also make it PASS
            // for the wrong reason, which is the worse half.
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            TmpDir(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn human() -> HumanRef {
        HumanRef::new("human:priya@org").unwrap()
    }

    fn actor() -> Actor {
        Actor::Human { id: human() }
    }

    #[test]
    fn the_assurance_actor_still_reads_logs_written_as_sentinel() {
        // The component was renamed sentinel -> assurance. The event log is
        // append-only, so rows already on disk keep the old spelling and a rebuild
        // that dropped them would lose precisely the automated actions no human
        // was watching.
        let old: Actor = serde_json::from_str(r#"{"type":"sentinel"}"#).unwrap();
        assert_eq!(old, Actor::Assurance);

        let current: Actor = serde_json::from_str(r#"{"type":"assurance"}"#).unwrap();
        assert_eq!(current, Actor::Assurance);

        // New rows are written with the new spelling.
        assert_eq!(
            serde_json::to_string(&Actor::Assurance).unwrap(),
            r#"{"type":"assurance"}"#
        );
    }

    fn agent_id() -> EntityId {
        EntityId::new("spiffe://org/ns/agents/sa/recon-bot-7").unwrap()
    }

    fn server_id() -> EntityId {
        EntityId::new("spiffe://org/ns/tools/sa/payments-mcp").unwrap()
    }

    fn entity(id: &EntityId, kind: Kind) -> Entity {
        Entity::pending(
            id.clone(),
            kind,
            human(),
            ZoneId::new("internal.payments").unwrap(),
            Tier::TWO,
            1_000,
        )
    }

    fn pin(manifest: &str) -> Pin {
        let mut items = BTreeMap::new();
        items.insert("get_balance".to_string(), "sha256:aa".to_string());
        Pin {
            alg: PIN_ALG.to_string(),
            manifest: manifest.to_string(),
            items,
            pinned_at: 1,
        }
    }

    fn contract(
        cid: &str,
        caller: EntityId,
        callee: EntityId,
        manifest: &str,
        exp: u64,
    ) -> ContractRecord {
        ContractRecord {
            cid: Cid::new(cid).unwrap(),
            jti: Jti::new("cx_84be0011").unwrap(),
            caller,
            callee,
            caller_zone: ZoneId::new("internal.apac-ops").unwrap(),
            callee_zone: ZoneId::new("internal.payments").unwrap(),
            callee_tier: Tier::TWO,
            callee_manifest: manifest.to_string(),
            surface_digest: "sha256:digest".to_string(),
            surface: Surface {
                tools: vec!["get_balance".to_string()],
                ..Default::default()
            },
            terms: Terms::default(),
            aud: vec!["warden:mediator:apac-ops".to_string()],
            jws_sha256: "sha256:deadbeef".to_string(),
            status: ContractStatus::Active,
            approval: ApprovalRef::standing(),
            policy_version: "connect-policy@v37".to_string(),
            iat: 1_000,
            exp,
            offer_version: None,
            schema: CONTRACT_SCHEMA,
        }
    }

    // --- Log mechanics ---

    // --- the contract set a mediator should hold (W6b) -----------------------

    fn projection_with(records: Vec<ContractRecord>) -> Projection {
        let mut p = Projection::default();
        for r in records {
            p.contracts.insert(r.cid.clone(), r);
        }
        p
    }

    fn for_mediator(cid: &str, mediator: &str, exp: u64, status: ContractStatus) -> ContractRecord {
        let mut r = contract(cid, agent_id(), server_id(), "sha256:m", exp);
        r.aud = vec![mediator.to_string()];
        r.status = status;
        r
    }

    #[test]
    fn a_mediators_set_contains_only_its_own_contracts() {
        // A contract names one `aud`. A set that leaked another mediator's contracts would hand
        // a mediator artifacts it must refuse, and its ack would confirm a hash nobody expected.
        let p = projection_with(vec![
            for_mediator(
                "conn_aaaaaaaa",
                "warden:mediator:a",
                9_000,
                ContractStatus::Active,
            ),
            for_mediator(
                "conn_bbbbbbbb",
                "warden:mediator:b",
                9_000,
                ContractStatus::Active,
            ),
        ]);
        let a = p.contract_set_for("warden:mediator:a", 1_000);
        assert_eq!(a.active.len(), 1);
        assert_eq!(a.active[0].as_str(), "conn_aaaaaaaa");
        assert_ne!(
            a.set_hash,
            p.contract_set_for("warden:mediator:b", 1_000).set_hash,
            "two mediators holding different sets must confirm different hashes"
        );
    }

    #[test]
    fn the_hash_does_not_depend_on_insertion_order() {
        // The digest is a concatenation and `contracts` is a HashMap, so without the sort two
        // identical states could produce different hashes — and a gate comparing them would
        // never release.
        let one = for_mediator(
            "conn_11111111",
            "warden:mediator:a",
            9_000,
            ContractStatus::Active,
        );
        let two = for_mediator(
            "conn_22222222",
            "warden:mediator:a",
            9_000,
            ContractStatus::Active,
        );
        let forward = projection_with(vec![one.clone(), two.clone()]);
        let backward = projection_with(vec![two, one]);
        assert_eq!(
            forward
                .contract_set_for("warden:mediator:a", 1_000)
                .set_hash,
            backward
                .contract_set_for("warden:mediator:a", 1_000)
                .set_hash
        );
    }

    #[test]
    fn an_expired_or_revoked_contract_is_named_as_removed_not_left_absent() {
        // A mediator must be told to drop it rather than inferring removal from an absence it
        // cannot distinguish from a partial fetch.
        let p = projection_with(vec![
            for_mediator(
                "conn_aaaaaaaa",
                "warden:mediator:a",
                9_000,
                ContractStatus::Active,
            ),
            for_mediator(
                "conn_cccccccc",
                "warden:mediator:a",
                100,
                ContractStatus::Active,
            ),
            for_mediator(
                "conn_dddddddd",
                "warden:mediator:a",
                9_000,
                ContractStatus::Revoked,
            ),
        ]);
        let view = p.contract_set_for("warden:mediator:a", 1_000);
        assert_eq!(view.active.len(), 1, "{:?}", view.active);
        assert_eq!(view.removed.len(), 2, "{:?}", view.removed);
    }

    #[test]
    fn the_hash_covers_the_active_set_so_a_revocation_moves_it() {
        // What makes the hash usable as a distribution signal: revoking a contract changes it,
        // so a mediator that still echoes the old hash has demonstrably not caught up.
        let active = for_mediator(
            "conn_aaaaaaaa",
            "warden:mediator:a",
            9_000,
            ContractStatus::Active,
        );
        let before = projection_with(vec![active.clone()]);
        let mut revoked = active;
        revoked.status = ContractStatus::Revoked;
        let after = projection_with(vec![revoked]);
        assert_ne!(
            before.contract_set_for("warden:mediator:a", 1_000).set_hash,
            after.contract_set_for("warden:mediator:a", 1_000).set_hash
        );
    }

    #[test]
    fn a_mediator_with_no_contracts_still_has_a_stable_hash() {
        // The empty set has a hash too, and it must be the same every time — otherwise a
        // mediator holding nothing could never confirm anything.
        let p = Projection::default();
        let a = p.contract_set_for("warden:mediator:nobody", 1_000);
        let b = p.contract_set_for("warden:mediator:nobody", 5_000);
        assert!(a.active.is_empty());
        assert_eq!(a.set_hash, b.set_hash);
    }

    // --- offers (W1) --------------------------------------------------------

    fn an_offer(asset: &EntityId, version: u64) -> crate::offer::Offer {
        crate::offer::Offer {
            asset: asset.clone(),
            version,
            surface_kind: wc_core::canon::SurfaceKind::McpTools,
            surface_digest: format!("sha256:v{version}"),
            terms: vec![crate::offer::Term {
                items: vec!["get_balance".to_string()],
                to: crate::offer::Audience::default(),
                approval: crate::offer::TermApproval::PreGranted,
                ttl_max: 3_600,
                deprecates: Vec::new(),
            }],
            source: crate::offer::OfferSource {
                repo: "bank/payments-mcp".to_string(),
                sha: format!("sha-{version}"),
                manifest_digest: format!("sha256:m{version}"),
            },
            consent: None,
            approval: None,
        }
    }

    #[test]
    fn an_offer_survives_a_replay_so_provider_consent_is_not_held_in_memory() {
        // The provider's half of a bilateral contract arrives days before the consumer's. If it
        // lived only in memory, restarting the plane would silently discard consent that a
        // reviewed commit established — and the next `need apply` would refuse for want of an
        // offer that had in fact been published.
        let tmp = TmpDir::new("offer-replay");
        let asset = agent_id();
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(
                &Event::OfferPublished {
                    offer: Box::new(an_offer(&asset, 7)),
                    actor: Actor::Service {
                        id: "urn:wc:oidc:gh:repo:bank/payments-mcp:ref:refs/heads/main".into(),
                    },
                },
                1_000,
                Durability::Durable,
            )
            .unwrap();
        }
        let (projection, report) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert!(report.is_clean(), "{report:?}");
        let held = projection
            .offers
            .get(&asset)
            .expect("the offer must persist");
        assert_eq!(held.version, 7);
        assert_eq!(held.source.sha, "sha-7");
    }

    #[test]
    fn a_stale_republish_cannot_roll_an_offer_back_to_withdrawn_terms() {
        // Highest version wins, not last write. A pipeline retrying an older commit — or a log
        // replayed in an unexpected order — must not reinstate terms the provider has already
        // superseded, because that would silently re-grant something they withdrew.
        let tmp = TmpDir::new("offer-stale");
        let asset = agent_id();
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            for v in [7, 5] {
                log.append(
                    &Event::OfferPublished {
                        offer: Box::new(an_offer(&asset, v)),
                        actor: actor(),
                    },
                    1_000 + v,
                    Durability::Durable,
                )
                .unwrap();
            }
        }
        let (projection, report) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert_eq!(
            projection.offers.get(&asset).unwrap().version,
            7,
            "version 5 arrived last and must not win"
        );
        assert!(
            !report.is_clean(),
            "the superseded row must be reported, not silently dropped — a replay that discarded \
             half a log would otherwise look clean"
        );
    }

    #[test]
    fn a_newer_offer_replaces_the_terms_that_came_before_it() {
        let tmp = TmpDir::new("offer-newer");
        let asset = agent_id();
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            for v in [5, 7] {
                log.append(
                    &Event::OfferPublished {
                        offer: Box::new(an_offer(&asset, v)),
                        actor: actor(),
                    },
                    1_000 + v,
                    Durability::Durable,
                )
                .unwrap();
            }
        }
        let (projection, report) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert!(report.is_clean(), "{report:?}");
        let held = projection.offers.get(&asset).unwrap();
        assert_eq!(held.version, 7);
        assert_eq!(
            held.surface_digest, "sha256:v7",
            "a new offer version carries the new surface digest with it"
        );
    }

    #[test]
    fn append_then_replay_round_trips() {
        let tmp = TmpDir::new("roundtrip");
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            let e = entity(&agent_id(), Kind::Agent);
            assert_eq!(
                log.append(
                    &Event::EntityPut {
                        entity: Box::new(e),
                        actor: actor()
                    },
                    1_000,
                    Durability::Durable
                )
                .unwrap(),
                1
            );
            assert_eq!(
                log.append(
                    &Event::EntityTransition {
                        id: agent_id(),
                        to: Lifecycle::Active,
                        why: "admitted".into(),
                        actor: actor(),
                    },
                    1_001,
                    Durability::Durable
                )
                .unwrap(),
                2
            );
            assert_eq!(log.last_seq(), 2);
        }

        let replay = StateLog::replay(tmp.path(), STATE_LOG_NAME).unwrap();
        assert_eq!(replay.records.len(), 2);
        assert!(!replay.truncated_tail);
        assert_eq!(replay.records[0].seq, 1);
        assert_eq!(replay.records[0].ts, 1_000);
        assert!(matches!(
            replay.records[1].rec,
            Event::EntityTransition { .. }
        ));
    }

    #[test]
    fn sequence_continues_across_reopen() {
        let tmp = TmpDir::new("reopen");
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(&Event::Unknown, 1, Durability::Durable).unwrap();
        }
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            assert_eq!(log.last_seq(), 1, "must resume from the persisted head");
            assert_eq!(
                log.append(&Event::Unknown, 2, Durability::Durable).unwrap(),
                2
            );
        }
    }

    #[test]
    fn a_second_writer_is_refused() {
        let tmp = TmpDir::new("lock");
        let _held = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
        let err = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap_err();
        assert_eq!(err.code(), Code::STORE_LOCKED);
    }

    #[test]
    fn the_lock_is_released_on_drop() {
        let tmp = TmpDir::new("unlock");
        {
            let _held = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
        }
        assert!(StateLog::open(tmp.path(), STATE_LOG_NAME).is_ok());
    }

    #[test]
    fn a_read_only_store_coexists_with_the_writer_and_refuses_to_append() {
        // The topology this exists for: `connect serve --read-only` distributing contract sets
        // while a consumer's pipeline holds the writer lock. Before it, `serve` held that lock for
        // the life of the process, so `offer publish` and `need apply` — the pipeline verbs the
        // whole offer/acceptance design is built on — could not run against a live control plane.
        let tmp = TmpDir::new("read-only");
        let (mut writer, _) = Store::open(tmp.path()).unwrap();
        writer
            .commit(
                Event::EntityPosture {
                    id: agent_id(),
                    posture: Posture::Attested,
                    score: 90,
                },
                1_000,
                Durability::Batched,
            )
            .unwrap();

        // Opens while the writer holds the lock. `Store::open` here would fail with WC-8003.
        let (mut reader, _) = Store::open_read_only(tmp.path()).unwrap();
        assert_eq!(reader.projection.seq, writer.projection.seq);

        // And it cannot write, at the choke point every log append goes through — so a route that
        // forgot its own guard fails loudly instead of appending to a log it does not own.
        let err = reader
            .commit(
                Event::EntityPosture {
                    id: agent_id(),
                    posture: Posture::Unattested,
                    score: 0,
                },
                1_100,
                Durability::Batched,
            )
            .unwrap_err();
        assert_eq!(err.code(), Code::STORE_LOCKED);
        assert!(
            err.to_string().contains("read-only"),
            "the refusal must say why: {err}"
        );

        // The reader's projection is a snapshot, so it must be refreshed or it serves an
        // ever-staler set — which for a mediator pulling contracts means never seeing a newly
        // minted one.
        let before = reader.projection.seq;
        writer
            .commit(
                Event::EntityPosture {
                    id: server_id(),
                    posture: Posture::Attested,
                    score: 91,
                },
                1_200,
                Durability::Durable,
            )
            .unwrap();
        assert_eq!(
            reader.projection.seq, before,
            "a snapshot does not move on its own"
        );
        reader.refresh().unwrap();
        assert_eq!(reader.projection.seq, writer.projection.seq);
    }

    #[test]
    fn rotation_starts_a_new_segment_and_replay_spans_them() {
        let tmp = TmpDir::new("rotate");
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME)
                .unwrap()
                .with_segment_bytes(200);
            for i in 0..12 {
                log.append(
                    &Event::EntityPosture {
                        id: agent_id(),
                        posture: Posture::Attested,
                        score: i,
                    },
                    1_000 + u64::from(i),
                    Durability::Durable,
                )
                .unwrap();
            }
            assert!(log.segment() > 1, "should have rotated");
        }

        let found = segments(tmp.path(), STATE_LOG_NAME).unwrap();
        assert!(found.len() > 1, "expected multiple segments, got {found:?}");

        let replay = StateLog::replay(tmp.path(), STATE_LOG_NAME).unwrap();
        assert_eq!(replay.records.len(), 12);
        // Sequence numbers stay globally monotonic across segment boundaries.
        for (i, framed) in replay.records.iter().enumerate() {
            assert_eq!(framed.seq, i as u64 + 1);
        }
    }

    #[test]
    fn a_truncated_tail_is_tolerated() {
        let tmp = TmpDir::new("tail");
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(&Event::Unknown, 1, Durability::Durable).unwrap();
        }
        // Simulate a crash mid-append: a partial final line.
        let path = segment_path(tmp.path(), STATE_LOG_NAME, 1);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"seq\":2,\"ts\":2,\"rec\":{\"kind\":\"entity.p");
        std::fs::write(&path, text).unwrap();

        let replay = StateLog::replay(tmp.path(), STATE_LOG_NAME).unwrap();
        assert_eq!(replay.records.len(), 1);
        assert!(replay.truncated_tail, "the partial line must be reported");
    }

    #[test]
    fn interior_corruption_is_fatal() {
        let tmp = TmpDir::new("corrupt");
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(&Event::Unknown, 1, Durability::Durable).unwrap();
            log.append(&Event::Unknown, 2, Durability::Durable).unwrap();
        }
        let path = segment_path(tmp.path(), STATE_LOG_NAME, 1);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines[0] = "{ this is not json";
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        // Tolerating this would silently drop state, so it must fail loudly.
        let err = StateLog::replay(tmp.path(), STATE_LOG_NAME).unwrap_err();
        assert_eq!(err.code(), Code::CHAIN_BROKEN);
    }

    #[test]
    fn unknown_event_kinds_survive_replay() {
        // §8.14.4: an older replica replaying a newer log must not fail, and must
        // not pretend it applied something it did not understand.
        let tmp = TmpDir::new("forward");
        let path = segment_path(tmp.path(), STATE_LOG_NAME, 1);
        std::fs::write(
            &path,
            "{\"seq\":1,\"ts\":1,\"rec\":{\"kind\":\"entity.teleported\",\"whatever\":true}}\n",
        )
        .unwrap();

        let replay = StateLog::replay(tmp.path(), STATE_LOG_NAME).unwrap();
        assert_eq!(replay.records.len(), 1);
        assert_eq!(replay.records[0].rec, Event::Unknown);

        let (_, report) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert_eq!(report.unknown, 1);
        assert_eq!(report.applied, 0);
        assert!(!report.is_clean());
    }

    // --- Projection ---

    fn seed(tmp: &TmpDir) {
        let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
        for (id, kind) in [(agent_id(), Kind::Agent), (server_id(), Kind::McpServer)] {
            log.append(
                &Event::EntityPut {
                    entity: Box::new(entity(&id, kind)),
                    actor: actor(),
                },
                1_000,
                Durability::Durable,
            )
            .unwrap();
            log.append(
                &Event::EntityTransition {
                    id: id.clone(),
                    to: Lifecycle::Active,
                    why: "admitted".into(),
                    actor: actor(),
                },
                1_001,
                Durability::Durable,
            )
            .unwrap();
            log.append(
                &Event::EntityPosture {
                    id,
                    posture: Posture::Attested,
                    score: 95,
                },
                1_002,
                Durability::Durable,
            )
            .unwrap();
        }
        log.append(
            &Event::EntityRepin {
                id: server_id(),
                pin: Box::new(pin("sha256:m1")),
                cause: RepinCause::Admission,
                diff: PinDiff::default(),
            },
            1_003,
            Durability::Durable,
        )
        .unwrap();
        log.append(
            &Event::ContractMint {
                record: Box::new(contract(
                    "conn_11111111",
                    agent_id(),
                    server_id(),
                    "sha256:m1",
                    9_000,
                )),
            },
            1_004,
            Durability::Durable,
        )
        .unwrap();
    }

    #[test]
    fn projection_applies_the_entity_lifecycle() {
        let tmp = TmpDir::new("proj");
        seed(&tmp);
        let (p, report) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();

        assert!(report.is_clean(), "{report:?}");
        assert_eq!(p.entities.len(), 2);
        let server = &p.entities[&server_id()];
        assert_eq!(server.lifecycle, Lifecycle::Active);
        assert_eq!(server.posture, Posture::Attested);
        assert_eq!(server.posture_score, 95);
        assert_eq!(server.pin.manifest, "sha256:m1");
        assert_eq!(p.seq, 8);
    }

    #[test]
    fn contracts_are_indexed_three_ways() {
        let tmp = TmpDir::new("index");
        seed(&tmp);
        let (p, _) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();

        let cid = Cid::new("conn_11111111").unwrap();
        assert_eq!(p.contracts.len(), 1);
        assert_eq!(p.contracts_for(&agent_id()), vec![cid.clone()]);
        assert_eq!(p.contracts_for(&server_id()), vec![cid.clone()]);
        assert_eq!(p.contracts_for_pin("sha256:m1"), vec![cid]);
        assert!(p.contracts_for_pin("sha256:other").is_empty());
    }

    #[test]
    fn revoke_suspend_and_reinstate_move_status() {
        let tmp = TmpDir::new("status");
        seed(&tmp);
        let cid = Cid::new("conn_11111111").unwrap();
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(
                &Event::ContractSuspend {
                    cid: cid.clone(),
                    cause: SuspendCause::Drift,
                },
                2_000,
                Durability::Durable,
            )
            .unwrap();
        }
        let (p, _) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert_eq!(p.contracts[&cid].status, ContractStatus::Suspended);
        assert!(!p.contracts[&cid].is_live(5_000));

        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(
                &Event::ContractReinstate { cid: cid.clone() },
                2_001,
                Durability::Durable,
            )
            .unwrap();
        }
        let (p, _) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert_eq!(p.contracts[&cid].status, ContractStatus::Active);

        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(
                &Event::ContractRevoke {
                    cid: cid.clone(),
                    reason: "SOC-2291".into(),
                    actor: actor(),
                },
                2_002,
                Durability::Durable,
            )
            .unwrap();
        }
        let (p, _) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert_eq!(p.contracts[&cid].status, ContractStatus::Revoked);
    }

    #[test]
    fn quarantine_revokes_contracts_in_both_directions() {
        let tmp = TmpDir::new("quarantine");
        seed(&tmp);
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            // A second contract where the server is the *caller*, to prove
            // containment is not one-directional.
            log.append(
                &Event::ContractMint {
                    record: Box::new(contract(
                        "conn_22222222",
                        server_id(),
                        agent_id(),
                        "sha256:m1",
                        9_000,
                    )),
                },
                2_000,
                Durability::Durable,
            )
            .unwrap();
            log.append(
                &Event::QuarantineOrder {
                    party: server_id(),
                    reason: "SOC-2291 credential theft".into(),
                    actor: actor(),
                    dual_control: vec![],
                },
                2_001,
                Durability::Durable,
            )
            .unwrap();
        }

        let (p, _) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        let server = &p.entities[&server_id()];
        assert_eq!(server.posture, Posture::Quarantined);
        assert_eq!(server.lifecycle, Lifecycle::Suspended);
        for cid in ["conn_11111111", "conn_22222222"] {
            let cid = Cid::new(cid).unwrap();
            assert_eq!(
                p.contracts[&cid].status,
                ContractStatus::Revoked,
                "{cid} must be cut"
            );
        }
    }

    #[test]
    fn inconsistent_events_are_reported_not_fatal() {
        let tmp = TmpDir::new("inconsistent");
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(
                &Event::EntityTransition {
                    id: agent_id(),
                    to: Lifecycle::Active,
                    why: "no such entity".into(),
                    actor: actor(),
                },
                1_000,
                Durability::Durable,
            )
            .unwrap();
        }
        let (p, report) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert!(p.entities.is_empty());
        assert_eq!(report.applied, 0);
        assert_eq!(report.inconsistent.len(), 1);
        assert!(report.inconsistent[0].contains("unknown entity"));
    }

    #[test]
    fn expiring_before_lists_only_live_contracts() {
        let tmp = TmpDir::new("expiring");
        seed(&tmp);
        let (p, _) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert!(p.expiring_before(8_000).is_empty());
        assert_eq!(p.expiring_before(9_000).len(), 1);

        // A revoked contract is not "expiring", it is already gone.
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(
                &Event::ContractRevoke {
                    cid: Cid::new("conn_11111111").unwrap(),
                    reason: "done".into(),
                    actor: actor(),
                },
                2_000,
                Durability::Durable,
            )
            .unwrap();
        }
        let (p, _) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert!(p.expiring_before(9_000).is_empty());
    }

    // --- snapshots ---

    #[test]
    fn snapshot_plus_tail_equals_full_replay() {
        let tmp = TmpDir::new("snapshot");
        seed(&tmp);

        let (full, _) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        full.save_snapshot(tmp.path()).unwrap();

        // Append more after the snapshot.
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(
                &Event::EntityPosture {
                    id: server_id(),
                    posture: Posture::Degraded,
                    score: 40,
                },
                3_000,
                Durability::Durable,
            )
            .unwrap();
        }

        let (from_snapshot, report) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert!(report.is_clean(), "{report:?}");
        // Only the tail was replayed, not the eight seeded events.
        assert_eq!(report.applied, 1);
        assert_eq!(
            from_snapshot.entities[&server_id()].posture,
            Posture::Degraded
        );
        assert_eq!(from_snapshot.entities[&server_id()].posture_score, 40);
        assert_eq!(from_snapshot.contracts.len(), 1);
        // Indexes survive the snapshot round trip.
        assert_eq!(
            from_snapshot.contracts_for_pin("sha256:m1"),
            vec![Cid::new("conn_11111111").unwrap()]
        );
    }

    #[test]
    fn a_partial_snapshot_is_never_loaded() {
        let tmp = TmpDir::new("partial");
        seed(&tmp);
        // A `.tmp` file is what a crash mid-write leaves behind; it must be
        // invisible to the loader, which only sees renamed files.
        std::fs::write(tmp.path().join("snapshot-000099.json.tmp"), "{ partial").unwrap();
        let (p, report) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert!(report.is_clean());
        assert_eq!(p.entities.len(), 2);
    }

    // --- point in time ---

    #[test]
    fn as_of_ignores_later_events() {
        let tmp = TmpDir::new("asof");
        seed(&tmp);
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(
                &Event::QuarantineOrder {
                    party: server_id(),
                    reason: "later".into(),
                    actor: actor(),
                    dual_control: vec![],
                },
                5_000,
                Durability::Durable,
            )
            .unwrap();
        }

        // As of before the quarantine, the estate was healthy — which is exactly
        // what a regulator asking "what did you have on 30 June" needs.
        let (before, _) = Projection::as_of(tmp.path(), STATE_LOG_NAME, 4_000).unwrap();
        assert_eq!(before.entities[&server_id()].posture, Posture::Attested);
        assert_eq!(
            before.contracts[&Cid::new("conn_11111111").unwrap()].status,
            ContractStatus::Active
        );

        let (after, _) = Projection::as_of(tmp.path(), STATE_LOG_NAME, 6_000).unwrap();
        assert_eq!(after.entities[&server_id()].posture, Posture::Quarantined);
    }

    #[test]
    fn as_of_does_not_use_snapshots() {
        let tmp = TmpDir::new("asof-snap");
        seed(&tmp);
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            log.append(
                &Event::EntityPosture {
                    id: server_id(),
                    posture: Posture::Degraded,
                    score: 10,
                },
                5_000,
                Durability::Durable,
            )
            .unwrap();
        }
        // Snapshot the *current* (degraded) state, then ask for the past.
        let (now, _) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        now.save_snapshot(tmp.path()).unwrap();

        let (past, _) = Projection::as_of(tmp.path(), STATE_LOG_NAME, 4_000).unwrap();
        assert_eq!(
            past.entities[&server_id()].posture,
            Posture::Attested,
            "a snapshot of later state must not leak into a point-in-time query"
        );
    }

    #[test]
    fn helpers_are_deterministic() {
        let tmp = TmpDir::new("helpers");
        seed(&tmp);
        let (p, _) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        let ids = sorted_entity_ids(&p);
        assert_eq!(ids.len(), 2);
        assert!(ids[0].as_str() < ids[1].as_str());
        assert_eq!(entity_map(&p).len(), 2);
    }
    #[test]
    fn a_needs_manifest_records_its_approver_set_and_last_write_wins() {
        // Unlike offers, a needs manifest carries no version — its identity is the commit it was
        // read at, so the fold follows the log's order rather than taking a maximum.
        let tmp = TmpDir::new("need-declared");
        let asset = agent_id();
        let mk = |who: &[&str], sha: &str| NeedRecord {
            asset: asset.clone(),
            approval: Some(crate::authority::ApprovalBlock {
                approvers: who.iter().map(|s| (*s).to_string()).collect(),
                min: 1,
            }),
            repo: "acme/recon".to_string(),
            sha: sha.to_string(),
        };
        {
            let mut log = StateLog::open(tmp.path(), STATE_LOG_NAME).unwrap();
            for (who, sha, at) in [(&["a"][..], "s1", 1_000u64), (&["a", "b"][..], "s2", 1_001)] {
                log.append(
                    &Event::NeedDeclared {
                        need: Box::new(mk(who, sha)),
                        actor: actor(),
                    },
                    at,
                    Durability::Durable,
                )
                .unwrap();
            }
        }
        let (projection, report) = Projection::rebuild(tmp.path(), STATE_LOG_NAME).unwrap();
        assert!(report.is_clean(), "{report:?}");
        let held = projection.needs.get(&asset).expect("the declaration persists");
        assert_eq!(held.sha, "s2", "last write wins for a versionless manifest");
        assert_ne!(
            held.approval_digest(),
            mk(&["a"], "s1").approval_digest(),
            "adding an approver on the consumer side must be visible too"
        );
    }

    #[test]
    fn offers_and_needs_reduce_an_approver_set_identically() {
        // One rule, both sides. Two implementations would drift, and the one that mattered would
        // be whichever side the estate happened to look at.
        let block = crate::authority::ApprovalBlock {
            approvers: vec!["human:S.Iyer".to_string(), "p.rao".to_string()],
            min: 2,
        };
        let need = crate::store::NeedRecord {
            asset: EntityId::new("urn:acme:agent:recon").unwrap(),
            approval: Some(block.clone()),
            repo: "r".to_string(),
            sha: "s".to_string(),
        };
        assert_eq!(
            need.approval_digest(),
            crate::offer::approval_digest(Some(&block))
        );
    }

}
