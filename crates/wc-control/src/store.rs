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
    _lock: crate::lock::LockGuard,
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
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| {
            WcError::with_detail(
                Code::STORE_LOCKED,
                format!("cannot create {}", dir.display()),
            )
            .with_source(e)
        })?;

        let lock = crate::lock::acquire(&dir, name)?;

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
    /// The control plane's own scheduler.
    Sentinel,
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
    /// An event kind this binary does not know. Counted, never silently dropped.
    #[serde(other)]
    Unknown,
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

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
                    match entity.clear_quarantine(framed.ts) {
                        Ok(()) => report.applied += 1,
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
    anomalies: Vec<String>,
}

impl Store {
    /// Open the state directory: rebuild the projection, then take the writer
    /// lock. The report says whether the rebuild was clean.
    pub fn open(dir: impl AsRef<Path>) -> Result<(Store, RebuildReport)> {
        let dir = dir.as_ref().to_path_buf();
        let (projection, report) = Projection::rebuild(&dir, STATE_LOG_NAME)?;
        let log = StateLog::open(&dir, STATE_LOG_NAME)?;
        Ok((
            Store {
                projection,
                log,
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
            schema: CONTRACT_SCHEMA,
        }
    }

    // --- Log mechanics ---

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
}
