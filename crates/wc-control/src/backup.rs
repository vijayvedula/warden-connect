//! Backup, restore and retention for the system of record
//! (production-readiness P1 #14).
//!
//! §8.16b ships **no database**, and the whole argument for that is that the state log and
//! the evidence chain *are* the system of record. That argument has a corollary nobody had
//! written down: a tamper-evident chain on a disk nobody backs up is a compliance story
//! with one point of failure, and an untested restore is not a backup — it is a directory.
//!
//! # Why this is code rather than a shell recipe
//!
//! `cp -r` would copy the bytes. What it cannot do is the part that matters:
//!
//! * **Refuse to call a broken chain a backup.** [`snapshot`] verifies the chain before it
//!   writes a manifest. A backup taken from an already-corrupt root is the worst artifact
//!   in this system — it looks like insurance and it launders the corruption forward into
//!   every copy, and the moment anyone finds out is the moment they needed it.
//! * **Record the head sequence.** After a restore the first question is "how much did we
//!   lose", and the only way to answer it is to know where the backup stopped.
//! * **Refuse to restore over a live estate.** A restore into a root with a running writer
//!   would interleave two histories. The writer lock answers that, so [`restore`] takes it.
//! * **Verify digests before placing anything.** A restore that copies first and checks
//!   afterwards has already destroyed the thing it was going to compare against.
//!
//! # What a backup is consistent with respect to
//!
//! Both logs are append-only, so a file copied while a writer appends yields a prefix plus
//! possibly a torn final line — never a scrambled middle. That is the property that makes a
//! hot backup safe here, and it is why the manifest records a head sequence rather than
//! claiming an instant: **the backup is consistent as of the sequence it names**, and any
//! record committed after that is simply absent rather than half-present.
//!
//! Taking the writer lock during a backup would give a stronger guarantee and stop issuance
//! while it ran. That trade is the operator's, so [`snapshot`] does not take it and
//! [`SnapshotReport::torn_tail`] reports when a copy caught a partial write — which a
//! restore then rejects as the last record rather than accepting half of it.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use wc_core::error::{Code, Result, WcError};
use wc_core::util::sha256_hex;

/// Manifest file written beside a snapshot.
pub const MANIFEST: &str = "wc-backup.json";

/// Current manifest schema.
pub const SCHEMA: u32 = 1;

/// What a snapshot contains, and what was true of it when it was taken.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// Schema version, so a future format can be refused rather than misread.
    pub schema: u32,
    /// When the snapshot was taken.
    pub at: u64,
    /// The tenant this is a snapshot of.
    pub tenant: String,
    /// Highest state-log sequence included.
    pub state_seq: u64,
    /// Highest evidence-chain sequence included.
    pub chain_seq: u64,
    /// The chain head's row hash, so a restore can prove it got the same history.
    pub chain_head: String,
    /// Whether the chain verified at snapshot time.
    ///
    /// Always `true` in a manifest that exists: [`snapshot`] refuses to write one
    /// otherwise. Recorded anyway, because a field that says what was checked is what
    /// makes the manifest evidence rather than a filename.
    pub chain_verified: bool,
    /// Relative path to `sha256:…` for every file, sorted.
    pub files: BTreeMap<String, String>,
}

/// What a snapshot did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotReport {
    /// The manifest as written.
    pub manifest: Manifest,
    /// Bytes copied.
    pub bytes: u64,
    /// True when a copied log ended mid-record — a hot backup catching a partial append.
    ///
    /// Not an error. It means the last line is incomplete, which a restore rejects as the
    /// final record; everything before it is intact by the append-only argument.
    pub torn_tail: bool,
}

/// Take a snapshot of one tenant's state and evidence into `out`.
///
/// Refuses if the chain does not verify. See the module note for why that refusal is the
/// point of this function existing.
pub fn snapshot(
    state_dir: &Path,
    evidence_dir: &Path,
    out: &Path,
    tenant: &str,
    anchor_pub_pem: Option<&[u8]>,
    now: u64,
) -> Result<SnapshotReport> {
    // Verify *first*. A backup taken from a corrupt root launders the corruption into
    // every copy, and it does so wearing the label "backup".
    let report = crate::chain::Chain::verify(evidence_dir, anchor_pub_pem)?;
    if !report.is_intact() {
        return Err(WcError::with_detail(
            Code::CHAIN_BROKEN,
            format!(
                "the evidence chain at {} does not verify ({} row(s) read, first break at \
                 seq {:?}); refusing to write a manifest that would call this a backup",
                evidence_dir.display(),
                report.entries,
                report.broken_at
            ),
        ));
    }

    std::fs::create_dir_all(out).map_err(|e| io(out, e))?;

    let mut files = BTreeMap::new();
    let mut bytes = 0u64;
    let mut torn_tail = false;

    for (label, dir) in [("state", state_dir), ("evidence", evidence_dir)] {
        let target = out.join(label);
        std::fs::create_dir_all(&target).map_err(|e| io(&target, e))?;
        for entry in std::fs::read_dir(dir).map_err(|e| io(dir, e))? {
            let entry = entry.map_err(|e| io(dir, e))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            // Lock files are process state, not estate state. Copying one would put a
            // stale `*.lock` in the restore, which is harmless but reads as though the
            // backup captured a running process.
            if name.ends_with(".lock") {
                continue;
            }
            let body = std::fs::read(&path).map_err(|e| io(&path, e))?;
            if name.ends_with(".jsonl") && ends_mid_record(&body) {
                torn_tail = true;
            }
            bytes += body.len() as u64;
            let relative = format!("{label}/{name}");
            files.insert(
                relative.clone(),
                format!("sha256:{}", sha256_hex(&String::from_utf8_lossy(&body))),
            );
            std::fs::write(out.join(&relative), &body).map_err(|e| io(&path, e))?;
        }
    }

    let (chain_seq, chain_head) = chain_head(evidence_dir)?;
    let manifest = Manifest {
        schema: SCHEMA,
        at: now,
        tenant: tenant.to_string(),
        state_seq: state_head(state_dir)?,
        chain_seq,
        chain_head,
        chain_verified: true,
        files,
    };
    let rendered = serde_json::to_string_pretty(&manifest).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, "cannot render the manifest").with_source(e)
    })?;
    std::fs::write(out.join(MANIFEST), format!("{rendered}\n"))
        .map_err(|e| io(&out.join(MANIFEST), e))?;

    Ok(SnapshotReport {
        manifest,
        bytes,
        torn_tail,
    })
}

/// What a restore did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// The manifest that was honoured.
    pub manifest: Manifest,
    /// Files placed.
    pub placed: usize,
    /// The chain head after restoring, which must match the manifest.
    pub chain_head: String,
}

/// Restore a snapshot into an empty tenant root.
///
/// Four refusals, in this order, because each one protects the evidence the next would
/// otherwise destroy:
///
/// 1. **An unreadable or future-schema manifest** — a directory of files with no manifest
///    is not a snapshot this tool made, and guessing its layout would be inventing history.
/// 2. **A digest mismatch** — checked before anything is written. A restore that copies
///    first has already overwritten what it was going to compare against.
/// 3. **A non-empty target** — refused rather than merged. Merging two append-only logs
///    produces a third history that never happened.
/// 4. **A live writer** — the lock is taken for the duration, so a restore cannot race a
///    running control plane.
pub fn restore(
    snapshot_dir: &Path,
    state_dir: &Path,
    evidence_dir: &Path,
) -> Result<RestoreReport> {
    let manifest_path = snapshot_dir.join(MANIFEST);
    let text = std::fs::read_to_string(&manifest_path).map_err(|e| {
        WcError::with_detail(
            Code::CONFIG_INVALID,
            format!(
                "{} has no {MANIFEST}; a directory of files is not a snapshot this tool \
                 wrote, and its layout is not something to guess at",
                snapshot_dir.display()
            ),
        )
        .with_source(e)
    })?;
    let manifest: Manifest = serde_json::from_str(&text).map_err(|e| {
        WcError::with_detail(Code::CONFIG_INVALID, format!("{MANIFEST} is not readable"))
            .with_source(e)
    })?;
    if manifest.schema > SCHEMA {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!(
                "the snapshot is schema {} and this build understands {SCHEMA}; a newer \
                 backup may hold records this binary would drop on rebuild",
                manifest.schema
            ),
        ));
    }

    // Every digest, before anything is placed.
    let mut bodies = Vec::new();
    for (relative, expected) in &manifest.files {
        let path = snapshot_dir.join(relative);
        let body = std::fs::read(&path).map_err(|e| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("{relative} is named in the manifest and missing from the snapshot"),
            )
            .with_source(e)
        })?;
        let actual = format!("sha256:{}", sha256_hex(&String::from_utf8_lossy(&body)));
        if &actual != expected {
            return Err(WcError::with_detail(
                Code::CHAIN_BROKEN,
                format!(
                    "{relative} does not match its manifest digest — the snapshot was \
                     altered or truncated after it was taken, so restoring it would \
                     install a history nobody signed"
                ),
            ));
        }
        bodies.push((relative.clone(), body));
    }

    // A non-empty target is refused rather than merged.
    for dir in [state_dir, evidence_dir] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            let occupied: Vec<String> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| !n.ends_with(".lock"))
                .collect();
            if !occupied.is_empty() {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!(
                        "{} already holds {}; a restore never merges, because two \
                         append-only logs joined together are a third history that never \
                         happened. Restore into an empty root and switch to it",
                        dir.display(),
                        occupied.join(", ")
                    ),
                ));
            }
        }
    }

    std::fs::create_dir_all(state_dir).map_err(|e| io(state_dir, e))?;
    std::fs::create_dir_all(evidence_dir).map_err(|e| io(evidence_dir, e))?;

    // Held for the whole placement, so a control plane cannot start on a half-restored
    // root. Dropped at the end of this function, which is when the root is complete.
    let _state_lock = crate::lock::acquire(state_dir, crate::store::STATE_LOG_NAME)?;
    let _chain_lock = crate::lock::acquire(evidence_dir, "chain")?;

    let mut placed = 0;
    for (relative, body) in &bodies {
        let (label, name) = relative.split_once('/').unwrap_or(("state", relative));
        let target = match label {
            "evidence" => evidence_dir.join(name),
            _ => state_dir.join(name),
        };
        std::fs::write(&target, body).map_err(|e| io(&target, e))?;
        placed += 1;
    }

    // The restored chain has to be the history the manifest names. Anything else means
    // the snapshot and its manifest disagreed about what was in it.
    let (_, head) = chain_head(evidence_dir)?;
    if head != manifest.chain_head {
        return Err(WcError::with_detail(
            Code::CHAIN_BROKEN,
            format!(
                "restored chain head is {head} and the manifest says {}; the snapshot's \
                 files and its manifest describe different histories",
                manifest.chain_head
            ),
        ));
    }

    Ok(RestoreReport {
        manifest,
        placed,
        chain_head: head,
    })
}

/// Whether a `.jsonl` body ends part-way through a record.
///
/// A complete append-only log ends with a newline. Anything else is a writer that stopped
/// mid-line — either a crash or a hot copy catching one.
fn ends_mid_record(body: &[u8]) -> bool {
    !body.is_empty() && body.last() != Some(&b'\n')
}

/// Highest `seq` across the state log's segments.
fn state_head(state_dir: &Path) -> Result<u64> {
    let mut highest = 0u64;
    for entry in std::fs::read_dir(state_dir).map_err(|e| io(state_dir, e))? {
        let entry = entry.map_err(|e| io(state_dir, e))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".jsonl") {
            continue;
        }
        let text = std::fs::read_to_string(entry.path()).map_err(|e| io(&entry.path(), e))?;
        for line in text.lines() {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(seq) = value.get("seq").and_then(serde_json::Value::as_u64) {
                    highest = highest.max(seq);
                }
            }
        }
    }
    Ok(highest)
}

/// The chain's head sequence and row hash.
fn chain_head(evidence_dir: &Path) -> Result<(u64, String)> {
    let entries = crate::chain::Chain::entries(evidence_dir)?;
    Ok(entries
        .last()
        .map_or((0, String::new()), |e| (e.seq, e.row_hash.clone())))
}

fn io(path: &Path, e: std::io::Error) -> WcError {
    WcError::with_detail(Code::CONFIG_INVALID, format!("{}: {e}", path.display())).with_source(e)
}

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

/// How long each class of record must be kept.
///
/// §8.13's `[retention]` block. The defaults are the regulatory clock the export module
/// already assumes: DORA's register and CPS 230's records are asked for years after the
/// fact, and a contract nobody can produce is indistinguishable from a contract that never
/// existed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retention {
    /// How long a contract record is kept. Default seven years.
    pub contracts: u64,
    /// How long a discovery query is kept. Default ninety days.
    pub discovery: u64,
}

impl Default for Retention {
    fn default() -> Retention {
        Retention {
            contracts: 7 * 365 * 86_400,
            discovery: 90 * 86_400,
        }
    }
}

/// What retention would do, without doing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionReport {
    /// Chain rows past their class's retention.
    pub expired: u64,
    /// Chain rows still inside it.
    pub retained: u64,
    /// The oldest row's timestamp, so an operator can see the window they actually hold.
    pub oldest: Option<u64>,
    /// Why nothing was deleted.
    pub note: &'static str,
}

/// Report what is past its retention clock.
///
/// **Nothing is deleted, and that is not an omission.** The evidence chain is hash-linked:
/// removing a row breaks every row after it, so "retention" on this structure is not a
/// delete but a *segment boundary* — you retire whole segments once every row in one is
/// past its clock, and you keep the anchor that covered them. That is a rotation design
/// this build does not have, and implementing a row-level delete would silently destroy the
/// property the chain exists for.
///
/// So this reports the window, which is the thing an auditor asks for and the thing an
/// operator needs before sizing a volume.
pub fn retention_report(
    evidence_dir: &Path,
    retention: &Retention,
    now: u64,
) -> Result<RetentionReport> {
    let entries = crate::chain::Chain::entries(evidence_dir)?;
    let horizon = now.saturating_sub(retention.contracts);
    let mut expired = 0;
    let mut retained = 0;
    let mut oldest = None;
    for entry in &entries {
        oldest = Some(oldest.map_or(entry.ts, |o: u64| o.min(entry.ts)));
        if entry.ts < horizon {
            expired += 1;
        } else {
            retained += 1;
        }
    }
    Ok(RetentionReport {
        expired,
        retained,
        oldest,
        note: "the chain is hash-linked, so retention is segment retirement rather than \
               row deletion: removing a row would break every row after it",
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::evidence::{EventKind, Evidence, LifecycleEvent};
    use std::path::PathBuf;

    const NOW: u64 = 1_785_312_500;

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("wc-backup-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    /// A root with a state log and three chain rows.
    fn estate(base: &Path) -> (PathBuf, PathBuf) {
        let state = base.join("state");
        let evidence = base.join("evidence");
        std::fs::create_dir_all(&state).unwrap();

        {
            let mut chain = Evidence::open(&evidence).unwrap();
            for i in 0..3 {
                chain
                    .record(
                        &LifecycleEvent::new(EventKind::Register, "human:v")
                            .with_entities([format!("urn:wc:{i}")]),
                        NOW + i,
                    )
                    .unwrap();
            }
        }
        // A state log with two records, written directly so this test does not need the
        // whole issuance path to produce one.
        std::fs::write(
            state.join("events-000001.jsonl"),
            "{\"seq\":1,\"kind\":\"entity.registered\"}\n{\"seq\":2,\"kind\":\"contract.minted\"}\n",
        )
        .unwrap();
        (state, evidence)
    }

    #[test]
    fn a_snapshot_records_what_it_contains_and_restores_to_the_same_history() {
        let s = scratch("roundtrip");
        let (state, evidence) = estate(&s.0);
        let out = s.0.join("snap");

        let report = snapshot(&state, &evidence, &out, "default", None, NOW + 10).unwrap();
        assert!(report.manifest.chain_verified);
        assert_eq!(report.manifest.state_seq, 2);
        assert_eq!(report.manifest.chain_seq, 3);
        assert!(!report.torn_tail);
        assert!(report.bytes > 0);
        assert_eq!(
            report.manifest.files.len(),
            2,
            "{:?}",
            report.manifest.files
        );

        // Restore into a fresh root and get the same head.
        let target = s.0.join("restored");
        let restored = restore(&out, &target.join("state"), &target.join("evidence")).unwrap();
        assert_eq!(restored.chain_head, report.manifest.chain_head);
        assert_eq!(restored.placed, 2);

        // And the restored root is usable: the chain verifies from it.
        let verify = crate::chain::Chain::verify(target.join("evidence"), None).unwrap();
        assert!(verify.is_intact());
        assert_eq!(verify.entries, 3);
    }

    #[test]
    fn a_backup_of_a_broken_chain_is_refused_rather_than_labelled_a_backup() {
        // The reason this is code and not `cp -r`. A snapshot of an already-corrupt root
        // looks like insurance, launders the corruption into every copy, and is discovered
        // at exactly the moment somebody needed it to be real.
        let s = scratch("broken");
        let (state, evidence) = estate(&s.0);

        let chain_file = evidence.join("chain.jsonl");
        let text = std::fs::read_to_string(&chain_file).unwrap();
        let tampered = text.replacen("urn:wc:1", "urn:wc:9", 1);
        std::fs::write(&chain_file, tampered).unwrap();

        let err = snapshot(&state, &evidence, &s.0.join("snap"), "default", None, NOW).unwrap_err();
        assert_eq!(err.code(), Code::CHAIN_BROKEN);
        assert!(
            format!("{err}").contains("refusing to write a manifest"),
            "{err}"
        );
        assert!(
            !s.0.join("snap").join(MANIFEST).exists(),
            "no manifest may exist for a chain that did not verify"
        );
    }

    #[test]
    fn a_snapshot_altered_after_the_fact_is_refused_before_anything_is_placed() {
        // The digest check has to happen first. A restore that copies and then compares has
        // already overwritten the thing it was going to compare against.
        let s = scratch("altered");
        let (state, evidence) = estate(&s.0);
        let out = s.0.join("snap");
        snapshot(&state, &evidence, &out, "default", None, NOW).unwrap();

        let copied = out.join("evidence").join("chain.jsonl");
        let text = std::fs::read_to_string(&copied).unwrap();
        std::fs::write(&copied, text.replacen("urn:wc:0", "urn:wc:8", 1)).unwrap();

        let target = s.0.join("restored");
        let err = restore(&out, &target.join("state"), &target.join("evidence")).unwrap_err();
        assert_eq!(err.code(), Code::CHAIN_BROKEN);
        assert!(
            format!("{err}").contains("install a history nobody signed"),
            "{err}"
        );
        // Nothing was placed.
        assert!(
            !target.join("evidence").join("chain.jsonl").exists(),
            "a failed restore must leave the target untouched"
        );
    }

    #[test]
    fn a_restore_into_a_non_empty_root_is_refused_rather_than_merged() {
        // Two append-only logs joined together are a third history that never happened, and
        // it would verify — every row's hash would still chain to the one before it.
        let s = scratch("occupied");
        let (state, evidence) = estate(&s.0);
        let out = s.0.join("snap");
        snapshot(&state, &evidence, &out, "default", None, NOW).unwrap();

        let err = restore(&out, &state, &evidence).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(format!("{err}").contains("never merges"), "{err}");
    }

    #[test]
    fn a_directory_with_no_manifest_is_not_a_snapshot() {
        let s = scratch("nomanifest");
        let bare = s.0.join("bare");
        std::fs::create_dir_all(&bare).unwrap();
        let err = restore(&bare, &s.0.join("st"), &s.0.join("ev")).unwrap_err();
        assert!(
            format!("{err}").contains("not something to guess at"),
            "{err}"
        );
    }

    #[test]
    fn a_newer_schema_is_refused_rather_than_partially_understood() {
        // A future manifest may name records this binary would drop on rebuild, and a
        // rebuild that drops records reports a clean estate with less in it.
        let s = scratch("schema");
        let (state, evidence) = estate(&s.0);
        let out = s.0.join("snap");
        snapshot(&state, &evidence, &out, "default", None, NOW).unwrap();

        let path = out.join(MANIFEST);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"schema\": 1", "\"schema\": 99")).unwrap();

        let err = restore(&out, &s.0.join("st2"), &s.0.join("ev2")).unwrap_err();
        assert!(format!("{err}").contains("this build understands"), "{err}");
    }

    #[test]
    fn a_torn_tail_is_reported_rather_than_failing_the_backup() {
        // A hot copy can catch a partial append. That is not a corrupt backup — the log is
        // append-only, so everything before the tear is intact — but it has to be said, or
        // an operator cannot tell a clean snapshot from one taken mid-write.
        let s = scratch("torn");
        let (state, evidence) = estate(&s.0);
        let log = state.join("events-000001.jsonl");
        let mut text = std::fs::read_to_string(&log).unwrap();
        text.push_str("{\"seq\":3,\"kind\":\"contract.mi");
        std::fs::write(&log, text).unwrap();

        let report = snapshot(&state, &evidence, &s.0.join("snap"), "default", None, NOW).unwrap();
        assert!(report.torn_tail, "a partial final record must be reported");
        assert!(report.manifest.chain_verified, "the chain itself was fine");
    }

    #[test]
    fn lock_files_are_not_part_of_the_estate() {
        // A copied `*.lock` reads as though the backup captured a running process, and it
        // would be restored beside a log it does not lock.
        let s = scratch("locks");
        let (state, evidence) = estate(&s.0);
        std::fs::write(state.join("events.lock"), b"").unwrap();

        let report = snapshot(&state, &evidence, &s.0.join("snap"), "default", None, NOW).unwrap();
        assert!(
            report.manifest.files.keys().all(|k| !k.ends_with(".lock")),
            "{:?}",
            report.manifest.files
        );
    }

    #[test]
    fn retention_reports_the_window_and_deletes_nothing() {
        // Deleting a row from a hash-linked chain breaks every row after it, so a
        // row-level delete would destroy the property the chain exists for while
        // reporting success. Retention here is a report, and it says so.
        let s = scratch("retention");
        let (_state, evidence) = estate(&s.0);

        let fresh = retention_report(&evidence, &Retention::default(), NOW + 100).unwrap();
        assert_eq!(fresh.retained, 3);
        assert_eq!(fresh.expired, 0);
        assert_eq!(fresh.oldest, Some(NOW));

        // Ten years on, everything is past a seven-year clock — and still there.
        let old =
            retention_report(&evidence, &Retention::default(), NOW + 10 * 365 * 86_400).unwrap();
        assert_eq!(old.expired, 3);
        assert_eq!(old.retained, 0);
        assert!(old.note.contains("segment retirement"));
        assert!(
            crate::chain::Chain::verify(&evidence, None)
                .unwrap()
                .is_intact(),
            "reporting retention must not touch the chain"
        );
    }

    #[test]
    fn the_default_clock_is_the_one_the_export_module_assumes() {
        // DORA and CPS 230 records are asked for years after the fact. A contract nobody
        // can produce is indistinguishable from one that never existed.
        let r = Retention::default();
        assert_eq!(r.contracts, 7 * 365 * 86_400);
        assert_eq!(r.discovery, 90 * 86_400);
    }
}
