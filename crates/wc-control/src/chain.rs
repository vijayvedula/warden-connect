//! The tamper-evident evidence chain and its signed anchors
//! (`docs/08-lld.md` §8.5.8, §8.8.1).
//!
//! Each entry's `row_hash` covers its own content **and the previous
//! `row_hash`**, so altering any past entry breaks the chain from that point
//! forward. The accountability fields — who was answerable, under which contract,
//! against which policy version — are folded into the hash too, which is the
//! property that makes "who was accountable" unrewritable rather than merely
//! recorded.
//!
//! # Why this is not the state log
//!
//! [`crate::store`] is *state*: compacted, snapshotted, rebuilt. This is
//! *evidence*: never compacted, never rewritten, and externally anchored. A
//! regulator's question is not "what does the system think now" but "what
//! happened, and prove nobody edited it since".
//!
//! # Anchors
//!
//! A chain verifies only against itself, so an attacker who can rewrite the whole
//! file can produce a self-consistent forgery. Signed checkpoints close that: every
//! `interval` appends, the head `(seq, row_hash)` is signed ES256 and written to a
//! separate file. Verification then proves the chain matches a signature made at a
//! point in time — and the signing key belongs somewhere the control plane cannot
//! reach (§8.12.1), which is what makes control-plane compromise *detectable*.
//!
//! # Format compatibility
//!
//! The row shape and hash construction match Warden core's `audit.rs` by design, so
//! one verifier and one SIEM pipeline handle both chains. That compatibility is held
//! by the golden vectors in `fixtures/chain/`, not by a shared library — checked
//! rather than assumed (§8.3).

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use wc_core::contract::IssuerKey;
use wc_core::error::{Code, Result, WcError};
use wc_core::util::{canonical_json, sha256_hex};

use crate::lock::{self, LockGuard};

/// The entry schema this build writes.
pub const ENTRY_SCHEMA: u16 = 1;

/// Conventional file names inside a tenant's `evidence/` directory.
pub const CHAIN_FILE: &str = "chain.jsonl";
/// Anchor file name.
pub const ANCHOR_FILE: &str = "anchor.jsonl";
/// The tombstone left behind when a segment is retired.
pub const RETIRED_FILE: &str = "retired.json";
/// Where retired segments are moved to.
pub const RETIRED_DIR: &str = "retired";

/// The `kid` an anchor stamps into its checkpoints.
///
/// A checkpoint is verified with a key the caller supplies (`--anchor-pub`), not one
/// resolved from the header, so this is a label rather than a lookup. It is fixed so
/// that a checkpoint says which role signed it when read by hand.
pub const ANCHOR_KID: &str = "wc-anchor";

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// What a caller supplies; the chain assigns everything else.
#[derive(Debug, Clone, Default)]
pub struct EntryDraft {
    /// Event kind, e.g. `contract.mint`.
    pub kind: String,
    /// Connection id, where the event has one. The correlation root.
    pub cid: Option<String>,
    /// The contract artifact's `jti`.
    pub contract_jti: Option<String>,
    /// Entities involved.
    pub entities: Vec<String>,
    /// Who acted.
    pub actor: String,
    /// `allow` | `deny` | `record` | `hold`.
    pub decision: String,
    /// Human reason.
    pub reason: String,
    /// Policy version in force.
    pub policy_version: String,
    /// Kind-specific payload. Redacted before it gets here.
    pub detail: Value,
}

/// One link in the chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// Monotonic sequence number, from 1.
    pub seq: u64,
    /// Append time, unix seconds.
    pub ts: u64,
    /// Event kind.
    pub kind: String,
    /// Connection id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// Contract `jti`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_jti: Option<String>,
    /// Entities involved.
    #[serde(default)]
    pub entities: Vec<String>,
    /// Who acted.
    pub actor: String,
    /// The decision recorded.
    pub decision: String,
    /// Human reason.
    pub reason: String,
    /// Policy version.
    #[serde(default)]
    pub policy_version: String,
    /// Kind-specific payload.
    #[serde(default)]
    pub detail: Value,
    /// Previous entry's `row_hash`; empty for the first entry.
    pub prev_hash: String,
    /// This entry's hash, over its content and `prev_hash`.
    pub row_hash: String,
    /// Row schema version.
    #[serde(default = "default_schema")]
    pub schema: u16,
}

fn default_schema() -> u16 {
    ENTRY_SCHEMA
}

impl Entry {
    /// The exact bytes `row_hash` is taken over.
    ///
    /// Canonical JSON of every field *except* `row_hash` itself, with `prev_hash`
    /// included — so the hash covers both this entry's content and its position in
    /// the chain. Every accountability field is in here: omitting `cid` would let
    /// an attacker re-attribute an action to a different connection without
    /// breaking the chain, which would defeat the whole correlation-root claim.
    #[must_use]
    pub fn hash_input(&self) -> String {
        canonical_json(&json!({
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "cid": self.cid,
            "contract_jti": self.contract_jti,
            "entities": self.entities,
            "actor": self.actor,
            "decision": self.decision,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
            "schema": self.schema,
        }))
    }

    /// Recompute this entry's hash.
    #[must_use]
    pub fn compute_row_hash(&self) -> String {
        sha256_hex(&self.hash_input())
    }

    /// Whether the stored hash matches the content.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.compute_row_hash() == self.row_hash
    }
}

// ---------------------------------------------------------------------------
// Anchors
// ---------------------------------------------------------------------------

/// A signed checkpoint of the chain head.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Head sequence at signing time.
    pub seq: u64,
    /// Head `row_hash` at signing time.
    pub row_hash: String,
    /// When it was signed.
    pub ts: u64,
}

/// Signs chain checkpoints. The key belongs offline or in an HSM: an attacker who
/// controls the control plane must not be able to re-sign a forged chain.
///
/// That sentence used to be aspirational — the key was an in-process `EncodingKey`
/// read from a PEM, so whoever held the box held the key. It now goes through
/// [`IssuerKey`], which means custody is a deployment choice
/// (`docs/key-custody.md`), and this is the **first** key that should move: a
/// checkpoint is periodic and off the request path, so there is no latency argument
/// against putting it behind a token, and it is the one key whose compromise makes
/// the evidence chain rewritable by the party the chain exists to constrain.
#[derive(Debug)]
pub struct Anchor {
    key: IssuerKey,
    path: PathBuf,
    interval: u64,
}

impl Anchor {
    /// Build a signer from an EC private key in PEM form.
    ///
    /// The weakest custody available, kept because it is the only one that needs no
    /// setup. Prefer [`Anchor::with_signer`] anywhere the chain is evidence somebody
    /// outside the operating team will be asked to rely on.
    pub fn from_ec_pem(key_pem: &[u8], path: impl Into<PathBuf>, interval: u64) -> Result<Anchor> {
        let key = IssuerKey::ec_pem(ANCHOR_KID, key_pem, Algorithm::ES256).map_err(|e| {
            WcError::with_detail(Code::CHAIN_APPEND_FAILED, "anchor key is not an EC PEM")
                .with_source(e)
        })?;
        Ok(Anchor::with_signer(key, path, interval))
    }

    /// Build a signer around a key whose private half may be elsewhere.
    #[must_use]
    pub fn with_signer(key: IssuerKey, path: impl Into<PathBuf>, interval: u64) -> Anchor {
        Anchor {
            key,
            path: path.into(),
            interval: interval.max(1),
        }
    }

    /// Whether a given head sequence is due a checkpoint.
    ///
    /// Derived from `seq`, not from a counter of appends made by this process. A
    /// CLI invocation is a whole process life, so a counter would mean an
    /// interval that never elapses — the anchor file would stay empty and the
    /// estate would have no external proof at all.
    #[must_use]
    pub fn is_due(&self, seq: u64) -> bool {
        seq > 0 && seq.is_multiple_of(self.interval)
    }

    /// Sign and append a checkpoint.
    pub fn write(&mut self, seq: u64, row_hash: &str, ts: u64) -> Result<String> {
        let checkpoint = Checkpoint {
            seq,
            row_hash: row_hash.to_string(),
            ts,
        };
        let jwt = wc_core::contract::sign_detached(&checkpoint, &self.key).map_err(|e| {
            // Keep the detail: with an external signer the useful part of the failure
            // is the signer's, and "cannot sign checkpoint" alone would send an
            // operator looking at the chain instead of at their token.
            WcError::with_detail(
                Code::CHAIN_APPEND_FAILED,
                format!("cannot sign checkpoint: {}", e.detail()),
            )
            .with_source(e)
        })?;

        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| io_err(&self.path, e))?;
        writeln!(file, "{jwt}").map_err(|e| io_err(&self.path, e))?;
        file.sync_data().map_err(|e| io_err(&self.path, e))?;
        Ok(jwt)
    }
}

/// The newest checkpoint in an anchor file: its sequence and when it was signed.
///
/// **The signature is not verified here, and that is deliberate.** This feeds the
/// `wc_anchor_age_seconds` gauge, so it runs on every metrics scrape and has no public key
/// to verify against — `Anchor` holds the *signing* side. Verification is
/// [`verify_anchors`], reached by `connect audit verify`, which is the path whose answer
/// anyone is asked to rely on.
///
/// The distinction matters because the number this produces is exactly the number an
/// attacker who could rewrite the chain would want to look healthy. It is a liveness
/// signal — "checkpoints are still being written" — not an integrity one.
#[must_use]
pub fn newest_checkpoint(path: impl AsRef<Path>) -> Option<Checkpoint> {
    use base64::Engine as _;

    let text = std::fs::read_to_string(path.as_ref()).ok()?;
    let last = text.lines().rfind(|l| !l.trim().is_empty())?;
    let payload = last.split('.').nth(1)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&raw).ok()
}

/// The highest sequence any checkpoint in `anchor_path` claims, **unverified**.
///
/// Zero when the file is absent or holds nothing parseable, which the caller must
/// read as "truncation could not be checked" rather than "no truncation".
///
/// The JWS payload is decoded without checking the signature on purpose: the value is
/// used only to *raise* an alarm about missing rows, never to clear one. An attacker
/// who rewrites this file can add false alarms and cannot remove a real one that
/// `--anchor-pub` would find, because that path verifies properly.
fn highest_checkpoint_seq(anchor_path: &Path) -> Result<u64> {
    use base64::Engine as _;

    let text = match std::fs::read_to_string(anchor_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(io_err(anchor_path, e)),
    };

    let mut highest = 0u64;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Some(payload) = line.split('.').nth(1) else {
            continue;
        };
        let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
            continue;
        };
        if let Ok(cp) = serde_json::from_slice::<Checkpoint>(&raw) {
            highest = highest.max(cp.seq);
        }
    }
    Ok(highest)
}

/// Verify every checkpoint in an anchor file against a chain's entries.
///
/// Returns the number verified, and the sequences where a checkpoint disagreed with
/// the chain — which is the signal that the chain was rewritten after signing.
pub fn verify_anchors(
    anchor_path: &Path,
    pub_pem: &[u8],
    entries: &[Entry],
    retired: Option<&Retirement>,
) -> Result<AnchorTally> {
    let key = DecodingKey::from_ec_pem(pub_pem).map_err(|e| {
        WcError::with_detail(Code::CHAIN_BROKEN, "anchor public key is not an EC PEM")
            .with_source(e)
    })?;

    let text = match std::fs::read_to_string(anchor_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(AnchorTally::default()),
        Err(e) => return Err(io_err(anchor_path, e)),
    };

    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;

    let mut verified = 0u64;
    let mut retired_count = 0u64;
    let mut mismatches: Vec<u64> = Vec::new();

    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let data = jsonwebtoken::decode::<Checkpoint>(line, &key, &validation).map_err(|e| {
            // An unverifiable checkpoint is not a mismatch — it is a forged or
            // corrupt anchor file, which is a different and more serious problem.
            WcError::with_detail(
                Code::CHAIN_BROKEN,
                format!(
                    "{}: a checkpoint failed signature verification",
                    anchor_path.display()
                ),
            )
            .with_source(e)
        })?;
        let checkpoint = data.claims;

        // Three cases once segments can be retired, and conflating them was the first
        // thing retirement broke: every checkpoint for a retired row read as a mismatch,
        // so retiring evidence made `audit verify` report tampering. An operator would
        // have concluded retention corrupts the chain and switched it off.
        let boundary = retired.map_or(0, |r| r.to);
        if checkpoint.seq < boundary {
            // The row it attests is in the archive. Not checkable here, and not a
            // mismatch — `verify_retired_segment` is what checks it. Counted separately so
            // "attested but not here" never reads as "verified".
            retired_count += 1;
            continue;
        }
        if checkpoint.seq == boundary {
            // The boundary is checkable for free: the tombstone carries that row's hash,
            // so a retirement cannot excuse a checkpoint it does not actually match.
            match retired {
                Some(r) if r.last_row_hash == checkpoint.row_hash => verified += 1,
                _ => mismatches.push(checkpoint.seq),
            }
            continue;
        }
        match entries.iter().find(|e| e.seq == checkpoint.seq) {
            Some(entry) if entry.row_hash == checkpoint.row_hash => verified += 1,
            // Either the row was altered, or it is gone entirely. Both mean the
            // chain no longer matches what was signed.
            _ => mismatches.push(checkpoint.seq),
        }
    }
    Ok(AnchorTally {
        verified,
        mismatches,
        retired: retired_count,
    })
}

/// What checking an anchor file came to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnchorTally {
    /// Checkpoints that matched a live row, or the retirement boundary.
    pub verified: u64,
    /// Checkpoint sequences that disagreed with what is here.
    pub mismatches: Vec<u64>,
    /// Checkpoints for rows that have been retired — attested once, not checkable now.
    pub retired: u64,
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

/// An open, exclusively-locked evidence chain.
#[derive(Debug)]
pub struct Chain {
    path: PathBuf,
    file: File,
    last_seq: u64,
    last_hash: String,
    anchor: Option<Anchor>,
    _lock: LockGuard,
}

impl Chain {
    /// Open (or create) the chain in `dir`, taking the writer lock.
    pub fn open(dir: impl AsRef<Path>) -> Result<Chain> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;
        let guard = lock::acquire(dir, "chain")?;

        let path = dir.join(CHAIN_FILE);
        let entries = read_entries(&path)?;
        // An empty live chain after a retirement is not a new chain. Resuming from zero
        // there would restart numbering at 1 and link to nothing, which is a fork — so the
        // tombstone is the fallback, not `(0, "")`.
        let retired = read_retirement(dir)?;
        let (last_seq, last_hash) = entries.last().map_or_else(
            || {
                retired
                    .as_ref()
                    .map_or((0, String::new()), |r| (r.to, r.last_row_hash.clone()))
            },
            |e| (e.seq, e.row_hash.clone()),
        );

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| io_err(&path, e))?;

        Ok(Chain {
            path,
            file,
            last_seq,
            last_hash,
            anchor: None,
            _lock: guard,
        })
    }

    /// Enable signed checkpoints every `interval` appends.
    pub fn with_anchor(
        mut self,
        key_pem: &[u8],
        path: impl Into<PathBuf>,
        interval: u64,
    ) -> Result<Chain> {
        self.anchor = Some(Anchor::from_ec_pem(key_pem, path, interval)?);
        Ok(self)
    }

    /// Attach an anchor whose signing key may be held outside this process.
    #[must_use]
    pub fn with_anchor_signer(
        mut self,
        key: IssuerKey,
        path: impl Into<PathBuf>,
        interval: u64,
    ) -> Chain {
        self.anchor = Some(Anchor::with_signer(key, path, interval));
        self
    }

    /// The current head.
    #[must_use]
    pub fn head(&self) -> (u64, &str) {
        (self.last_seq, &self.last_hash)
    }

    /// Where checkpoints are written, if this chain is anchored.
    #[must_use]
    pub fn anchor_path(&self) -> Option<&Path> {
        self.anchor.as_ref().map(|a| a.path.as_path())
    }

    /// Append an entry, returning it as written.
    ///
    /// Always `fsync`s: an authority that exists with no durable record of its
    /// creation is precisely the gap an audit finds, so evidence never rides the
    /// batched path that state records may.
    pub fn append(&mut self, draft: EntryDraft, now: u64) -> Result<Entry> {
        let mut entry = Entry {
            seq: self.last_seq + 1,
            ts: now,
            kind: draft.kind,
            cid: draft.cid,
            contract_jti: draft.contract_jti,
            entities: draft.entities,
            actor: draft.actor,
            decision: draft.decision,
            reason: draft.reason,
            policy_version: draft.policy_version,
            detail: draft.detail,
            prev_hash: self.last_hash.clone(),
            row_hash: String::new(),
            schema: ENTRY_SCHEMA,
        };
        entry.row_hash = entry.compute_row_hash();

        let line = serde_json::to_string(&entry).map_err(|e| {
            WcError::with_detail(Code::CHAIN_APPEND_FAILED, "cannot encode entry").with_source(e)
        })?;
        let mut buf = line.into_bytes();
        buf.push(b'\n');
        self.file
            .write_all(&buf)
            .map_err(|e| io_err(&self.path, e))?;
        self.file.sync_data().map_err(|e| io_err(&self.path, e))?;

        self.last_seq = entry.seq;
        self.last_hash = entry.row_hash.clone();

        if let Some(anchor) = &mut self.anchor {
            if anchor.is_due(entry.seq) {
                anchor.write(entry.seq, &entry.row_hash, now)?;
            }
        }
        Ok(entry)
    }

    /// Sign a checkpoint of the current head now, regardless of interval.
    pub fn checkpoint(&mut self, now: u64) -> Result<Option<String>> {
        if self.last_seq == 0 {
            return Ok(None);
        }
        let (seq, hash) = (self.last_seq, self.last_hash.clone());
        match &mut self.anchor {
            Some(anchor) => Ok(Some(anchor.write(seq, &hash, now)?)),
            None => Ok(None),
        }
    }

    /// Verify a chain on disk, and its anchors when a public key is supplied.
    pub fn verify(dir: impl AsRef<Path>, anchor_pub_pem: Option<&[u8]>) -> Result<ChainReport> {
        let dir = dir.as_ref();
        let entries = read_entries(&dir.join(CHAIN_FILE))?;

        let mut report = ChainReport {
            entries: entries.len() as u64,
            ..Default::default()
        };

        // Retirement moves the chain's beginning out of this file, so verification starts
        // where the tombstone says it does. Without this the first surviving row reads as a
        // numbering break and a broken link — retiring evidence would make `audit verify`
        // report a corrupt chain, which is the fastest way to get retention switched off.
        let retired = read_retirement(dir)?;
        let (mut expected_prev, mut expected_seq) = match &retired {
            Some(r) => (r.last_row_hash.clone(), r.to + 1),
            None => (String::new(), 1u64),
        };
        if let Some(r) = &retired {
            report.retired_through = r.to;
            // The tombstone is checked, not believed: its `anchor_row_hash` must belong to a
            // checkpoint, which is what `verify_anchors` below confirms when a key is
            // supplied. Said in the report either way so an operator knows which it was.
            report.problems.extend(retirement_problems(r, &entries));
        }
        for entry in &entries {
            if entry.seq != expected_seq {
                report.broken_at.get_or_insert(entry.seq);
                report.problems.push(format!(
                    "seq {} breaks numbering (expected {expected_seq})",
                    entry.seq
                ));
            }
            if entry.prev_hash != expected_prev {
                report.broken_at.get_or_insert(entry.seq);
                report.problems.push(format!(
                    "seq {} does not link to its predecessor",
                    entry.seq
                ));
            }
            if !entry.is_intact() {
                report.broken_at.get_or_insert(entry.seq);
                report.problems.push(format!(
                    "seq {} content does not match its row_hash",
                    entry.seq
                ));
            }
            expected_prev = entry.row_hash.clone();
            expected_seq = entry.seq + 1;
        }

        if let Some(entry) = entries.last() {
            report.head_seq = entry.seq;
            report.head_hash = entry.row_hash.clone();
        }

        // --- truncation ---
        //
        // A hash chain cannot detect its own truncation: drop the last N rows and what
        // remains links perfectly, which is why `audit verify` reported **"chain is
        // intact"** on a chain whose most recent evidence had been deleted. That is the
        // one edit an attacker who has just used break-glass actually wants.
        //
        // The checkpoint sequences are read here **without** the anchor key, and
        // deliberately so: a checkpoint claiming seq 100 beside a chain whose head is 40
        // is evidence of truncation whoever signed it, and an unverified claim is
        // allowed to *raise* an alarm even though it may never clear one. Verifying the
        // signatures is still what `--anchor-pub` is for, and a forged anchor file only
        // ever adds alarms.
        report.highest_checkpoint_seq = highest_checkpoint_seq(&dir.join(ANCHOR_FILE))?;
        if report.highest_checkpoint_seq > report.head_seq {
            report.broken_at.get_or_insert(report.head_seq + 1);
            report.problems.push(format!(
                "chain head is seq {} but a checkpoint records seq {}: {} row(s) have been removed",
                report.head_seq,
                report.highest_checkpoint_seq,
                report.highest_checkpoint_seq - report.head_seq
            ));
        }

        if let Some(pem) = anchor_pub_pem {
            let tally = verify_anchors(&dir.join(ANCHOR_FILE), pem, &entries, retired.as_ref())?;
            let (verified, mismatches) = (tally.verified, tally.mismatches);
            report.anchors_verified = verified;
            report.anchors_retired = tally.retired;
            for seq in &mismatches {
                report
                    .problems
                    .push(format!("anchor at seq {seq} does not match the chain"));
            }
            report.anchor_mismatches = mismatches;
            if verified == 0 && !entries.is_empty() {
                // Not a break, but not proof either: chain-only verification
                // cannot detect a wholesale rewrite (see the anchor tests).
                report
                    .problems
                    .push("no checkpoints verified: this chain has no external proof".to_string());
            }
        }
        Ok(report)
    }

    /// Every entry, for verification and export.
    pub fn entries(dir: impl AsRef<Path>) -> Result<Vec<Entry>> {
        read_entries(&dir.as_ref().join(CHAIN_FILE))
    }
}

// ---------------------------------------------------------------------------
// Segment retirement
// ---------------------------------------------------------------------------

/// The tombstone a retired segment leaves in the live chain's place.
///
/// Retention on a hash-linked chain cannot be a row delete: removing a row breaks every row
/// after it. So it is *segment retirement* — whole contiguous ranges leave the live chain and
/// this record replaces them, carrying exactly what verification needs to keep going.
///
/// # It is verified, not trusted
///
/// The obvious mistake would be to sign this with the anchor key and believe it. Then
/// "retirement" is a signed permission slip to delete evidence, and whoever holds the key can
/// erase the chain's beginning at will. Instead every field is *checkable against something
/// that already exists*:
///
/// * `last_row_hash` must equal the surviving first row's `prev_hash`, or the survivors do
///   not link to what was retired;
/// * `anchor_seq`/`anchor_row_hash` must match a **signed checkpoint**, which is what proves
///   the retired rows existed and were attested before they were moved;
/// * `segment_digest` must match the file the rows were moved to, so the archive cannot be
///   edited after the fact and still satisfy the tombstone.
///
/// An attacker rewriting this file to claim more rows were retired needs a signed checkpoint
/// at that sequence to be believed — which is the same thing they would need to forge to
/// truncate. Retirement therefore adds no new authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retirement {
    /// First sequence retired. Always 1: retirement is from the beginning, because a hole
    /// in the middle is not something the chain can express.
    pub from: u64,
    /// Last sequence retired.
    pub to: u64,
    /// How many rows moved.
    pub count: u64,
    /// The `row_hash` of sequence `to` — what the surviving chain links back to.
    pub last_row_hash: String,
    /// The checkpoint that attested the retired range.
    pub anchor_seq: u64,
    /// That checkpoint's head hash.
    pub anchor_row_hash: String,
    /// The file the rows were moved to, relative to the evidence directory.
    pub segment_file: String,
    /// `sha256:…` over that file's bytes.
    pub segment_digest: String,
    /// When retirement ran.
    pub retired_at: u64,
    /// The newest timestamp among the retired rows — the boundary an auditor asks about.
    pub newest_retired_ts: u64,
}

/// What a retirement did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetirementOutcome {
    /// The tombstone written.
    pub retirement: Retirement,
    /// Rows left in the live chain.
    pub remaining: u64,
    /// Where the segment now lives, absolute.
    pub segment_path: PathBuf,
}

/// Retire sequences `1..=upto` out of the live chain.
///
/// Four refusals, in this order, and each of them is the point rather than a formality:
///
/// 1. **A chain that does not verify is not retired from.** Same stance as
///    [`crate::backup`]: acting on a broken chain launders the break into the archive.
/// 2. **Every retired row must be older than `horizon`.** Retiring evidence still inside its
///    retention window is precisely what retention exists to prevent, so the clock is checked
///    against the rows rather than trusted from the caller's arithmetic.
/// 3. **A signed checkpoint must cover the range.** Without one the operation is
///    indistinguishable from truncation — and `--anchor-pub` is required for exactly that
///    reason, so this cannot be run "just this once" without the key.
/// 4. **The head is never retired.** Retiring everything would leave a chain with no rows
///    and no way to append that links to anything.
///
/// Nothing is deleted. The rows move to `retired/segment-*.jsonl`, which the operator ships
/// to WORM storage and then removes at their own hand — because a control plane that can
/// delete its own evidence is a control plane whose evidence is worth less.
pub fn retire_segment(
    dir: impl AsRef<Path>,
    upto: u64,
    horizon: u64,
    anchor_pub_pem: &[u8],
    now: u64,
) -> Result<RetirementOutcome> {
    let dir = dir.as_ref();

    // 1 · the chain must verify, including any earlier retirement.
    let report = Chain::verify(dir, Some(anchor_pub_pem))?;
    if !report.is_intact() {
        return Err(WcError::with_detail(
            Code::CHAIN_BROKEN,
            format!(
                "refusing to retire from a chain that does not verify: {}",
                report.problems.join("; ")
            ),
        ));
    }

    let entries = read_entries(&dir.join(CHAIN_FILE))?;
    let previous = read_retirement(dir)?;
    let from = previous.as_ref().map_or(1, |r| r.to + 1);
    if upto < from {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("sequences up to {} are already retired", from - 1),
        ));
    }

    let (retiring, surviving): (Vec<&Entry>, Vec<&Entry>) =
        entries.iter().partition(|e| e.seq <= upto);
    if retiring.is_empty() {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("no rows at or below seq {upto} are in the live chain"),
        ));
    }

    // 4 · never retire the head.
    if surviving.is_empty() {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            "retiring every row would leave a chain with nothing to append to; keep at \
             least the head",
        ));
    }

    // 2 · the clock, against the rows.
    if let Some(young) = retiring.iter().find(|e| e.ts >= horizon) {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!(
                "seq {} is dated {} which is inside the retention window (horizon {horizon}); \
                 retiring it is what retention exists to prevent",
                young.seq, young.ts
            ),
        ));
    }

    // 3 · a signed checkpoint covering the range.
    let tally = verify_anchors(
        &dir.join(ANCHOR_FILE),
        anchor_pub_pem,
        &entries,
        previous.as_ref(),
    )?;
    if !tally.mismatches.is_empty() {
        return Err(WcError::with_detail(
            Code::CHAIN_BROKEN,
            format!(
                "checkpoints disagree with the chain at {:?}",
                tally.mismatches
            ),
        ));
    }
    let covering = covering_checkpoint(&dir.join(ANCHOR_FILE), anchor_pub_pem, upto, &entries)?
        .ok_or_else(|| {
            WcError::with_detail(
                Code::CHAIN_BROKEN,
                format!(
                    "no signed checkpoint covers seq {upto}; without one, retiring these rows \
                     is indistinguishable from truncating them. Checkpoint first \
                     (--anchor-key, or a shorter --anchor-interval)"
                ),
            )
        })?;

    // --- write the segment, then the tombstone, then the survivors ---------
    //
    // In that order on purpose. A crash after the segment leaves an orphan file and an
    // unchanged chain, which is safe; a crash after the tombstone leaves survivors that
    // still verify against it. The reverse order could leave a chain whose beginning is
    // gone with nothing recording it.
    let last = retiring.last().unwrap_or_else(|| unreachable!());
    let newest_retired_ts = retiring.iter().map(|e| e.ts).max().unwrap_or(0);
    let archive_dir = dir.join(RETIRED_DIR);
    std::fs::create_dir_all(&archive_dir).map_err(|e| io_err(&archive_dir, e))?;
    let segment_name = format!("segment-{from:06}-{upto:06}.jsonl");
    let segment_path = archive_dir.join(&segment_name);

    let mut body = String::new();
    for entry in &retiring {
        body.push_str(
            &serde_json::to_string(entry)
                .map_err(|e| WcError::with_detail(Code::CHAIN_BROKEN, "row").with_source(e))?,
        );
        body.push('\n');
    }
    std::fs::write(&segment_path, &body).map_err(|e| io_err(&segment_path, e))?;

    let retirement = Retirement {
        from,
        to: upto,
        count: retiring.len() as u64,
        last_row_hash: last.row_hash.clone(),
        anchor_seq: covering.seq,
        anchor_row_hash: covering.row_hash,
        segment_file: format!("{RETIRED_DIR}/{segment_name}"),
        segment_digest: format!("sha256:{}", sha256_hex(&body)),
        retired_at: now,
        newest_retired_ts,
    };
    let tombstone = dir.join(RETIRED_FILE);
    std::fs::write(
        &tombstone,
        serde_json::to_string_pretty(&retirement)
            .map_err(|e| WcError::with_detail(Code::CHAIN_BROKEN, "tombstone").with_source(e))?
            + "\n",
    )
    .map_err(|e| io_err(&tombstone, e))?;

    let mut kept = String::new();
    for entry in &surviving {
        kept.push_str(
            &serde_json::to_string(entry)
                .map_err(|e| WcError::with_detail(Code::CHAIN_BROKEN, "row").with_source(e))?,
        );
        kept.push('\n');
    }
    let chain_path = dir.join(CHAIN_FILE);
    std::fs::write(&chain_path, kept).map_err(|e| io_err(&chain_path, e))?;

    Ok(RetirementOutcome {
        remaining: surviving.len() as u64,
        retirement,
        segment_path,
    })
}

/// The tombstone, if this chain has retired anything.
pub fn read_retirement(dir: impl AsRef<Path>) -> Result<Option<Retirement>> {
    let path = dir.as_ref().join(RETIRED_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(&path, e)),
    };
    serde_json::from_str(&text).map(Some).map_err(|e| {
        WcError::with_detail(Code::CHAIN_BROKEN, "retired.json is not a tombstone").with_source(e)
    })
}

/// The lowest-sequence signed checkpoint at or after `upto`, verified.
fn covering_checkpoint(
    anchor_path: &Path,
    pub_pem: &[u8],
    upto: u64,
    entries: &[Entry],
) -> Result<Option<Checkpoint>> {
    let key = DecodingKey::from_ec_pem(pub_pem).map_err(|e| {
        WcError::with_detail(Code::CHAIN_BROKEN, "anchor public key is not an EC PEM")
            .with_source(e)
    })?;
    let text = match std::fs::read_to_string(anchor_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(anchor_path, e)),
    };
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;

    let mut best: Option<Checkpoint> = None;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(data) = jsonwebtoken::decode::<Checkpoint>(line, &key, &validation) else {
            continue;
        };
        let cp = data.claims;
        if cp.seq < upto {
            continue;
        }
        // The checkpoint must actually match the chain it claims to attest, or a stale
        // signed checkpoint from a rewritten chain would authorise the retirement.
        if !entries
            .iter()
            .any(|e| e.seq == cp.seq && e.row_hash == cp.row_hash)
        {
            continue;
        }
        if best.as_ref().is_none_or(|b| cp.seq < b.seq) {
            best = Some(cp);
        }
    }
    Ok(best)
}

/// Verify a retired segment against the tombstone that replaced it.
///
/// Separate from [`Chain::verify`] because the archive is normally *not present* — it has
/// been shipped to WORM storage — and a verifier that failed when it was absent would make
/// shipping it look like corruption. This is what an auditor runs when they bring it back.
pub fn verify_retired_segment(dir: impl AsRef<Path>) -> Result<Vec<String>> {
    let dir = dir.as_ref();
    let Some(retirement) = read_retirement(dir)? else {
        return Ok(vec!["no segment has been retired".to_string()]);
    };
    let path = dir.join(&retirement.segment_file);
    let mut problems = Vec::new();

    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(vec![format!(
                "{} is not here; bring the archive back to verify it",
                retirement.segment_file
            )])
        }
        Err(e) => return Err(io_err(&path, e)),
    };
    if format!("sha256:{}", sha256_hex(&body)) != retirement.segment_digest {
        problems.push("the segment file does not match the digest in the tombstone".to_string());
    }

    let rows: Vec<Entry> = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| {
            WcError::with_detail(Code::CHAIN_BROKEN, "a retired row is not an entry").with_source(e)
        })?;

    let mut expected_prev = String::new();
    let mut expected_seq = retirement.from;
    for row in &rows {
        if row.seq != expected_seq {
            problems.push(format!("retired seq {} breaks numbering", row.seq));
        }
        if row.prev_hash != expected_prev && expected_seq != retirement.from {
            problems.push(format!("retired seq {} does not link", row.seq));
        }
        if !row.is_intact() {
            problems.push(format!(
                "retired seq {} does not match its row_hash",
                row.seq
            ));
        }
        expected_prev = row.row_hash.clone();
        expected_seq = row.seq + 1;
    }
    if rows.last().map(|r| r.row_hash.as_str()) != Some(retirement.last_row_hash.as_str()) {
        problems.push(
            "the segment's last row_hash is not the one the live chain links back to".to_string(),
        );
    }
    Ok(problems)
}

/// The result of verifying a chain.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChainReport {
    /// Entries read.
    pub entries: u64,
    /// Head sequence.
    pub head_seq: u64,
    /// Head hash — what an export references so it is verifiable rather than
    /// merely asserted.
    pub head_hash: String,
    /// First sequence where the chain broke, if any.
    pub broken_at: Option<u64>,
    /// Checkpoints that verified against the chain.
    pub anchors_verified: u64,
    /// Checkpoint sequences that disagreed with the chain.
    pub anchor_mismatches: Vec<u64>,
    /// Checkpoints whose rows have been retired — attested once, not checkable here.
    ///
    /// Reported separately from `anchors_verified` so "attested but in the archive" can
    /// never be read as "verified just now". Retirement made every such checkpoint look
    /// like a mismatch at first, which would have told an operator that retaining evidence
    /// corrupts the chain.
    pub anchors_retired: u64,
    /// Highest retired sequence, or zero when nothing has been retired.
    ///
    /// The live chain starts at `retired_through + 1`. An export or an auditor asking "what
    /// window does this root hold" needs this, or they read the head-minus-count and get an
    /// answer that stopped being true the first time a segment was retired.
    pub retired_through: u64,
    /// Highest sequence any checkpoint claims, read without verifying signatures.
    ///
    /// This is the only thing bounding truncation, so it is reported rather than
    /// merely used: **zero means truncation was not checked at all**, and a caller
    /// that prints a verdict without saying so is telling an operator the chain is
    /// whole when nothing looked.
    pub highest_checkpoint_seq: u64,
    /// Human-readable problems, in order found.
    pub problems: Vec<String>,
}

impl ChainReport {
    /// Whether the chain is intact and every checkpoint agrees with it.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.broken_at.is_none() && self.anchor_mismatches.is_empty()
    }

    /// Whether anything at all bounded truncation on this run.
    ///
    /// Linking every row proves no row was *altered* and says nothing about rows that
    /// are no longer there. Only a checkpoint recording a higher sequence can, so a
    /// verdict that does not distinguish the two is the misleading part.
    #[must_use]
    pub fn truncation_was_checked(&self) -> bool {
        self.highest_checkpoint_seq > 0
    }

    /// One line naming what was and was not established, for the operator-facing
    /// verdict. Never the word "intact" on its own.
    #[must_use]
    pub fn completeness(&self) -> String {
        if self.highest_checkpoint_seq > self.head_seq {
            format!(
                "INCOMPLETE — a checkpoint records seq {} and the head is seq {}, so {} \
                 row(s) are missing",
                self.highest_checkpoint_seq,
                self.head_seq,
                self.highest_checkpoint_seq - self.head_seq
            )
        } else if self.truncation_was_checked() {
            format!(
                "complete to seq {} (the newest checkpoint); anything appended after it \
                 could still be removed undetectably",
                self.highest_checkpoint_seq
            )
        } else {
            "TRUNCATION NOT CHECKED — no checkpoint exists yet, so removal of recent rows \
             would leave a chain that links perfectly"
                .to_string()
        }
    }
}

/// What is wrong with a tombstone, judged against the live rows it sits in front of.
///
/// Two checks, and the first is the one that matters: the surviving chain must link back to
/// the row the tombstone says was last. Without it, a tombstone could claim any range and the
/// remaining rows would verify happily among themselves.
fn retirement_problems(r: &Retirement, entries: &[Entry]) -> Vec<String> {
    let mut problems = Vec::new();
    if r.to < r.from {
        problems.push(format!(
            "retired.json claims {}..{}, which is not a range",
            r.from, r.to
        ));
    }
    match entries.first() {
        Some(first) if first.prev_hash != r.last_row_hash => problems.push(format!(
            "retired.json says seq {} ended in {} but the live chain starts from {}",
            r.to,
            &r.last_row_hash[..r.last_row_hash.len().min(12)],
            &first.prev_hash[..first.prev_hash.len().min(12)]
        )),
        Some(first) if first.seq != r.to + 1 => problems.push(format!(
            "retired.json retires through seq {} but the live chain starts at seq {}",
            r.to, first.seq
        )),
        _ => {}
    }
    problems
}

/// Read and parse a chain file. Unlike the state log, a truncated tail is **not**
/// tolerated silently: it is reported as a problem, because a missing evidence row
/// is exactly what someone tampering would want to look like a crash.
fn read_entries(path: &Path) -> Result<Vec<Entry>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err(path, e)),
    };
    let mut out: Vec<Entry> = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| io_err(path, e))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<Entry>(&line).map_err(|e| {
            WcError::with_detail(
                Code::CHAIN_BROKEN,
                format!("{}: line {} is not a valid entry", path.display(), i + 1),
            )
            .with_source(e)
        })?;
        out.push(entry);
    }
    Ok(out)
}

fn io_err(path: &Path, e: std::io::Error) -> WcError {
    WcError::with_detail(
        Code::CHAIN_APPEND_FAILED,
        format!("{}: {}", path.display(), e),
    )
    .with_source(e)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    const PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_anchor_priv.pem");
    const PUB: &[u8] = include_bytes!("../../../fixtures/keys/test_anchor_pub.pem");

    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> TmpDir {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("wc-chain-{}-{tag}-{n}", std::process::id()));
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

    fn draft(kind: &str) -> EntryDraft {
        EntryDraft {
            kind: kind.to_string(),
            cid: Some("conn_7f3a91c4".to_string()),
            contract_jti: Some("cx_84be0011".to_string()),
            entities: vec!["spiffe://org/ns/agents/sa/recon-bot-7".to_string()],
            actor: "human:priya@org".to_string(),
            decision: "record".to_string(),
            reason: "test".to_string(),
            policy_version: "connect-policy@v37".to_string(),
            detail: json!({"k": "v"}),
        }
    }

    // --- appending and linking ---

    #[test]
    fn entries_link_into_a_chain() {
        let tmp = TmpDir::new("link");
        let mut chain = Chain::open(tmp.path()).unwrap();

        let first = chain.append(draft("entity.register"), 1_000).unwrap();
        assert_eq!(first.seq, 1);
        assert!(
            first.prev_hash.is_empty(),
            "the first entry links to nothing"
        );
        assert!(first.is_intact());

        let second = chain.append(draft("contract.mint"), 1_001).unwrap();
        assert_eq!(second.seq, 2);
        assert_eq!(second.prev_hash, first.row_hash);
        assert_ne!(second.row_hash, first.row_hash);

        let (seq, head) = chain.head();
        assert_eq!(seq, 2);
        assert_eq!(head, second.row_hash);
    }

    #[test]
    fn the_chain_resumes_from_disk() {
        let tmp = TmpDir::new("resume");
        let head = {
            let mut chain = Chain::open(tmp.path()).unwrap();
            chain.append(draft("a"), 1).unwrap();
            let e = chain.append(draft("b"), 2).unwrap();
            e.row_hash
        };
        let mut chain = Chain::open(tmp.path()).unwrap();
        assert_eq!(chain.head(), (2, head.as_str()));
        let third = chain.append(draft("c"), 3).unwrap();
        assert_eq!(third.seq, 3);
        assert_eq!(third.prev_hash, head);
    }

    #[test]
    fn a_second_writer_is_refused() {
        let tmp = TmpDir::new("lock");
        let _held = Chain::open(tmp.path()).unwrap();
        assert_eq!(
            Chain::open(tmp.path()).unwrap_err().code(),
            Code::STORE_LOCKED
        );
    }

    // --- what the hash covers ---

    #[test]
    fn every_accountability_field_is_hashed() {
        // The property the regulatory posture needs: none of these can be
        // rewritten without breaking the chain.
        let tmp = TmpDir::new("fields");
        let mut chain = Chain::open(tmp.path()).unwrap();
        let entry = chain.append(draft("contract.mint"), 1_000).unwrap();

        type Mutation = Box<dyn Fn(&mut Entry)>;
        let mutate: Vec<(&str, Mutation)> = vec![
            (
                "cid",
                Box::new(|e: &mut Entry| e.cid = Some("conn_deadbeef".into())),
            ),
            (
                "contract_jti",
                Box::new(|e: &mut Entry| e.contract_jti = Some("cx_other01".into())),
            ),
            (
                "actor",
                Box::new(|e: &mut Entry| e.actor = "human:mallory@org".into()),
            ),
            (
                "decision",
                Box::new(|e: &mut Entry| e.decision = "allow".into()),
            ),
            (
                "reason",
                Box::new(|e: &mut Entry| e.reason = "rewritten".into()),
            ),
            (
                "policy_version",
                Box::new(|e: &mut Entry| e.policy_version = "v1".into()),
            ),
            (
                "entities",
                Box::new(|e: &mut Entry| e.entities = vec!["other".into()]),
            ),
            (
                "detail",
                Box::new(|e: &mut Entry| e.detail = json!({"k": "tampered"})),
            ),
            (
                "kind",
                Box::new(|e: &mut Entry| e.kind = "entity.register".into()),
            ),
            ("ts", Box::new(|e: &mut Entry| e.ts = 9_999)),
            ("seq", Box::new(|e: &mut Entry| e.seq = 42)),
            (
                "prev_hash",
                Box::new(|e: &mut Entry| e.prev_hash = "sha256:x".into()),
            ),
        ];

        for (field, mutation) in mutate {
            let mut tampered = entry.clone();
            mutation(&mut tampered);
            assert!(
                !tampered.is_intact(),
                "{field} can be changed without breaking the hash"
            );
        }
    }

    // --- verification ---

    #[test]
    fn a_clean_chain_verifies() {
        let tmp = TmpDir::new("verify");
        {
            let mut chain = Chain::open(tmp.path()).unwrap();
            for i in 0..5 {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
        }
        let report = Chain::verify(tmp.path(), None).unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.entries, 5);
        assert_eq!(report.head_seq, 5);
        assert!(!report.head_hash.is_empty());
        assert!(report.problems.is_empty());
    }

    #[test]
    fn an_empty_chain_verifies_as_empty() {
        let tmp = TmpDir::new("empty");
        let report = Chain::verify(tmp.path(), None).unwrap();
        assert!(report.is_intact());
        assert_eq!(report.entries, 0);
        assert_eq!(report.head_seq, 0);
    }

    #[test]
    fn an_edited_row_is_detected() {
        let tmp = TmpDir::new("edited");
        {
            let mut chain = Chain::open(tmp.path()).unwrap();
            for i in 0..4 {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
        }
        // Rewrite entry 2's reason, leaving its row_hash alone.
        let path = tmp.path().join(CHAIN_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        let mut entry: Entry = serde_json::from_str(&lines[1]).unwrap();
        entry.reason = "quietly changed".to_string();
        lines[1] = serde_json::to_string(&entry).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let report = Chain::verify(tmp.path(), None).unwrap();
        assert!(!report.is_intact());
        assert_eq!(report.broken_at, Some(2));
        assert!(report.problems.iter().any(|p| p.contains("row_hash")));
    }

    #[test]
    fn a_re_hashed_row_still_breaks_the_successor() {
        // The point of chaining: a careful attacker who recomputes the edited row's
        // own hash still breaks every row after it.
        let tmp = TmpDir::new("rehash");
        {
            let mut chain = Chain::open(tmp.path()).unwrap();
            for i in 0..4 {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
        }
        let path = tmp.path().join(CHAIN_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        let mut entry: Entry = serde_json::from_str(&lines[1]).unwrap();
        entry.reason = "carefully changed".to_string();
        entry.row_hash = entry.compute_row_hash(); // re-hash to look intact
        lines[1] = serde_json::to_string(&entry).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let report = Chain::verify(tmp.path(), None).unwrap();
        assert!(!report.is_intact());
        assert_eq!(report.broken_at, Some(3), "the successor no longer links");
        assert!(report.problems.iter().any(|p| p.contains("predecessor")));
    }

    #[test]
    fn a_deleted_row_is_detected() {
        let tmp = TmpDir::new("deleted");
        {
            let mut chain = Chain::open(tmp.path()).unwrap();
            for i in 0..4 {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
        }
        let path = tmp.path().join(CHAIN_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // Drop entry 2 entirely.
        let kept = [lines[0], lines[2], lines[3]].join("\n");
        std::fs::write(&path, kept + "\n").unwrap();

        let report = Chain::verify(tmp.path(), None).unwrap();
        assert!(!report.is_intact());
        assert_eq!(report.broken_at, Some(3));
        assert!(report.problems.iter().any(|p| p.contains("numbering")));
    }

    #[test]
    fn a_truncated_tail_is_detected_against_a_checkpoint_without_the_key() {
        // `audit verify` reported **"chain is intact", exit 0** on a chain whose last
        // rows had been deleted, because dropping the tail of a hash chain leaves
        // something that links perfectly. It is also the one edit worth making: it
        // removes the newest evidence, which is the break-glass you just used.
        //
        // Nothing here is a cryptographic fix — truncation is not detectable from the
        // chain alone, ever. What is detectable is disagreement with a checkpoint, and
        // that comparison needs no key, so it now happens on every run.
        let tmp = TmpDir::new("truncated");
        let anchor_path = tmp.path().join(ANCHOR_FILE);
        {
            let mut chain = Chain::open(tmp.path())
                .unwrap()
                .with_anchor(PRIV, &anchor_path, 2)
                .unwrap();
            for i in 0..6 {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
        }
        let path = tmp.path().join(CHAIN_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 6);
        // Keep a prefix. Every remaining row links to its predecessor, so the
        // link-only check has nothing to say.
        std::fs::write(&path, lines[..3].join("\n") + "\n").unwrap();

        // No anchor key at all — the case an operator gets when they forget the flag.
        let report = Chain::verify(tmp.path(), None).unwrap();
        assert!(
            report.truncation_was_checked(),
            "a checkpoint file exists, so truncation is checkable without the key"
        );
        assert!(
            !report.is_intact(),
            "a truncated chain is not intact: {report:?}"
        );
        assert_eq!(report.head_seq, 3);
        assert_eq!(report.highest_checkpoint_seq, 6);
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.contains("row(s) have been removed")),
            "{:?}",
            report.problems
        );

        // And with the key, the same conclusion by the stronger route.
        let verified = Chain::verify(tmp.path(), Some(PUB)).unwrap();
        assert!(!verified.is_intact());
        assert!(verified.anchor_mismatches.contains(&6));
    }

    #[test]
    fn with_no_checkpoint_at_all_completeness_is_reported_as_unverified() {
        // The honest half. Before any checkpoint is written there is nothing to compare
        // against, so truncation genuinely cannot be detected — and the verdict has to
        // say that rather than print one word that reads as "all good". Asserted on the
        // report so the CLI cannot quietly go back to a bare "intact".
        let tmp = TmpDir::new("unproven-completeness");
        {
            let mut chain = Chain::open(tmp.path()).unwrap();
            for i in 0..3 {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
        }
        let full = Chain::verify(tmp.path(), None).unwrap();
        assert!(full.is_intact(), "links are fine");
        assert!(
            !full.truncation_was_checked(),
            "with no checkpoint, nothing bounds truncation"
        );
        assert!(
            full.completeness().contains("TRUNCATION NOT CHECKED"),
            "{}",
            full.completeness()
        );

        // Truncating it really is undetectable here, which is the limitation being
        // stated rather than a bug being asserted as fixed.
        let path = tmp.path().join(CHAIN_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, lines[..2].join("\n") + "\n").unwrap();
        let cut = Chain::verify(tmp.path(), None).unwrap();
        assert!(cut.is_intact(), "links still verify — this is the residual");
        assert!(!cut.truncation_was_checked());
    }

    #[test]
    fn a_corrupt_line_is_an_error_not_a_skipped_row() {
        let tmp = TmpDir::new("corrupt");
        {
            let mut chain = Chain::open(tmp.path()).unwrap();
            chain.append(draft("e"), 1).unwrap();
        }
        let path = tmp.path().join(CHAIN_FILE);
        std::fs::write(&path, "{ not an entry\n").unwrap();
        assert_eq!(
            Chain::verify(tmp.path(), None).unwrap_err().code(),
            Code::CHAIN_BROKEN
        );
    }

    // --- anchors ---

    #[test]
    fn anchors_are_written_on_the_interval_and_verify() {
        let tmp = TmpDir::new("anchor");
        let anchor_path = tmp.path().join(ANCHOR_FILE);
        {
            let mut chain = Chain::open(tmp.path())
                .unwrap()
                .with_anchor(PRIV, &anchor_path, 2)
                .unwrap();
            for i in 0..4 {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
        }
        let text = std::fs::read_to_string(&anchor_path).unwrap();
        assert_eq!(text.lines().count(), 2, "one checkpoint every two appends");

        let report = Chain::verify(tmp.path(), Some(PUB)).unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.anchors_verified, 2);
        assert!(report.anchor_mismatches.is_empty());
    }

    #[test]
    fn a_checkpoint_written_before_the_custody_change_still_verifies() {
        // Routing the anchor through `IssuerKey` added a `kid` to the checkpoint
        // header. An estate upgrading in place has an `anchor.jsonl` full of the old
        // shape, and evidence that stops verifying on upgrade is indistinguishable
        // from evidence somebody tampered with — the worst possible false alarm.
        //
        // It holds because `verify_anchors` resolves its key from the caller, never
        // from the header. This test is what keeps that true.
        let tmp = TmpDir::new("anchor-legacy");
        let anchor_path = tmp.path().join(ANCHOR_FILE);
        let head = {
            let mut chain = Chain::open(tmp.path()).unwrap();
            let entry = chain.append(draft("e"), 1_000).unwrap();
            (entry.seq, entry.row_hash)
        };

        // A checkpoint in the pre-change shape: no `kid`, signed the old way.
        let legacy = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::ES256),
            &Checkpoint {
                seq: head.0,
                row_hash: head.1.clone(),
                ts: 1_000,
            },
            &jsonwebtoken::EncodingKey::from_ec_pem(PRIV).unwrap(),
        )
        .unwrap();
        assert!(
            !legacy.contains("a2lk"),
            "the fixture must actually lack a kid, or it proves nothing"
        );
        std::fs::write(&anchor_path, format!("{legacy}\n")).unwrap();

        let report = Chain::verify(tmp.path(), Some(PUB)).unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(
            report.anchors_verified, 1,
            "an old checkpoint must still verify"
        );
        assert!(report.anchor_mismatches.is_empty());
    }

    #[test]
    fn an_anchor_can_be_signed_by_a_key_this_process_does_not_hold() {
        // The point of the change: the key that proves the control plane did not
        // rewrite its own evidence should not be a file the control plane can read.
        #[derive(Debug)]
        struct Elsewhere(jsonwebtoken::EncodingKey);
        impl wc_core::contract::Signer for Elsewhere {
            fn sign(&self, input: &[u8]) -> Result<Vec<u8>> {
                use base64::Engine as _;
                let b64 =
                    jsonwebtoken::crypto::sign(input, &self.0, Algorithm::ES256).map_err(|e| {
                        WcError::with_detail(Code::CHAIN_APPEND_FAILED, "sign").with_source(e)
                    })?;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(b64)
                    .map_err(|e| {
                        WcError::with_detail(Code::CHAIN_APPEND_FAILED, "b64").with_source(e)
                    })
            }
        }

        let tmp = TmpDir::new("anchor-external");
        let anchor_path = tmp.path().join(ANCHOR_FILE);
        let key = IssuerKey::external(
            ANCHOR_KID,
            Algorithm::ES256,
            Box::new(Elsewhere(
                jsonwebtoken::EncodingKey::from_ec_pem(PRIV).unwrap(),
            )),
        )
        .unwrap();
        {
            let mut chain =
                Chain::open(tmp.path())
                    .unwrap()
                    .with_anchor_signer(key, &anchor_path, 1);
            chain.append(draft("e"), 1_000).unwrap();
        }

        let report = Chain::verify(tmp.path(), Some(PUB)).unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.anchors_verified, 1);
    }

    #[test]
    fn an_anchor_signer_that_fails_stops_the_append_and_says_whose_fault_it_is() {
        // A checkpoint that silently did not get written is the one failure an
        // anchor cannot afford: the chain would look anchored and be unanchored.
        #[derive(Debug)]
        struct Broken;
        impl wc_core::contract::Signer for Broken {
            fn sign(&self, _input: &[u8]) -> Result<Vec<u8>> {
                Err(WcError::with_detail(
                    Code::CHAIN_APPEND_FAILED,
                    "token not present",
                ))
            }
        }

        let tmp = TmpDir::new("anchor-broken");
        let key = IssuerKey::external(ANCHOR_KID, Algorithm::ES256, Box::new(Broken)).unwrap();
        let mut chain = Chain::open(tmp.path()).unwrap().with_anchor_signer(
            key,
            tmp.path().join(ANCHOR_FILE),
            1,
        );

        let err = chain.append(draft("e"), 1_000).unwrap_err();
        assert_eq!(err.code(), Code::CHAIN_APPEND_FAILED);
        assert!(
            err.detail().contains("token not present"),
            "the signer's own reason must survive: {}",
            err.detail()
        );
    }

    #[test]
    fn the_interval_survives_process_boundaries() {
        // Each CLI invocation is one process appending one entry. An interval
        // counted per process would never elapse.
        let tmp = TmpDir::new("interval");
        let anchor_path = tmp.path().join(ANCHOR_FILE);
        for i in 0..4 {
            let mut chain = Chain::open(tmp.path())
                .unwrap()
                .with_anchor(PRIV, &anchor_path, 2)
                .unwrap();
            chain.append(draft("e"), 1_000 + i).unwrap();
        }
        let text = std::fs::read_to_string(&anchor_path).unwrap();
        assert_eq!(text.lines().count(), 2, "seq 2 and seq 4 are due");

        let report = Chain::verify(tmp.path(), Some(PUB)).unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.anchors_verified, 2);
    }

    #[test]
    fn a_chain_with_no_checkpoints_is_reported_as_unproven() {
        let tmp = TmpDir::new("unproven");
        {
            let mut chain = Chain::open(tmp.path()).unwrap();
            chain.append(draft("e"), 1_000).unwrap();
        }
        let report = Chain::verify(tmp.path(), Some(PUB)).unwrap();
        // Intact, but with nothing signed there is no proof against a wholesale
        // rewrite — so it must not read as a clean bill of health.
        assert!(report.is_intact());
        assert_eq!(report.anchors_verified, 0);
        assert!(report
            .problems
            .iter()
            .any(|p| p.contains("no external proof")));
    }

    #[test]
    fn an_explicit_checkpoint_signs_the_current_head() {
        let tmp = TmpDir::new("checkpoint");
        let anchor_path = tmp.path().join(ANCHOR_FILE);
        let mut chain = Chain::open(tmp.path())
            .unwrap()
            .with_anchor(PRIV, &anchor_path, 1_000)
            .unwrap();

        // Nothing to checkpoint yet.
        assert!(chain.checkpoint(1).unwrap().is_none());

        chain.append(draft("e"), 1_000).unwrap();
        assert!(chain.checkpoint(1_001).unwrap().is_some());

        let report = Chain::verify(tmp.path(), Some(PUB)).unwrap();
        assert_eq!(report.anchors_verified, 1);
    }

    #[test]
    fn an_anchor_catches_a_wholesale_rewrite() {
        // The attack anchors exist for: an attacker who can rewrite the entire
        // chain file can make it internally consistent, but cannot re-sign it.
        let tmp = TmpDir::new("rewrite");
        let anchor_path = tmp.path().join(ANCHOR_FILE);
        {
            let mut chain = Chain::open(tmp.path())
                .unwrap()
                .with_anchor(PRIV, &anchor_path, 1)
                .unwrap();
            for i in 0..3 {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
        }
        // Rebuild a perfectly self-consistent chain with different content.
        {
            std::fs::remove_file(tmp.path().join(CHAIN_FILE)).unwrap();
            let mut chain = Chain::open(tmp.path()).unwrap();
            for i in 0..3 {
                let mut d = draft("e");
                d.reason = "forged".to_string();
                chain.append(d, 2_000 + i).unwrap();
            }
        }

        // Internally the forgery is flawless.
        let without_anchors = Chain::verify(tmp.path(), None).unwrap();
        assert!(
            without_anchors.is_intact(),
            "a self-consistent forgery passes chain-only verification"
        );

        // Against the signatures, it is not.
        let with_anchors = Chain::verify(tmp.path(), Some(PUB)).unwrap();
        assert!(!with_anchors.is_intact());
        assert_eq!(with_anchors.anchor_mismatches.len(), 3);
    }

    #[test]
    fn a_forged_anchor_file_is_rejected_outright() {
        let tmp = TmpDir::new("forged-anchor");
        {
            let mut chain = Chain::open(tmp.path()).unwrap();
            chain.append(draft("e"), 1_000).unwrap();
        }
        // An unsigned or wrongly-signed checkpoint is a different problem from a
        // mismatch, and must not be reported as a mere disagreement.
        std::fs::write(tmp.path().join(ANCHOR_FILE), "not.a.jwt\n").unwrap();
        assert_eq!(
            Chain::verify(tmp.path(), Some(PUB)).unwrap_err().code(),
            Code::CHAIN_BROKEN
        );
    }

    #[test]
    fn a_truncated_anchor_key_is_rejected() {
        let tmp = TmpDir::new("badkey");
        assert_eq!(
            Chain::open(tmp.path())
                .unwrap()
                .with_anchor(b"-----BEGIN PRIVATE KEY-----\nnope\n", "x", 1)
                .unwrap_err()
                .code(),
            Code::CHAIN_APPEND_FAILED
        );
    }

    // --- determinism ---

    #[test]
    fn hashing_is_deterministic_and_field_order_independent() {
        let a = Entry {
            seq: 1,
            ts: 1_000,
            kind: "contract.mint".into(),
            cid: Some("conn_7f3a91c4".into()),
            contract_jti: None,
            entities: vec!["x".into()],
            actor: "human:a@b".into(),
            decision: "record".into(),
            reason: "r".into(),
            policy_version: "v1".into(),
            detail: json!({"b": 1, "a": 2}),
            prev_hash: String::new(),
            row_hash: String::new(),
            schema: ENTRY_SCHEMA,
        };
        let mut b = a.clone();
        // Same content, different key order in the detail payload.
        b.detail = json!({"a": 2, "b": 1});
        assert_eq!(a.compute_row_hash(), b.compute_row_hash());
        assert_eq!(a.compute_row_hash(), a.compute_row_hash());
    }

    // --- segment retirement ---------------------------------------------
    //
    // `connect retention` reported a window and deleted nothing, because a row delete breaks
    // every row after it. These cover the alternative: whole ranges leave the live chain,
    // a tombstone keeps verification going, and — the part that matters — retirement grants
    // no authority a truncation would not already need.

    fn seeded_chain(tmp: &TmpDir, rows: u64, interval: u64) -> std::path::PathBuf {
        let anchor_path = tmp.path().join(ANCHOR_FILE);
        {
            let mut chain = Chain::open(tmp.path())
                .unwrap()
                .with_anchor(PRIV, &anchor_path, interval)
                .unwrap();
            for i in 0..rows {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
        }
        tmp.path().to_path_buf()
    }

    #[test]
    fn a_retired_segment_leaves_a_chain_that_still_verifies() {
        let tmp = TmpDir::new("retire-ok");
        let dir = seeded_chain(&tmp, 8, 2);

        // Retire the first four. `horizon` is later than their timestamps, so they are
        // outside the window; the newest rows are not.
        let out = retire_segment(&dir, 4, 1_004, PUB, 9_999).unwrap();
        assert_eq!(out.retirement.from, 1);
        assert_eq!(out.retirement.to, 4);
        assert_eq!(out.retirement.count, 4);
        assert_eq!(out.remaining, 4);
        assert!(
            out.segment_path.is_file(),
            "the rows are moved, not deleted"
        );

        // The live chain verifies, and says where it starts.
        let report = Chain::verify(&dir, Some(PUB)).unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.retired_through, 4);
        assert_eq!(report.entries, 4);
        assert_eq!(report.head_seq, 8);

        // The archive verifies against the tombstone.
        assert!(verify_retired_segment(&dir).unwrap().is_empty());

        // And the chain is still appendable, continuing the numbering.
        {
            let mut chain = Chain::open(&dir).unwrap();
            let e = chain.append(draft("after"), 2_000).unwrap();
            assert_eq!(e.seq, 9);
        }
        assert!(Chain::verify(&dir, Some(PUB)).unwrap().is_intact());
    }

    #[test]
    fn retirement_without_a_covering_checkpoint_is_refused() {
        // The property that stops retirement being a permission slip for truncation. With no
        // checkpoint at or past the range, "retired" and "deleted" are the same operation.
        let tmp = TmpDir::new("retire-unanchored");
        {
            let mut chain = Chain::open(tmp.path()).unwrap();
            for i in 0..6 {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
        }
        let err = retire_segment(tmp.path(), 3, 1_004, PUB, 9_999).unwrap_err();
        assert_eq!(err.code(), Code::CHAIN_BROKEN);
        assert!(
            err.detail().contains("indistinguishable from truncating"),
            "{}",
            err.detail()
        );
        // Nothing moved.
        assert_eq!(Chain::verify(tmp.path(), None).unwrap().entries, 6);
    }

    #[test]
    fn a_checkpoint_that_only_covers_part_of_the_range_does_not_authorise_it() {
        // A checkpoint at seq 2 attests rows 1-2. It must not authorise retiring row 3.
        let tmp = TmpDir::new("retire-partial");
        let anchor_path = tmp.path().join(ANCHOR_FILE);
        {
            // Interval 10 with 6 rows: no checkpoint is written at all past seq 0...
            let mut chain = Chain::open(tmp.path())
                .unwrap()
                .with_anchor(PRIV, &anchor_path, 2)
                .unwrap();
            for i in 0..4 {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
            // ...so checkpoints exist at 2 and 4. Retiring through 3 needs one at >= 3.
        }
        let ok = retire_segment(tmp.path(), 2, 1_004, PUB, 9_999);
        assert!(ok.is_ok(), "seq 2 is checkpointed: {ok:?}");

        let tmp2 = TmpDir::new("retire-partial2");
        let anchor2 = tmp2.path().join(ANCHOR_FILE);
        {
            let mut chain = Chain::open(tmp2.path())
                .unwrap()
                .with_anchor(PRIV, &anchor2, 5)
                .unwrap();
            for i in 0..7 {
                chain.append(draft("e"), 1_000 + i).unwrap();
            }
        }
        // Checkpoint at 5 only. Retiring through 6 is unauthorised.
        let err = retire_segment(tmp2.path(), 6, 1_010, PUB, 9_999).unwrap_err();
        assert!(
            err.detail().contains("no signed checkpoint covers seq 6"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn rows_inside_the_retention_window_are_refused() {
        // Retention exists to keep evidence for a period. Retiring inside that period is the
        // one thing this command must never do, so the clock is checked against the rows.
        let tmp = TmpDir::new("retire-young");
        let dir = seeded_chain(&tmp, 6, 2);
        let err = retire_segment(&dir, 4, 1_000, PUB, 9_999).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(
            err.detail().contains("inside the retention window"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn retiring_the_whole_chain_is_refused() {
        let tmp = TmpDir::new("retire-all");
        let dir = seeded_chain(&tmp, 4, 2);
        let err = retire_segment(&dir, 4, 9_000, PUB, 9_999).unwrap_err();
        assert!(
            err.detail().contains("keep at least the head"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_broken_chain_is_not_retired_from() {
        // Same stance as `backup`: acting on a break launders it into the archive.
        let tmp = TmpDir::new("retire-broken");
        let dir = seeded_chain(&tmp, 6, 2);
        let path = dir.join(CHAIN_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut rows: Vec<&str> = text.lines().collect();
        rows.swap(2, 3);
        std::fs::write(&path, rows.join("\n") + "\n").unwrap();

        let err = retire_segment(&dir, 2, 9_000, PUB, 9_999).unwrap_err();
        assert_eq!(err.code(), Code::CHAIN_BROKEN);
        assert!(err.detail().contains("does not verify"), "{}", err.detail());
    }

    #[test]
    fn a_forged_tombstone_does_not_make_a_short_chain_verify() {
        // The attack retirement could otherwise enable: delete the beginning, then write a
        // tombstone claiming it was retired. The surviving rows link to each other, so only
        // the tombstone's own claim can catch it — and it must link to what remains.
        let tmp = TmpDir::new("retire-forged");
        let dir = seeded_chain(&tmp, 8, 2);
        let entries = Chain::entries(&dir).unwrap();

        // Cut rows 1-4 by hand and forge a tombstone with a plausible-but-wrong hash.
        let kept: String = entries[4..]
            .iter()
            .map(|e| serde_json::to_string(e).unwrap() + "\n")
            .collect();
        std::fs::write(dir.join(CHAIN_FILE), kept).unwrap();
        let forged = Retirement {
            from: 1,
            to: 4,
            count: 4,
            last_row_hash: "0".repeat(64),
            anchor_seq: 4,
            anchor_row_hash: "0".repeat(64),
            segment_file: "retired/nope.jsonl".to_string(),
            segment_digest: format!("sha256:{}", "0".repeat(64)),
            retired_at: 1,
            newest_retired_ts: 1,
        };
        std::fs::write(
            dir.join(RETIRED_FILE),
            serde_json::to_string(&forged).unwrap(),
        )
        .unwrap();

        let report = Chain::verify(&dir, Some(PUB)).unwrap();
        assert!(!report.is_intact(), "a forged tombstone must not verify");
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.contains("the live chain starts from")),
            "{:?}",
            report.problems
        );
    }

    #[test]
    fn an_edited_archive_is_caught_by_its_digest() {
        let tmp = TmpDir::new("retire-edited");
        let dir = seeded_chain(&tmp, 8, 2);
        let out = retire_segment(&dir, 4, 1_004, PUB, 9_999).unwrap();
        assert!(verify_retired_segment(&dir).unwrap().is_empty());

        let text = std::fs::read_to_string(&out.segment_path).unwrap();
        std::fs::write(&out.segment_path, text.replace("\"e\"", "\"tampered\"")).unwrap();
        let problems = verify_retired_segment(&dir).unwrap();
        assert!(
            problems
                .iter()
                .any(|p| p.contains("does not match the digest")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_shipped_away_archive_is_reported_as_absent_not_as_corrupt() {
        // The normal state: the segment is in WORM storage. A verifier that failed here
        // would make shipping evidence off-box look like losing it.
        let tmp = TmpDir::new("retire-shipped");
        let dir = seeded_chain(&tmp, 8, 2);
        let out = retire_segment(&dir, 4, 1_004, PUB, 9_999).unwrap();
        std::fs::remove_file(&out.segment_path).unwrap();

        let problems = verify_retired_segment(&dir).unwrap();
        assert_eq!(problems.len(), 1);
        assert!(
            problems[0].contains("bring the archive back"),
            "{problems:?}"
        );
        // And the live chain is unaffected by the archive being gone.
        assert!(Chain::verify(&dir, Some(PUB)).unwrap().is_intact());
    }

    #[test]
    fn retirement_is_resumable_and_never_reruns_a_range() {
        let tmp = TmpDir::new("retire-twice");
        let dir = seeded_chain(&tmp, 10, 2);
        retire_segment(&dir, 4, 1_005, PUB, 9_999).unwrap();

        // The same range again is refused rather than double-archived.
        let err = retire_segment(&dir, 4, 1_006, PUB, 9_999).unwrap_err();
        assert!(err.detail().contains("already retired"), "{}", err.detail());

        // A later range continues from where the first stopped.
        let second = retire_segment(&dir, 6, 1_007, PUB, 9_999).unwrap();
        assert_eq!(second.retirement.from, 5);
        assert_eq!(second.retirement.to, 6);
        let report = Chain::verify(&dir, Some(PUB)).unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.retired_through, 6);
    }

    #[test]
    fn truncation_after_a_retirement_is_still_detected() {
        // The two features must not cancel out: retirement moves the boundary, and the
        // truncation check has to move with it rather than treat a retired chain as short.
        let tmp = TmpDir::new("retire-then-truncate");
        let dir = seeded_chain(&tmp, 10, 2);
        retire_segment(&dir, 4, 1_005, PUB, 9_999).unwrap();

        let text = std::fs::read_to_string(dir.join(CHAIN_FILE)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(dir.join(CHAIN_FILE), lines[..2].join("\n") + "\n").unwrap();

        let report = Chain::verify(&dir, None).unwrap();
        assert!(
            !report.is_intact(),
            "a truncated retired chain must not verify"
        );
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.contains("have been removed")),
            "{:?}",
            report.problems
        );
    }
}
