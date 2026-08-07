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

/// Verify every checkpoint in an anchor file against a chain's entries.
///
/// Returns the number verified, and the sequences where a checkpoint disagreed with
/// the chain — which is the signal that the chain was rewritten after signing.
pub fn verify_anchors(
    anchor_path: &Path,
    pub_pem: &[u8],
    entries: &[Entry],
) -> Result<(u64, Vec<u64>)> {
    let key = DecodingKey::from_ec_pem(pub_pem).map_err(|e| {
        WcError::with_detail(Code::CHAIN_BROKEN, "anchor public key is not an EC PEM")
            .with_source(e)
    })?;

    let text = match std::fs::read_to_string(anchor_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, Vec::new())),
        Err(e) => return Err(io_err(anchor_path, e)),
    };

    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;

    let mut verified = 0u64;
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

        match entries.iter().find(|e| e.seq == checkpoint.seq) {
            Some(entry) if entry.row_hash == checkpoint.row_hash => verified += 1,
            // Either the row was altered, or it is gone entirely. Both mean the
            // chain no longer matches what was signed.
            _ => mismatches.push(checkpoint.seq),
        }
    }
    Ok((verified, mismatches))
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
        let (last_seq, last_hash) = entries
            .last()
            .map_or((0, String::new()), |e| (e.seq, e.row_hash.clone()));

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

        let mut expected_prev = String::new();
        let mut expected_seq = 1u64;
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

        if let Some(pem) = anchor_pub_pem {
            let (verified, mismatches) = verify_anchors(&dir.join(ANCHOR_FILE), pem, &entries)?;
            report.anchors_verified = verified;
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
    /// Human-readable problems, in order found.
    pub problems: Vec<String>,
}

impl ChainReport {
    /// Whether the chain is intact and every checkpoint agrees with it.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.broken_at.is_none() && self.anchor_mismatches.is_empty()
    }
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
}
