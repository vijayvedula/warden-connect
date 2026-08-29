//! The decision trail an enforcement point writes, and the chain that makes it evidence.
//!
//! # Why a file, and not a SIEM client
//!
//! `terms.evidence.sink` names something like `ocsf://siem`, and the temptation is to have the
//! enforcement point speak that protocol. It cannot, and the reason is structural rather than
//! effort: `wc-kong` is a `cdylib` loaded into an nginx worker, §8.2 forbids an async runtime in
//! anything embeddable, and `dep-count.sh` enforces it. An HTTP client with retries, batching
//! and backpressure has no home there.
//!
//! So the enforcement point writes a local file and something else ships it — the same shape
//! this project already chose for metrics, where `obs` writes a node-exporter textfile rather
//! than opening a port. `ocsf://siem` means *point a shipper at the file*.
//!
//! # Why a chain, and what it is honestly worth
//!
//! Appending JSON lines gives an operator a trail. It does not give them **evidence**: anyone
//! who can write the file can rewrite it. Each row therefore carries the hash of the row before
//! it, so an edit anywhere invalidates every row after — [`verify`] finds the first break.
//!
//! That still only defeats an adversary who cannot run sha256. Someone with write access can
//! rewrite the file *and* recompute the chain. What closes that is an anchor the node cannot
//! forge, and the enforcement point already has a channel to one: it acknowledges contract sets
//! to the control plane. Putting [`Head`] on that acknowledgement is what turns this from
//! tamper-*detecting* into tamper-*evident*, and it needs no new port and no new transport.
//! That step is not built yet, and this module is deliberately shaped so it can be added
//! without changing the file format.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use wc_core::obs::Decision;
use wc_core::util::sha256_hex;

/// The chain's position: how many rows, and the hash of the last one.
///
/// This is what an acknowledgement would carry. Two enforcement points on the same contract
/// keep independent chains, so a `Head` identifies a file rather than a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// Rows written. Zero for an empty trail.
    pub seq: u64,
    /// Hash of the last row, or [`GENESIS`] when there is none.
    pub hash: String,
}

/// The `prev` of the first row. A literal rather than an empty string, so a truncated file
/// cannot be mistaken for a fresh one.
pub const GENESIS: &str = "wc-evidence-genesis";

/// What the enforcement point does when a record cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// `terms.evidence.delivery = "blocking"` — no call proceeds without a recorded trail.
    /// A failed write is a refusal.
    Blocking,
    /// `"fail-safe"` — the call proceeds and the failure is reported once, loudly. The default,
    /// and the right one when the trail matters less than the traffic.
    FailSafe,
}

impl Delivery {
    /// Parse the contract's term. Anything unrecognised is [`Delivery::Blocking`].
    ///
    /// Unknown means "a term this build does not understand", and treating that as the
    /// permissive option would let a future term silently weaken an existing deployment.
    #[must_use]
    pub fn parse(s: &str) -> Delivery {
        match s {
            "fail-safe" | "" => Delivery::FailSafe,
            _ => Delivery::Blocking,
        }
    }
}

/// An append-only, hash-chained decision trail.
struct State {
    file: std::fs::File,
    head: Head,
}

/// One trail. Cheap to clone by `Arc`; every enforcement point on a process shares one.
pub struct FileSink {
    path: PathBuf,
    delivery: Delivery,
    state: Mutex<State>,
    /// Set once when a write has failed under `FailSafe`, so the operator is told once rather
    /// than once per call — a log that repeats itself at request rate is a log nobody reads.
    complained: std::sync::atomic::AtomicBool,
}

impl FileSink {
    /// Open a trail, resuming an existing chain or starting one.
    ///
    /// # Errors
    ///
    /// Refuses to open a file whose chain is already broken. Appending to a trail that does not
    /// verify would produce evidence that cannot be distinguished from evidence somebody edited,
    /// and the operator needs to know before the first call, not at the audit.
    pub fn open(path: impl AsRef<Path>, delivery: Delivery) -> Result<FileSink, String> {
        let path = path.as_ref().to_path_buf();
        let head = if path.exists() {
            verify(&path)?
        } else {
            Head {
                seq: 0,
                hash: GENESIS.to_string(),
            }
        };
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("evidence sink {}: {e}", path.display()))?;
        Ok(FileSink {
            path,
            delivery,
            state: Mutex::new(State { file, head }),
            complained: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Where the trail is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The chain's current position.
    #[must_use]
    pub fn head(&self) -> Head {
        self.lock().head.clone()
    }

    /// What a connection with no terms of its own gets.
    #[must_use]
    pub fn default_delivery(&self) -> Delivery {
        self.delivery
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A poisoned lock means another thread panicked mid-write. The chain is still readable
        // and the alternative is losing the trail entirely, so the poison is stepped over —
        // `verify` is what says whether the file is sound, not the lock's flag.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Append one decision.
    ///
    /// # Errors
    ///
    /// The write failure, for a binding that must decide what to do about it. Under
    /// [`Delivery::FailSafe`] the binding should forward anyway; under [`Delivery::Blocking`]
    /// it must refuse.
    pub fn record(&self, d: &Decision<'_>) -> Result<Head, String> {
        let mut st = self.lock();
        let seq = st.head.seq + 1;
        let line = d.to_line();
        let hash = row_hash(&st.head.hash, &line);
        // `rec` is embedded verbatim: it is already a complete JSON object, it is the same line
        // the inline mediator writes, and an operator greps both with one expression.
        let row = format!(
            "{{\"seq\":{seq},\"prev\":\"{}\",\"hash\":\"{hash}\",\"rec\":{line}}}\n",
            st.head.hash
        );
        st.file
            .write_all(row.as_bytes())
            .and_then(|()| st.file.flush())
            .map_err(|e| format!("evidence sink {}: {e}", self.path.display()))?;
        st.head = Head { seq, hash };
        Ok(st.head.clone())
    }

    /// Record, and say whether the call may proceed.
    ///
    /// `delivery` is passed per call because it is a **contract term**, not a property of the
    /// file: two connections writing to one trail can disagree about whether a lost record is
    /// worth refusing over. `None` — no contract matched, so there are no terms — falls back to
    /// what the sink was opened with.
    ///
    /// Returns `false` only when the write failed **and** delivery is blocking. The failure is
    /// reported to stderr once per process under fail-safe, because the alternative is a line
    /// per call and an operator who stops reading them.
    pub fn record_or_refuse(&self, d: &Decision<'_>, delivery: Option<Delivery>) -> bool {
        let delivery = delivery.unwrap_or(self.delivery);
        match self.record(d) {
            Ok(_) => true,
            Err(e) => {
                if delivery == Delivery::Blocking {
                    eprintln!("evidence: {e} — delivery is blocking, so this call is refused");
                    false
                } else {
                    if !self
                        .complained
                        .swap(true, std::sync::atomic::Ordering::SeqCst)
                    {
                        eprintln!(
                            "evidence: {e} — delivery is fail-safe, so calls continue and this \
                             trail is INCOMPLETE from here. Reported once."
                        );
                    }
                    true
                }
            }
        }
    }
}

/// The record text of a row, exactly as it was written.
///
/// The row is `{"seq":N,"prev":"..","hash":"..","rec":<record>}` and `<record>` is a complete
/// JSON object, so it runs from after `,"rec":` to the row's final `}`.
fn raw_rec(row: &str) -> Option<&str> {
    let row = row.trim_end();
    let start = row.find(",\"rec\":")? + 7;
    let end = row.len().checked_sub(1)?;
    if end <= start || !row.ends_with('}') {
        return None;
    }
    Some(&row[start..end])
}

/// The hash of one row: the previous hash and this record, in that order.
///
/// Separated by a newline so that no pair of (prev, line) values can produce the same input as
/// a different pair — the previous hash is fixed-width hex and cannot contain one.
#[must_use]
pub fn row_hash(prev: &str, line: &str) -> String {
    sha256_hex(&format!("{prev}\n{line}"))
}

/// The records after `seq`, once the whole trail has been verified.
///
/// Verification first, always. Handing back rows from a chain that does not hold would let a
/// reader act on records an editor chose for them, which is the one thing the chain exists to
/// prevent — and the tail of an edited file is exactly where the interesting rows would be.
///
/// Returns the verbatim record text of each row, so what a caller reads is what was hashed.
///
/// # Errors
///
/// If the trail does not verify, or cannot be read.
pub fn records_since(path: impl AsRef<Path>, seq: u64) -> Result<Vec<String>, String> {
    let path = path.as_ref();
    verify(path)?;
    let file =
        std::fs::File::open(path).map_err(|e| format!("evidence {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.map_err(|e| format!("evidence {}: {e}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        // `verify` has already established that every row parses and carries these fields.
        let row: serde_json::Value =
            serde_json::from_str(&line).map_err(|e| format!("evidence {}: {e}", path.display()))?;
        if row
            .get("seq")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            > seq
        {
            if let Some(raw) = raw_rec(&line) {
                out.push(raw.to_string());
            }
        }
    }
    Ok(out)
}

/// Walk a trail and confirm every row follows from the one before it.
///
/// # Errors
///
/// The first row that does not, by sequence number — which is where an edit begins. A later
/// intact-looking row proves nothing once an earlier one is broken.
pub fn verify(path: impl AsRef<Path>) -> Result<Head, String> {
    let path = path.as_ref();
    let file =
        std::fs::File::open(path).map_err(|e| format!("evidence {}: {e}", path.display()))?;
    let mut prev = GENESIS.to_string();
    let mut seq = 0u64;
    for (i, line) in std::io::BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("evidence {} row {}: {e}", path.display(), i + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let row: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| format!("evidence {} row {}: not JSON: {e}", path.display(), i + 1))?;
        let got_seq = row.get("seq").and_then(serde_json::Value::as_u64);
        let got_prev = row.get("prev").and_then(serde_json::Value::as_str);
        let got_hash = row.get("hash").and_then(serde_json::Value::as_str);
        let rec = row.get("rec");
        let (Some(got_seq), Some(got_prev), Some(got_hash), Some(rec)) =
            (got_seq, got_prev, got_hash, rec)
        else {
            return Err(format!(
                "evidence {} row {}: missing seq, prev, hash or rec",
                path.display(),
                i + 1
            ));
        };
        if got_seq != seq + 1 {
            return Err(format!(
                "evidence {} row {}: seq {got_seq}, expected {}",
                path.display(),
                i + 1,
                seq + 1
            ));
        }
        if got_prev != prev {
            return Err(format!(
                "evidence {} row {got_seq}: prev does not follow the row before it — the trail \
                 was edited at or before here",
                path.display()
            ));
        }
        // The VERBATIM record text, not a re-serialisation. `Decision::to_line` is hand-rolled
        // with a fixed field order; `serde_json` would re-emit the same object with its own
        // ordering and spacing, and every honest row would fail to verify. The row format is
        // this module's, so slicing it is exact rather than a guess.
        let Some(raw) = raw_rec(&line) else {
            return Err(format!(
                "evidence {} row {got_seq}: cannot locate the record text",
                path.display()
            ));
        };
        let _ = rec;
        let want = row_hash(&prev, raw);
        if got_hash != want {
            return Err(format!(
                "evidence {} row {got_seq}: hash does not match its contents — this row was \
                 edited",
                path.display()
            ));
        }
        prev = got_hash.to_string();
        seq = got_seq;
    }
    Ok(Head { seq, hash: prev })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn dir(name: &str) -> PathBuf {
        // Per-test, because a shared path across tests is a flake this repository has paid for.
        let d = std::env::temp_dir().join(format!("wc-evidence-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn decision<'a>(cid: &'a str, verdict: &'a str, code: &'a str, tool: &'a str) -> Decision<'a> {
        Decision {
            cid,
            decision: verdict,
            code,
            mode: "enforce",
            tool,
            caller: "spiffe://org/ns/agents/sa/recon-bot",
            callee: "spiffe://org/ns/tools/sa/payments-mcp",
            jti: "cx_84be0011",
            at: 1_800_000_000,
            micros: 42,
        }
    }

    #[test]
    fn a_trail_verifies_and_reports_its_head() {
        let p = dir("basic").join("trail.jsonl");
        let _ = std::fs::remove_file(&p);
        let sink = FileSink::open(&p, Delivery::FailSafe).unwrap();
        assert_eq!(sink.head().seq, 0);
        assert_eq!(sink.head().hash, GENESIS);

        sink.record(&decision("conn_a", "allow", "WC-0000", "get_balance"))
            .unwrap();
        let h = sink
            .record(&decision("conn_a", "deny", "WC-4002", "transfer_funds"))
            .unwrap();
        assert_eq!(h.seq, 2);
        assert_eq!(verify(&p).unwrap(), h, "the head must match a full walk");
    }

    #[test]
    fn records_since_returns_the_tail_and_refuses_an_edited_trail() {
        let p = dir("since").join("trail.jsonl");
        let _ = std::fs::remove_file(&p);
        let sink = FileSink::open(&p, Delivery::FailSafe).unwrap();
        for i in 0..4 {
            sink.record(&decision("conn_a", "allow", "WC-0000", "get_balance"))
                .unwrap();
            let _ = i;
        }

        assert_eq!(records_since(&p, 0).unwrap().len(), 4);
        assert_eq!(records_since(&p, 2).unwrap().len(), 2);
        assert!(records_since(&p, 4).unwrap().is_empty());
        // Verbatim record text, so what a caller reads is what was hashed.
        assert!(records_since(&p, 3).unwrap()[0].contains("\"cid\":\"conn_a\""));

        // The part worth having a test for. An edited trail must yield NOTHING, not the rows
        // that happen to sit after the break — the tail of an edited file is exactly where an
        // editor would put what they wanted read.
        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.replace("get_balance", "transfer_funds")).unwrap();
        let err = records_since(&p, 0).unwrap_err();
        assert!(err.contains("edited"), "{err}");
    }

    /// The point of the chain. Editing any row must invalidate the trail from there.
    #[test]
    fn an_edited_record_is_detected_and_the_row_is_named() {
        let p = dir("tamper").join("trail.jsonl");
        let _ = std::fs::remove_file(&p);
        let sink = FileSink::open(&p, Delivery::FailSafe).unwrap();
        for i in 0..5 {
            let tool = if i == 2 {
                "transfer_funds"
            } else {
                "get_balance"
            };
            let verdict = if i == 2 { "deny" } else { "allow" };
            let code = if i == 2 { "WC-4002" } else { "WC-0000" };
            sink.record(&decision("conn_a", verdict, code, tool))
                .unwrap();
        }
        drop(sink);
        assert!(
            verify(&p).is_ok(),
            "the trail must be sound before it is edited"
        );

        // Somebody turns the refusal into an allow, which is the edit that matters.
        let text = std::fs::read_to_string(&p).unwrap();
        let doctored = text.replace("\"decision\":\"deny\"", "\"decision\":\"allow\"");
        assert_ne!(
            doctored, text,
            "the test must actually have changed something"
        );
        std::fs::write(&p, &doctored).unwrap();

        let e = verify(&p).expect_err("an edited row must not verify");
        assert!(e.contains("row 3"), "the failure must name the row: {e}");
        assert!(e.contains("edited"), "{e}");
    }

    /// Deleting a row is the other half: the survivors are individually well-formed.
    #[test]
    fn a_deleted_row_breaks_the_chain_rather_than_shortening_it() {
        let p = dir("delete").join("trail.jsonl");
        let _ = std::fs::remove_file(&p);
        let sink = FileSink::open(&p, Delivery::FailSafe).unwrap();
        for _ in 0..4 {
            sink.record(&decision("conn_a", "deny", "WC-4002", "transfer_funds"))
                .unwrap();
        }
        drop(sink);
        let text = std::fs::read_to_string(&p).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&p, kept.join("\n") + "\n").unwrap();

        let e = verify(&p).expect_err("a removed row must not verify");
        assert!(e.contains("seq 3, expected 2"), "{e}");
    }

    #[test]
    fn a_trail_resumes_where_it_left_off() {
        let p = dir("resume").join("trail.jsonl");
        let _ = std::fs::remove_file(&p);
        {
            let sink = FileSink::open(&p, Delivery::FailSafe).unwrap();
            sink.record(&decision("conn_a", "allow", "WC-0000", "get_balance"))
                .unwrap();
        }
        let sink = FileSink::open(&p, Delivery::FailSafe).unwrap();
        assert_eq!(
            sink.head().seq,
            1,
            "a restart must not start a second chain"
        );
        sink.record(&decision("conn_a", "allow", "WC-0000", "get_balance"))
            .unwrap();
        assert_eq!(verify(&p).unwrap().seq, 2);
    }

    /// Appending to a trail that already does not verify would produce evidence indistinguishable
    /// from evidence somebody edited.
    #[test]
    fn opening_a_broken_trail_is_refused() {
        let p = dir("broken").join("trail.jsonl");
        let _ = std::fs::remove_file(&p);
        {
            let sink = FileSink::open(&p, Delivery::FailSafe).unwrap();
            sink.record(&decision("conn_a", "deny", "WC-4002", "transfer_funds"))
                .unwrap();
        }
        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.replace("WC-4002", "WC-0000")).unwrap();
        let e = match FileSink::open(&p, Delivery::FailSafe) {
            Ok(_) => panic!("appending to a broken trail must be refused"),
            Err(e) => e,
        };
        assert!(e.contains("edited"), "{e}");
    }

    #[test]
    fn an_unknown_delivery_term_is_blocking_not_permissive() {
        assert_eq!(Delivery::parse("blocking"), Delivery::Blocking);
        assert_eq!(Delivery::parse("fail-safe"), Delivery::FailSafe);
        assert_eq!(Delivery::parse(""), Delivery::FailSafe);
        assert_eq!(
            Delivery::parse("some-future-mode"),
            Delivery::Blocking,
            "a term this build does not understand must not weaken an existing deployment"
        );
    }

    #[test]
    fn a_failed_write_refuses_only_when_delivery_is_blocking() {
        let d = dir("refuse");
        let p = d.join("trail.jsonl");
        let _ = std::fs::remove_file(&p);
        let sink = FileSink::open(&p, Delivery::Blocking).unwrap();
        assert_eq!(sink.default_delivery(), Delivery::Blocking);
        assert!(sink.record_or_refuse(&decision("conn_a", "allow", "WC-0000", "get_balance"), None));

        let safe = FileSink::open(d.join("other.jsonl"), Delivery::FailSafe).unwrap();
        assert_eq!(safe.default_delivery(), Delivery::FailSafe);
        // A contract may be stricter than the file's default, and the term is what decides.
        assert!(safe.record_or_refuse(
            &decision("conn_a", "allow", "WC-0000", "get_balance"),
            Some(Delivery::Blocking)
        ));
    }

    /// The record embedded in a row must be byte-identical to what the inline mediator logs, or
    /// an operator cannot grep both with one expression — and the hash would not verify.
    #[test]
    fn the_embedded_record_is_the_same_line_the_mediator_writes() {
        let p = dir("shape").join("trail.jsonl");
        let _ = std::fs::remove_file(&p);
        let sink = FileSink::open(&p, Delivery::FailSafe).unwrap();
        let d = decision("conn_a", "deny", "WC-4002", "transfer_funds");
        sink.record(&d).unwrap();
        let row = std::fs::read_to_string(&p).unwrap();
        assert!(
            row.contains(&d.to_line()),
            "the row must embed to_line() verbatim:\n{row}"
        );
    }

    #[test]
    fn concurrent_writers_produce_one_unbroken_chain() {
        let p = dir("threads").join("trail.jsonl");
        let _ = std::fs::remove_file(&p);
        let sink = std::sync::Arc::new(FileSink::open(&p, Delivery::FailSafe).unwrap());
        let mut hs = Vec::new();
        for _ in 0..8 {
            let s = std::sync::Arc::clone(&sink);
            hs.push(std::thread::spawn(move || {
                for _ in 0..25 {
                    s.record(&decision("conn_a", "allow", "WC-0000", "get_balance"))
                        .unwrap();
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        let head = verify(&p).expect("8 threads must still leave one sound chain");
        assert_eq!(head.seq, 200);
        assert_eq!(head, sink.head());
    }
}
