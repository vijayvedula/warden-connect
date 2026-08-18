//! Contract-set distribution: which mediators are holding the current set (W6b).
//!
//! Two ack ledgers exist and they answer different questions. [`crate::contain::AckLedger`] is
//! keyed by revocation `feed_seq` and answers *"did mediators confirm a cut?"* — the containment
//! question, and the one an incident is judged on. This one is keyed by the **state-log
//! sequence** and answers *"did mediators pick up the new set?"* — the distribution question, and
//! the one a deploy gate needs.
//!
//! Confusing them was a real mistake, made in writing: the architecture notes proposed
//! `wc_mediator_unconfirmed`, the containment metric, as the deploy gate. It cannot be. A
//! revocation ack says nothing about whether a *newly minted* contract has arrived, and a
//! mediator with no outstanding revocations is fully confirmed by that metric while holding a
//! contract set from an hour ago.
//!
//! # Why the sequence and not the set hash
//!
//! A mediator acks both. The gate compares **`seq`**, because the expected set hash is
//! clock-dependent: `Projection::contract_set_for` filters on `now < exp`, so the hash a control
//! plane would compute drifts as contracts lapse even with no state change at all. A gate built
//! on it would flap for reasons nobody could see. The sequence only moves when the log does.
//!
//! The hash is still recorded, because it is what tells two mediators apart when one is applying
//! a set built from the same sequence and disagreeing about its contents — which would be a bug
//! worth having the evidence for.
//!
//! # What a gate can and cannot promise
//!
//! Reaching `seq` means the mediator **fetched and installed** a set built at or after that
//! point in the log. It does not mean every contract in it verified: a mediator reports
//! `installed` and `rejected` separately, and an artifact that fails verification is omitted
//! rather than fatal. A gate that treated an ack as proof of a working contract would be
//! reporting the wrong thing, so [`Lag::rejected`] is carried through and
//! [`Distribution::clean`] is separate from [`Distribution::caught_up`].

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use wc_core::error::{Code, Result, WcError};

/// What one mediator last reported applying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetAck {
    /// The set hash it applied.
    pub set_hash: String,
    /// The state-log sequence the set was built from. What a gate compares.
    pub seq: u64,
    /// When it acked.
    pub at: u64,
    /// Contracts it reported as cut while applying.
    #[serde(default)]
    pub revoked: Vec<String>,
    /// In-flight calls it aborted.
    #[serde(default)]
    pub aborted: u64,
    /// Artifacts in the set that failed verification at this mediator.
    ///
    /// Carried because an ack is not proof of a working contract — one bad artifact is omitted
    /// and reported rather than being fatal, so a gate that read an ack as success would be
    /// answering a question nobody asked.
    #[serde(default)]
    pub rejected: u64,
}

/// The durable record of what every mediator has applied.
///
/// Durable is the whole point. This state lived in a `Mutex<HashMap<_, _>>` built with
/// `HashMap::new()` and never loaded or saved, so a control-plane restart zeroed it — and a gate
/// built naively on that would block every deploy until every mediator happened to refresh.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetAckLedger {
    /// Latest ack per mediator id.
    #[serde(default)]
    pub acked: BTreeMap<String, SetAck>,
}

impl SetAckLedger {
    /// Load from disk, or start empty.
    pub fn open(path: &Path) -> Result<SetAckLedger> {
        if !path.exists() {
            return Ok(SetAckLedger::default());
        }
        let text = std::fs::read_to_string(path).map_err(|e| {
            WcError::with_detail(
                Code::MEDIATOR_ACK_MISSING,
                format!("cannot read {}", path.display()),
            )
            .with_source(e)
        })?;
        serde_json::from_str(&text).map_err(|e| {
            WcError::with_detail(
                Code::MEDIATOR_ACK_MISSING,
                format!("{} is not a readable set-ack ledger", path.display()),
            )
            .with_source(e)
        })
    }

    /// Persist.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                WcError::with_detail(
                    Code::MEDIATOR_ACK_MISSING,
                    format!("cannot create {}", parent.display()),
                )
                .with_source(e)
            })?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| {
            WcError::with_detail(
                Code::MEDIATOR_ACK_MISSING,
                "cannot serialise the set-ack ledger",
            )
            .with_source(e)
        })?;
        std::fs::write(path, text).map_err(|e| {
            WcError::with_detail(
                Code::MEDIATOR_ACK_MISSING,
                format!("cannot write {}", path.display()),
            )
            .with_source(e)
        })
    }

    /// Record what a mediator applied.
    ///
    /// **Monotonic in `seq`.** A late ack carrying an older sequence is dropped rather than
    /// written, because two mediator processes for the same id — a rolling restart, a
    /// misconfigured duplicate — would otherwise take turns moving the ledger backwards, and a
    /// gate that had already passed would start failing for a set that is still installed
    /// somewhere. Returns whether the ledger moved.
    pub fn record(&mut self, mediator: &str, ack: SetAck) -> bool {
        match self.acked.get(mediator) {
            Some(held) if held.seq > ack.seq => false,
            _ => {
                self.acked.insert(mediator.to_string(), ack);
                true
            }
        }
    }

    /// How far one mediator has got.
    #[must_use]
    pub fn ack_for(&self, mediator: &str) -> Option<&SetAck> {
        self.acked.get(mediator)
    }

    /// Judge every expected mediator against a target sequence.
    ///
    /// `expected` is the set that must confirm — normally every mediator in the estate's
    /// `mediators.toml`. A mediator absent from the ledger is `Lag { acked: None }` and is
    /// **not** caught up: never-heard-from and up-to-date must not render the same, which is the
    /// distinction the ephemeral map could not make after a restart.
    #[must_use]
    pub fn distribution(&self, expected: &[String], target_seq: u64) -> Distribution {
        let mut lags: Vec<Lag> = expected
            .iter()
            .map(|m| {
                let ack = self.acked.get(m);
                Lag {
                    mediator: m.clone(),
                    acked_seq: ack.map(|a| a.seq),
                    set_hash: ack.map(|a| a.set_hash.clone()),
                    at: ack.map(|a| a.at),
                    rejected: ack.map_or(0, |a| a.rejected),
                }
            })
            .collect();
        lags.sort_by(|a, b| a.mediator.cmp(&b.mediator));
        Distribution { target_seq, lags }
    }
}

/// How far behind one mediator is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lag {
    /// Which mediator.
    pub mediator: String,
    /// The sequence it last applied, if it has ever acked.
    pub acked_seq: Option<u64>,
    /// The set hash it applied.
    pub set_hash: Option<String>,
    /// When it acked.
    pub at: Option<u64>,
    /// Artifacts it could not verify in that set.
    pub rejected: u64,
}

impl Lag {
    /// Whether this mediator has applied a set built at or after the target.
    #[must_use]
    pub fn caught_up(&self, target_seq: u64) -> bool {
        self.acked_seq.is_some_and(|s| s >= target_seq)
    }
}

/// The estate's distribution state against one target sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distribution {
    /// The sequence every mediator must reach.
    pub target_seq: u64,
    /// Per mediator, sorted by id so two runs render identically.
    pub lags: Vec<Lag>,
}

impl Distribution {
    /// Whether every expected mediator has reached the target.
    ///
    /// An empty expected set is **not** caught up. A gate configured with no mediators would
    /// otherwise pass instantly and read as though distribution had been confirmed, which is the
    /// failure this whole module exists to stop being possible.
    #[must_use]
    pub fn caught_up(&self) -> bool {
        !self.lags.is_empty() && self.lags.iter().all(|l| l.caught_up(self.target_seq))
    }

    /// Whether every mediator reached the target *and* verified everything in the set.
    ///
    /// Separate from [`Distribution::caught_up`] on purpose: an ack means the set was installed,
    /// not that every artifact in it verified.
    #[must_use]
    pub fn clean(&self) -> bool {
        self.caught_up() && self.lags.iter().all(|l| l.rejected == 0)
    }

    /// Mediators that have not reached the target.
    #[must_use]
    pub fn behind(&self) -> Vec<&Lag> {
        self.lags
            .iter()
            .filter(|l| !l.caught_up(self.target_seq))
            .collect()
    }

    /// One line an operator or a pipeline log can read.
    #[must_use]
    pub fn summary(&self) -> String {
        let total = self.lags.len();
        if total == 0 {
            return "NO MEDIATORS EXPECTED, so nothing confirms distribution".to_string();
        }
        let there = total - self.behind().len();
        let rejected: u64 = self.lags.iter().map(|l| l.rejected).sum();
        let mut s = format!("{there}/{total} mediator(s) hold seq {}", self.target_seq);
        if rejected > 0 {
            s.push_str(&format!(
                " · {rejected} artifact(s) failed verification at a mediator"
            ));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn ack(seq: u64) -> SetAck {
        SetAck {
            set_hash: format!("sha256:{seq:0>4}"),
            seq,
            at: 1_000 + seq,
            revoked: Vec::new(),
            aborted: 0,
            rejected: 0,
        }
    }

    fn expected(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn a_ledger_survives_a_round_trip_through_disk() {
        // The whole point of the module. The state this replaces was a `HashMap::new()` that was
        // never loaded or saved, so a control-plane restart zeroed it and a gate built on it
        // would have blocked every deploy until every mediator happened to refresh.
        let dir = std::env::temp_dir().join(format!("wc-dist-{}", std::process::id()));
        let path = dir.join("set-acks.json");
        let mut ledger = SetAckLedger::default();
        ledger.record("warden:mediator:apac", ack(7));
        ledger.save(&path).unwrap();

        let read = SetAckLedger::open(&path).unwrap();
        assert_eq!(read, ledger);
        assert_eq!(read.ack_for("warden:mediator:apac").unwrap().seq, 7);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_file_is_an_empty_ledger_not_an_error() {
        // A control plane starting for the first time has no ledger, and refusing to start would
        // be worse than starting with nothing confirmed — which is the honest state anyway.
        let ledger = SetAckLedger::open(Path::new("/nonexistent/set-acks.json")).unwrap();
        assert!(ledger.acked.is_empty());
    }

    #[test]
    fn an_unreadable_ledger_is_an_error_rather_than_an_empty_one() {
        // The distinction that matters: absent means nothing has acked, corrupt means the record
        // is unknown. Treating the second as the first would silently reset a gate.
        let dir = std::env::temp_dir().join(format!("wc-dist-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("set-acks.json");
        std::fs::write(&path, "{ not json").unwrap();
        let err = SetAckLedger::open(&path).unwrap_err();
        assert_eq!(err.code(), Code::MEDIATOR_ACK_MISSING);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_ack_never_moves_the_ledger_backwards() {
        // A rolling restart, or a duplicate mediator sharing an id, would otherwise take turns
        // moving the ledger back and forth — and a gate that had already passed would start
        // failing for a set still installed somewhere.
        let mut ledger = SetAckLedger::default();
        assert!(ledger.record("m", ack(9)));
        assert!(!ledger.record("m", ack(4)), "an older ack must be dropped");
        assert_eq!(ledger.ack_for("m").unwrap().seq, 9);

        // Equal is allowed through: a re-ack of the same set is how a mediator refreshes `at`,
        // and an operator asking "when did it last confirm?" needs that to move.
        let mut same = ack(9);
        same.at = 99_999;
        assert!(ledger.record("m", same));
        assert_eq!(ledger.ack_for("m").unwrap().at, 99_999);
    }

    #[test]
    fn a_mediator_that_never_acked_is_not_caught_up() {
        // Never-heard-from and up-to-date must not render the same. The ephemeral map could not
        // tell them apart after a restart, which is exactly how a gate would have passed while
        // confirming nothing.
        let mut ledger = SetAckLedger::default();
        ledger.record("a", ack(10));
        let d = ledger.distribution(&expected(&["a", "b"]), 10);

        assert!(!d.caught_up());
        assert_eq!(d.behind().len(), 1);
        assert_eq!(d.behind()[0].mediator, "b");
        assert_eq!(d.behind()[0].acked_seq, None);
        assert!(d.summary().contains("1/2"));
    }

    #[test]
    fn ahead_counts_as_caught_up() {
        // The comparison is `>=`, not `==`. A mediator that polled after two more contracts were
        // minted holds a later set which still contains everything the gate is waiting for, and
        // requiring equality would make a busy estate never pass.
        let mut ledger = SetAckLedger::default();
        ledger.record("a", ack(12));
        assert!(ledger.distribution(&expected(&["a"]), 10).caught_up());
    }

    #[test]
    fn an_empty_expected_set_is_not_confirmation() {
        // The failure this module exists to prevent: a gate configured with no mediators passing
        // instantly and reading as though distribution had been confirmed.
        let d = SetAckLedger::default().distribution(&[], 10);
        assert!(!d.caught_up());
        assert!(!d.clean());
        assert!(d.summary().contains("NO MEDIATORS EXPECTED"));
    }

    #[test]
    fn caught_up_and_clean_are_different_questions() {
        // An ack says the set was installed, not that every artifact in it verified. A gate that
        // conflated the two would report a working contract on the strength of a mediator having
        // fetched something.
        let mut ledger = SetAckLedger::default();
        let mut a = ack(10);
        a.rejected = 1;
        ledger.record("a", a);
        let d = ledger.distribution(&expected(&["a"]), 10);

        assert!(d.caught_up());
        assert!(!d.clean());
        assert!(d.summary().contains("failed verification"));
    }
}
