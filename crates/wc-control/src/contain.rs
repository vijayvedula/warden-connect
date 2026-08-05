//! Containment: the signed revocation feed, fan-out, and ACK deadlines
//! (`docs/08-lld.md` §8.7.7, §8.6.7).
//!
//! Quarantine is the demo moment and the easiest thing in the system to get
//! dishonestly right. Marking a party `Quarantined` in the registry takes five
//! milliseconds and proves nothing: the party keeps working until every mediator
//! holding one of its contracts stops honouring it. So the interesting output of
//! containment is not "done" — it is **which mediators have confirmed, which have
//! not, and what bounds the ones that have not.**
//!
//! # Three mechanisms, in order of how much they are relied on
//!
//! 1. **The revocation feed** is the source of truth: append-only, monotonically
//!    sequenced, and every event individually signed. A mediator pulls it, so a
//!    control plane that is down cannot un-revoke anything, and a compromised one
//!    cannot forge a revocation without the revocation key.
//! 2. **Push** is latency optimisation only. It gets the p50 under a couple of
//!    seconds instead of under the poll interval. Every push failure is reported
//!    and none of them changes the guarantee, because the mediator pulls anyway.
//! 3. **The ACK ledger** is what turns "contained" into a claim with evidence. A
//!    mediator that has not acked by its deadline is `unconfirmed` — never
//!    contained, never assumed, and still listed days later.
//!
//! # `bounded_by` is the honest part
//!
//! An unconfirmed mediator is not an unbounded risk, and saying so precisely is
//! more useful than either "contained" or "unknown". The bound is
//! `poll_interval + verify`, and past that the mediator's cached contracts expire
//! on their own. [`ContainmentReport::bounded_by`] states it in seconds so an
//! incident report can quote a number instead of a hope.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use wc_core::contract::{IssuerKey, IssuerKeys};
use wc_core::error::{Code, Result, WcError};
use wc_core::model::{Cid, EntityId, Jti};
use wc_core::util::sha256_hex;

// ---------------------------------------------------------------------------
// Revocation events
// ---------------------------------------------------------------------------

/// What a revocation names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Revoked {
    /// Every contract in which this party appears, in either direction.
    ///
    /// The blunt instrument, and the backstop: it holds even if the control
    /// plane's contract-set construction has a bug, because a mediator can apply
    /// it without knowing which contracts exist.
    Party {
        /// The contained party.
        id: EntityId,
    },
    /// One connection.
    Connection {
        /// The connection id.
        cid: Cid,
    },
    /// One artifact, by its `jti`. For a leaked contract whose relationship is
    /// otherwise fine.
    Artifact {
        /// The artifact id.
        jti: Jti,
    },
}

impl Revoked {
    /// The target as a string, for indexes and reports.
    #[must_use]
    pub fn target(&self) -> String {
        match self {
            Revoked::Party { id } => id.as_str().to_string(),
            Revoked::Connection { cid } => cid.as_str().to_string(),
            Revoked::Artifact { jti } => jti.as_str().to_string(),
        }
    }

    /// Label for output.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Revoked::Party { .. } => "party",
            Revoked::Connection { .. } => "cid",
            Revoked::Artifact { .. } => "jti",
        }
    }
}

/// One entry in the revocation feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEvent {
    /// Monotonic sequence. A mediator asks for everything after the last one it
    /// applied, so a gap is detectable rather than invisible.
    pub seq: u64,
    /// What is revoked.
    #[serde(flatten)]
    pub revoked: Revoked,
    /// Why, for the record an auditor reads.
    pub reason: String,
    /// The accountable actor.
    pub actor: String,
    /// When the order was made.
    pub at: u64,
    /// Never expires implicitly: a revocation that ages out is a revocation that
    /// silently stops applying. `None` means permanent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

impl RevocationEvent {
    /// Whether this event still applies at `now`.
    #[must_use]
    pub fn applies_at(&self, now: u64) -> bool {
        self.until.is_none_or(|until| now < until)
    }
}

/// A feed entry with its detached signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRevocation {
    /// The event.
    pub event: RevocationEvent,
    /// Detached JWS over the event, signed with the revocation key.
    pub jws: String,
    /// Key id that signed it.
    pub kid: String,
}

// ---------------------------------------------------------------------------
// The feed
// ---------------------------------------------------------------------------

/// The append-only, signed revocation feed.
///
/// Separate from the evidence chain on purpose. The chain is a tamper-evident
/// record of what happened; this is an *instruction* a mediator acts on, and it is
/// signed with a different key (§8.12.1) so an operator who can write history
/// cannot thereby cut connections.
#[derive(Debug)]
pub struct RevocationFeed {
    path: PathBuf,
    events: Vec<SignedRevocation>,
}

impl RevocationFeed {
    /// Open or create a feed, replaying what is already there.
    ///
    /// A line that does not parse is a **hard error**, not a skip: a revocation
    /// the feed cannot read is a revocation that is not being applied, and
    /// continuing past it would mean serving a feed that silently omits a cut.
    pub fn open(path: &Path) -> Result<RevocationFeed> {
        let mut events: Vec<SignedRevocation> = Vec::new();
        if path.exists() {
            let text = std::fs::read_to_string(path).map_err(|e| {
                WcError::with_detail(
                    Code::REVOCATION_FEED_UNWRITABLE,
                    format!("cannot read {}", path.display()),
                )
                .with_source(e)
            })?;
            for (i, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let entry: SignedRevocation = serde_json::from_str(line).map_err(|e| {
                    WcError::with_detail(
                        Code::REVOCATION_FEED_UNWRITABLE,
                        format!("{}:{}: unreadable revocation", path.display(), i + 1),
                    )
                    .with_source(e)
                })?;
                events.push(entry);
            }
        }
        // Sequence gaps mean an event was lost. A feed with a hole cannot be
        // served as complete, because a mediator asking `since=N` would be told
        // it is current when it is not.
        for (i, entry) in events.iter().enumerate() {
            let expected = i as u64 + 1;
            if entry.event.seq != expected {
                return Err(WcError::with_detail(
                    Code::REVOCATION_FEED_UNWRITABLE,
                    format!(
                        "{}: sequence gap — entry {} has seq {}, expected {expected}",
                        path.display(),
                        i + 1,
                        entry.event.seq
                    ),
                ));
            }
        }
        Ok(RevocationFeed {
            path: path.to_path_buf(),
            events,
        })
    }

    /// The next sequence number.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.events.len() as u64 + 1
    }

    /// How many events the feed holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the feed is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Sign and append a revocation, flushing before returning.
    ///
    /// The write is durable before the caller is told it succeeded: reporting a
    /// containment that did not reach disk is the one failure this file exists to
    /// prevent.
    pub fn append(
        &mut self,
        revoked: Revoked,
        reason: &str,
        actor: &str,
        now: u64,
        key: &IssuerKey,
    ) -> Result<SignedRevocation> {
        let event = RevocationEvent {
            seq: self.next_seq(),
            revoked,
            reason: reason.to_string(),
            actor: actor.to_string(),
            at: now,
            until: None,
        };
        let jws = wc_core::contract::sign_detached(&event, key).map_err(|e| {
            WcError::with_detail(
                Code::REVOCATION_FEED_UNWRITABLE,
                "cannot sign the revocation",
            )
            .with_source(e)
        })?;
        let entry = SignedRevocation {
            event,
            jws,
            kid: key.kid().to_string(),
        };

        let line = serde_json::to_string(&entry).map_err(|e| {
            WcError::with_detail(
                Code::REVOCATION_FEED_UNWRITABLE,
                "cannot serialise the revocation",
            )
            .with_source(e)
        })?;
        self.write_line(&line)?;
        self.events.push(entry.clone());
        Ok(entry)
    }

    fn write_line(&self, line: &str) -> Result<()> {
        use std::io::Write as _;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                WcError::with_detail(
                    Code::REVOCATION_FEED_UNWRITABLE,
                    format!("cannot create {}", parent.display()),
                )
                .with_source(e)
            })?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| {
                WcError::with_detail(
                    Code::REVOCATION_FEED_UNWRITABLE,
                    format!("cannot open {}", self.path.display()),
                )
                .with_source(e)
            })?;
        writeln!(file, "{line}").and_then(|()| file.sync_all()).map_err(|e| {
            WcError::with_detail(
                Code::REVOCATION_FEED_UNWRITABLE,
                format!("cannot append to {}", self.path.display()),
            )
            .with_source(e)
        })
    }

    /// Events after `since`, oldest first.
    #[must_use]
    pub fn since(&self, since: u64) -> Vec<&SignedRevocation> {
        self.events
            .iter()
            .filter(|e| e.event.seq > since)
            .collect()
    }

    /// Every event, for a full resync.
    #[must_use]
    pub fn all(&self) -> &[SignedRevocation] {
        &self.events
    }

    /// A digest over the feed as of its head, so a mediator's ACK can name
    /// exactly what it applied.
    #[must_use]
    pub fn head_digest(&self) -> String {
        let joined: String = self.events.iter().map(|e| e.jws.as_str()).collect();
        format!("sha256:{}", sha256_hex(&joined))
    }

    /// Verify every signature in the feed against the trusted revocation keys.
    ///
    /// Used by `connect audit verify`. The feed is an instruction set, so an
    /// unverifiable entry is not a curiosity — it is a cut that may not have been
    /// authorised.
    pub fn verify(&self, keys: &IssuerKeys) -> Result<usize> {
        for entry in &self.events {
            let decoded: RevocationEvent =
                wc_core::contract::verify_detached(&entry.jws, &entry.kid, keys).map_err(|e| {
                    WcError::with_detail(
                        Code::REVOCATION_FEED_UNWRITABLE,
                        format!("revocation seq {} does not verify", entry.event.seq),
                    )
                    .with_source(e)
                })?;
            if decoded != entry.event {
                // The signature is valid over *something else*. The plaintext line
                // was edited after signing.
                return Err(WcError::with_detail(
                    Code::REVOCATION_FEED_UNWRITABLE,
                    format!(
                        "revocation seq {} does not match its signed payload",
                        entry.event.seq
                    ),
                ));
            }
        }
        Ok(self.events.len())
    }
}

// ---------------------------------------------------------------------------
// Mediators
// ---------------------------------------------------------------------------

/// A mediator the control plane expects to confirm containment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediatorTarget {
    /// The mediator id, matching each contract's `aud`.
    pub id: String,
    /// Where to push. Absent means pull-only, which is slower and equally safe.
    #[serde(default)]
    pub push_url: Option<String>,
    /// How often this mediator pulls, in seconds. This is what bounds an
    /// unconfirmed mediator, so it is configuration rather than a guess.
    #[serde(default = "default_poll_interval")]
    pub poll_interval: u32,
}

fn default_poll_interval() -> u32 {
    5
}

/// The mediators in this estate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediatorSet {
    /// Every known mediator.
    #[serde(default, rename = "mediator")]
    pub mediators: Vec<MediatorTarget>,
}

impl MediatorSet {
    /// Parse from TOML.
    pub fn parse(text: &str) -> Result<MediatorSet> {
        let set: MediatorSet = toml::from_str(text).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, "mediator set is not valid TOML")
                .with_source(e)
        })?;
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for m in &set.mediators {
            if !seen.insert(m.id.as_str()) {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("mediator {:?} is listed twice", m.id),
                ));
            }
            if m.poll_interval == 0 {
                // A zero interval would make the unconfirmed bound zero, which
                // would read as "already contained".
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("mediator {:?} has poll_interval = 0", m.id),
                ));
            }
        }
        Ok(set)
    }

    /// Read from disk.
    pub fn load(path: &Path) -> Result<MediatorSet> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("cannot read mediator set {}", path.display()),
            )
            .with_source(e)
        })?;
        MediatorSet::parse(&text)
    }

    /// Look one up.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&MediatorTarget> {
        self.mediators.iter().find(|m| m.id == id)
    }

    /// The worst-case seconds before an unpushed mediator applies a revocation.
    #[must_use]
    pub fn worst_poll_interval(&self) -> u32 {
        self.mediators
            .iter()
            .map(|m| m.poll_interval)
            .max()
            .unwrap_or(default_poll_interval())
    }
}

// ---------------------------------------------------------------------------
// Push
// ---------------------------------------------------------------------------

/// How a push attempt turned out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// The mediator accepted the notification.
    Accepted,
    /// No push endpoint is configured; the mediator will pull.
    PullOnly,
    /// Every attempt failed. Reported, and harmless — the pull is the guarantee.
    Failed {
        /// Attempts made.
        attempts: u32,
        /// The last error.
        detail: String,
    },
}

impl PushOutcome {
    /// Whether the mediator was reached.
    #[must_use]
    pub fn reached(&self) -> bool {
        matches!(self, PushOutcome::Accepted)
    }
}

/// Notifying a mediator that the feed moved.
///
/// A trait so containment is testable without a network, and so an estate can
/// substitute its own transport. The push is never load-bearing: an
/// implementation that always fails must still yield a correct containment
/// report.
pub trait Push {
    /// Tell one mediator to refresh now.
    fn notify(&self, target: &MediatorTarget, feed_seq: u64) -> PushOutcome;
}

/// Pull-only containment. Correct, just slower to confirm.
#[derive(Debug, Default)]
pub struct NoPush;

impl Push for NoPush {
    fn notify(&self, _target: &MediatorTarget, _feed_seq: u64) -> PushOutcome {
        PushOutcome::PullOnly
    }
}

/// HTTP push with bounded retries.
#[derive(Debug, Clone)]
pub struct HttpPush {
    /// Bearer token presented to the mediator.
    pub token: String,
    /// Per-attempt timeout.
    pub timeout: Duration,
    /// Attempts per mediator.
    pub attempts: u32,
}

impl Default for HttpPush {
    fn default() -> Self {
        HttpPush {
            token: String::new(),
            timeout: Duration::from_secs(2),
            attempts: 3,
        }
    }
}

impl Push for HttpPush {
    fn notify(&self, target: &MediatorTarget, feed_seq: u64) -> PushOutcome {
        let Some(url) = &target.push_url else {
            return PushOutcome::PullOnly;
        };
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();

        let body = serde_json::json!({ "feed_seq": feed_seq }).to_string();
        let mut last = String::new();
        for attempt in 1..=self.attempts.max(1) {
            let result = agent
                .post(url)
                .header("authorization", &format!("Bearer {}", self.token))
                .header("content-type", "application/json")
                .send(body.clone());
            match result {
                Ok(response) => {
                    let status = response.status().as_u16();
                    if (200..300).contains(&status) {
                        return PushOutcome::Accepted;
                    }
                    last = format!("attempt {attempt}: HTTP {status}");
                }
                Err(e) => last = format!("attempt {attempt}: {e}"),
            }
        }
        PushOutcome::Failed {
            attempts: self.attempts.max(1),
            detail: last,
        }
    }
}

// ---------------------------------------------------------------------------
// The ACK ledger
// ---------------------------------------------------------------------------

/// What one mediator confirmed applying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// Which mediator.
    pub mediator: String,
    /// The feed sequence it has applied up to.
    pub feed_seq: u64,
    /// Connections it reports as cut.
    #[serde(default)]
    pub revoked: Vec<String>,
    /// In-flight calls it aborted, which is the number an incident report wants.
    #[serde(default)]
    pub aborted: u64,
    /// When it confirmed.
    pub at: u64,
}

/// Durable ACK state: who must confirm what, by when, and who has.
///
/// Persisted, because the question "did every mediator confirm the cut we made at
/// 03:14?" is asked long after the process that made the cut has exited.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AckLedger {
    /// Highest feed sequence each mediator has confirmed.
    #[serde(default)]
    pub confirmed: BTreeMap<String, Confirmation>,
    /// Outstanding containment orders, by feed sequence.
    #[serde(default)]
    pub orders: Vec<Order>,
}

/// A containment order awaiting confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// Feed sequence this order corresponds to.
    pub feed_seq: u64,
    /// What was revoked.
    pub target: String,
    /// Which mediators must confirm.
    pub expected: Vec<String>,
    /// When the order was made.
    pub at: u64,
    /// When an unconfirmed mediator becomes overdue.
    pub deadline_at: u64,
}

/// Per-mediator confirmation state for one order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckState {
    /// Confirmed at or beyond the order's sequence.
    Confirmed {
        /// The confirmation.
        confirmation: Confirmation,
    },
    /// Not confirmed, and the deadline has not passed.
    Waiting {
        /// Seconds left before it is overdue.
        seconds_left: u64,
    },
    /// Not confirmed by the deadline.
    ///
    /// Not "probably fine". This is the state an incident report has to carry.
    Overdue {
        /// Seconds past the deadline.
        seconds_late: u64,
        /// The last sequence it confirmed, if ever.
        last_seq: Option<u64>,
    },
}

impl AckState {
    /// Whether this counts as confirmed.
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        matches!(self, AckState::Confirmed { .. })
    }
}

impl AckLedger {
    /// Load from disk, or start empty.
    pub fn open(path: &Path) -> Result<AckLedger> {
        if !path.exists() {
            return Ok(AckLedger::default());
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
                format!("{} is not a readable ack ledger", path.display()),
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
            WcError::with_detail(Code::MEDIATOR_ACK_MISSING, "cannot serialise the ledger")
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

    /// Record an order that mediators must confirm.
    pub fn expect(&mut self, order: Order) {
        self.orders.retain(|o| o.feed_seq != order.feed_seq);
        self.orders.push(order);
        self.orders.sort_by_key(|o| o.feed_seq);
    }

    /// Record a confirmation.
    ///
    /// A mediator's confirmed sequence only ever moves forward: a stale ACK
    /// arriving late must not walk back a confirmation already recorded.
    pub fn record(&mut self, confirmation: Confirmation) {
        match self.confirmed.get(&confirmation.mediator) {
            Some(existing) if existing.feed_seq >= confirmation.feed_seq => {}
            _ => {
                self.confirmed
                    .insert(confirmation.mediator.clone(), confirmation);
            }
        }
    }

    /// Confirmation state for one order.
    #[must_use]
    pub fn state_of(&self, order: &Order, now: u64) -> BTreeMap<String, AckState> {
        order
            .expected
            .iter()
            .map(|mediator| {
                let state = match self.confirmed.get(mediator) {
                    Some(c) if c.feed_seq >= order.feed_seq => AckState::Confirmed {
                        confirmation: c.clone(),
                    },
                    other => {
                        if now >= order.deadline_at {
                            AckState::Overdue {
                                seconds_late: now - order.deadline_at,
                                last_seq: other.map(|c| c.feed_seq),
                            }
                        } else {
                            AckState::Waiting {
                                seconds_left: order.deadline_at - now,
                            }
                        }
                    }
                };
                (mediator.clone(), state)
            })
            .collect()
    }

    /// Orders with at least one mediator still unconfirmed.
    #[must_use]
    pub fn outstanding(&self, now: u64) -> Vec<(&Order, BTreeMap<String, AckState>)> {
        self.orders
            .iter()
            .map(|o| (o, self.state_of(o, now)))
            .filter(|(_, states)| states.values().any(|s| !s.is_confirmed()))
            .collect()
    }

    /// Drop orders every expected mediator has confirmed.
    ///
    /// Returns how many were retired. Orders are never dropped merely for being
    /// old: an order nobody confirmed must stay visible.
    pub fn retire_confirmed(&mut self, now: u64) -> usize {
        let before = self.orders.len();
        let confirmed = self.confirmed.clone();
        self.orders.retain(|o| {
            let all = o.expected.iter().all(|m| {
                confirmed
                    .get(m)
                    .is_some_and(|c| c.feed_seq >= o.feed_seq)
            });
            !all
        });
        let _ = now;
        before - self.orders.len()
    }
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// One mediator's line in a containment report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatorResult {
    /// Which mediator.
    pub mediator: String,
    /// How the push went.
    pub push: PushOutcome,
    /// Whether it has confirmed.
    pub ack: AckState,
    /// Seconds within which this mediator applies the revocation even with no
    /// push and no ACK, from its own poll interval.
    pub bounded_by: u32,
}

/// The outcome of a containment order.
///
/// `unconfirmed` is a field rather than a footnote. A containment tool that
/// reports success for a mediator it never heard from manufactures exactly the
/// false confidence that makes an incident worse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentReport {
    /// What was contained.
    pub target: String,
    /// Feed sequence of the order.
    pub feed_seq: u64,
    /// Contracts the control plane revoked.
    pub revoked: Vec<String>,
    /// Per-mediator state.
    pub mediators: Vec<MediatorResult>,
    /// When an unconfirmed mediator becomes overdue.
    pub deadline_at: u64,
    /// Worst-case seconds until every mediator has applied this, assuming every
    /// push failed and no ACK ever arrives.
    pub bounded_by: u32,
}

impl ContainmentReport {
    /// Mediators that have confirmed.
    #[must_use]
    pub fn confirmed(&self) -> Vec<&MediatorResult> {
        self.mediators.iter().filter(|m| m.ack.is_confirmed()).collect()
    }

    /// Mediators that have not confirmed. Never treated as contained.
    #[must_use]
    pub fn unconfirmed(&self) -> Vec<&MediatorResult> {
        self.mediators
            .iter()
            .filter(|m| !m.ack.is_confirmed())
            .collect()
    }

    /// Whether every expected mediator confirmed.
    #[must_use]
    pub fn fully_confirmed(&self) -> bool {
        !self.mediators.is_empty() && self.unconfirmed().is_empty()
    }

    /// A line an operator can act on.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.mediators.is_empty() {
            // No mediator means nothing enforces the cut. Never phrase that as
            // success.
            return format!(
                "{} revoked in the registry · NO MEDIATORS CONFIGURED, so nothing enforces it",
                self.revoked.len()
            );
        }
        format!(
            "{} contract(s) revoked · {}/{} mediator(s) confirmed · unconfirmed bounded by {}s",
            self.revoked.len(),
            self.confirmed().len(),
            self.mediators.len(),
            self.bounded_by
        )
    }
}

/// Default seconds a mediator has to confirm before it is reported overdue.
pub const DEFAULT_ACK_DEADLINE: u32 = 60;

/// Everything a containment order needs.
pub struct ContainCtx<'a> {
    /// The signed feed.
    pub feed: &'a mut RevocationFeed,
    /// Durable ACK state.
    pub ledger: &'a mut AckLedger,
    /// Mediators expected to confirm.
    pub mediators: &'a MediatorSet,
    /// Push transport.
    pub push: &'a dyn Push,
    /// The revocation signing key.
    pub key: &'a IssuerKey,
    /// Seconds a mediator has to confirm.
    pub ack_deadline: u32,
}

impl std::fmt::Debug for ContainCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainCtx")
            .field("feed_len", &self.feed.len())
            .field("mediators", &self.mediators.mediators.len())
            .field("ack_deadline", &self.ack_deadline)
            .finish_non_exhaustive()
    }
}

/// Append a revocation, notify every mediator, and report what is confirmed.
///
/// The registry transition and contract revocation happen before this — they are
/// the control plane's own state. This is the part that makes the cut reach the
/// data plane, and the part that refuses to overstate how far it got.
pub fn contain(
    revoked: Revoked,
    contracts: &[Cid],
    reason: &str,
    actor: &str,
    now: u64,
    ctx: &mut ContainCtx<'_>,
) -> Result<ContainmentReport> {
    // The feed first. If this fails there is no order, and saying so beats
    // reporting a containment that only exists in memory.
    ctx.feed.append(revoked.clone(), reason, actor, now, ctx.key)?;

    // Then each affected connection by name, so a mediator can apply the cut
    // without having to derive the contract set itself.
    for cid in contracts {
        ctx.feed.append(
            Revoked::Connection { cid: cid.clone() },
            reason,
            actor,
            now,
            ctx.key,
        )?;
    }
    let head_seq = ctx.feed.next_seq() - 1;

    let deadline_at = now + u64::from(ctx.ack_deadline);
    let expected: Vec<String> = ctx.mediators.mediators.iter().map(|m| m.id.clone()).collect();
    ctx.ledger.expect(Order {
        feed_seq: head_seq,
        target: revoked.target(),
        expected: expected.clone(),
        at: now,
        deadline_at,
    });

    let order = Order {
        feed_seq: head_seq,
        target: revoked.target(),
        expected,
        at: now,
        deadline_at,
    };
    let states = ctx.ledger.state_of(&order, now);

    let mediators: Vec<MediatorResult> = ctx
        .mediators
        .mediators
        .iter()
        .map(|target| MediatorResult {
            mediator: target.id.clone(),
            push: ctx.push.notify(target, head_seq),
            ack: states
                .get(&target.id)
                .cloned()
                .unwrap_or(AckState::Waiting {
                    seconds_left: u64::from(ctx.ack_deadline),
                }),
            bounded_by: target.poll_interval,
        })
        .collect();

    Ok(ContainmentReport {
        target: revoked.target(),
        feed_seq: head_seq,
        revoked: contracts.iter().map(|c| c.as_str().to_string()).collect(),
        mediators,
        deadline_at,
        // The worst case is the slowest poller, not the average.
        bounded_by: ctx.mediators.worst_poll_interval(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use jsonwebtoken::Algorithm;

    fn tmp(label: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "wc-contain-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    fn keys_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/keys")
    }

    fn signing_key() -> IssuerKey {
        let pem = std::fs::read(keys_dir().join("test_issuer_es256_priv.pem")).unwrap();
        IssuerKey::ec_pem("revoke-1", &pem, Algorithm::ES256).unwrap()
    }

    fn trust() -> IssuerKeys {
        let pem = std::fs::read(keys_dir().join("test_issuer_es256_pub.pem")).unwrap();
        let mut keys = IssuerKeys::new();
        keys.add_ec_pem("revoke-1", &pem, Algorithm::ES256).unwrap();
        keys
    }

    fn party() -> Revoked {
        Revoked::Party {
            id: EntityId::new("spiffe://org/ns/agents/sa/recon").unwrap(),
        }
    }

    fn cid(n: u32) -> Cid {
        Cid::new(format!("conn_{n:08x}")).unwrap()
    }

    fn mediator_set(specs: &[(&str, Option<&str>, u32)]) -> MediatorSet {
        MediatorSet {
            mediators: specs
                .iter()
                .map(|(id, url, poll)| MediatorTarget {
                    id: (*id).to_string(),
                    push_url: url.map(str::to_string),
                    poll_interval: *poll,
                })
                .collect(),
        }
    }

    // --- the feed ----------------------------------------------------------

    #[test]
    fn a_feed_signs_appends_and_verifies() {
        let dir = tmp("feed");
        let path = dir.join("revocations.jsonl");
        let key = signing_key();

        let mut feed = RevocationFeed::open(&path).unwrap();
        assert!(feed.is_empty());
        assert_eq!(feed.next_seq(), 1);

        let entry = feed
            .append(party(), "SOC-1: exfiltration", "human:sam", 1_000, &key)
            .unwrap();
        assert_eq!(entry.event.seq, 1);
        assert_eq!(entry.kid, "revoke-1");
        feed.append(
            Revoked::Connection { cid: cid(1) },
            "SOC-1",
            "human:sam",
            1_000,
            &key,
        )
        .unwrap();

        assert_eq!(feed.verify(&trust()).unwrap(), 2);

        // And it survives a reopen.
        let reopened = RevocationFeed::open(&path).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.verify(&trust()).unwrap(), 2);
        assert_eq!(reopened.head_digest(), feed.head_digest());
    }

    #[test]
    fn since_returns_only_what_a_mediator_has_not_applied() {
        let dir = tmp("since");
        let path = dir.join("r.jsonl");
        let key = signing_key();
        let mut feed = RevocationFeed::open(&path).unwrap();
        for i in 1..=4u32 {
            feed.append(
                Revoked::Connection { cid: cid(i) },
                "r",
                "a",
                1_000,
                &key,
            )
            .unwrap();
        }
        assert_eq!(feed.since(0).len(), 4);
        assert_eq!(feed.since(2).len(), 2);
        assert_eq!(feed.since(4).len(), 0);
        assert_eq!(feed.since(99).len(), 0);
    }

    #[test]
    fn an_edited_feed_line_fails_verification() {
        // The signature covers the event, so changing the plaintext must not go
        // unnoticed — a revocation feed an operator can edit is a revocation feed
        // an operator can un-apply.
        let dir = tmp("tamper");
        let path = dir.join("r.jsonl");
        let key = signing_key();
        let mut feed = RevocationFeed::open(&path).unwrap();
        feed.append(party(), "SOC-1", "human:sam", 1_000, &key).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let edited = text.replace("SOC-1", "SOC-9");
        std::fs::write(&path, edited).unwrap();

        let reopened = RevocationFeed::open(&path).unwrap();
        let err = reopened.verify(&trust()).unwrap_err();
        assert_eq!(err.code(), Code::REVOCATION_FEED_UNWRITABLE);
        assert!(err.to_string().contains("does not match its signed payload"));
    }

    #[test]
    fn an_unreadable_line_is_an_error_not_a_skip() {
        // Skipping it would serve a feed that silently omits a cut.
        let dir = tmp("garbage");
        let path = dir.join("r.jsonl");
        std::fs::write(&path, "{not json}\n").unwrap();
        assert_eq!(
            RevocationFeed::open(&path).unwrap_err().code(),
            Code::REVOCATION_FEED_UNWRITABLE
        );
    }

    #[test]
    fn a_sequence_gap_is_refused() {
        // A hole means an event was lost. Serving `since=N` off a holed feed would
        // tell a mediator it is current when it is not.
        let dir = tmp("gap");
        let path = dir.join("r.jsonl");
        let key = signing_key();
        let mut feed = RevocationFeed::open(&path).unwrap();
        feed.append(party(), "r", "a", 1_000, &key).unwrap();
        feed.append(Revoked::Connection { cid: cid(1) }, "r", "a", 1_000, &key)
            .unwrap();

        // Drop the middle entry.
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().skip(1).collect();
        std::fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

        let err = RevocationFeed::open(&path).unwrap_err();
        assert_eq!(err.code(), Code::REVOCATION_FEED_UNWRITABLE);
        assert!(err.to_string().contains("sequence gap"));
    }

    #[test]
    fn a_revocation_has_no_implicit_expiry() {
        let e = RevocationEvent {
            seq: 1,
            revoked: party(),
            reason: "r".to_string(),
            actor: "a".to_string(),
            at: 1_000,
            until: None,
        };
        assert!(e.applies_at(1_000));
        assert!(e.applies_at(u64::MAX), "a cut must not age out on its own");
    }

    // --- the mediator set --------------------------------------------------

    #[test]
    fn a_mediator_set_parses_and_rejects_the_dangerous_shapes() {
        let set = MediatorSet::parse(
            r#"
            [[mediator]]
            id = "warden:mediator:apac-ops"
            push_url = "https://apac-ops.internal/refresh"
            poll_interval = 5

            [[mediator]]
            id = "warden:mediator:emea-ops"
            "#,
        )
        .unwrap();
        assert_eq!(set.mediators.len(), 2);
        assert_eq!(set.get("warden:mediator:emea-ops").unwrap().poll_interval, 5);
        assert!(set.get("warden:mediator:emea-ops").unwrap().push_url.is_none());

        // Zero interval would make the unconfirmed bound zero, which reads as
        // "already contained".
        assert_eq!(
            MediatorSet::parse("[[mediator]]\nid = \"a\"\npoll_interval = 0")
                .unwrap_err()
                .code(),
            Code::CONFIG_INVALID
        );
        assert_eq!(
            MediatorSet::parse("[[mediator]]\nid = \"a\"\n[[mediator]]\nid = \"a\"")
                .unwrap_err()
                .code(),
            Code::CONFIG_INVALID
        );
    }

    #[test]
    fn the_worst_case_bound_is_the_slowest_poller() {
        let set = mediator_set(&[("a", None, 5), ("b", None, 30), ("c", None, 10)]);
        assert_eq!(set.worst_poll_interval(), 30);
    }

    // --- the ledger --------------------------------------------------------

    fn order(seq: u64, expected: &[&str], at: u64, deadline: u64) -> Order {
        Order {
            feed_seq: seq,
            target: "spiffe://org/ns/agents/sa/recon".to_string(),
            expected: expected.iter().map(|s| (*s).to_string()).collect(),
            at,
            deadline_at: deadline,
        }
    }

    fn confirmation(mediator: &str, seq: u64, at: u64) -> Confirmation {
        Confirmation {
            mediator: mediator.to_string(),
            feed_seq: seq,
            revoked: vec!["conn_00000001".to_string()],
            aborted: 2,
            at,
        }
    }

    #[test]
    fn an_unconfirmed_mediator_is_waiting_then_overdue_never_confirmed() {
        let mut ledger = AckLedger::default();
        let o = order(5, &["a", "b"], 1_000, 1_060);
        ledger.expect(o.clone());
        ledger.record(confirmation("a", 5, 1_002));

        let at_ten = ledger.state_of(&o, 1_010);
        assert!(at_ten["a"].is_confirmed());
        assert_eq!(at_ten["b"], AckState::Waiting { seconds_left: 50 });

        let past = ledger.state_of(&o, 1_100);
        assert!(past["a"].is_confirmed());
        assert_eq!(
            past["b"],
            AckState::Overdue {
                seconds_late: 40,
                last_seq: None
            }
        );
    }

    #[test]
    fn a_mediator_confirming_an_older_sequence_is_not_confirmed_for_this_order() {
        // The subtle one: b has acked, just not far enough. Counting any ACK as
        // confirmation of the latest order is how a containment report lies.
        let mut ledger = AckLedger::default();
        let o = order(9, &["b"], 1_000, 1_060);
        ledger.record(confirmation("b", 4, 1_001));
        let states = ledger.state_of(&o, 1_100);
        assert_eq!(
            states["b"],
            AckState::Overdue {
                seconds_late: 40,
                last_seq: Some(4)
            }
        );
    }

    #[test]
    fn a_confirmed_sequence_only_moves_forward() {
        // A stale ACK arriving late must not walk back a confirmation.
        let mut ledger = AckLedger::default();
        ledger.record(confirmation("a", 9, 2_000));
        ledger.record(confirmation("a", 3, 2_001));
        assert_eq!(ledger.confirmed["a"].feed_seq, 9);
    }

    #[test]
    fn outstanding_orders_are_those_with_anyone_unconfirmed() {
        let mut ledger = AckLedger::default();
        ledger.expect(order(1, &["a", "b"], 1_000, 1_060));
        ledger.expect(order(2, &["a"], 1_000, 1_060));
        ledger.record(confirmation("a", 2, 1_005));

        let out = ledger.outstanding(1_010);
        assert_eq!(out.len(), 1, "only order 1, waiting on b");
        assert_eq!(out[0].0.feed_seq, 1);

        ledger.record(confirmation("b", 2, 1_006));
        assert!(ledger.outstanding(1_010).is_empty());
    }

    #[test]
    fn only_fully_confirmed_orders_retire() {
        // An order nobody confirmed must stay visible however old it gets.
        let mut ledger = AckLedger::default();
        ledger.expect(order(1, &["a", "b"], 1_000, 1_060));
        ledger.expect(order(2, &["a"], 1_000, 1_060));
        ledger.record(confirmation("a", 2, 1_005));

        assert_eq!(ledger.retire_confirmed(9_999_999), 1);
        assert_eq!(ledger.orders.len(), 1);
        assert_eq!(ledger.orders[0].feed_seq, 1, "the unconfirmed one stays");
    }

    #[test]
    fn a_ledger_round_trips_through_disk() {
        let dir = tmp("ledger");
        let path = dir.join("acks.json");
        let mut ledger = AckLedger::default();
        ledger.expect(order(7, &["a", "b"], 1_000, 1_060));
        ledger.record(confirmation("a", 7, 1_005));
        ledger.save(&path).unwrap();

        // The question "did every mediator confirm the 03:14 cut?" is asked long
        // after the process that made it exited.
        let reloaded = AckLedger::open(&path).unwrap();
        assert_eq!(reloaded.orders.len(), 1);
        assert_eq!(reloaded.confirmed["a"].aborted, 2);
        assert!(reloaded.state_of(&reloaded.orders[0], 1_010)["a"].is_confirmed());
    }

    #[test]
    fn an_absent_ledger_opens_empty_rather_than_failing() {
        let dir = tmp("absent");
        let l = AckLedger::open(&dir.join("nope.json")).unwrap();
        assert!(l.orders.is_empty() && l.confirmed.is_empty());
    }

    // --- push --------------------------------------------------------------

    #[derive(Debug, Default)]
    struct FailingPush;
    impl Push for FailingPush {
        fn notify(&self, _t: &MediatorTarget, _s: u64) -> PushOutcome {
            PushOutcome::Failed {
                attempts: 3,
                detail: "connection refused".to_string(),
            }
        }
    }

    #[derive(Debug, Default)]
    struct OkPush;
    impl Push for OkPush {
        fn notify(&self, _t: &MediatorTarget, _s: u64) -> PushOutcome {
            PushOutcome::Accepted
        }
    }

    #[test]
    fn an_unreachable_mediator_is_reported_and_bounded_not_failed() {
        let dir = tmp("push-fail");
        let key = signing_key();
        let mut feed = RevocationFeed::open(&dir.join("r.jsonl")).unwrap();
        let mut ledger = AckLedger::default();
        let set = mediator_set(&[("a", Some("http://127.0.0.1:1/x"), 5)]);
        let push = FailingPush;
        let mut ctx = ContainCtx {
            feed: &mut feed,
            ledger: &mut ledger,
            mediators: &set,
            push: &push,
            key: &key,
            ack_deadline: DEFAULT_ACK_DEADLINE,
        };

        let report = contain(party(), &[cid(1)], "SOC-1", "human:sam", 1_000, &mut ctx).unwrap();

        // The push failed and containment is still correct — the pull is the
        // guarantee, the push is only latency.
        assert!(matches!(
            report.mediators[0].push,
            PushOutcome::Failed { .. }
        ));
        assert!(!report.fully_confirmed());
        assert_eq!(report.unconfirmed().len(), 1);
        assert_eq!(report.bounded_by, 5);
        assert!(report.summary().contains("0/1 mediator(s) confirmed"));
        assert!(report.summary().contains("bounded by 5s"));
    }

    #[test]
    fn containment_writes_the_party_and_every_contract_to_the_feed() {
        let dir = tmp("feed-order");
        let key = signing_key();
        let mut feed = RevocationFeed::open(&dir.join("r.jsonl")).unwrap();
        let mut ledger = AckLedger::default();
        let set = mediator_set(&[("a", None, 5)]);
        let push = NoPush;
        let mut ctx = ContainCtx {
            feed: &mut feed,
            ledger: &mut ledger,
            mediators: &set,
            push: &push,
            key: &key,
            ack_deadline: 60,
        };

        let report = contain(
            party(),
            &[cid(1), cid(2)],
            "SOC-1",
            "human:sam",
            1_000,
            &mut ctx,
        )
        .unwrap();

        // Party first as the backstop, then each connection by name so a mediator
        // does not have to derive the set itself.
        assert_eq!(feed.len(), 3);
        assert_eq!(feed.all()[0].event.revoked.kind(), "party");
        assert_eq!(feed.all()[1].event.revoked.kind(), "cid");
        assert_eq!(feed.all()[2].event.revoked.kind(), "cid");
        assert_eq!(report.feed_seq, 3, "the order names the head");
        assert_eq!(report.revoked.len(), 2);
        assert_eq!(feed.verify(&trust()).unwrap(), 3);
    }

    #[test]
    fn an_estate_with_no_mediators_never_reads_as_contained() {
        // Nothing enforces the cut. Phrasing that as success is the worst
        // available outcome.
        let dir = tmp("no-mediators");
        let key = signing_key();
        let mut feed = RevocationFeed::open(&dir.join("r.jsonl")).unwrap();
        let mut ledger = AckLedger::default();
        let set = MediatorSet::default();
        let push = OkPush;
        let mut ctx = ContainCtx {
            feed: &mut feed,
            ledger: &mut ledger,
            mediators: &set,
            push: &push,
            key: &key,
            ack_deadline: 60,
        };
        let report = contain(party(), &[cid(1)], "SOC-1", "human:sam", 1_000, &mut ctx).unwrap();
        assert!(!report.fully_confirmed());
        assert!(report.summary().contains("NO MEDIATORS CONFIGURED"));
    }

    #[test]
    fn a_successful_push_still_does_not_count_as_a_confirmation() {
        // HTTP 200 from a mediator means the notification was accepted, not that
        // the revocation was applied. Only a signed ACK naming the sequence does.
        let dir = tmp("push-ok");
        let key = signing_key();
        let mut feed = RevocationFeed::open(&dir.join("r.jsonl")).unwrap();
        let mut ledger = AckLedger::default();
        let set = mediator_set(&[("a", Some("https://a/x"), 5)]);
        let push = OkPush;
        let mut ctx = ContainCtx {
            feed: &mut feed,
            ledger: &mut ledger,
            mediators: &set,
            push: &push,
            key: &key,
            ack_deadline: 60,
        };
        let report = contain(party(), &[], "SOC-1", "human:sam", 1_000, &mut ctx).unwrap();
        assert!(report.mediators[0].push.reached());
        assert!(!report.mediators[0].ack.is_confirmed());
        assert!(!report.fully_confirmed());
    }

    #[test]
    fn the_order_is_recorded_durably_so_it_can_be_chased_later() {
        let dir = tmp("order-persist");
        let key = signing_key();
        let mut feed = RevocationFeed::open(&dir.join("r.jsonl")).unwrap();
        let mut ledger = AckLedger::default();
        let set = mediator_set(&[("a", None, 5), ("b", None, 30)]);
        let push = NoPush;
        {
            let mut ctx = ContainCtx {
                feed: &mut feed,
                ledger: &mut ledger,
                mediators: &set,
                push: &push,
                key: &key,
                ack_deadline: 60,
            };
            contain(party(), &[cid(1)], "SOC-1", "human:sam", 1_000, &mut ctx).unwrap();
        }
        assert_eq!(ledger.orders.len(), 1);
        assert_eq!(ledger.orders[0].expected, vec!["a", "b"]);
        assert_eq!(ledger.orders[0].deadline_at, 1_060);

        // Later, an operator asks who still has not confirmed.
        let outstanding = ledger.outstanding(1_200);
        assert_eq!(outstanding.len(), 1);
        let states = &outstanding[0].1;
        assert!(matches!(states["a"], AckState::Overdue { .. }));
        assert!(matches!(states["b"], AckState::Overdue { .. }));
    }
}
