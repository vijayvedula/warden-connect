//! What happens to work already in flight when a revocation lands
//! (`docs/08-lld.md` §8.6.7).
//!
//! Two settings, and one rule about the space between them.
//!
//! | Mode | In-flight | New calls | Bound |
//! |---|---|---|---|
//! | `drain` | allowed to finish | refused | `drain_timeout`, then aborted |
//! | `abort` | cut immediately, JSON-RPC error to the agent | refused | immediate |
//!
//! **Anything unparsable is `abort`.** A mediator that cannot understand its own
//! revocation configuration must not choose the permissive reading — and `drain`
//! is the permissive reading, because it keeps serving a connection somebody has
//! just ordered cut.
//!
//! # What in-flight means here
//!
//! In the stdio sidecar topology `connect-mediate` serves one agent over one
//! synchronous loop, so at most one call is ever in flight and `drain` and `abort`
//! differ only in whether that single call is allowed to return. The distinction
//! earns its keep in the shared-gateway topology (§7.9), where one mediator fronts
//! many agents and aborting cuts work belonging to parties nobody revoked.
//!
//! Either way `new calls are refused` is unconditional. That half is the
//! containment; the drain window only decides how gracefully the current call
//! ends.
//!
//! # NOT WIRED — read this before believing the table above
//!
//! **Nothing in this crate calls [`OnRevoke`].** There is no `--on-revoke` flag on
//! `connect-mediate`, the binary does not reference this module, and no mediation path
//! consults it. So the table describes a design, and the shipped behaviour is:
//!
//! * **new calls are refused** — the containment half, and it is real *now*. See the
//!   correction below, because this line was wrong for as long as it has existed;
//! * **the in-flight call finishes**, bounded only by `--upstream-timeout` (30s by
//!   default) rather than by `drain_timeout`.
//!
//! Which means the effective mode is `drain` with the wrong bound — and this file's own
//! rule is that `abort` is the default *because* `drain` is the permissive reading. The
//! stated default is not in force.
//!
//! ## The correction, kept because it is more instructive than the design above
//!
//! This section used to say of the first bullet: *"this half is real, and it is the
//! containment half. [`crate::cache::Cache`] applies revocation at lookup time, so the next
//! call after a pull installs a revocation is refused with no cache rebuild."*
//!
//! Every clause of that was true about [`crate::cache::Cache::resolve`] and false about the
//! mediator, **because the per-call path did not call `resolve`.** It resolved once at
//! `initialize` and every later call used the cached `Admitted`. So a revoked contract was
//! served until it expired, and this file confidently described the containment as working
//! while sitting two modules away from the code that did not do it.
//!
//! `scripts/rotation-drill.sh` found it by running a rotation against a live process instead
//! of reading about one. [`crate::gate::MediatedUpstream`] now re-checks before every method
//! and the bullet is finally accurate.
//!
//! Two lessons, both already in `docs/threat-model.md` Part 1 and both re-earned here: a doc
//! comment is not a control, and *"which caller reaches this?"* is the question. The second
//! hardening pass asked it of `OnRevoke` and found no callers. Nobody thought to ask it of
//! `resolve`, which has plenty of callers — just not the one that mattered.
//!
//! For the stdio sidecar the remaining exposure is one already-authorised call, bounded by the
//! upstream timeout, which is why this is documented rather than urgently fixed. The
//! distinction this module exists for belongs to the shared-gateway topology, and that
//! topology is not deployable either (`docs/limitations.md`). Wiring a flag that could
//! not interrupt a blocking upstream read would be worse than having none: a control that
//! reads as configured and does nothing is the defect class this codebase keeps producing.

use std::time::Duration;

use wc_core::error::{Code, Result, WcError};

/// Default grace period for `drain`.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// How to treat in-flight work on revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnRevoke {
    /// Let the current call finish, within a bound.
    Drain {
        /// How long a call may keep running after the revocation.
        timeout: Duration,
    },
    /// Cut immediately. The default, because quarantine is a security revocation
    /// and `drain` is the permissive reading.
    #[default]
    Abort,
}

impl OnRevoke {
    /// Parse `--on-revoke`.
    ///
    /// An unrecognised value is an error rather than a fallback, so a typo is
    /// caught at startup by `WC-8004: refuse to start` instead of quietly
    /// selecting a mode the operator did not choose.
    pub fn parse(value: &str, timeout: Option<Duration>) -> Result<OnRevoke> {
        match value.trim() {
            "abort" => Ok(OnRevoke::Abort),
            "drain" => Ok(OnRevoke::Drain {
                timeout: timeout.unwrap_or(DEFAULT_DRAIN_TIMEOUT),
            }),
            other => Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("--on-revoke must be drain|abort, got {other:?}"),
            )),
        }
    }

    /// The mode to use when configuration could not be understood.
    ///
    /// Named rather than inlined, because "fail closed" is a claim that should be
    /// checkable in one place.
    #[must_use]
    pub const fn on_ambiguous_config() -> OnRevoke {
        OnRevoke::Abort
    }

    /// Label for the ACK and for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            OnRevoke::Drain { .. } => "drain",
            OnRevoke::Abort => "abort",
        }
    }

    /// The grace period, zero for `abort`.
    #[must_use]
    pub const fn grace(self) -> Duration {
        match self {
            OnRevoke::Drain { timeout } => timeout,
            OnRevoke::Abort => Duration::ZERO,
        }
    }
}

/// What to do with one in-flight call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlight {
    /// Let it return.
    Allow,
    /// Cut it, and count it.
    Abort,
}

/// One call that was running when the revocation landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Call {
    /// When the call started.
    pub started_at: u64,
}

/// Decide the fate of an in-flight call.
///
/// `revoked_at` is when the revocation was applied locally, not when the control
/// plane issued it: the grace period an operator configured is a grace period from
/// the mediator's own clock, and using the order's timestamp would silently
/// shorten it by the propagation delay.
#[must_use]
pub fn decide(mode: OnRevoke, call: Call, revoked_at: u64, now: u64) -> InFlight {
    match mode {
        OnRevoke::Abort => InFlight::Abort,
        OnRevoke::Drain { timeout } => {
            // A call that started *after* the revocation is not in flight — it is a
            // new call, and new calls are refused regardless of mode. Allowing it
            // through the drain window would turn a 10-second grace period into a
            // 10-second hole.
            if call.started_at >= revoked_at {
                return InFlight::Abort;
            }
            let deadline = revoked_at.saturating_add(timeout.as_secs());
            if now < deadline {
                InFlight::Allow
            } else {
                InFlight::Abort
            }
        }
    }
}

/// Running count of what a revocation cost, for the ACK.
///
/// The control plane reports `aborted` in incident timelines, so it has to be a
/// real count rather than a flag.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainTally {
    /// Calls allowed to finish.
    pub drained: u64,
    /// Calls cut.
    pub aborted: u64,
    /// New calls refused because their contract was revoked.
    pub refused: u64,
}

impl DrainTally {
    /// Record an in-flight decision.
    pub fn record(&mut self, outcome: InFlight) {
        match outcome {
            InFlight::Allow => self.drained += 1,
            InFlight::Abort => self.aborted += 1,
        }
    }

    /// Record a new call turned away.
    pub fn refuse(&mut self) {
        self.refused += 1;
    }

    /// Whether anything happened worth reporting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.drained == 0 && self.aborted == 0 && self.refused == 0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn abort_is_the_default_and_the_fallback() {
        // Quarantine is a security revocation, and `drain` is the permissive
        // reading of an unclear configuration.
        assert_eq!(OnRevoke::default(), OnRevoke::Abort);
        assert_eq!(OnRevoke::on_ambiguous_config(), OnRevoke::Abort);
    }

    #[test]
    fn a_mistyped_mode_refuses_to_start_rather_than_picking_one() {
        let err = OnRevoke::parse("drian", None).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(err.to_string().contains("drain|abort"));
        assert_eq!(
            OnRevoke::parse("", None).unwrap_err().code(),
            Code::CONFIG_INVALID
        );
    }

    #[test]
    fn modes_parse_with_their_bounds() {
        assert_eq!(OnRevoke::parse("abort", None).unwrap(), OnRevoke::Abort);
        assert_eq!(
            OnRevoke::parse("drain", None).unwrap(),
            OnRevoke::Drain {
                timeout: DEFAULT_DRAIN_TIMEOUT
            }
        );
        assert_eq!(
            OnRevoke::parse(" drain ", Some(Duration::from_secs(3))).unwrap(),
            OnRevoke::Drain {
                timeout: Duration::from_secs(3)
            }
        );
        assert_eq!(OnRevoke::Abort.grace(), Duration::ZERO);
    }

    #[test]
    fn abort_cuts_in_flight_work_immediately() {
        let call = Call { started_at: 100 };
        assert_eq!(decide(OnRevoke::Abort, call, 110, 110), InFlight::Abort);
    }

    #[test]
    fn drain_allows_an_existing_call_inside_the_window_and_not_after() {
        let mode = OnRevoke::Drain {
            timeout: Duration::from_secs(10),
        };
        let call = Call { started_at: 100 };
        assert_eq!(decide(mode, call, 110, 110), InFlight::Allow);
        assert_eq!(decide(mode, call, 110, 119), InFlight::Allow);
        assert_eq!(
            decide(mode, call, 110, 120),
            InFlight::Abort,
            "at the bound"
        );
        assert_eq!(decide(mode, call, 110, 500), InFlight::Abort);
    }

    #[test]
    fn a_call_starting_after_the_revocation_is_new_not_in_flight() {
        // Otherwise a 10-second grace period is a 10-second hole: every call
        // arriving inside the window would be treated as pre-existing.
        let mode = OnRevoke::Drain {
            timeout: Duration::from_secs(10),
        };
        assert_eq!(
            decide(mode, Call { started_at: 115 }, 110, 116),
            InFlight::Abort
        );
        assert_eq!(
            decide(mode, Call { started_at: 110 }, 110, 111),
            InFlight::Abort,
            "same second counts as new"
        );
    }

    #[test]
    fn the_grace_period_runs_from_local_application_not_from_the_order() {
        // Using the order's timestamp would shorten the operator's window by the
        // propagation delay, which is the one part of it nobody controls.
        let mode = OnRevoke::Drain {
            timeout: Duration::from_secs(10),
        };
        let call = Call { started_at: 100 };
        let applied_locally = 130; // the order was issued at 110, arrived at 130
        assert_eq!(decide(mode, call, applied_locally, 139), InFlight::Allow);
        assert_eq!(decide(mode, call, applied_locally, 140), InFlight::Abort);
    }

    #[test]
    fn a_tally_counts_what_the_incident_report_needs() {
        let mut t = DrainTally::default();
        assert!(t.is_empty());
        t.record(InFlight::Allow);
        t.record(InFlight::Abort);
        t.record(InFlight::Abort);
        t.refuse();
        assert_eq!(
            t,
            DrainTally {
                drained: 1,
                aborted: 2,
                refused: 1
            }
        );
        assert!(!t.is_empty());
    }

    #[test]
    fn this_module_is_still_not_wired_into_the_binary() {
        // A guard on the module docs, not on behaviour. `OnRevoke` has no caller: no
        // `--on-revoke` flag, no reference from `connect-mediate`, nothing in the
        // mediation path. The docs say so at the top, and a doc comment is not a control —
        // so if somebody wires it, this test fails and the docs get corrected with it.
        //
        // Deliberately checks the *source* rather than behaviour, because "is this
        // reachable from the thing that deploys it?" is the question the second hardening
        // pass was built around and it is not answerable from inside a unit test any
        // other way.
        let binary = include_str!("bin/connect-mediate.rs");
        assert!(
            !binary.contains("OnRevoke") && !binary.contains("on-revoke"),
            "drain is now wired — delete the NOT WIRED section from this module's docs, \
             the drain entry in docs/limitations.md, and this test"
        );
    }
}
