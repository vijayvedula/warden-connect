//! Rate, spend and concurrency ceilings (`docs/08-lld.md` §8.6.5).
//!
//! A breach denies the call, notifies the owner, and **leaves the contract
//! valid**. That distinction is deliberate: a rate breach is a signal, not a
//! compromise, and revoking on breach would turn a noisy neighbour into an
//! outage.
//!
//! Counters are per-connection and in-memory here. A deployment that must survive
//! a mediator restart without resetting a ceiling persists them, exactly as Warden
//! core's budget file does — otherwise restarting the proxy is a way to reset a
//! spend cap.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use wc_core::contract::Terms;
use wc_core::error::{Code, Result, WcError};

/// Buckets in the sliding call-rate window. Sixty one-minute buckets give an
/// hourly window that decays smoothly instead of resetting on the hour — a
/// fixed window lets a caller spend two full allowances across its boundary.
const WINDOW_BUCKETS: usize = 60;

/// Seconds per bucket.
const BUCKET_SECS: u64 = 60;

/// A sliding-window counter.
#[derive(Debug)]
struct SlidingWindow {
    buckets: Vec<u32>,
    /// The bucket index most recently written, as an absolute minute.
    last_minute: u64,
}

impl SlidingWindow {
    fn new() -> SlidingWindow {
        SlidingWindow {
            buckets: vec![0; WINDOW_BUCKETS],
            last_minute: 0,
        }
    }

    /// Advance to `now`, clearing buckets the window has moved past.
    fn advance(&mut self, now: u64) {
        let minute = now / BUCKET_SECS;
        if minute == self.last_minute {
            return;
        }
        let elapsed = minute.saturating_sub(self.last_minute);
        if elapsed >= WINDOW_BUCKETS as u64 {
            self.buckets.iter_mut().for_each(|b| *b = 0);
        } else {
            for step in 1..=elapsed {
                let index = ((self.last_minute + step) % WINDOW_BUCKETS as u64) as usize;
                self.buckets[index] = 0;
            }
        }
        self.last_minute = minute;
    }

    fn total(&self) -> u32 {
        self.buckets.iter().copied().sum()
    }

    fn record(&mut self, now: u64) {
        let index = ((now / BUCKET_SECS) % WINDOW_BUCKETS as u64) as usize;
        self.buckets[index] = self.buckets[index].saturating_add(1);
    }
}

/// A held concurrency slot. Released on drop, so a panicking call site cannot
/// leak the slot and slowly strangle the connection.
#[derive(Debug)]
pub struct Slot<'a> {
    counter: &'a AtomicU32,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A concurrency slot that owns its counter, released on drop.
///
/// [`Slot`] borrows the [`Ceilings`] it came from, which is right for a caller that holds the
/// ceilings on its own stack — the inline mediator. A gateway filter cannot use it: the slot has
/// to live for the length of an HTTP stream while the ceilings are shared between streams behind
/// an `Arc`, and a borrow from inside an `Arc` cannot be stored beside it.
///
/// So this variant holds the `Arc` instead. Same counter, same release-on-drop, no lifetime.
#[derive(Debug)]
pub struct OwnedSlot {
    ceilings: std::sync::Arc<Ceilings>,
}

impl Drop for OwnedSlot {
    fn drop(&mut self) {
        self.ceilings.concurrent.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Per-connection ceilings.
#[derive(Debug, Default)]
pub struct Ceilings {
    calls: Mutex<Option<SlidingWindow>>,
    spend_usd: Mutex<f64>,
    spend_day: Mutex<u64>,
    concurrent: AtomicU32,
}

impl Ceilings {
    /// Fresh counters.
    #[must_use]
    pub fn new() -> Ceilings {
        Ceilings::default()
    }

    /// Reserve one call against the contract's terms.
    ///
    /// Records the call on success. Holding the lock across the check and the
    /// increment closes the check-then-increment race where N concurrent callers
    /// each read a stale count under the cap and all proceed.
    pub fn reserve(&self, terms: &Terms, now: u64) -> Result<()> {
        if let Some(limit) = terms.max_calls_per_hour {
            let mut guard = match self.calls.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let window = guard.get_or_insert_with(SlidingWindow::new);
            window.advance(now);
            if window.total() >= limit {
                return Err(WcError::with_detail(
                    Code::RATE_CEILING,
                    format!(
                        "{} calls in the last hour, ceiling is {limit}",
                        window.total()
                    ),
                ));
            }
            window.record(now);
        }
        Ok(())
    }

    /// Charge spend against the daily ceiling.
    pub fn charge(&self, terms: &Terms, amount_usd: f64, now: u64) -> Result<()> {
        let Some(limit) = terms.max_spend_usd_per_day else {
            return Ok(());
        };
        let day = now / 86_400;

        let mut current_day = match self.spend_day.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut spent = match self.spend_usd.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if *current_day != day {
            *current_day = day;
            *spent = 0.0;
        }
        if *spent + amount_usd > limit {
            return Err(WcError::with_detail(
                Code::SPEND_CEILING,
                format!(
                    "{:.2} + {amount_usd:.2} exceeds the daily ceiling of {limit:.2}",
                    *spent
                ),
            ));
        }
        *spent += amount_usd;
        Ok(())
    }

    /// Take a concurrency slot for the duration of a call.
    pub fn enter(&self, terms: &Terms) -> Result<Option<Slot<'_>>> {
        let Some(limit) = terms.max_concurrent else {
            return Ok(None);
        };
        // Compare-and-swap rather than load-then-store: two callers at the cap must
        // not both see room.
        loop {
            let current = self.concurrent.load(Ordering::SeqCst);
            if current >= limit {
                return Err(WcError::with_detail(
                    Code::CONCURRENCY_CEILING,
                    format!("{current} calls in flight, ceiling is {limit}"),
                ));
            }
            if self
                .concurrent
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(Some(Slot {
                    counter: &self.concurrent,
                }));
            }
        }
    }

    /// Take a concurrency slot that outlives the borrow, for a caller holding the ceilings
    /// behind an `Arc`.
    ///
    /// `Ok(None)` means the contract sets no concurrency ceiling, exactly as [`Ceilings::enter`]
    /// does — and it must not be mistaken for "no slot was available", which is the `Err`.
    pub fn enter_owned(self: &std::sync::Arc<Self>, terms: &Terms) -> Result<Option<OwnedSlot>> {
        let Some(limit) = terms.max_concurrent else {
            return Ok(None);
        };
        loop {
            let current = self.concurrent.load(Ordering::SeqCst);
            if current >= limit {
                return Err(WcError::with_detail(
                    Code::CONCURRENCY_CEILING,
                    format!("{current} calls in flight, ceiling is {limit}"),
                ));
            }
            if self
                .concurrent
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(Some(OwnedSlot {
                    ceilings: std::sync::Arc::clone(self),
                }));
            }
        }
    }

    /// Calls recorded in the current window.
    #[must_use]
    pub fn calls_in_window(&self) -> u32 {
        match self.calls.lock() {
            Ok(g) => g.as_ref().map_or(0, SlidingWindow::total),
            Err(poisoned) => poisoned
                .into_inner()
                .as_ref()
                .map_or(0, SlidingWindow::total),
        }
    }

    /// Spend recorded today.
    #[must_use]
    pub fn spent_today(&self) -> f64 {
        match self.spend_usd.lock() {
            Ok(g) => *g,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// Calls currently in flight.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.concurrent.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn terms(calls: Option<u32>, spend: Option<f64>, concurrent: Option<u32>) -> Terms {
        Terms {
            max_calls_per_hour: calls,
            max_spend_usd_per_day: spend,
            max_concurrent: concurrent,
            ..Default::default()
        }
    }

    #[test]
    fn no_ceiling_means_no_limit() {
        let c = Ceilings::new();
        let unlimited = terms(None, None, None);
        for i in 0..1_000 {
            assert!(c.reserve(&unlimited, 1_000 + i).is_ok());
        }
        assert!(c.charge(&unlimited, 1_000_000.0, 1_000).is_ok());
        assert!(c.enter(&unlimited).unwrap().is_none());
    }

    #[test]
    fn the_rate_ceiling_denies_at_the_limit() {
        let c = Ceilings::new();
        let t = terms(Some(3), None, None);
        for _ in 0..3 {
            assert!(c.reserve(&t, 1_000).is_ok());
        }
        let err = c.reserve(&t, 1_000).unwrap_err();
        assert_eq!(err.code(), Code::RATE_CEILING);
        assert_eq!(c.calls_in_window(), 3);
    }

    #[test]
    fn the_window_slides_rather_than_resetting() {
        // A fixed hourly window would let a caller spend two full allowances
        // across its boundary. Sixty buckets decay smoothly instead.
        let c = Ceilings::new();
        let t = terms(Some(2), None, None);
        assert!(c.reserve(&t, 0).is_ok());
        assert!(c.reserve(&t, 60).is_ok());
        assert!(c.reserve(&t, 120).is_err(), "still two in the window");

        // An hour later the first calls have aged out.
        assert!(c.reserve(&t, 3_700).is_ok());
    }

    #[test]
    fn a_long_gap_clears_the_whole_window() {
        let c = Ceilings::new();
        let t = terms(Some(1), None, None);
        assert!(c.reserve(&t, 0).is_ok());
        assert!(c.reserve(&t, 30).is_err());
        // Far beyond the window: nothing carries over.
        assert!(c.reserve(&t, 1_000_000).is_ok());
    }

    #[test]
    fn spend_accumulates_and_resets_daily() {
        let c = Ceilings::new();
        let t = terms(None, Some(100.0), None);
        assert!(c.charge(&t, 60.0, 1_000).is_ok());
        assert!(c.charge(&t, 30.0, 1_000).is_ok());
        assert_eq!(c.spent_today(), 90.0);

        let err = c.charge(&t, 20.0, 1_000).unwrap_err();
        assert_eq!(err.code(), Code::SPEND_CEILING);
        // The refused charge is not applied.
        assert_eq!(c.spent_today(), 90.0);

        // Next day, fresh allowance.
        assert!(c.charge(&t, 90.0, 1_000 + 86_400).is_ok());
        assert_eq!(c.spent_today(), 90.0);
    }

    #[test]
    fn concurrency_slots_are_released_on_drop() {
        let c = Ceilings::new();
        let t = terms(None, None, Some(2));
        {
            let _a = c.enter(&t).unwrap();
            let _b = c.enter(&t).unwrap();
            assert_eq!(c.in_flight(), 2);
            assert_eq!(c.enter(&t).unwrap_err().code(), Code::CONCURRENCY_CEILING);
        }
        // Both guards dropped: the connection is not permanently strangled.
        assert_eq!(c.in_flight(), 0);
        assert!(c.enter(&t).is_ok());
    }

    #[test]
    fn a_denied_reservation_does_not_consume_allowance() {
        let c = Ceilings::new();
        let t = terms(Some(1), None, None);
        assert!(c.reserve(&t, 1_000).is_ok());
        for _ in 0..5 {
            assert!(c.reserve(&t, 1_000).is_err());
        }
        // Still exactly one recorded: refusals must not count against the caller.
        assert_eq!(c.calls_in_window(), 1);
    }

    #[test]
    fn ceilings_are_independent_of_one_another() {
        let c = Ceilings::new();
        let t = terms(Some(1), Some(10.0), Some(1));
        assert!(c.reserve(&t, 1_000).is_ok());
        // The rate ceiling is spent, but spend and concurrency are not.
        assert!(c.reserve(&t, 1_000).is_err());
        assert!(c.charge(&t, 5.0, 1_000).is_ok());
        assert!(c.enter(&t).is_ok());
    }
}

#[cfg(test)]
mod owned_slot_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::sync::Arc;

    fn terms(max: Option<u32>) -> Terms {
        Terms {
            max_concurrent: max,
            ..Terms::default()
        }
    }

    #[test]
    fn no_ceiling_yields_no_slot_and_is_not_a_refusal() {
        let c = Arc::new(Ceilings::new());
        assert!(c.enter_owned(&terms(None)).unwrap().is_none());
        assert_eq!(
            c.in_flight(),
            0,
            "a contract with no ceiling still counted a call"
        );
    }

    #[test]
    fn slots_are_released_on_drop() {
        let c = Arc::new(Ceilings::new());
        {
            let _a = c.enter_owned(&terms(Some(2))).unwrap().expect("slot a");
            let _b = c.enter_owned(&terms(Some(2))).unwrap().expect("slot b");
            assert_eq!(c.in_flight(), 2);
            // At the ceiling: a third must be refused, not queued.
            let denied = c.enter_owned(&terms(Some(2))).unwrap_err();
            assert_eq!(denied.code(), Code::CONCURRENCY_CEILING);
        }
        assert_eq!(c.in_flight(), 0, "slots did not release when dropped");
        assert!(c.enter_owned(&terms(Some(2))).unwrap().is_some());
    }

    #[test]
    fn the_owned_slot_outlives_the_borrow_that_made_it() {
        // The whole reason this exists: a gateway holds the ceilings behind an Arc and the slot
        // for the length of a stream. `Slot<'_>` cannot be stored that way.
        let c = Arc::new(Ceilings::new());
        let held: Option<OwnedSlot> = c.enter_owned(&terms(Some(1))).unwrap();
        drop(c); // the caller's handle goes; the slot keeps its own
        assert!(held.is_some());
    }

    #[test]
    fn concurrent_callers_at_the_ceiling_do_not_both_get_in() {
        // Compare-and-swap, not load-then-store. Ten threads, ceiling of three.
        let c = Arc::new(Ceilings::new());
        let held = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut hs = Vec::new();
        for _ in 0..10 {
            let c = Arc::clone(&c);
            let held = Arc::clone(&held);
            hs.push(std::thread::spawn(move || {
                if let Ok(Some(slot)) = c.enter_owned(&terms(Some(3))) {
                    held.lock().unwrap().push(slot);
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(
            held.lock().unwrap().len(),
            3,
            "more callers were admitted than the ceiling allows"
        );
        assert_eq!(c.in_flight(), 3);
    }
}
