//! Performance gates (`docs/08-lld.md` §8.10.3).
//!
//! > A latency claim in a design document that is not asserted by a test is a
//! > marketing claim.
//!
//! The HLD promises p99 < 5 ms added at connection establishment and a
//! sub-minute estate-wide quarantine. This module is what turns those from
//! sentences into a build step.
//!
//! # Why the harness is here rather than in a `criterion` benchmark
//!
//! A `cargo bench` run is something a developer does. A **gate** is something CI
//! fails on, and it has to run on the same reference machine every time, produce
//! a machine-readable verdict, and exit non-zero. Criterion is the better tool
//! for finding out *why* something is slow; this is for finding out *that* it
//! became slow.
//!
//! # Honesty about what a number from this means
//!
//! Every measurement here is single-process, warm, and on whatever machine
//! happened to run it. [`Gate::margin`] reports how much headroom a result had,
//! because a gate that passes at 99% of its threshold is a gate about to start
//! failing for reasons nobody changed — and [`Report::marginal`] surfaces those
//! before they become a flaky build.
//!
//! Thresholds are the LLD's, not the machine's. A run on a slower box reports
//! honest failures rather than adjusting to fit, because a gate that calibrates
//! itself to the hardware measures nothing.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// One measured operation and the ceiling it must stay under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate {
    /// Gate name, matching §8.10.3.
    pub name: String,
    /// What was measured.
    pub detail: String,
    /// Iterations run.
    pub iterations: usize,
    /// Observed p50, nanoseconds.
    pub p50_ns: u64,
    /// Observed p99, nanoseconds.
    pub p99_ns: u64,
    /// The ceiling, nanoseconds.
    pub threshold_ns: u64,
}

impl Gate {
    /// Whether the gate held.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.p99_ns <= self.threshold_ns
    }

    /// Headroom as a fraction of the threshold, 0.0 at the limit.
    ///
    /// A gate passing at 2% margin is a gate about to start failing for reasons
    /// nobody changed, which is worse than one that fails outright.
    #[must_use]
    pub fn margin(&self) -> f64 {
        if self.threshold_ns == 0 {
            return 0.0;
        }
        1.0 - (self.p99_ns as f64 / self.threshold_ns as f64)
    }

    /// Whether the gate held but with little room.
    #[must_use]
    pub fn is_marginal(&self) -> bool {
        self.passed() && self.margin() < 0.20
    }

    /// A line an operator or a CI log can read.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "{:<28} p50 {:>9} · p99 {:>9} / {:<9} {}{}",
            self.name,
            fmt_ns(self.p50_ns),
            fmt_ns(self.p99_ns),
            fmt_ns(self.threshold_ns),
            if self.passed() { "ok" } else { "FAIL" },
            if self.is_marginal() {
                format!("  MARGINAL ({:.0}% headroom)", self.margin() * 100.0)
            } else {
                String::new()
            }
        )
    }
}

/// Nanoseconds in the largest unit that stays readable.
#[must_use]
pub fn fmt_ns(ns: u64) -> String {
    match ns {
        n if n < 1_000 => format!("{n} ns"),
        n if n < 1_000_000 => format!("{:.1} µs", n as f64 / 1_000.0),
        n if n < 1_000_000_000 => format!("{:.2} ms", n as f64 / 1_000_000.0),
        n => format!("{:.2} s", n as f64 / 1_000_000_000.0),
    }
}

/// A gate that did not run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    /// Which gate.
    pub name: String,
    /// Why.
    pub reason: String,
    /// Whether the operator asked for this subset, or the run was simply
    /// incomplete.
    ///
    /// The distinction is the whole reason this type exists. `--gate mint` is a
    /// deliberate subset and should exit zero; a gate that could not run for want
    /// of a key is an incomplete CI run reporting green, which is the failure this
    /// codebase keeps designing against.
    pub deliberate: bool,
}

/// The result of a gate run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    /// Every gate measured.
    pub gates: Vec<Gate>,
    /// Gates that did not run, and why.
    #[serde(default)]
    pub skipped: Vec<Skipped>,
}

impl Report {
    /// Record a gate that could not run.
    pub fn skip(&mut self, name: &str, reason: &str, deliberate: bool) {
        self.skipped.push(Skipped {
            name: name.to_string(),
            reason: reason.to_string(),
            deliberate,
        });
    }

    /// Gates that were skipped for want of configuration rather than by request.
    #[must_use]
    pub fn incomplete(&self) -> Vec<&Skipped> {
        self.skipped.iter().filter(|s| !s.deliberate).collect()
    }

    /// Gates that failed.
    #[must_use]
    pub fn failed(&self) -> Vec<&Gate> {
        self.gates.iter().filter(|g| !g.passed()).collect()
    }

    /// Gates that held with little headroom.
    #[must_use]
    pub fn marginal(&self) -> Vec<&Gate> {
        self.gates.iter().filter(|g| g.is_marginal()).collect()
    }

    /// Whether every gate held **and** every gate ran.
    #[must_use]
    pub fn passed(&self) -> bool {
        // An empty report is not a pass. A run that measured nothing and exited
        // zero is exactly the "control that reports success without checking"
        // this project keeps having to design against — and so is a run that
        // silently skipped half its gates for want of a key.
        !self.gates.is_empty() && self.failed().is_empty() && self.incomplete().is_empty()
    }
}

/// Run one operation repeatedly and summarise the distribution.
///
/// The closure is run `warmup` times first and those samples are discarded: the
/// first call through any of these paths pays for lazily-built caches and page
/// faults, and including it measures the allocator rather than the code.
pub fn measure<F: FnMut()>(
    name: &str,
    detail: &str,
    threshold: Duration,
    iterations: usize,
    warmup: usize,
    mut op: F,
) -> Gate {
    for _ in 0..warmup {
        op();
    }

    let mut samples: Vec<u64> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        op();
        samples.push(started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
    }
    samples.sort_unstable();

    Gate {
        name: name.to_string(),
        detail: detail.to_string(),
        iterations,
        p50_ns: percentile(&samples, 50),
        p99_ns: percentile(&samples, 99),
        threshold_ns: threshold.as_nanos().min(u128::from(u64::MAX)) as u64,
    }
}

/// The `p`th percentile of a sorted sample set, nearest-rank.
///
/// Nearest-rank rather than interpolated: with 1000 samples the p99 should be a
/// measurement that actually happened, not an average of two that did.
#[must_use]
pub fn percentile(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p * sorted.len()).div_ceil(100).max(1);
    sorted[rank.min(sorted.len()) - 1]
}

/// The thresholds from §8.10.3.
///
/// Named constants rather than literals at each call site, so the design document
/// and the gate cannot drift apart without one edit touching both.
pub mod thresholds {
    use std::time::Duration;

    /// `gate::verify` steady state.
    pub const VERIFY_WARM: Duration = Duration::from_micros(1_500);
    /// `gate::verify` cold.
    pub const VERIFY_COLD: Duration = Duration::from_micros(3_000);
    /// `filter_tools_list` with 256 tools.
    pub const FILTER_256: Duration = Duration::from_micros(50);
    /// `contract::mint`.
    pub const MINT: Duration = Duration::from_millis(20);
    /// `blast_radius` over 10⁵ edges.
    pub const BLAST_RADIUS: Duration = Duration::from_millis(40);
    /// `Projection::rebuild` with 10⁵ contracts.
    pub const REBUILD: Duration = Duration::from_millis(600);
    /// `wcs1` canonicalisation of a 256-tool surface.
    pub const CANON_256: Duration = Duration::from_millis(10);
    /// Screening a 256-tool surface.
    pub const SCREEN_256: Duration = Duration::from_millis(50);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn gate(p99: u64, threshold: u64) -> Gate {
        Gate {
            name: "g".to_string(),
            detail: String::new(),
            iterations: 100,
            p50_ns: p99 / 2,
            p99_ns: p99,
            threshold_ns: threshold,
        }
    }

    #[test]
    fn a_gate_holds_at_the_threshold_and_fails_above_it() {
        assert!(gate(1_000, 1_000).passed());
        assert!(!gate(1_001, 1_000).passed());
    }

    #[test]
    fn a_gate_that_barely_holds_is_reported_as_marginal() {
        // A gate passing at 2% headroom is about to start failing for reasons
        // nobody changed, which is worse than one that fails outright.
        let tight = gate(990, 1_000);
        assert!(tight.passed());
        assert!(tight.is_marginal());
        assert!(tight.line().contains("MARGINAL"));

        let roomy = gate(500, 1_000);
        assert!(!roomy.is_marginal());
        assert!(!roomy.line().contains("MARGINAL"));
        assert!((roomy.margin() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn an_empty_report_is_not_a_pass() {
        // A run that measured nothing and exited zero is exactly the "control that
        // reports success without checking" this project keeps designing against.
        assert!(!Report::default().passed());

        let one = Report {
            gates: vec![gate(1, 1_000)],
            ..Report::default()
        };
        assert!(one.passed());
    }

    #[test]
    fn a_gate_skipped_for_want_of_configuration_fails_the_run() {
        // `--gate mint` is a deliberate subset and exits zero. A gate that could
        // not run for want of a key is an incomplete CI run reporting green.
        let mut deliberate = Report {
            gates: vec![gate(1, 1_000)],
            ..Report::default()
        };
        deliberate.skip("mint", "not selected", true);
        assert!(deliberate.passed());
        assert!(deliberate.incomplete().is_empty());

        let mut incomplete = Report {
            gates: vec![gate(1, 1_000)],
            ..Report::default()
        };
        incomplete.skip("mint", "no --signing-key", false);
        assert!(!incomplete.passed(), "an incomplete run must not read as green");
        assert_eq!(incomplete.incomplete().len(), 1);
    }

    #[test]
    fn a_report_separates_failures_from_marginals() {
        let r = Report {
            gates: vec![gate(500, 1_000), gate(990, 1_000), gate(2_000, 1_000)],
            ..Report::default()
        };
        assert_eq!(r.failed().len(), 1);
        assert_eq!(r.marginal().len(), 1, "the failure is not also marginal");
        assert!(!r.passed());
    }

    #[test]
    fn percentiles_use_nearest_rank_so_a_p99_is_a_real_measurement() {
        let samples: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&samples, 50), 50);
        assert_eq!(percentile(&samples, 99), 99);
        assert_eq!(percentile(&samples, 100), 100);
        assert_eq!(percentile(&samples, 1), 1);
        // Degenerate inputs do not panic.
        assert_eq!(percentile(&[], 99), 0);
        assert_eq!(percentile(&[7], 99), 7);
    }

    #[test]
    fn measure_discards_the_warmup_samples() {
        // The first call through any of these paths pays for lazily-built caches
        // and page faults; including it measures the allocator rather than the
        // code.
        let mut calls = 0usize;
        let gate = measure(
            "counting",
            "",
            Duration::from_secs(1),
            50,
            10,
            || calls += 1,
        );
        assert_eq!(calls, 60, "warmup runs but is not sampled");
        assert_eq!(gate.iterations, 50);
        assert!(gate.passed());
    }

    #[test]
    fn a_slow_operation_actually_fails_its_gate() {
        // The harness has to be able to fail, or every green run means nothing.
        let gate = measure(
            "slow",
            "",
            Duration::from_nanos(1),
            5,
            0,
            || std::thread::sleep(Duration::from_millis(1)),
        );
        assert!(!gate.passed());
        assert!(gate.line().contains("FAIL"));
    }

    #[test]
    fn durations_read_in_the_right_unit() {
        assert_eq!(fmt_ns(900), "900 ns");
        assert_eq!(fmt_ns(1_500), "1.5 µs");
        assert_eq!(fmt_ns(1_500_000), "1.50 ms");
        assert_eq!(fmt_ns(2_500_000_000), "2.50 s");
    }

    #[test]
    fn the_thresholds_match_the_design_document() {
        // §8.10.3 in one place, so the table and the gate cannot drift apart
        // without one edit touching both.
        assert_eq!(thresholds::VERIFY_WARM, Duration::from_micros(1_500));
        assert_eq!(thresholds::VERIFY_COLD, Duration::from_micros(3_000));
        assert_eq!(thresholds::FILTER_256, Duration::from_micros(50));
        assert_eq!(thresholds::MINT, Duration::from_millis(20));
        assert_eq!(thresholds::BLAST_RADIUS, Duration::from_millis(40));
        assert_eq!(thresholds::REBUILD, Duration::from_millis(600));
    }
}
