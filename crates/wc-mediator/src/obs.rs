//! The data plane's telemetry: a decision log and the §8.14 families the mediator owns
//! (production-readiness P1 #11).
//!
//! #11's sharpest sentence was that there is **no structured decision log on the mediator
//! path at all**, "which is the thing an operator would actually alert on". That is right,
//! and the reason is worth stating: the control plane's `/metrics` describes issuance, and
//! issuance can be perfectly healthy while every call in the estate is being refused. The
//! only process that knows a call was denied is this one.
//!
//! # Where the numbers go, given there is no HTTP here
//!
//! `connect-mediate` speaks stdio to one agent. It has no listener, so it cannot serve
//! `/metrics`, and adding one would mean adding a port, a bind address and an
//! authentication decision to a sidecar whose whole argument is that it adds no surface.
//!
//! So:
//!
//! * **Decisions** go to **stderr** as one JSON object per line. That is where a container
//!   runtime already collects, and it needs no configuration to be useful.
//! * **Metrics** go to a **file** (`--metrics-file`), in Prometheus text format, rewritten
//!   on a cadence. This is the node-exporter textfile-collector convention: the scrape is
//!   somebody else's problem and this process keeps no socket open.
//!
//! # Why allows are not logged by default
//!
//! A mediator in front of a busy agent makes thousands of allow decisions a second. A line
//! each turns the decision log into a cost centre, and the observable outcome of a cost
//! centre is that somebody switches it off — at which point the *denials* are lost too,
//! which is the opposite of what the logging was for. So `LogLevel::Notable` is the
//! default: denials and observe-mode findings always, allows on request.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use wc_core::error::{Code, Mode};
use wc_core::obs::{Decision, Kind, LogLevel, Registry};

/// Tools exposed or hidden by the catalogue filter.
pub const FILTER_TOOLS: &str = "wc_filter_tools";
/// Catalogues emptied because the filter could not verify anything.
pub const FILTER_FAILCLOSED: &str = "wc_filter_failclosed_total";
/// Attempts to exceed a contract's ceiling, by kind.
pub const CEILING_BREACHES: &str = "wc_ceiling_breaches_total";
/// Contract verification time, warm and cold.
pub const VERIFY_DURATION: &str = "wc_verify_duration_seconds";
/// Decisions by outcome, mode and code.
pub const DECISIONS: &str = "wc_decisions_total";
/// Whether the revocation set is currently trusted.
///
/// The gauge the control plane **cannot** produce: distrust is local to this process. A
/// mediator that cannot verify the feed refuses everything, and from the control plane's
/// side that is indistinguishable from a healthy estate with no traffic.
pub const REVOCATION_TRUSTED: &str = "wc_revocation_trusted";
/// Whether this mediator has a revocation source at all.
///
/// Zero means `--contract FILE` with no `--contracts URL`: contracts were loaded once
/// from disk, no feed will ever arrive, and **quarantine fan-out cannot reach this
/// process**. Separate from [`REVOCATION_TRUSTED`] so an operator can tell "the feed
/// broke" from "there was never a feed" — two different pages at three in the morning.
pub const REVOCATION_SOURCE: &str = "wc_revocation_source_configured";
/// Contracts held in the local cache.
pub const CONTRACTS_HELD: &str = "wc_contracts_held";

/// The `code` label on a decision that had nothing to report.
pub const NO_CODE: &str = "WC-0000";

/// Verification-latency buckets, in seconds.
///
/// §7.10 puts connection establishment at p99 under 5 ms and each later call under 1 ms,
/// so both numbers are bucket boundaries. A histogram whose boundaries miss the stated
/// target can only ever say "somewhere near it".
const VERIFY_BUCKETS: &[f64] = &[0.000_1, 0.000_5, 0.001, 0.002, 0.005, 0.01, 0.05];

/// Where a decision line goes.
enum Out {
    /// Standard error, one line per decision.
    Stderr,
    /// Collected in memory. For tests, which is the only way to assert on a log without
    /// capturing a process's stderr.
    Captured(Mutex<Vec<String>>),
}

/// The mediator's telemetry.
///
/// One object rather than two so a call site cannot record a metric and forget the log
/// line, or the reverse — the pairing is what makes the two agree.
pub struct Telemetry {
    registry: Registry,
    level: LogLevel,
    out: Out,
    metrics_file: Option<PathBuf>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry")
            .field("level", &self.level.as_str())
            .field("metrics_file", &self.metrics_file)
            .finish_non_exhaustive()
    }
}

impl Default for Telemetry {
    fn default() -> Telemetry {
        Telemetry::new(LogLevel::default())
    }
}

impl Telemetry {
    /// Telemetry writing decision lines to stderr.
    #[must_use]
    pub fn new(level: LogLevel) -> Telemetry {
        let registry = Registry::new();
        register(&registry);
        Telemetry {
            registry,
            level,
            out: Out::Stderr,
            metrics_file: None,
        }
    }

    /// Telemetry that keeps its lines in memory, for tests.
    #[must_use]
    pub fn captured(level: LogLevel) -> Telemetry {
        let mut t = Telemetry::new(level);
        t.out = Out::Captured(Mutex::new(Vec::new()));
        t
    }

    /// Also write the Prometheus exposition to this path when [`Telemetry::flush`] runs.
    #[must_use]
    pub fn with_metrics_file(mut self, path: impl Into<PathBuf>) -> Telemetry {
        self.metrics_file = Some(path.into());
        self
    }

    /// The metric registry, for a caller that wants to observe something directly.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Which decisions are logged.
    #[must_use]
    pub fn level(&self) -> LogLevel {
        self.level
    }

    /// Lines written so far. Empty unless this is a captured `Telemetry`.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        match &self.out {
            Out::Stderr => Vec::new(),
            Out::Captured(lines) => lines
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        }
    }

    /// Record one decision: bump the counter, and write the line if the level wants it.
    ///
    /// The counter is bumped **regardless of the level**, which is the point of having
    /// both. An operator who turns the log down to `off` for volume still has
    /// `wc_decisions_total{decision="deny",code="WC-3102"}`, so turning logging down
    /// costs detail and not visibility.
    pub fn decision(&self, decision: &Decision<'_>) {
        self.registry.inc(
            DECISIONS,
            &[
                ("decision", decision.decision),
                ("mode", decision.mode),
                ("code", decision.code),
            ],
            1,
        );
        if !self.level.logs(decision.decision) {
            return;
        }
        let line = decision.to_line();
        match &self.out {
            Out::Stderr => {
                // Locked and written in one call so two threads cannot interleave halves
                // of two JSON objects onto one line, which would make both unparseable.
                let stderr = std::io::stderr();
                let mut handle = stderr.lock();
                let _ = writeln!(handle, "{line}");
            }
            Out::Captured(lines) => lines
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line),
        }
    }

    /// A convenience for the common shape: everything but `cid` and the tool is fixed by
    /// the connection.
    ///
    /// `code` is an `Option` because **an allow has no code.** There is no `Code::OK` in
    /// the taxonomy and inventing one would mean a success and a failure sharing a
    /// namespace — a dashboard grouping by code would show the estate's most common
    /// "error" being everything working. `None` renders as `WC-0000`, which sorts first
    /// and reads as absence.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        cid: &str,
        outcome: Outcome,
        code: Option<Code>,
        mode: Mode,
        tool: &str,
        caller: &str,
        callee: &str,
        jti: &str,
        at: u64,
        micros: u64,
    ) {
        let rendered = code.map_or_else(|| NO_CODE.to_string(), |c| c.to_string());
        self.decision(&Decision {
            cid,
            decision: outcome.as_str(),
            code: &rendered,
            mode: mode_label(mode),
            tool,
            caller,
            callee,
            jti,
            at,
            micros,
        });
    }

    /// Note the catalogue filter's effect.
    pub fn filtered(&self, exposed: u64, hidden: u64, fail_closed: bool) {
        self.registry
            .set(FILTER_TOOLS, &[("state", "exposed")], exposed);
        self.registry
            .set(FILTER_TOOLS, &[("state", "hidden")], hidden);
        if fail_closed {
            self.registry.inc(FILTER_FAILCLOSED, &[], 1);
        }
    }

    /// Note an attempt to exceed a ceiling.
    pub fn ceiling_breach(&self, kind: &str) {
        self.registry.inc(CEILING_BREACHES, &[("kind", kind)], 1);
    }

    /// Note how long a verification took, and whether the cache was warm.
    pub fn verified(&self, warm: bool, seconds: f64) {
        let path = if warm { "warm" } else { "cold" };
        self.registry
            .observe(VERIFY_DURATION, &[("path", path)], seconds);
    }

    /// Note whether the revocation set is trusted, and how many contracts are held.
    ///
    /// `source_configured` is not decoration. A mediator started with `--contract FILE`
    /// and no `--contracts URL` has no revocation feed and never will: no pull happens,
    /// so nothing ever distrusts the empty set, so `distrusted()` stays `None` and this
    /// gauge read **1 — "the revocation set verifies"** on a mediator that cannot be
    /// contained at all. The `wc_revocation_trusted == 0` alert could therefore never
    /// fire for the one topology where containment is entirely absent.
    ///
    /// An empty set nobody can update is not a trusted set. It is the same
    /// unknown-is-not-allowed rule [`crate::cache::Revocations::distrust`] states, one
    /// level up: here it costs a gauge rather than a denial, because denying every call
    /// would take the documented air-gapped path away rather than make it honest.
    pub fn cache_state(&self, revocation_trusted: bool, source_configured: bool, contracts: u64) {
        self.registry.set(
            REVOCATION_TRUSTED,
            &[],
            u64::from(revocation_trusted && source_configured),
        );
        self.registry
            .set(REVOCATION_SOURCE, &[], u64::from(source_configured));
        self.registry.set(CONTRACTS_HELD, &[], contracts);
    }

    /// Write the exposition to the configured file, if there is one.
    ///
    /// Written to a temporary path and renamed, because a scraper reading a half-written
    /// file gets a truncated exposition and reports the whole endpoint as broken — the
    /// same "everything goes dark" failure as an unescaped label.
    pub fn flush(&self) {
        let Some(path) = &self.metrics_file else {
            return;
        };
        let body = self.registry.to_prometheus();
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

/// What happened to a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Forwarded.
    Allow,
    /// Refused.
    Deny,
    /// Forwarded with a finding — observe mode.
    Record,
}

impl Outcome {
    /// The word in the log line and the metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Deny => "deny",
            Outcome::Record => "record",
        }
    }
}

fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Enforce => "enforce",
        Mode::Observe => "observe",
    }
}

/// Declare the families this crate emits.
fn register(registry: &Registry) {
    registry.register(
        DECISIONS,
        Kind::Counter,
        "Decisions by outcome, mode and code.",
    );
    registry.register(
        FILTER_FAILCLOSED,
        Kind::Counter,
        "Catalogues emptied because nothing could be verified.",
    );
    registry.register(
        CEILING_BREACHES,
        Kind::Counter,
        "Attempts to exceed a contract's ceiling, by kind.",
    );
    registry.register(
        FILTER_TOOLS,
        Kind::Gauge,
        "Tools exposed or hidden by the catalogue filter.",
    );
    registry.register(
        REVOCATION_TRUSTED,
        Kind::Gauge,
        "1 when a revocation feed is configured and verifies; 0 when it is distrusted \
         (every connection fails closed) or when there is no feed at all.",
    );
    registry.register(
        REVOCATION_SOURCE,
        Kind::Gauge,
        "1 when a revocation feed is configured; 0 for --contract FILE with no control \
         plane, where quarantine fan-out cannot reach this mediator.",
    );
    registry.register(CONTRACTS_HELD, Kind::Gauge, "Contracts in the local cache.");
    registry.register_histogram(
        VERIFY_DURATION,
        "Contract verification time.",
        VERIFY_BUCKETS,
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn parsed(t: &Telemetry) -> Vec<serde_json::Value> {
        t.lines()
            .iter()
            .map(|l| serde_json::from_str(l).expect("every line must be valid JSON"))
            .collect()
    }

    #[test]
    fn a_denial_produces_a_line_an_operator_can_alert_on() {
        let t = Telemetry::captured(LogLevel::default());
        t.record(
            "conn_7f3a",
            Outcome::Deny,
            Some(Code::TOOL_UNCONTRACTED),
            Mode::Enforce,
            "transfer_funds",
            "spiffe://org/ns/a/sa/x",
            "spiffe://org/ns/t/sa/y",
            "art_1",
            1_785_312_500,
            88,
        );
        let lines = parsed(&t);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["cid"], "conn_7f3a");
        assert_eq!(lines[0]["decision"], "deny");
        assert_eq!(lines[0]["mode"], "enforce");
        assert_eq!(lines[0]["tool"], "transfer_funds");
        assert!(lines[0]["code"].as_str().unwrap().starts_with("WC-"));
    }

    #[test]
    fn allows_are_counted_even_when_they_are_not_logged() {
        // The reason metrics and the log are one object. An operator who turns logging
        // down for volume must not lose the *count* — otherwise the cheapest way to
        // reduce log spend is to become blind, and that is what people do.
        let t = Telemetry::captured(LogLevel::Notable);
        for _ in 0..5 {
            t.record(
                "c",
                Outcome::Allow,
                None,
                Mode::Enforce,
                "read",
                "a",
                "b",
                "j",
                1,
                1,
            );
        }
        assert!(t.lines().is_empty(), "notable must not log allows");
        assert_eq!(
            t.registry().value(
                DECISIONS,
                &[
                    ("decision", "allow"),
                    ("mode", "enforce"),
                    ("code", NO_CODE)
                ]
            ),
            Some(5),
            "but the counter has to see them"
        );
    }

    #[test]
    fn observe_mode_findings_are_logged_at_the_default_level() {
        // These are the whole point of an observe deployment: the evidence for turning
        // enforcement on. Losing them to a volume default would make observe mode
        // pointless while looking configured.
        let t = Telemetry::captured(LogLevel::default());
        t.record(
            "",
            Outcome::Record,
            Some(Code::NO_CONTRACT),
            Mode::Observe,
            "list_transactions",
            "a",
            "b",
            "",
            1,
            2,
        );
        let lines = parsed(&t);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["decision"], "record");
        assert_eq!(lines[0]["mode"], "observe");
    }

    #[test]
    fn off_stops_the_log_and_keeps_the_metrics() {
        let t = Telemetry::captured(LogLevel::Off);
        t.record(
            "c",
            Outcome::Deny,
            Some(Code::NO_CONTRACT),
            Mode::Enforce,
            "x",
            "a",
            "b",
            "j",
            1,
            1,
        );
        assert!(t.lines().is_empty());
        assert!(t.registry().to_prometheus().contains("wc_decisions_total{"));
    }

    #[test]
    fn the_data_plane_families_the_control_plane_cannot_emit_are_here() {
        // §8.14 lists these and `wc-control`'s `/metrics` deliberately does not carry
        // them: they describe what happened to a *call*, and the control plane never sees
        // a call. Left in neither place they would be a specification nobody implemented.
        let t = Telemetry::captured(LogLevel::Off);
        t.filtered(3, 17, true);
        t.ceiling_breach("rate");
        t.verified(true, 0.000_3);
        t.cache_state(false, true, 42);

        let text = t.registry().to_prometheus();
        assert!(
            text.contains("wc_filter_tools{state=\"exposed\"} 3"),
            "{text}"
        );
        assert!(
            text.contains("wc_filter_tools{state=\"hidden\"} 17"),
            "{text}"
        );
        assert!(text.contains("wc_filter_failclosed_total 1"), "{text}");
        assert!(
            text.contains("wc_ceiling_breaches_total{kind=\"rate\"} 1"),
            "{text}"
        );
        assert!(text.contains("wc_contracts_held 42"), "{text}");
        assert!(
            text.contains("wc_revocation_trusted 0"),
            "the gauge the control plane cannot produce: {text}"
        );
    }

    #[test]
    fn the_verify_histogram_has_boundaries_at_the_numbers_7_10_promises() {
        // p99 < 5 ms on establishment, < 1 ms per later call. A histogram whose bounds
        // miss those can only say "somewhere near it", which is not a gate.
        assert!(VERIFY_BUCKETS.contains(&0.001), "{VERIFY_BUCKETS:?}");
        assert!(VERIFY_BUCKETS.contains(&0.005), "{VERIFY_BUCKETS:?}");

        let t = Telemetry::captured(LogLevel::Off);
        t.verified(true, 0.000_8);
        t.verified(false, 0.004);
        let text = t.registry().to_prometheus();
        assert!(text.contains("path=\"warm\""), "{text}");
        assert!(text.contains("path=\"cold\""), "{text}");
        assert!(
            text.contains("wc_verify_duration_seconds_count 2"),
            "{text}"
        );
    }

    #[test]
    fn the_metrics_file_is_written_atomically() {
        // A scraper that reads a half-written file reports the whole exposition as broken,
        // so every panel goes blank at once — the same failure as an unescaped label, for
        // the same reason.
        let dir = std::env::temp_dir().join(format!("wc-obs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mediator.prom");

        let t = Telemetry::captured(LogLevel::Off).with_metrics_file(&path);
        t.cache_state(true, true, 7);
        t.flush();

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("wc_contracts_held 7"), "{body}");
        assert!(
            !path.with_extension("tmp").exists(),
            "the temporary file must be renamed away, not left beside it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_metrics_file_configured_is_not_an_error() {
        // A sidecar with no metrics collector is an ordinary deployment.
        Telemetry::captured(LogLevel::Off).flush();
    }
}
