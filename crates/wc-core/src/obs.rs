//! Labelled metrics and structured decision logs (`docs/08-lld.md` §8.14,
//! production-readiness P1 #11).
//!
//! §8.14 specifies about fifteen metric families with labels — `wc_denials_total{code}`
//! for every `WC-*` code, `wc_verify_duration_seconds_bucket{path}`,
//! `wc_filter_tools{state}`, `wc_drift_total{class}`. What existed was seven unlabelled
//! `AtomicU64`s behind `/metrics`, and **no structured decision log on the mediator path
//! at all** — which is the thing an operator would actually alert on, because the control
//! plane can be perfectly healthy while every call is being denied.
//!
//! # Why this is in `wc-core`
//!
//! Both planes need it and they cannot share anything else. `wc-control` may not depend
//! on Warden core (§8.3 — the control plane stays independently adoptable), so
//! `warden::obs` is unavailable to it; `wc-mediator` may, but `warden::obs` is a
//! fixed-shape counter set with no `cid`, no `WC-*` code and no mode, which is exactly
//! the three fields #11 asks for. So it lives here: no I/O, no HTTP, no new dependency —
//! `BTreeMap` and atomics.
//!
//! # Cardinality is capped, and overflow is visible
//!
//! The failure mode of a labelled metric is not a wrong number, it is a monitoring system
//! taken down by a label nobody bounded. `zone_pair` is quadratic in zones; `mediator` is
//! fine until somebody generates ephemeral ids.
//!
//! So each family has a **cap**. Past it, a series folds into `overflow="true"` and
//! `wc_obs_series_dropped_total{metric}` counts what folded. The reason it folds rather
//! than being dropped is that a silently missing series reads as *zero* on a dashboard —
//! an alert that never fires because its metric stopped existing is the worst possible
//! outcome for a monitoring change, and it is this repository's recurring bug class
//! wearing a different hat.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// How many distinct label sets one family may hold before folding into `overflow`.
///
/// 256 is chosen against the real bounds: `wc_denials_total{code}` is bounded by the
/// number of `WC-*` codes (about fifty), `wc_filter_tools{state}` by two, and
/// `wc_contracts_active{zone_pair,tier}` by zones² × tiers, which is where an estate with
/// thirty zones would exceed it and be told so rather than quietly ballooning.
pub const DEFAULT_CARDINALITY_CAP: usize = 256;

/// What a metric measures, so the exposition can declare it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Monotonically increasing.
    Counter,
    /// Point-in-time value.
    Gauge,
    /// Bucketed observations.
    Histogram,
}

impl Kind {
    /// The word Prometheus expects after `# TYPE`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
            Kind::Histogram => "histogram",
        }
    }
}

/// One family's identity and documentation.
#[derive(Debug, Clone)]
struct Family {
    kind: Kind,
    help: &'static str,
    /// Upper bounds for a histogram, ascending. Empty for other kinds.
    buckets: Vec<f64>,
    /// Label set → value. For a histogram, the value is the count in that bucket, keyed
    /// with a synthetic `le` label.
    series: BTreeMap<String, u64>,
    /// Sum of observations, for a histogram's `_sum`.
    sum: f64,
    /// Series that did not fit under the cap.
    dropped: u64,
}

/// A metrics registry.
///
/// Registration is explicit and up front: a family must be declared before it can be
/// touched. `emit_to_an_unregistered_family_is_a_no_op_and_counted` is the test that
/// keeps a typo from becoming a metric nobody notices is missing.
#[derive(Debug)]
pub struct Registry {
    families: Mutex<BTreeMap<&'static str, Family>>,
    cap: usize,
    /// Emits naming a family that was never declared.
    unknown: AtomicU64,
}

impl Default for Registry {
    fn default() -> Registry {
        Registry::new()
    }
}

impl Registry {
    /// An empty registry with the default cardinality cap.
    #[must_use]
    pub fn new() -> Registry {
        Registry {
            families: Mutex::new(BTreeMap::new()),
            cap: DEFAULT_CARDINALITY_CAP,
            unknown: AtomicU64::new(0),
        }
    }

    /// Override the cardinality cap. Zero is refused up to one, because a cap of zero
    /// would fold every series and report an empty registry as healthy.
    #[must_use]
    pub fn with_cap(mut self, cap: usize) -> Registry {
        self.cap = cap.max(1);
        self
    }

    /// Declare a counter or gauge.
    pub fn register(&self, name: &'static str, kind: Kind, help: &'static str) {
        self.declare(name, kind, help, Vec::new());
    }

    /// Declare a histogram with ascending upper bounds.
    pub fn register_histogram(&self, name: &'static str, help: &'static str, buckets: &[f64]) {
        let mut sorted = buckets.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        self.declare(name, Kind::Histogram, help, sorted);
    }

    fn declare(&self, name: &'static str, kind: Kind, help: &'static str, buckets: Vec<f64>) {
        let mut families = self.lock();
        families.entry(name).or_insert_with(|| Family {
            kind,
            help,
            buckets,
            series: BTreeMap::new(),
            sum: 0.0,
            dropped: 0,
        });
    }

    /// Add to a counter.
    pub fn inc(&self, name: &str, labels: &[(&str, &str)], by: u64) {
        self.mutate(name, labels, |slot| *slot = slot.saturating_add(by));
    }

    /// Set a gauge.
    pub fn set(&self, name: &str, labels: &[(&str, &str)], value: u64) {
        self.mutate(name, labels, |slot| *slot = value);
    }

    /// Observe a value into a histogram.
    ///
    /// Cumulative buckets, as Prometheus requires: an observation lands in its own bucket
    /// and every bucket above it. `+Inf` is always present, so `_count` is derivable
    /// without knowing the bucket layout.
    pub fn observe(&self, name: &str, labels: &[(&str, &str)], value: f64) {
        let mut families = self.lock();
        let Some(family) = families.get_mut(name) else {
            self.unknown.fetch_add(1, Ordering::Relaxed);
            return;
        };
        family.sum += value;
        let bounds: Vec<f64> = family.buckets.clone();
        let base = encode_labels(labels);
        for bound in bounds.iter().copied().chain(std::iter::once(f64::INFINITY)) {
            if value > bound {
                continue;
            }
            let key = with_le(&base, bound);
            let capped = family.series.len() >= self.cap && !family.series.contains_key(&key);
            if capped {
                family.dropped += 1;
                let overflow = with_le(&encode_labels(&[("overflow", "true")]), bound);
                *family.series.entry(overflow).or_insert(0) += 1;
            } else {
                *family.series.entry(key).or_insert(0) += 1;
            }
        }
    }

    fn mutate<F: FnOnce(&mut u64)>(&self, name: &str, labels: &[(&str, &str)], f: F) {
        let mut families = self.lock();
        let Some(family) = families.get_mut(name) else {
            // Not a panic: a metric is telemetry, and taking a request down because a
            // counter name was misspelled would make observability a liveness risk. It is
            // counted, and `wc_obs_unknown_family_total` is what surfaces the typo.
            self.unknown.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let key = encode_labels(labels);
        if family.series.len() >= self.cap && !family.series.contains_key(&key) {
            family.dropped += 1;
            f(family
                .series
                .entry(encode_labels(&[("overflow", "true")]))
                .or_insert(0));
            return;
        }
        f(family.series.entry(key).or_insert(0));
    }

    /// Current value of one series, for tests and for a status page.
    #[must_use]
    pub fn value(&self, name: &str, labels: &[(&str, &str)]) -> Option<u64> {
        self.lock()
            .get(name)
            .and_then(|f| f.series.get(&encode_labels(labels)).copied())
    }

    /// How many series folded into `overflow` for a family.
    #[must_use]
    pub fn dropped(&self, name: &str) -> u64 {
        self.lock().get(name).map_or(0, |f| f.dropped)
    }

    /// Emits that named a family nobody declared.
    #[must_use]
    pub fn unknown_emits(&self) -> u64 {
        self.unknown.load(Ordering::Relaxed)
    }

    /// Render Prometheus text exposition.
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        let families = self.lock();
        let mut out = String::new();
        for (name, family) in families.iter() {
            out.push_str(&format!("# HELP {name} {}\n", family.help));
            out.push_str(&format!("# TYPE {name} {}\n", family.kind.as_str()));
            match family.kind {
                Kind::Histogram => {
                    for (labels, count) in &family.series {
                        out.push_str(&format!("{name}_bucket{{{labels}}} {count}\n"));
                    }
                    // `_sum` and `_count` are what a rate() over a histogram needs; the
                    // count is the `+Inf` bucket by definition.
                    let total: u64 = family
                        .series
                        .iter()
                        .filter(|(k, _)| k.contains("le=\"+Inf\""))
                        .map(|(_, v)| *v)
                        .sum();
                    out.push_str(&format!("{name}_sum {}\n", format_float(family.sum)));
                    out.push_str(&format!("{name}_count {total}\n"));
                }
                _ => {
                    for (labels, value) in &family.series {
                        if labels.is_empty() {
                            out.push_str(&format!("{name} {value}\n"));
                        } else {
                            out.push_str(&format!("{name}{{{labels}}} {value}\n"));
                        }
                    }
                }
            }
            if family.dropped > 0 {
                out.push_str(&format!(
                    "wc_obs_series_dropped_total{{metric=\"{name}\"}} {}\n",
                    family.dropped
                ));
            }
        }
        let unknown = self.unknown.load(Ordering::Relaxed);
        if unknown > 0 {
            out.push_str("# HELP wc_obs_unknown_family_total Emits naming an undeclared metric.\n");
            out.push_str("# TYPE wc_obs_unknown_family_total counter\n");
            out.push_str(&format!("wc_obs_unknown_family_total {unknown}\n"));
        }
        out
    }

    /// Render as JSON, for a caller that would rather not parse the text format.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let families = self.lock();
        let mut out = serde_json::Map::new();
        for (name, family) in families.iter() {
            let series: Vec<serde_json::Value> = family
                .series
                .iter()
                .map(|(labels, value)| {
                    serde_json::json!({ "labels": decode_labels(labels), "value": value })
                })
                .collect();
            out.insert(
                (*name).to_string(),
                serde_json::json!({
                    "type": family.kind.as_str(),
                    "help": family.help,
                    "series": series,
                    "dropped": family.dropped,
                }),
            );
        }
        serde_json::Value::Object(out)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<&'static str, Family>> {
        // A poisoned metrics mutex must not take the process down: telemetry is not
        // load-bearing, and a panic here would convert a monitoring bug into an outage.
        self.families
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// `a="1",b="2"`, sorted, with values escaped.
fn encode_labels(labels: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(&str, &str)> = labels.to_vec();
    pairs.sort_unstable();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
        .collect::<Vec<_>>()
        .join(",")
}

fn with_le(base: &str, bound: f64) -> String {
    let le = if bound.is_infinite() {
        "+Inf".to_string()
    } else {
        format_float(bound)
    };
    if base.is_empty() {
        format!("le=\"{le}\"")
    } else {
        // `le` sorts after most label names, and Prometheus does not care about order —
        // but the string is also the map key, so it has to be deterministic.
        format!("{base},le=\"{le}\"")
    }
}

/// Prometheus label-value escaping: backslash, quote, newline. Without this, a label
/// carrying a quote — a tool name, an error detail — produces an exposition that a
/// scraper rejects, and the whole endpoint goes dark rather than one series.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

fn decode_labels(encoded: &str) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for part in encoded.split("\",") {
        if let Some((k, v)) = part.split_once("=\"") {
            out.insert(
                k.trim_matches(',').to_string(),
                serde_json::Value::String(v.trim_end_matches('"').to_string()),
            );
        }
    }
    serde_json::Value::Object(out)
}

/// Shortest representation that round-trips, so bucket bounds read as `0.005` not
/// `0.005000000000000000104`.
fn format_float(v: f64) -> String {
    if v == v.trunc() && v.abs() < 1e15 {
        format!("{v}")
    } else {
        let mut s = format!("{v:.6}");
        while s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Decision logs
// ---------------------------------------------------------------------------

/// One line of the structured decision log.
///
/// The three fields #11 names — `cid`, the `WC-*` code, and the mode — are mandatory
/// rather than optional, because they are the difference between a log an operator can act
/// on and a log they can only read. `cid` correlates across the family (`warden-trace`
/// joins by it); the code says *why* in a form a dashboard can group; the mode says
/// whether the decision was enforced or merely recorded, and without it an observe-mode
/// estate looks like an estate under attack.
#[derive(Debug, Clone)]
pub struct Decision<'a> {
    /// Connection id, the correlation root. Empty when no contract matched at all.
    pub cid: &'a str,
    /// `allow` | `deny` | `record`.
    pub decision: &'a str,
    /// `WC-0000` when there is nothing to say.
    pub code: &'a str,
    /// `enforce` | `observe`.
    pub mode: &'a str,
    /// What was being attempted.
    pub tool: &'a str,
    /// Authenticated caller.
    pub caller: &'a str,
    /// Authenticated callee.
    pub callee: &'a str,
    /// Contract artifact id, where one was in force.
    pub jti: &'a str,
    /// Wall-clock seconds.
    pub at: u64,
    /// How long the decision took.
    pub micros: u64,
}

impl Decision<'_> {
    /// Render one JSON line, without a trailing newline.
    ///
    /// Hand-rolled rather than via `serde_json::to_string` on a temporary map, because
    /// this is on the per-call path and the field order is fixed — an operator greps
    /// these, and a stable order makes them diffable.
    #[must_use]
    pub fn to_line(&self) -> String {
        format!(
            "{{\"ts\":{},\"ev\":\"connect.decision\",\"service.name\":\"warden-connect\",\
             \"cid\":{},\"decision\":{},\"code\":{},\"mode\":{},\"tool\":{},\"caller\":{},\
             \"callee\":{},\"jti\":{},\"latency_us\":{}}}",
            self.at,
            quote(self.cid),
            quote(self.decision),
            quote(self.code),
            quote(self.mode),
            quote(self.tool),
            quote(self.caller),
            quote(self.callee),
            quote(self.jti),
            self.micros,
        )
    }
}

/// A JSON string literal, escaped. Control characters are escaped rather than passed
/// through: a tool name is attacker-influenced (§7.8 A4), and a raw newline in it would
/// let one decision forge a second log line.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Which decisions get a log line.
///
/// The default is deliberately not "everything". A mediator in front of a busy agent
/// makes thousands of allow decisions a second, and a line each turns the decision log
/// into a cost centre nobody keeps switched on — at which point the denials are lost too,
/// because the whole thing was disabled. Denials and findings are always logged; allows
/// are opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    /// Nothing. For a deployment shipping evidence some other way.
    Off,
    /// Denials, drift and ceiling breaches. The default.
    #[default]
    Notable,
    /// Every decision, including allows.
    All,
}

impl LogLevel {
    /// Parse an operator's word.
    #[must_use]
    pub fn parse(value: &str) -> Option<LogLevel> {
        match value {
            "off" | "none" => Some(LogLevel::Off),
            "notable" | "deny" => Some(LogLevel::Notable),
            "all" => Some(LogLevel::All),
            _ => None,
        }
    }

    /// Whether a decision with this outcome is logged.
    #[must_use]
    pub fn logs(self, decision: &str) -> bool {
        match self {
            LogLevel::Off => false,
            LogLevel::All => true,
            // `record` is an observe-mode finding: the call proceeded and something was
            // wrong with it, which is the single most important line in an observe
            // deployment because it is the evidence for turning enforcement on.
            LogLevel::Notable => decision != "allow",
        }
    }

    /// The word for output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Notable => "notable",
            LogLevel::All => "all",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn registry() -> Registry {
        let r = Registry::new();
        r.register("wc_denials_total", Kind::Counter, "Denials by code.");
        r.register("wc_entities", Kind::Gauge, "Entities by posture.");
        r.register_histogram(
            "wc_verify_duration_seconds",
            "Contract verification.",
            &[0.001, 0.005, 0.01],
        );
        r
    }

    #[test]
    fn a_labelled_counter_renders_as_prometheus_expects() {
        let r = registry();
        r.inc("wc_denials_total", &[("code", "WC-3102")], 1);
        r.inc("wc_denials_total", &[("code", "WC-3102")], 2);
        r.inc("wc_denials_total", &[("code", "WC-4001")], 1);

        assert_eq!(r.value("wc_denials_total", &[("code", "WC-3102")]), Some(3));
        let text = r.to_prometheus();
        assert!(text.contains("# TYPE wc_denials_total counter"), "{text}");
        assert!(
            text.contains("wc_denials_total{code=\"WC-3102\"} 3"),
            "{text}"
        );
        assert!(
            text.contains("wc_denials_total{code=\"WC-4001\"} 1"),
            "{text}"
        );
    }

    #[test]
    fn labels_are_order_independent() {
        // Otherwise the same series counted from two call sites becomes two series, and
        // every rate() over it is half the truth.
        let r = Registry::new();
        r.register("m", Kind::Counter, "h");
        r.inc("m", &[("a", "1"), ("b", "2")], 1);
        r.inc("m", &[("b", "2"), ("a", "1")], 1);
        assert_eq!(r.value("m", &[("a", "1"), ("b", "2")]), Some(2));
    }

    #[test]
    fn a_histogram_is_cumulative_with_sum_and_count() {
        let r = registry();
        for v in [0.0005, 0.003, 0.02] {
            r.observe("wc_verify_duration_seconds", &[("path", "warm")], v);
        }
        let text = r.to_prometheus();
        // 0.0005 lands in every bucket; 0.003 in 0.005 and up; 0.02 only in +Inf.
        assert!(text.contains("le=\"0.001\"} 1"), "{text}");
        assert!(text.contains("le=\"0.005\"} 2"), "{text}");
        assert!(text.contains("le=\"0.01\"} 2"), "{text}");
        assert!(text.contains("le=\"+Inf\"} 3"), "{text}");
        assert!(
            text.contains("wc_verify_duration_seconds_count 3"),
            "{text}"
        );
        assert!(
            text.contains("wc_verify_duration_seconds_sum 0.0235"),
            "{text}"
        );
    }

    #[test]
    fn cardinality_overflow_folds_and_is_counted_rather_than_dropped() {
        // The failure this cap prevents is a monitoring system taken down by an unbounded
        // label. The failure the *fold* prevents is worse: a silently missing series reads
        // as zero on a dashboard, so an alert stops firing and nothing says why.
        let r = Registry::new().with_cap(3);
        r.register("m", Kind::Counter, "h");
        for i in 0..10 {
            r.inc("m", &[("id", &format!("{i}"))], 1);
        }
        assert_eq!(r.dropped("m"), 7);
        assert_eq!(r.value("m", &[("overflow", "true")]), Some(7));

        let text = r.to_prometheus();
        assert!(
            text.contains("wc_obs_series_dropped_total{metric=\"m\"} 7"),
            "the overflow has to be visible in the exposition: {text}"
        );
    }

    #[test]
    fn a_cap_of_zero_is_raised_to_one() {
        // A cap of zero would fold every series and render an endpoint that looks
        // healthy and says nothing.
        let r = Registry::new().with_cap(0);
        r.register("m", Kind::Counter, "h");
        r.inc("m", &[("a", "1")], 5);
        assert_eq!(r.value("m", &[("a", "1")]), Some(5));
    }

    #[test]
    fn emitting_to_an_undeclared_family_is_counted_not_silent_and_never_panics() {
        // A misspelled metric name must not take a request down — telemetry is not
        // load-bearing — but it must not vanish either, or a dashboard shows a flat line
        // and everyone assumes the estate is quiet.
        let r = registry();
        r.inc("wc_denials_totl", &[("code", "WC-1")], 1);
        r.observe("nope", &[], 1.0);
        assert_eq!(r.unknown_emits(), 2);
        assert!(r.to_prometheus().contains("wc_obs_unknown_family_total 2"));
    }

    #[test]
    fn a_label_value_with_a_quote_cannot_break_the_exposition() {
        // Tool names are attacker-influenced (§7.8 A4). An unescaped quote produces an
        // exposition a scraper rejects, and then *every* metric goes dark rather than one
        // series — a denial of service on the monitoring, delivered through a tool name.
        let r = Registry::new();
        r.register("m", Kind::Counter, "h");
        r.inc("m", &[("tool", "get\"balance\nrogue_metric 1")], 1);
        let text = r.to_prometheus();
        assert!(text.contains("\\\""), "{text}");
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("rogue_metric"))
                .count(),
            0,
            "a label must not be able to inject a line: {text}"
        );
    }

    #[test]
    fn the_json_rendering_carries_the_same_series() {
        let r = registry();
        r.inc("wc_denials_total", &[("code", "WC-3102")], 4);
        let json = r.to_json();
        let series = &json["wc_denials_total"]["series"];
        assert_eq!(series[0]["labels"]["code"], "WC-3102");
        assert_eq!(series[0]["value"], 4);
        assert_eq!(json["wc_denials_total"]["type"], "counter");
    }

    #[test]
    fn a_gauge_can_go_down() {
        let r = registry();
        r.set("wc_entities", &[("posture", "attested")], 10);
        r.set("wc_entities", &[("posture", "attested")], 4);
        assert_eq!(r.value("wc_entities", &[("posture", "attested")]), Some(4));
    }

    #[test]
    fn an_unlabelled_series_renders_without_empty_braces() {
        // `wc_chain_length{} 3` is accepted by Prometheus but is noise in a file an
        // operator reads with their eyes.
        let r = Registry::new();
        r.register("wc_chain_length", Kind::Gauge, "Chain rows.");
        r.set("wc_chain_length", &[], 3);
        assert!(r.to_prometheus().contains("\nwc_chain_length 3\n"));
    }

    // --- decision logs -----------------------------------------------------

    #[test]
    fn a_decision_line_carries_cid_code_and_mode() {
        // The three fields P1 #11 names, and the reason it names them: `cid` correlates
        // across the family, the code groups on a dashboard, and the mode is what stops an
        // observe deployment reading as an estate under attack.
        let line = Decision {
            cid: "conn_7f3a",
            decision: "deny",
            code: "WC-3102",
            mode: "enforce",
            tool: "transfer_funds",
            caller: "spiffe://org/ns/a/sa/x",
            callee: "spiffe://org/ns/t/sa/y",
            jti: "art_1",
            at: 1_785_312_500,
            micros: 412,
        }
        .to_line();

        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["cid"], "conn_7f3a");
        assert_eq!(parsed["code"], "WC-3102");
        assert_eq!(parsed["mode"], "enforce");
        assert_eq!(parsed["ev"], "connect.decision");
        assert_eq!(parsed["latency_us"], 412);
    }

    #[test]
    fn a_tool_name_cannot_forge_a_second_log_line() {
        // §7.8 A4: the callee's declared surface is untrusted. A newline in a tool name
        // would let one decision write two lines, and the second could claim an allow.
        let line = Decision {
            cid: "",
            decision: "deny",
            code: "WC-4001",
            mode: "enforce",
            tool: "x\"}\n{\"ev\":\"connect.decision\",\"decision\":\"allow",
            caller: "a",
            callee: "b",
            jti: "",
            at: 1,
            micros: 0,
        }
        .to_line();
        assert_eq!(line.lines().count(), 1, "{line}");
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["decision"], "deny");
    }

    #[test]
    fn the_default_level_logs_denials_and_findings_but_not_allows() {
        // A line per allow in front of a busy agent turns the decision log into a cost
        // centre nobody keeps on — and then the denials are lost too, because the whole
        // thing was switched off.
        let d = LogLevel::default();
        assert_eq!(d, LogLevel::Notable);
        assert!(d.logs("deny"));
        assert!(
            d.logs("record"),
            "an observe-mode finding is the evidence for turning enforcement on"
        );
        assert!(!d.logs("allow"));

        assert!(LogLevel::All.logs("allow"));
        assert!(!LogLevel::Off.logs("deny"));
    }

    #[test]
    fn log_levels_parse_the_words_an_operator_would_type() {
        assert_eq!(LogLevel::parse("all"), Some(LogLevel::All));
        assert_eq!(LogLevel::parse("off"), Some(LogLevel::Off));
        assert_eq!(LogLevel::parse("deny"), Some(LogLevel::Notable));
        assert_eq!(LogLevel::parse("verbose"), None);
    }
}
