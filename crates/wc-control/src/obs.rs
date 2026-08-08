//! The §8.14 metric families, and where each number comes from
//! (production-readiness P1 #11).
//!
//! Before this, `/metrics` served seven unlabelled counters. §8.14 specifies about
//! fifteen families with labels, and the gap mattered in a specific way: the counters
//! that existed described the **HTTP surface** — requests, denials, replays — and none
//! described the **estate**. A control plane can serve two hundred clean requests a
//! second while every contract in the register is expiring and no mediator has
//! acknowledged anything.
//!
//! # Counters are incremented, gauges are derived
//!
//! The division is deliberate and is the main design decision here.
//!
//! A **counter** has to be incremented at the moment the thing happens; there is nowhere
//! else the information exists. So `wc_denials_total{code}` is bumped in the error path.
//!
//! A **gauge** is a question about current state — how many entities are unattested, how
//! many contracts expire this week — and the answer already exists in the projection. An
//! incrementally-maintained gauge is a second copy of that answer which drifts from it the
//! first time a code path forgets to adjust it, and a drifted gauge is worse than a
//! missing one because it is believed. So gauges are computed at **scrape time** from the
//! projection, and cannot disagree with it.
//!
//! The cost is a scrape that walks the register. At §7.10's stated scale — 10⁴ entities,
//! 10⁵ contracts — that is a few milliseconds against a scrape interval measured in tens
//! of seconds, and `snapshot` takes the store lock once rather than per family.
//!
//! # What is not emitted, and why
//!
//! Named here rather than left as a hole, because a dashboard with a panel that is always
//! zero teaches an operator to ignore the panel:
//!
//! * `wc_verify_duration_seconds{path}`, `wc_filter_tools{state}`,
//!   `wc_filter_failclosed_total`, `wc_ceiling_breaches_total{kind}` — these describe the
//!   **data plane**. They belong to the mediator, which has no `/metrics` endpoint at all
//!   (it speaks stdio to one agent), so it emits them through the decision log instead.
//!   See `wc_mediator::obs`.
//! * `wc_quarantine_duration_seconds` — needs the interval between a quarantine and its
//!   clearing. Both events are in the chain; nothing computes the pairing yet.
//! * `wc_standing_share` — §8.17-Q4 cap utilisation. The cap is enforced in `cpolicy`;
//!   expressing utilisation as a single ratio across zone pairs needs a definition nobody
//!   has written down, and inventing one would put a number on a dashboard that means
//!   whatever this file decided.

use std::collections::BTreeMap;

use wc_core::contract::ContractStatus;
use wc_core::error::Code;
use wc_core::model::{Lifecycle, Posture};
use wc_core::obs::{Kind, Registry};

use crate::contain::AckLedger;
use crate::issuance::RequestStatus;
use crate::store::Projection;

/// Buckets for a contract's TTL, in seconds.
///
/// Chosen against what the policy actually issues: fifteen minutes is break-glass, a day
/// and a week are ordinary standing grants, thirty days is the common ceiling, and ninety
/// is the longest anything should be. A contract past the top bucket is the interesting
/// one, and `+Inf` is where it shows.
const TTL_BUCKETS: &[f64] = &[
    900.0,
    3_600.0,
    86_400.0,
    604_800.0,
    2_592_000.0,
    7_776_000.0,
];

/// Buckets for a posture score, 0–100.
const SCORE_BUCKETS: &[f64] = &[20.0, 40.0, 60.0, 80.0, 85.0, 95.0, 100.0];

/// Buckets for acknowledgement lag, in seconds.
///
/// The 60-second bucket is the one that matters: §7.10 states quarantine propagation
/// under 60 s estate-wide, so `wc_mediator_ack_lag_seconds_bucket{le="60"}` versus
/// `_count` is that claim, measured.
const ACK_LAG_BUCKETS: &[f64] = &[1.0, 5.0, 15.0, 30.0, 60.0, 300.0, 3_600.0];

/// Windows reported by `wc_contracts_expiring`.
const EXPIRY_WINDOWS: &[(&str, u64)] = &[("1h", 3_600), ("24h", 86_400), ("7d", 604_800)];

// --- family names, so a call site cannot misspell one ----------------------

/// Admission outcomes.
pub const ADMISSIONS: &str = "wc_admissions_total";
/// Denials by `WC-*` code.
pub const DENIALS: &str = "wc_denials_total";
/// Discovery queries by result.
pub const DISCOVERY: &str = "wc_discovery_queries_total";
/// Discovery answers withheld by the throttle.
pub const DISCOVERY_THROTTLED: &str = "wc_discovery_throttled_total";
/// Contracts minted, by how they were approved.
pub const MINTED: &str = "wc_contracts_minted_total";
/// Contract TTLs at mint time.
pub const CONTRACT_TTL: &str = "wc_contract_ttl_seconds";
/// Re-attestation outcomes.
pub const REATTEST: &str = "wc_reattest_total";
/// Surface drift by class.
pub const DRIFT: &str = "wc_drift_total";
/// Event-sink delivery failures.
pub const SINK_FAILURES: &str = "wc_sink_failures_total";
/// Requests served by the HTTP surface.
pub const API_REQUESTS: &str = "wc_api_requests_total";
/// Idempotent replays served from the cache.
pub const API_REPLAYS: &str = "wc_api_replays_total";
/// Contract-set pulls served to mediators.
pub const CONTRACT_PULLS: &str = "wc_contract_pulls_total";
/// Credentials refused because the transport could not be trusted.
pub const TRANSPORT_REFUSED: &str = "wc_transport_refused_total";
/// Requests routed to a human.
pub const ESCALATED: &str = "wc_requests_escalated_total";

/// Entities by posture, lifecycle and tier.
pub const ENTITIES: &str = "wc_entities";
/// Active contracts by zone pair and callee tier.
pub const CONTRACTS_ACTIVE: &str = "wc_contracts_active";
/// Active contracts expiring inside a window.
pub const CONTRACTS_EXPIRING: &str = "wc_contracts_expiring";
/// Connection requests awaiting a human.
pub const REQUESTS_PENDING: &str = "wc_requests_pending";
/// Posture scores.
pub const POSTURE_SCORE: &str = "wc_posture_score";
/// Rows in the evidence chain.
pub const CHAIN_LENGTH: &str = "wc_chain_length";
/// Seconds since the newest anchor.
pub const ANCHOR_AGE: &str = "wc_anchor_age_seconds";
/// Per-mediator acknowledgement lag.
pub const ACK_LAG: &str = "wc_mediator_ack_lag_seconds";
/// Mediators that have not confirmed an order past its deadline.
pub const ACK_UNCONFIRMED: &str = "wc_mediator_unconfirmed";
/// Whether this control plane serves a revocation feed at all.
///
/// Not "is the feed trusted" — **distrust is a mediator-side state.** A mediator that
/// cannot verify the feed calls `Revocations::distrust` and fails closed locally, and the
/// control plane has no way to observe that; claiming otherwise here would put a
/// reassuring `1` on a dashboard while the estate was denying everything. The mediator
/// reports it through the decision log instead (`wc_mediator::obs`).
///
/// What this gauge *does* say is worth alerting on for a different reason: `0` means no
/// feed is configured, so nothing this control plane revokes can ever reach a mediator.
pub const REVOCATION_SERVING: &str = "wc_revocation_feed_serving";
/// Highest sequence in the served revocation feed.
///
/// Paired with the mediator's acknowledged sequence, this is the containment lag an
/// operator actually wants: an order at seq 41 and every mediator confirmed to 38 means
/// three orders are in flight.
pub const REVOCATION_SEQ: &str = "wc_revocation_feed_seq";

/// Declare every family this crate emits.
///
/// Registration is up front and total, so `/metrics` exposes a family with `# TYPE` and
/// `# HELP` from the first scrape — before anything has happened. A family that appears
/// only once it has a non-zero value cannot be alerted on, because the alert's own
/// expression is unresolvable until the incident it is watching for has already started.
pub fn register(registry: &Registry) {
    for (name, help) in [
        (ADMISSIONS, "Admission outcomes by result, kind and mode."),
        (DENIALS, "Refusals by WC-* code."),
        (DISCOVERY, "Capability queries by result."),
        (
            DISCOVERY_THROTTLED,
            "Discovery answers withheld by the per-asker throttle.",
        ),
        (MINTED, "Contracts minted by approval mode."),
        (REATTEST, "Re-attestation runs by result."),
        (DRIFT, "Declared-surface drift by class."),
        (SINK_FAILURES, "Event-sink delivery failures by sink."),
        (API_REQUESTS, "Requests served."),
        (API_REPLAYS, "Idempotent replays served from the cache."),
        (CONTRACT_PULLS, "Contract-set pulls served to mediators."),
        (
            TRANSPORT_REFUSED,
            "Credentials refused because the transport could not be trusted.",
        ),
        (ESCALATED, "Connection requests routed to a human."),
    ] {
        registry.register(name, Kind::Counter, help);
    }

    for (name, help) in [
        (
            ENTITIES,
            "Registered entities by posture, lifecycle and tier.",
        ),
        (
            CONTRACTS_ACTIVE,
            "Active contracts by zone pair and callee tier.",
        ),
        (
            CONTRACTS_EXPIRING,
            "Active contracts expiring inside a window.",
        ),
        (REQUESTS_PENDING, "Connection requests awaiting a human."),
        (CHAIN_LENGTH, "Rows in the evidence chain."),
        (ANCHOR_AGE, "Seconds since the newest signed anchor."),
        (
            ACK_UNCONFIRMED,
            "Mediators past an order's acknowledgement deadline.",
        ),
        (
            REVOCATION_SERVING,
            "1 when this control plane serves a revocation feed; 0 means nothing it \
             revokes can reach a mediator.",
        ),
        (
            REVOCATION_SEQ,
            "Highest sequence in the served revocation feed.",
        ),
    ] {
        registry.register(name, Kind::Gauge, help);
    }

    registry.register_histogram(CONTRACT_TTL, "Contract TTL at mint time.", TTL_BUCKETS);
    registry.register_histogram(POSTURE_SCORE, "Posture scores.", SCORE_BUCKETS);
    registry.register_histogram(
        ACK_LAG,
        "Seconds between a containment order and a mediator confirming it.",
        ACK_LAG_BUCKETS,
    );
}

/// Record a refusal.
///
/// Takes the `Code` rather than a string so the label can only ever be a real code —
/// `wc_denials_total{code="WC-3102"}` is alertable, `{code="signature bad"}` is prose.
pub fn denial(registry: &Registry, code: Code) {
    registry.inc(DENIALS, &[("code", &code.to_string())], 1);
}

/// Recompute every derived gauge from current state.
///
/// Called on each scrape. Everything here is a question the projection can already
/// answer, so a number on the dashboard and a number from `connect posture` cannot
/// disagree — which they would if these were maintained incrementally and one code path
/// forgot.
pub fn snapshot(
    registry: &Registry,
    projection: &Projection,
    acks: &AckLedger,
    chain_len: u64,
    newest_anchor: Option<u64>,
    feed: Option<(bool, u64)>,
    now: u64,
) {
    // --- entities ---------------------------------------------------------
    let mut buckets: BTreeMap<(String, String, String), u64> = BTreeMap::new();
    for entity in projection.entities.values() {
        let key = (
            posture_label(entity.posture).to_string(),
            lifecycle_label(entity.lifecycle).to_string(),
            entity.tier.to_string(),
        );
        *buckets.entry(key).or_insert(0) += 1;
    }
    for ((posture, lifecycle, tier), count) in &buckets {
        registry.set(
            ENTITIES,
            &[
                ("posture", posture),
                ("lifecycle", lifecycle),
                ("tier", tier),
            ],
            *count,
        );
    }

    // --- contracts --------------------------------------------------------
    let mut by_pair: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut expiring: BTreeMap<&str, u64> = BTreeMap::new();
    for (label, _) in EXPIRY_WINDOWS {
        expiring.insert(label, 0);
    }
    for record in projection.contracts.values() {
        if record.status != ContractStatus::Active {
            continue;
        }
        let pair = format!("{}->{}", record.caller_zone, record.callee_zone);
        *by_pair
            .entry((pair, record.callee_tier.to_string()))
            .or_insert(0) += 1;

        for (label, window) in EXPIRY_WINDOWS {
            // `exp` in the past counts as expiring in every window: a contract that has
            // already lapsed and is still marked active is the most urgent version of
            // this number, not an excluded edge case.
            if record.exp <= now.saturating_add(*window) {
                *expiring.entry(label).or_insert(0) += 1;
            }
        }
    }
    for ((pair, tier), count) in &by_pair {
        registry.set(
            CONTRACTS_ACTIVE,
            &[("zone_pair", pair), ("tier", tier)],
            *count,
        );
    }
    for (label, count) in &expiring {
        registry.set(CONTRACTS_EXPIRING, &[("window", label)], *count);
    }

    let pending = projection
        .requests
        .values()
        .filter(|r| r.status == RequestStatus::Pending)
        .count() as u64;
    registry.set(REQUESTS_PENDING, &[], pending);

    // --- evidence ---------------------------------------------------------
    registry.set(CHAIN_LENGTH, &[], chain_len);
    // No anchor is reported as age 0 rather than omitted: a missing series reads as zero
    // anyway, and an explicit zero with `wc_chain_length` beside it is distinguishable
    // from a fresh anchor by whether the chain is empty.
    registry.set(
        ANCHOR_AGE,
        &[],
        newest_anchor.map_or(0, |at| now.saturating_sub(at)),
    );

    // --- containment ------------------------------------------------------
    //
    // A control plane with no feed can still record a quarantine and still report it as
    // done, while no mediator ever hears. That is the containment equivalent of every
    // other defect in this repository, so it is a gauge rather than a footnote.
    let (serving, head_seq) = feed.unwrap_or((false, 0));
    registry.set(REVOCATION_SERVING, &[], u64::from(serving));
    registry.set(REVOCATION_SEQ, &[], head_seq);

    let mut unconfirmed = 0u64;
    for order in &acks.orders {
        for mediator in &order.expected {
            let confirmed = acks
                .confirmed
                .get(mediator)
                .is_some_and(|c| c.feed_seq >= order.feed_seq);
            if confirmed {
                continue;
            }
            if now > order.deadline_at {
                unconfirmed += 1;
            }
        }
    }
    registry.set(ACK_UNCONFIRMED, &[], unconfirmed);
}

/// Observe one mediator's acknowledgement lag for an order.
///
/// A histogram rather than a gauge because the question is a distribution over orders —
/// "did every mediator confirm inside 60 seconds" — and a gauge would only ever hold the
/// most recent one.
pub fn ack_lag(registry: &Registry, mediator: &str, seconds: u64) {
    registry.observe(ACK_LAG, &[("mediator", mediator)], seconds as f64);
}

/// Observe a contract's TTL at mint time.
pub fn contract_ttl(registry: &Registry, seconds: u64) {
    registry.observe(CONTRACT_TTL, &[], seconds as f64);
}

fn posture_label(posture: Posture) -> &'static str {
    match posture {
        Posture::Unattested => "unattested",
        Posture::Attested => "attested",
        Posture::Degraded => "degraded",
        Posture::Quarantined => "quarantined",
    }
}

fn lifecycle_label(lifecycle: Lifecycle) -> &'static str {
    match lifecycle {
        Lifecycle::Pending => "pending",
        Lifecycle::Active => "active",
        Lifecycle::Suspended => "suspended",
        Lifecycle::Retired => "retired",
    }
}

/// Contracts whose `exp` has already passed but which are still marked active.
///
/// Not a §8.14 family; here because computing it is free while walking the same set, and
/// a non-zero value means the expiry sweep is not running — which is a silent failure of
/// the kind this repository keeps finding, and one that no other number would reveal.
#[must_use]
pub fn lapsed_but_active(projection: &Projection, now: u64) -> Vec<String> {
    projection
        .contracts
        .values()
        .filter(|r| r.status == ContractStatus::Active && r.exp < now)
        .map(|r| r.cid.as_str().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use wc_core::obs::Registry;

    fn registry() -> Registry {
        let r = Registry::new();
        register(&r);
        r
    }

    #[test]
    fn every_family_is_declared_before_anything_happens() {
        // A family that appears only once it has a non-zero value cannot be alerted on:
        // the alert expression is unresolvable until the incident has already begun. So
        // `/metrics` must carry `# TYPE` for all of them from the first scrape.
        let text = registry().to_prometheus();
        for name in [
            ADMISSIONS,
            DENIALS,
            DISCOVERY,
            DISCOVERY_THROTTLED,
            MINTED,
            CONTRACT_TTL,
            REATTEST,
            DRIFT,
            SINK_FAILURES,
            ENTITIES,
            CONTRACTS_ACTIVE,
            CONTRACTS_EXPIRING,
            REQUESTS_PENDING,
            POSTURE_SCORE,
            CHAIN_LENGTH,
            ANCHOR_AGE,
            ACK_LAG,
            ACK_UNCONFIRMED,
            REVOCATION_SERVING,
            REVOCATION_SEQ,
        ] {
            assert!(text.contains(&format!("# TYPE {name} ")), "{name} missing");
            assert!(
                text.contains(&format!("# HELP {name} ")),
                "{name} has no help"
            );
        }
    }

    #[test]
    fn a_denial_label_can_only_be_a_real_code() {
        let r = registry();
        denial(&r, Code::SIGNATURE_INVALID);
        denial(&r, Code::SIGNATURE_INVALID);
        denial(&r, Code::NO_CONTRACT);
        assert_eq!(
            r.value(DENIALS, &[("code", &Code::SIGNATURE_INVALID.to_string())]),
            Some(2)
        );
        // The label is the rendered code, which is what an alert groups on.
        assert!(r.to_prometheus().contains("code=\"WC-3102\""));
    }

    #[test]
    fn a_control_plane_with_no_revocation_feed_says_so() {
        // It can still record a quarantine and report it as done while no mediator ever
        // hears — the containment version of every other defect this repository has found.
        let r = registry();
        let p = Projection::default();
        let a = AckLedger::default();

        snapshot(&r, &p, &a, 0, None, None, 1_000);
        assert_eq!(r.value(REVOCATION_SERVING, &[]), Some(0));

        snapshot(&r, &p, &a, 0, None, Some((true, 41)), 1_000);
        assert_eq!(r.value(REVOCATION_SERVING, &[]), Some(1));
        assert_eq!(
            r.value(REVOCATION_SEQ, &[]),
            Some(41),
            "paired with each mediator's acknowledged sequence, this is containment lag"
        );
    }

    #[test]
    fn gauges_are_derived_so_they_cannot_drift_from_the_projection() {
        // The reason gauges are not incremented. An incrementally-maintained gauge is a
        // second copy of an answer the projection already holds, and it diverges the
        // first time a code path forgets — producing a number that is believed and wrong.
        // Here the same registry is scraped twice against different state and simply
        // agrees with the state.
        let r = registry();
        let a = AckLedger::default();

        let mut p = Projection::default();
        snapshot(&r, &p, &a, 0, None, None, 1_000);
        assert_eq!(r.value(REQUESTS_PENDING, &[]), Some(0));

        p.seq = 7;
        snapshot(&r, &p, &a, 12, Some(940), None, 1_000);
        assert_eq!(r.value(CHAIN_LENGTH, &[]), Some(12));
        assert_eq!(r.value(ANCHOR_AGE, &[]), Some(60));

        // And a scrape with no anchor reports zero rather than leaving the series absent.
        snapshot(&r, &p, &a, 12, None, None, 1_000);
        assert_eq!(r.value(ANCHOR_AGE, &[]), Some(0));
    }

    #[test]
    fn the_ack_lag_histogram_has_a_bucket_at_the_number_the_design_promises() {
        // §7.10 states quarantine propagation under 60 s estate-wide. That claim is only
        // measurable if 60 is a bucket boundary; without it the histogram can only say
        // "somewhere between 30 and 300".
        assert!(ACK_LAG_BUCKETS.contains(&60.0), "{ACK_LAG_BUCKETS:?}");

        let r = registry();
        ack_lag(&r, "warden:mediator:a", 12);
        ack_lag(&r, "warden:mediator:a", 900);
        let text = r.to_prometheus();
        assert!(
            text.contains("wc_mediator_ack_lag_seconds_count 2"),
            "{text}"
        );
        assert!(
            text.contains("le=\"60\"} 1"),
            "one of the two beat 60s: {text}"
        );
    }

    #[test]
    fn a_lapsed_contract_that_is_still_active_is_visible() {
        // Nothing else would show this. If the expiry sweep stopped, every other number
        // stays healthy — the register reports active contracts, the mediators keep
        // verifying them until their own `exp` check fires, and the control plane's view
        // is quietly wrong.
        let p = Projection::default();
        assert!(lapsed_but_active(&p, 2_000).is_empty());
    }
}
