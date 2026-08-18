//! Failure injection (`docs/08-lld.md` §8.15.5).
//!
//! The e2e tier proves the use cases work on the day everything works. This tier
//! is the other days, and it is where the design actually lives: a control that
//! is correct while healthy and ambiguous while broken is not a control.
//!
//! Every scenario here asserts the same shape of thing twice — that the operation
//! was refused, *and* that nothing partial survived it. "It returned an error" is
//! half the claim; "and no contract exists, and the chain has no gap" is the other
//! half, and it is the half that fails in practice.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod harness;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::json;

use wc_mediator::upstream::Upstream;

use harness::*;
use wc_control::evidence::{Evidence, LifecycleEvent};
use wc_control::sink::{Delivery, EventSink};
use wc_control::store::{Projection, Store, STATE_LOG_NAME};
use wc_core::canon::SurfaceKind;
use wc_core::contract::{self, AnyZone, PeerIdentity, VerifyOpts};
use wc_core::error::{Code, Mode};
use wc_core::model::Kind;
use wc_mediator::cache::{Cache, Revocations, Snapshot};
use wc_mediator::ceiling::Ceilings;
use wc_mediator::gate::{GateCfg, MediatedUpstream};

const AGENT: &str = "spiffe://org/ns/agents/sa/recon";
const SERVER: &str = "spiffe://org/ns/tools/sa/payments";

/// An estate with one agent, one server and one live contract.
fn wired(label: &str) -> (Estate, wc_control::issuance::Issued) {
    let mut e = Estate::new(label);
    let agent = e.register(
        AGENT,
        Kind::Agent,
        "internal.apac-ops",
        &agent_card(),
        SurfaceKind::A2aCard,
        Some("payments-recon"),
    );
    let server = e.register(
        SERVER,
        Kind::McpServer,
        "internal.payments",
        &surface_of(6),
        SurfaceKind::McpTools,
        Some("payments-core"),
    );
    e.activate(&agent.id);
    e.activate(&server.id);
    let issued = e.connect(&agent.id, &server.id, &["get_balance"], 30 * DAY);
    (e, issued)
}

/// A mediator over the given artifacts.
fn mediator(
    artifacts: &[String],
    surface: &serde_json::Value,
    now: u64,
) -> (MediatedUpstream, Recorder, Arc<Cache>) {
    let keys = verifier();
    let (stub, recorder) = StubServer::new(surface);
    let cache = Arc::new(Cache::new());
    cache.install(Snapshot::build(artifacts, &trusting(&keys), now));

    let mut cfg = GateCfg::new(
        MEDIATOR,
        PeerIdentity {
            caller: wc_core::model::EntityId::new(AGENT).unwrap(),
            callee: wc_core::model::EntityId::new(SERVER).unwrap(),
        },
        || NOW,
    );
    cfg.mode = Mode::Enforce;
    cfg.zones = Box::new(AnyZone);
    let mediated = MediatedUpstream::new(Box::new(stub), Arc::clone(&cache), cfg)
        .with_ceilings(Ceilings::new());
    (mediated, recorder, cache)
}

// ===========================================================================
// 1 · The control plane is killed mid-mint
// ===========================================================================

#[test]
fn a_kill_at_any_point_in_a_mint_leaves_no_half_contract() {
    let (e, issued) = wired("fi-killed");
    let log = e.state_log();
    let full = std::fs::read_to_string(&log).expect("state log");
    let lines: Vec<&str> = full.lines().collect();
    assert!(
        lines.len() > 4,
        "the scenario needs several records to cut between"
    );

    // A kill lands between two appends, or part-way through one. Both are exercised
    // by cutting the log at every prefix and rebuilding, which is exactly what the
    // next process start would do.
    for cut in 0..lines.len() {
        let prefix = format!("{}\n", lines[..cut].join("\n"));
        std::fs::write(&log, if cut == 0 { String::new() } else { prefix }).unwrap();

        let (projection, report) = Projection::rebuild(e.root.state(), STATE_LOG_NAME)
            .expect("a truncated log must still rebuild");

        // The invariant: a contract in the projection is complete. There is no
        // state in which authority exists but the record of it is half-written.
        for (cid, record) in &projection.contracts {
            assert!(!record.surface.items().is_empty(), "{cid} has no surface");
            assert!(record.exp > record.iat, "{cid} has no validity window");
            assert!(
                projection.entities.contains_key(&record.caller)
                    || report.inconsistent.iter().any(|s| s.contains(cid.as_str())),
                "{cid} names a caller this projection does not have, unreported"
            );
        }
        assert!(
            !report.truncated_tail,
            "a clean line cut is not a torn write"
        );
    }

    // Now a torn write: the last line cut mid-JSON, which is what a kill during
    // `write` actually leaves behind.
    let torn = format!(
        "{}\n{}",
        lines[..lines.len() - 1].join("\n"),
        &lines[lines.len() - 1][..lines[lines.len() - 1].len() / 2]
    );
    std::fs::write(&log, torn).unwrap();
    let (projection, report) =
        Projection::rebuild(e.root.state(), STATE_LOG_NAME).expect("a torn log must still rebuild");
    assert!(
        report.truncated_tail,
        "a torn tail must be reported, not silently dropped — that is the difference \
         between a crash we understand and one we do not"
    );
    // The torn line is the last one. Everything before it was appended and fsynced,
    // so it is *supposed* to survive — the guarantee is not "lose the tail" but
    // "never present half a record as whole".
    for (cid, record) in &projection.contracts {
        assert!(!record.surface.items().is_empty(), "{cid} has no surface");
        assert!(record.exp > record.iat, "{cid} has no validity window");
    }
    if let Some(record) = projection.contracts.get(&issued.record.cid) {
        assert_eq!(
            record.surface, issued.record.surface,
            "a surviving record must be byte-for-byte what was written, not a partial read"
        );
    }
}

#[test]
fn the_artifact_is_written_after_the_record_so_a_kill_between_them_is_visible() {
    // The ordering is deliberate: evidence, then the record, then the artifact. A
    // kill in the last gap leaves a contract the register knows about and no signed
    // document — and that state is *reportable* rather than silent, because a
    // mediator asking for the set gets the cid listed with no `jws`.
    let (e, issued) = wired("fi-artifact");
    let cid = issued.record.cid.as_str();
    let path = e
        .store
        .artifacts_dir()
        .join(wc_control::store::artifact_name(cid, MEDIATOR));
    assert!(path.exists());

    std::fs::remove_file(&path).unwrap();
    assert!(
        e.store.read_artifact(cid, MEDIATOR).is_none(),
        "a missing artifact must read as missing, not as an empty document"
    );
    assert!(
        e.store
            .projection
            .contracts
            .contains_key(&issued.record.cid),
        "the record survives, so the gap is discoverable rather than forgotten"
    );

    // And a mediator handed nothing cannot be tricked into admitting anything.
    let (mut m, recorder, _) = mediator(&[], &surface_of(6), e.now);
    m.request(&req(1, "initialize", json!({})));
    assert!(refusal(&m.request(&req(2, "tools/call", json!({"name": "get_balance"})))).is_some());
    assert!(recorder.executed().is_empty());
}

// ===========================================================================
// 2 · The control plane is down for an hour
// ===========================================================================

#[test]
fn existing_connections_survive_a_control_plane_outage_and_no_new_ones_appear() {
    let (e, issued) = wired("fi-cp-down");
    let artifact = e.artifact(issued.record.cid.as_str());
    let contracts_before = e.store.projection.contracts.len();

    // The mediator holds its snapshot. There is no control plane in this test at
    // all — that is the point.
    let keys = verifier();
    let (stub, recorder) = StubServer::new(&surface_of(6));
    let cache = Arc::new(Cache::new());
    cache.install(Snapshot::build(
        std::slice::from_ref(&artifact),
        &trusting(&keys),
        e.now,
    ));

    for offset in [0, 600, 1_800, 3_600] {
        let clock = e.now + offset;
        let mut cfg = GateCfg::new(
            MEDIATOR,
            PeerIdentity {
                caller: issued.record.caller.clone(),
                callee: issued.record.callee.clone(),
            },
            || NOW,
        );
        cfg.mode = Mode::Enforce;
        cfg.zones = Box::new(AnyZone);
        assert!(
            issued.record.is_live(clock),
            "a 30-day contract must not care about a one-hour outage"
        );
        assert!(contract::verify_artifact(
            &artifact,
            &VerifyOpts::new(&keys, MEDIATOR, clock).issued_by(ISS)
        )
        .is_ok());
    }
    let _ = (stub, recorder, cache);

    // Past `exp` the outage stops mattering, because the contract does.
    let after = issued.record.exp + 1;
    let err = contract::verify_artifact(
        &artifact,
        &VerifyOpts::new(&keys, MEDIATOR, after).issued_by(ISS),
    )
    .unwrap_err();
    assert_eq!(
        err.code(),
        Code::CONTRACT_EXPIRED,
        "a control-plane outage is not a reason to extend authority"
    );

    // And nothing new was minted, because minting needs the control plane.
    assert_eq!(e.store.projection.contracts.len(), contracts_before);
}

// ===========================================================================
// 3 · The revocation feed is truncated or corrupted
// ===========================================================================

#[test]
fn an_unverifiable_revocation_feed_denies_everything() {
    let (e, issued) = wired("fi-feed");
    let artifact = e.artifact(issued.record.cid.as_str());
    let (mut m, recorder, cache) = mediator(&[artifact], &surface_of(6), e.now);

    // Healthy first, or the refusal below proves nothing.
    m.request(&req(1, "initialize", json!({})));
    assert!(allowed(&m.request(&req(
        2,
        "tools/call",
        json!({"name": "get_balance"})
    ))));
    assert_eq!(recorder.ran("get_balance"), 1);

    // The feed comes back corrupt. Not "nothing is revoked" — *unknown*, and
    // unknown must read as revoked.
    let mut poisoned = Revocations::new();
    poisoned.distrust("feed is not contiguous after seq 4");
    cache.set_revocations(poisoned);

    let (mut m2, recorder2, _) = {
        let keys = verifier();
        let (stub, rec) = StubServer::new(&surface_of(6));
        let mut cfg = GateCfg::new(
            MEDIATOR,
            PeerIdentity {
                caller: issued.record.caller.clone(),
                callee: issued.record.callee.clone(),
            },
            || NOW,
        );
        cfg.mode = Mode::Enforce;
        cfg.zones = Box::new(AnyZone);
        let _ = keys;
        (
            MediatedUpstream::new(Box::new(stub), Arc::clone(&cache), cfg)
                .with_ceilings(Ceilings::new()),
            rec,
            (),
        )
    };
    let init = m2.request(&req(1, "initialize", json!({})));
    let why = refusal(&init).expect("a distrusted revocation set must admit nothing");
    assert!(why.contains("WC-3105"), "{why}");
    assert!(
        why.contains("cannot be relied on"),
        "the alarm must say what is wrong: {why}"
    );
    assert!(refusal(&m2.request(&req(2, "tools/call", json!({"name": "get_balance"})))).is_some());
    assert_eq!(recorder2.executed().len(), 0, "deny all means all");

    // Observe mode does not soften this. The absence of a contract is the shadow
    // case; an unverifiable revocation state is a containment failure.
    let (stub, rec3) = StubServer::new(&surface_of(6));
    let mut cfg = GateCfg::new(
        MEDIATOR,
        PeerIdentity {
            caller: issued.record.caller.clone(),
            callee: issued.record.callee.clone(),
        },
        || NOW,
    );
    cfg.mode = Mode::Observe;
    cfg.zones = Box::new(AnyZone);
    let mut m3 = MediatedUpstream::new(Box::new(stub), Arc::clone(&cache), cfg)
        .with_ceilings(Ceilings::new());
    m3.request(&req(1, "initialize", json!({})));
    assert!(
        refusal(&m3.request(&req(2, "tools/call", json!({"name": "get_balance"})))).is_some(),
        "observe mode softens an absent contract, never an unverifiable revocation set"
    );
    assert_eq!(rec3.executed().len(), 0);
}

// ===========================================================================
// 4 · A blocking evidence sink is down
// ===========================================================================

/// A sink that refuses, on demand.
#[derive(Debug)]
struct BrokenSink {
    down: Arc<AtomicBool>,
    delivery: Delivery,
}

impl EventSink for BrokenSink {
    fn name(&self) -> &str {
        "e2e-broken-siem"
    }
    fn accepts(&self, _event: &LifecycleEvent) -> bool {
        true
    }
    fn ship(&self, _event: &LifecycleEvent, _now: u64) -> wc_core::error::Result<()> {
        if self.down.load(Ordering::SeqCst) {
            return Err(wc_core::error::WcError::with_detail(
                Code::BLOCKING_SINK_UNAVAILABLE,
                "connection refused",
            ));
        }
        Ok(())
    }
    fn delivery(&self) -> Delivery {
        self.delivery
    }
}

#[test]
fn a_blocking_sink_that_is_down_stops_issuance_and_leaves_nothing_behind() {
    // Up while the estate is built: with the sink down, *registration* is refused
    // too — correctly, and it would mask what this scenario is about.
    let down = Arc::new(AtomicBool::new(false));
    let mut e = Estate::with_event_sinks(
        "fi-sink",
        vec![Arc::new(BrokenSink {
            down: Arc::clone(&down),
            delivery: Delivery::Blocking,
        })],
    );
    assert!(e.evidence.has_blocking_sinks());
    let agent = e.register(
        AGENT,
        Kind::Agent,
        "internal.apac-ops",
        &agent_card(),
        SurfaceKind::A2aCard,
        Some("payments-recon"),
    );
    let server = e.register(
        SERVER,
        Kind::McpServer,
        "internal.payments",
        &surface_of(6),
        SurfaceKind::McpTools,
        Some("payments-core"),
    );
    e.activate(&agent.id);
    e.activate(&server.id);

    down.store(true, Ordering::SeqCst);
    let (head_seq, head_hash) = e.evidence.head();
    let contracts_before = e.store.projection.contracts.len();

    let err = e
        .try_request(&agent.id, &server.id, &["get_balance"], 30 * DAY)
        .expect_err("no durable trail, no authority");
    assert_eq!(err.code(), Code::BLOCKING_SINK_UNAVAILABLE);

    // Nothing committed, nothing signed, nothing on disk. This is the assertion:
    // WC-7001 is only a real control if the mint did not happen anyway.
    assert_eq!(e.store.projection.contracts.len(), contracts_before);
    assert_eq!(
        e.evidence.head(),
        (head_seq, head_hash),
        "the chain did not move"
    );
    assert!(!e.root.chain_has("contract.mint"));

    // The sink comes back and the same request goes through.
    down.store(false, Ordering::SeqCst);
    let issued = e.connect(&agent.id, &server.id, &["get_balance"], 30 * DAY);
    assert!(!e.artifact(issued.record.cid.as_str()).is_empty());
    assert!(e.root.chain_has("contract.mint"));
}

#[test]
fn a_fail_safe_sink_that_is_down_is_a_warning_not_an_outage() {
    // The other half of the same decision. Refusing an issuance because a SIEM
    // hiccuped would be its own kind of outage, so a fail-safe sink warns and the
    // chain — which is authoritative — carries the record regardless.
    let mut e = Estate::with_event_sinks(
        "fi-sink-safe",
        vec![Arc::new(BrokenSink {
            down: Arc::new(AtomicBool::new(true)),
            delivery: Delivery::FailSafe,
        })],
    );
    assert!(!e.evidence.has_blocking_sinks());
    let agent = e.register(
        AGENT,
        Kind::Agent,
        "internal.apac-ops",
        &agent_card(),
        SurfaceKind::A2aCard,
        Some("payments-recon"),
    );
    let server = e.register(
        SERVER,
        Kind::McpServer,
        "internal.payments",
        &surface_of(6),
        SurfaceKind::McpTools,
        Some("payments-core"),
    );
    e.activate(&agent.id);
    e.activate(&server.id);

    let issued = e.connect(&agent.id, &server.id, &["get_balance"], 30 * DAY);
    assert!(
        e.root.chain_has("contract.mint"),
        "the authoritative copy landed"
    );
    assert!(!e.artifact(issued.record.cid.as_str()).is_empty());
}

// ===========================================================================
// 5 · Clock skew of ±10 minutes
// ===========================================================================

#[test]
fn clock_skew_is_bounded_by_leeway_and_fails_closed_past_it() {
    let (e, issued) = wired("fi-skew");
    let artifact = e.artifact(issued.record.cid.as_str());
    let keys = verifier();
    let skew = 600;

    // A mediator whose clock runs 10 minutes fast, at the moment of expiry.
    let mut lenient = VerifyOpts::new(&keys, MEDIATOR, issued.record.exp + skew - 1).issued_by(ISS);
    lenient.leeway = skew;
    assert!(
        contract::verify_artifact(&artifact, &lenient).is_ok(),
        "leeway must absorb the configured skew"
    );

    // One second past it, the same contract is refused. Leeway is a bound on skew,
    // not a grace period — a contract does not get eleven minutes because somebody
    // configured ten.
    let mut past = VerifyOpts::new(&keys, MEDIATOR, issued.record.exp + skew).issued_by(ISS);
    past.leeway = skew;
    assert_eq!(
        contract::verify_artifact(&artifact, &past)
            .unwrap_err()
            .code(),
        Code::CONTRACT_EXPIRED
    );

    // And the same on the other side: a clock 10 minutes slow, before `nbf`.
    let mut early = VerifyOpts::new(&keys, MEDIATOR, issued.record.iat - skew - 1).issued_by(ISS);
    early.leeway = skew;
    assert_eq!(
        contract::verify_artifact(&artifact, &early)
            .unwrap_err()
            .code(),
        Code::CONTRACT_EXPIRED
    );

    // The default is zero, so an operator gets skew tolerance only by asking for it.
    assert_eq!(
        VerifyOpts::new(&keys, MEDIATOR, e.now)
            .issued_by(ISS)
            .leeway,
        0
    );
}

// ===========================================================================
// 6 · Two writers race for the store lock
// ===========================================================================

#[test]
fn a_second_writer_is_refused_rather_than_interleaved() {
    let (mut e, issued) = wired("fi-race");
    let before = std::fs::read_to_string(e.state_log()).unwrap();

    // A second process opens the same directory while the first holds the lock.
    let err = Store::open(e.root.state()).expect_err("two writers must not both proceed");
    assert_eq!(err.code(), Code::STORE_LOCKED);

    // The first writer is unaffected and its log is byte-identical plus its own
    // appends — no interleaving, no partial record from the loser.
    let agent = e.entity(&issued.record.caller);
    let server = e.entity(&issued.record.callee);
    let second = e.connect(&agent.id, &server.id, &["list_transactions"], 7 * DAY);
    let after = std::fs::read_to_string(e.state_log()).unwrap();
    assert!(
        after.starts_with(&before),
        "the loser must not have written into the middle"
    );
    assert!(after.contains(second.record.cid.as_str()));

    let (rebuilt, report) = Projection::rebuild(e.root.state(), STATE_LOG_NAME).unwrap();
    assert!(report.is_clean());
    assert_eq!(rebuilt.contracts.len(), 2);

    // Once the holder is gone the lock is available. A crash must not leave the
    // estate permanently unwritable.
    drop(e);
}

#[test]
fn the_lock_is_released_when_the_writer_goes_away() {
    let root = Root::new("fi-race-release");
    {
        let (_store, report) = Store::open(root.state()).unwrap();
        assert!(report.is_clean());
        assert_eq!(
            Store::open(root.state()).unwrap_err().code(),
            Code::STORE_LOCKED
        );
    }
    Store::open(root.state()).expect("a released lock must be reacquirable");
}

// ===========================================================================
// 7 · A mediator with a stale snapshot
// ===========================================================================

#[test]
fn a_stale_mediator_closes_on_a_revoked_cid_at_the_next_refresh() {
    let (mut e, issued) = wired("fi-stale");
    let artifact = e.artifact(issued.record.cid.as_str());
    let cid = issued.record.cid.as_str().to_string();
    let (mut m, recorder, cache) = mediator(std::slice::from_ref(&artifact), &surface_of(6), e.now);

    m.request(&req(1, "initialize", json!({})));
    assert!(allowed(&m.request(&req(
        2,
        "tools/call",
        json!({"name": "get_balance"})
    ))));

    // The control plane revokes. The mediator has not refreshed, so it is stale —
    // and being honest about that window is the point: the artifact is still
    // cryptographically valid, and only the feed says otherwise.
    let outcome = e
        .store
        .registry(e.actor(), e.now)
        .quarantine(&issued.record.caller, "SOC-STALE", &[])
        .unwrap();
    assert_eq!(outcome.revoked.len(), 1);
    assert!(
        contract::verify_artifact(&artifact, &VerifyOpts::new(&verifier(), MEDIATOR, e.now))
            .is_ok(),
        "revocation is a feed fact, not a signature fact — which is why the feed matters"
    );

    // The refresh arrives.
    let mut revoked = Revocations::new();
    revoked.revoke_cid(cid.clone());
    cache.set_revocations(revoked);

    // A new connection is refused. The already-open one is refused too, on its next
    // call, because `resolve` runs per call rather than once at handshake.
    let (stub, rec2) = StubServer::new(&surface_of(6));
    let mut cfg = GateCfg::new(
        MEDIATOR,
        PeerIdentity {
            caller: issued.record.caller.clone(),
            callee: issued.record.callee.clone(),
        },
        || NOW,
    );
    cfg.mode = Mode::Enforce;
    cfg.zones = Box::new(AnyZone);
    let mut fresh = MediatedUpstream::new(Box::new(stub), Arc::clone(&cache), cfg)
        .with_ceilings(Ceilings::new());
    let why = refusal(&fresh.request(&req(1, "initialize", json!({}))))
        .expect("a revoked cid must not be admitted");
    assert!(why.contains("WC-3105"), "{why}");
    assert!(rec2.executed().is_empty());

    // Revocation is cumulative: a later refresh that does not mention the cid must
    // not resurrect it.
    let mut later = (*cache.revocations()).clone();
    later.revoke_party("spiffe://org/ns/agents/sa/somebody-else");
    cache.set_revocations(later);
    let (stub2, rec3) = StubServer::new(&surface_of(6));
    let mut cfg2 = GateCfg::new(
        MEDIATOR,
        PeerIdentity {
            caller: issued.record.caller.clone(),
            callee: issued.record.callee.clone(),
        },
        || NOW,
    );
    cfg2.mode = Mode::Enforce;
    cfg2.zones = Box::new(AnyZone);
    let mut again = MediatedUpstream::new(Box::new(stub2), Arc::clone(&cache), cfg2)
        .with_ceilings(Ceilings::new());
    assert!(refusal(&again.request(&req(1, "initialize", json!({})))).is_some());
    assert!(rec3.executed().is_empty());
    let _ = recorder;
}

// ===========================================================================
// 8 · The disk fills during an append
// ===========================================================================

#[test]
fn a_failed_chain_append_stops_the_operation_and_leaves_no_gap() {
    let (e, _issued) = wired("fi-disk");
    let chain = e.root.evidence().join("chain.jsonl");
    let good = std::fs::read_to_string(&chain).unwrap();
    let (head_seq, head_hash) = e.evidence.head();
    let rows: Vec<&str> = good.lines().collect();
    assert!(rows.len() >= 4, "the scenario needs a middle to cut out of");

    // ENOSPC is not reproducible in-process — the chain holds an open descriptor, so
    // permissions and quotas do not reach it. What *is* reproducible, and is the
    // property the scenario is named for, is the other half: whatever a failed append
    // leaves on disk, the chain must never verify as though nothing were missing.
    // Every shape a torn or lost write can take is exercised here.

    // A row lost from the middle.
    std::fs::write(&chain, format!("{}\n{}\n", rows[0], rows[2..].join("\n"))).unwrap();
    let hole = Evidence::verify(e.root.evidence(), None).unwrap();
    assert!(
        hole.broken_at.is_some(),
        "a missing row must break the chain, not shorten it quietly"
    );

    // A row altered in place — the same length, a different fact.
    let mut tampered: serde_json::Value = serde_json::from_str(rows[1]).unwrap();
    tampered["reason"] = json!("something else entirely");
    std::fs::write(
        &chain,
        format!(
            "{}\n{}\n{}\n",
            rows[0],
            serde_json::to_string(&tampered).unwrap(),
            rows[2..].join("\n")
        ),
    )
    .unwrap();
    let edited = Evidence::verify(e.root.evidence(), None).unwrap();
    assert_eq!(
        edited.broken_at,
        Some(2),
        "the break must be located, not merely announced — an auditor needs the row"
    );

    // A torn final row, which is what a kill during `write` actually leaves.
    let last = rows[rows.len() - 1];
    std::fs::write(
        &chain,
        format!(
            "{}\n{}",
            rows[..rows.len() - 1].join("\n"),
            &last[..last.len() / 2]
        ),
    )
    .unwrap();
    assert!(
        Evidence::verify(e.root.evidence(), None).is_err_and(|err| {
            err.code() == Code::CHAIN_BROKEN || err.code() == Code::CHAIN_APPEND_FAILED
        }) || Evidence::verify(e.root.evidence(), None).is_ok_and(|r| r.broken_at.is_some()),
        "a torn tail must be an error or a located break, never a clean verify"
    );

    // Restored, the chain verifies again from the same head — so the detection above
    // was about the damage, not about the chain being fragile.
    std::fs::write(&chain, &good).unwrap();
    let restored = Evidence::verify(e.root.evidence(), None).unwrap();
    assert_eq!(restored.broken_at, None);
    assert_eq!(
        (restored.head_seq, restored.head_hash),
        (head_seq, head_hash)
    );
}

#[test]
fn no_authority_is_issued_when_the_trail_cannot_be_written() {
    // The ordering that makes the above matter: evidence is recorded *before* the
    // record is committed, so a failed append cannot leave a contract behind. The
    // injectable version of "the disk is unusable" is a blocking sink that refuses —
    // it fails at the same point in `Evidence::record`, before `chain.append`.
    let down = Arc::new(AtomicBool::new(false));
    let mut e = Estate::with_event_sinks(
        "fi-no-trail",
        vec![Arc::new(BrokenSink {
            down: Arc::clone(&down),
            delivery: Delivery::Blocking,
        })],
    );
    let agent = e.register(
        AGENT,
        Kind::Agent,
        "internal.apac-ops",
        &agent_card(),
        SurfaceKind::A2aCard,
        Some("payments-recon"),
    );
    let server = e.register(
        SERVER,
        Kind::McpServer,
        "internal.payments",
        &surface_of(6),
        SurfaceKind::McpTools,
        Some("payments-core"),
    );
    e.activate(&agent.id);
    e.activate(&server.id);

    down.store(true, Ordering::SeqCst);
    let (head_seq, _) = e.evidence.head();
    e.try_request(&agent.id, &server.id, &["get_balance"], 30 * DAY)
        .expect_err("no durable trail, no authority");

    assert_eq!(e.evidence.head().0, head_seq, "the chain did not move");
    assert!(e.store.projection.contracts.is_empty());
    let verified = Evidence::verify(e.root.evidence(), None).unwrap();
    assert_eq!(verified.broken_at, None, "and the chain still verifies");
}

// ===========================================================================
// 13 · Active/standby handover (P1 #10)
// ===========================================================================
//
// The two tests above prove a second writer is *refused* and that the lock is released.
// P1 #10's point was that neither exercises a **handover**: what a standby does with a
// projection that is behind, how long election takes, and what happens to work the
// outgoing writer committed while the standby was waiting.
//
// Before `Store::open_waiting` there was no standby at all — the second process failed at
// startup and exited, so "active/standby with that lock as the election primitive" (§8.5.2)
// had a primitive and no standby.

/// Release the writer while keeping the storage — a process exiting, not a host being
/// wiped.
///
/// `Root::drop` removes the directory, so `drop(estate)` models a disk going away rather
/// than a failover. Destructuring keeps the `Root` alive and drops only the handles that
/// hold the lock, which is what an active writer exiting actually looks like.
fn release_writer(e: Estate) -> Root {
    let Estate {
        root,
        store,
        evidence,
        ..
    } = e;
    drop(store);
    drop(evidence);
    root
}

#[test]
fn a_standby_takes_over_and_sees_everything_the_active_writer_committed() {
    // The question P1 #10 asked: the standby is waiting, the active writer keeps working,
    // and the successor must not start from the view it had when it began waiting.
    let (mut e, issued) = wired("fi-ha-handover");
    let state = e.root.state();
    let first_cid = issued.record.cid.as_str().to_string();

    // A second contract, written *after* a standby would plausibly have started waiting.
    let agent = e.entity(&issued.record.caller);
    let server = e.entity(&issued.record.callee);
    let second = e.connect(&agent.id, &server.id, &["list_transactions"], 7 * DAY);
    let second_cid = second.record.cid.as_str().to_string();

    // While the active writer holds the lock, a standby cannot take it.
    assert_eq!(Store::open(&state).unwrap_err().code(), Code::STORE_LOCKED);

    // The active writer goes away — cleanly here; a crash is the same mechanism, because a
    // `flock` is owned by the descriptor and the kernel closes it either way.
    let _root = release_writer(e);

    let (store, report, election) = Store::open_waiting(
        &state,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_millis(10),
        |_| {},
    )
    .expect("the standby must be able to take over");

    assert!(report.is_clean(), "{report:?}");
    assert!(
        election.uncontended,
        "the previous writer had already exited, so nothing was contended: {election:?}"
    );

    // Both contracts are present — including the one written after the standby would have
    // begun waiting. This is the assertion the item is about: a successor that rebuilt
    // before electing would be missing the second one.
    let cids: Vec<String> = store
        .projection
        .contracts
        .keys()
        .map(|c| c.as_str().to_string())
        .collect();
    assert!(
        cids.contains(&first_cid),
        "successor lost the first contract: {cids:?}"
    );
    assert!(
        cids.contains(&second_cid),
        "successor started from a projection behind the log: {cids:?}"
    );
}

#[test]
fn a_standby_waits_through_a_handover_rather_than_exiting() {
    // The behaviour that did not exist. `Store::open` fails instantly, which is right for
    // `connect register` competing with a running `serve` — and it made failover mean an
    // external supervisor restarting a process that would then race the dying one.
    let (e, _issued) = wired("fi-ha-wait");
    let state = e.root.state();

    let waiting = state.clone();
    let standby = std::thread::spawn(move || {
        Store::open_waiting(
            &waiting,
            std::time::Duration::from_secs(10),
            std::time::Duration::from_millis(5),
            |_| {},
        )
    });

    // Long enough that the standby has certainly failed at least one attempt, so this is a
    // handover and not a race it happened to win.
    std::thread::sleep(std::time::Duration::from_millis(60));
    let _root = release_writer(e);

    let (store, report, election) = standby.join().unwrap().expect("the standby must win");
    assert!(report.is_clean());
    assert!(
        !election.uncontended,
        "a successor must know it succeeded somebody: {election:?}"
    );
    assert!(election.describe().contains("took over"), "{election:?}");
    assert!(!store.projection.contracts.is_empty());
}

#[test]
fn a_standby_that_cannot_elect_refuses_to_serve_rather_than_becoming_a_second_writer() {
    // The dangerous alternative. A standby whose wait expired and started anyway would be
    // a second writer — the one thing the lock exists to prevent — and it would present as
    // a successful failover, with two processes appending to one hash-chained log.
    let (_e, _issued) = wired("fi-ha-timeout");
    let state = _e.root.state();

    let err = Store::open_waiting(
        &state,
        std::time::Duration::from_millis(80),
        std::time::Duration::from_millis(10),
        |_| {},
    )
    .expect_err("the active writer still holds the lock");
    assert_eq!(err.code(), Code::STORE_LOCKED);
    assert!(
        format!("{err}").contains("giving up rather than starting without the lock"),
        "{err}"
    );
}

#[test]
fn an_in_flight_write_is_either_committed_or_absent_never_half() {
    // P1 #10's last question: what happens to an in-flight approval. The answer has to be
    // structural rather than lucky — a successor rebuilding a log with a torn final record
    // must reject that record and say so, not accept a half-parsed one.
    let (e, issued) = wired("fi-ha-torn");
    let state = e.root.state();
    let log = e.state_log();
    let cid = issued.record.cid.as_str().to_string();
    let _root = release_writer(e);

    // A process killed mid-append leaves a truncated final line: exactly what an un-fsynced
    // tail looks like after a hard stop.
    let mut text = std::fs::read_to_string(&log).unwrap();
    text.push_str("{\"seq\":9999,\"kind\":\"contract.min");
    std::fs::write(&log, &text).unwrap();

    let (store, report, _election) = Store::open_waiting(
        &state,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_millis(10),
        |_| {},
    )
    .expect("a torn tail must not stop a successor from starting");

    // Everything committed before the tear survives.
    let cids: Vec<String> = store
        .projection
        .contracts
        .keys()
        .map(|c| c.as_str().to_string())
        .collect();
    assert!(cids.contains(&cid), "{cids:?}");

    // And the tear is reported rather than silently dropped: a successor that started clean
    // on a damaged log would be asserting the estate is intact when it is not.
    assert!(
        !report.is_clean(),
        "a torn final record must be visible in the rebuild report: {report:?}"
    );
}
