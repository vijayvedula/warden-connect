//! Where an admitted connection comes from.
//!
//! The gateway resolves a contract per (caller, callee) out of a cached set, exactly as the
//! mediator does — `wc_mediator::cache` is the same code, and this module is the wiring, not a
//! second implementation.
//!
//! # Why admission can happen without the catalogue
//!
//! Gate 8 compares the callee's presented surface against the pinned digest, and at the moment a
//! contract is resolved the gateway has not seen a catalogue. That is not a gap: `admit_context`
//! takes an empty [`Pin`] and does not perform gate 8 at all — the mediator passes one too. The
//! comparison happens when a `tools/list` response arrives, which for this filter is the response
//! body phase.
//!
//! What that leaves is a real hole, and it is named rather than papered over: a caller that
//! issues `tools/call` and never `tools/list` is never checked against the pin. The mediator
//! closes it by fetching the catalogue itself; a filter cannot. What bounds the hole is
//! [`crate::PinLedger`] and `FilterCfg::pin_max_age`, not a policy type.

use std::sync::Arc;

use wc_core::contract::{AdmitCtx, Admitted};
use wc_core::model::EntityId;
use wc_core::model::Pin;
use wc_mediator::cache::{Cache, Snapshot, Trust};
use crate::adapter::binding;
use wc_mediator::jwks::KeySource;

/// An admitted connection and the contract it came from.
pub struct Resolved {
    /// Gates 1-7 and 9-14, already run.
    pub admitted: Admitted,
    /// The contract itself, so gate 8 runs through the shared `check_pin` when a catalogue
    /// arrives. Carrying the digest instead and comparing it here would be a second
    /// implementation of a check that already exists — and the wrong one: the contract pins a
    /// digest over exactly the contracted items, not over the whole presented manifest.
    pub contract: std::sync::Arc<wc_core::contract::VerifiedContract>,
}

/// Resolve an admitted connection for a caller.
pub trait Contracts: Send + Sync + 'static {
    /// The admitted connection for this pair, or `None` if there is no contract.
    fn resolve(&self, caller: Option<&str>, callee: &str) -> Option<Resolved>;
}

/// A contract set held in memory and refreshed by whatever installed it.
pub struct ContractSet {
    cache: Arc<Cache>,
    /// When the set was last known good, as a unix time.
    ///
    /// A verifier that keeps serving a cached set forever cannot be contained: `connect revoke`
    /// lands in the control plane and never reaches here, and the only remaining containment is
    /// contract expiry. So the age is tracked and [`ContractSet::stale`] refuses once it passes
    /// the bound.
    last_good: Arc<std::sync::atomic::AtomicU64>,
    /// Seconds the set may go without a successful refresh before every call is refused.
    /// Zero disables the bound, which is right only when there is no refresh source at all.
    max_stale: u64,
    zones: Arc<dyn wc_core::contract::ZoneRule + Send + Sync>,
    mode: wc_core::error::Mode,
    now: fn() -> u64,
}

impl ContractSet {
    /// Build a set from contract artifacts already on disk.
    ///
    /// Verification happens here, once, not per request: a contract that does not verify is not
    /// in the snapshot at all, so the hot path cannot reach one.
    ///
    /// Eight parameters, which clippy dislikes and which is right here: every one is a distinct
    /// authority — who the contracts must be addressed to, which plane they must come from,
    /// which zone pairs are allowed, and how stale the set may get. Bundling them into a config
    /// struct would hide that the caller has to decide all eight, and the value of the lint is
    /// the reminder, not the count.
    #[allow(clippy::too_many_arguments)]
    pub fn from_artifacts(
        artifacts: &[String],
        trust: &mut KeySource,
        mediator_id: impl Into<String>,
        issuer: impl Into<String>,
        zones: Arc<dyn wc_core::contract::ZoneRule + Send + Sync>,
        mode: wc_core::error::Mode,
        now: fn() -> u64,
        max_stale: u64,
    ) -> Result<ContractSet, String> {
        let mediator_id = mediator_id.into();
        let issuer = issuer.into();
        let at = now();
        let (keys, _warn) = trust.keys(at);
        let keys = keys.map_err(|e| e.to_string())?;
        let trusted = Trust {
            keys,
            mediator_id: &mediator_id,
            issuer: &issuer,
        };
        let snapshot = Snapshot::build(artifacts, &trusted, at);
        // A second contract for one party pair is verified, counted and then unreachable: the
        // resolver here never names a `cid`, so it can only ever find one per pair. Saying so at
        // startup is the difference between "2 contracts verified" meaning two usable contracts
        // and meaning one — a walkthrough lost an afternoon to exactly that.
        for sh in &snapshot.shadowed {
            eprintln!(
                "{}: WARNING contract {} is UNREACHABLE — {} covers the same pair \
                 ({} -> {}) and this filter resolves by pair, never by cid. Put the tools you \
                 need in ONE contract",
                binding(), sh.cid, sh.shadowed_by, sh.caller, sh.callee
            );
        }
        let cache = Arc::new(Cache::new());
        cache.install(snapshot);
        Ok(ContractSet {
            cache,
            last_good: Arc::new(std::sync::atomic::AtomicU64::new(at)),
            max_stale,
            zones,
            mode,
            now,
        })
    }

    /// How many contracts verified into the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.snapshot().len()
    }

    /// Whether the set holds no contract at all.
    ///
    /// A binding that starts with an empty set refuses every request, which is correct and
    /// almost never intended — say so at startup rather than in the access log.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ContractSet {
    /// The cache the refresh loop installs into.
    #[must_use]
    pub fn cache(&self) -> Arc<Cache> {
        Arc::clone(&self.cache)
    }

    /// Record a successful refresh.
    pub fn mark_fresh(&self, at: u64) {
        self.last_good
            .store(at, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether the set is too old to be trusted, and by how long.
    ///
    /// Checked on the resolve path rather than by the refresh loop, because the loop may not be
    /// running at all — a thread that panicked would otherwise leave a permanently fresh set.
    #[must_use]
    pub fn stale(&self) -> Option<u64> {
        if self.max_stale == 0 {
            return None;
        }
        let last = self.last_good.load(std::sync::atomic::Ordering::SeqCst);
        let age = (self.now)().saturating_sub(last);
        (age > self.max_stale).then_some(age)
    }
}

impl Contracts for ContractSet {
    fn resolve(&self, caller: Option<&str>, callee: &str) -> Option<Resolved> {
        // A set nobody has been able to refresh is a set a revocation cannot reach. Refusing
        // is the only honest answer: the alternative is admitting calls on a contract that may
        // have been withdrawn an hour ago.
        if let Some(age) = self.stale() {
            eprintln!(
                "{}: refusing every call — the contract set is {age}s old and the \
                 staleness bound is {}s. A revocation cannot have reached this process.",
                binding(), self.max_stale
            );
            return None;
        }

        // No identity, no contract. This is the line that decides an unauthenticated caller is
        // not a permitted one, and it is first so nothing below can accidentally reach past it.
        //
        // The identity arrives already authenticated: `PeerSource::Mesh` resolved it from the
        // XFCC header AND checked the origin the header came from, which is the half that makes
        // it authentication rather than a request field with a hyphen in it.
        let caller = caller?;
        let caller = EntityId::new(caller).ok()?;
        let callee = EntityId::new(callee).ok()?;
        let contract = match self.cache.resolve(None, &caller, &callee) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "{}: no contract for {caller} -> {callee}: {} {}",
                    binding(),
                    e.code(),
                    e.detail()
                );
                return None;
            }
        };

        let peer = wc_core::contract::PeerIdentity {
            caller: caller.clone(),
            callee: callee.clone(),
        };
        let unused = Pin::empty((self.now)());
        let ctx = AdmitCtx {
            peer: &peer,
            // Gate 8 is not run here and is not skipped either: the comparison happens when a
            // catalogue arrives. The mediator passes an empty pin at this point for the same
            // reason.
            presented: &unused,
            token_wcid: None,
            zones: self.zones.as_ref(),
            mode: self.mode,
        };
        // The gates. Swallowing this error was the worst of the three: a contract that exists
        // and fails gate 9, 10 or 11 was reported as "no contract for this caller and callee",
        // which sends the reader to look for a contract that is sitting right there.
        let admitted = match contract.admit_context(&ctx) {
            Ok(a) => a,
            Err(e) => {
                eprintln!(
                    "{}: contract {} found for {caller} -> {callee} but NOT admitted: {} {}",
                    binding(),
                    contract.payload.cid.as_str(),
                    e.code(),
                    e.detail()
                );
                return None;
            }
        };
        // The contract travels with the admitted connection. A filter that cannot reach it
        // cannot run gate 8, and a gate that cannot run is not a gate.
        Some(Resolved {
            admitted,
            contract: std::sync::Arc::clone(&contract),
        })
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the REAL contract source.
    //!
    //! The phase-loop tests in `main.rs` drive a stub `Contracts` impl, which means none of them
    //! reach this file. A mutation that made `ContractSet::resolve` fall back to a default caller
    //! survived the whole daemon suite for exactly that reason — the production identity gate was
    //! uncovered while eleven tests passed.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use wc_core::contract as c;

    const PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");
    const PUB: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_pub.pem");
    const KID: &str = "wc-test-es256";
    const MED: &str = "warden:mediator:extproc-test";
    const ISS: &str = "https://connect.internal";
    const T_NOW: u64 = 1_800_000_000;
    const CALLER: &str = "spiffe://org/ns/agents/sa/recon-bot";
    const CALLEE: &str = "spiffe://org/ns/tools/sa/payments-mcp";

    use std::cell::Cell;

    thread_local! {
        /// A clock the tests can move. Staleness is a function of time, and a test that slept
        /// for it would be slow and flaky in equal measure.
        ///
        /// THREAD-LOCAL, not a static: the harness runs these in parallel, and a shared clock
        /// would let one test's time travel decide another test's staleness. Every set is built
        /// and resolved on its own test's thread, so a per-thread clock is exact.
        static CLOCK: Cell<u64> = const { Cell::new(T_NOW) };
    }

    fn now() -> u64 {
        CLOCK.with(Cell::get)
    }

    fn set_clock(v: u64) {
        CLOCK.with(|c| c.set(v));
    }

    /// One signed artifact for (CALLER, CALLEE) contracting `get_balance`.
    fn artifact() -> String {
        let callee = wc_core::model::EntityId::new(CALLEE).unwrap();
        let served = serde_json::json!({"tools":[
            {"name":"get_balance","description":"Read an account balance."},
            {"name":"wire_funds","description":"Move money."}
        ]});
        let pin = wc_core::canon::pin(
            wc_core::canon::SurfaceKind::McpTools,
            &callee,
            &served,
            &wc_core::canon::Limits::default(),
            T_NOW,
        )
        .unwrap();
        let surface = c::Surface {
            tools: vec!["get_balance".to_string()],
            skills: Vec::new(),
            resources: Vec::new(),
        };
        let digest = pin.surface_digest(&surface.items()).unwrap();
        let mut payload = c::ContractPayload::new(
            wc_core::model::Cid::new("conn_7f3a91c4").unwrap(),
            wc_core::model::Jti::new("cx_84be0011").unwrap(),
            ISS,
            MED,
            c::Party {
                id: wc_core::model::EntityId::new(CALLER).unwrap(),
                zone: wc_core::model::ZoneId::new("internal.ops").unwrap(),
                tier: wc_core::model::Tier::TWO,
                card: None,
                manifest: None,
                surface_digest: None,
            },
            c::Party {
                id: callee,
                zone: wc_core::model::ZoneId::new("internal.payments").unwrap(),
                tier: wc_core::model::Tier::TWO,
                card: None,
                manifest: Some(pin.manifest.clone()),
                surface_digest: Some(digest),
            },
        );
        payload.iat = T_NOW - 100;
        payload.nbf = T_NOW - 100;
        payload.exp = T_NOW + 3_600;
        payload.surface = surface;
        payload.terms = c::Terms::default();
        payload.assurance = c::Assurance::default();
        c::mint(
            &payload,
            &c::IssuerKey::ec_pem(KID, PRIV, c::Algorithm::ES256).unwrap(),
        )
        .unwrap()
    }

    fn set_with_bound(max_stale: u64) -> ContractSet {
        set_clock(T_NOW);
        let mut keys = c::IssuerKeys::new();
        keys.add_ec_pem(KID, PUB, c::Algorithm::ES256).unwrap();
        let mut trust = wc_mediator::jwks::KeySource::Pinned(keys);
        ContractSet::from_artifacts(
            &[artifact()],
            &mut trust,
            MED,
            ISS,
            Arc::new(wc_core::contract::AnyZone),
            wc_core::error::Mode::Enforce,
            now,
            max_stale,
        )
        .expect("the set should build")
    }

    fn set() -> ContractSet {
        let mut keys = c::IssuerKeys::new();
        keys.add_ec_pem(KID, PUB, c::Algorithm::ES256).unwrap();
        let mut trust = wc_mediator::jwks::KeySource::Pinned(keys);
        ContractSet::from_artifacts(
            &[artifact()],
            &mut trust,
            MED,
            ISS,
            Arc::new(wc_core::contract::AnyZone),
            wc_core::error::Mode::Enforce,
            now,
            0,
        )
        .expect("the set should build")
    }

    #[test]
    fn one_artifact_verifies_into_the_set() {
        assert_eq!(set().len(), 1);
    }

    #[test]
    fn the_contracted_caller_resolves_and_carries_its_contract() {
        let r = set().resolve(Some(CALLER), CALLEE).expect("should resolve");
        assert!(r.admitted.items.contains("get_balance"));
        assert!(
            !r.admitted.items.contains("wire_funds"),
            "the admitted set is the contract's, not the callee's"
        );
        assert!(
            r.contract.payload.callee.surface_digest.is_some(),
            "no pinned digest travelled with the contract, so gate 8 cannot run"
        );
    }

    #[test]
    fn an_absent_identity_resolves_to_nothing() {
        // The line that decides an unauthenticated caller is not a permitted one.
        assert!(set().resolve(None, CALLEE).is_none());
    }

    #[test]
    fn a_different_caller_resolves_to_nothing() {
        assert!(set()
            .resolve(Some("spiffe://org/ns/agents/sa/somebody-else"), CALLEE)
            .is_none());
    }

    #[test]
    fn a_different_callee_resolves_to_nothing() {
        // The callee is configuration. A contract for one callee must not satisfy another.
        assert!(set()
            .resolve(Some(CALLER), "spiffe://org/ns/tools/sa/other-mcp")
            .is_none());
    }

    #[test]
    fn a_malformed_caller_id_resolves_to_nothing() {
        assert!(set().resolve(Some("not-a-spiffe-id"), CALLEE).is_none());
    }

    #[test]
    fn a_set_past_its_staleness_bound_refuses_every_call() {
        // The control that makes withdrawal meaningful. A verifier serving a cached set forever
        // cannot be contained: `connect revoke` lands in the control plane and never arrives.
        let s = set_with_bound(60);
        assert!(
            s.resolve(Some(CALLER), CALLEE).is_some(),
            "fresh set should resolve"
        );

        set_clock(T_NOW + 61);
        assert!(
            s.resolve(Some(CALLER), CALLEE).is_none(),
            "a set older than its bound still admitted a call"
        );

        // A successful refresh clears it.
        s.mark_fresh(T_NOW + 61);
        assert!(
            s.resolve(Some(CALLER), CALLEE).is_some(),
            "marking the set fresh did not clear the refusal"
        );
        set_clock(T_NOW);
    }

    #[test]
    fn a_bound_of_zero_never_goes_stale() {
        // Disk-only mode: the set is immutable and its containment is contract expiry. A bound
        // would refuse a correctly-configured air-gapped deployment.
        let s = set_with_bound(0);
        set_clock(T_NOW + 10_000_000);
        assert!(s.resolve(Some(CALLER), CALLEE).is_some());
        assert_eq!(s.stale(), None);
        set_clock(T_NOW);
    }

    #[test]
    fn staleness_is_checked_on_the_resolve_path_not_by_a_timer() {
        // If a refresh thread panicked, a timer-driven check would stop running and the set
        // would look permanently fresh. Asking on resolve cannot be skipped that way.
        let s = set_with_bound(30);
        set_clock(T_NOW + 31);
        assert_eq!(s.stale(), Some(31));
        set_clock(T_NOW);
    }

    #[test]
    fn an_artifact_for_a_different_mediator_does_not_verify() {
        // aud is a boundary, not decoration.
        let mut keys = c::IssuerKeys::new();
        keys.add_ec_pem(KID, PUB, c::Algorithm::ES256).unwrap();
        let mut trust = wc_mediator::jwks::KeySource::Pinned(keys);
        let s = ContractSet::from_artifacts(
            &[artifact()],
            &mut trust,
            "warden:mediator:somebody-else",
            ISS,
            Arc::new(wc_core::contract::AnyZone),
            wc_core::error::Mode::Enforce,
            now,
            0,
        )
        .unwrap();
        assert_eq!(s.len(), 0, "a contract addressed elsewhere was installed");
    }

    #[test]
    fn an_artifact_from_a_different_issuer_does_not_verify() {
        let mut keys = c::IssuerKeys::new();
        keys.add_ec_pem(KID, PUB, c::Algorithm::ES256).unwrap();
        let mut trust = wc_mediator::jwks::KeySource::Pinned(keys);
        let s = ContractSet::from_artifacts(
            &[artifact()],
            &mut trust,
            MED,
            "https://connect.other",
            Arc::new(wc_core::contract::AnyZone),
            wc_core::error::Mode::Enforce,
            now,
            0,
        )
        .unwrap();
        assert_eq!(s.len(), 0, "a contract from another plane was installed");
    }
}
