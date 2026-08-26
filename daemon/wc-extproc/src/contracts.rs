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
//! closes it by fetching the catalogue itself; a filter cannot. See [`PinPolicy`].

use std::sync::Arc;

use wc_core::contract::{AdmitCtx, Admitted};
use wc_core::model::EntityId;
use wc_core::model::Pin;
use wc_mediator::cache::{Cache, Snapshot, Trust};
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
    zones: Arc<dyn wc_core::contract::ZoneRule + Send + Sync>,
    mode: wc_core::error::Mode,
    now: fn() -> u64,
}

impl ContractSet {
    /// Build a set from contract artifacts already on disk.
    ///
    /// Verification happens here, once, not per request: a contract that does not verify is not
    /// in the snapshot at all, so the hot path cannot reach one.
    pub fn from_artifacts(
        artifacts: &[String],
        trust: &mut KeySource,
        mediator_id: impl Into<String>,
        issuer: impl Into<String>,
        zones: Arc<dyn wc_core::contract::ZoneRule + Send + Sync>,
        mode: wc_core::error::Mode,
        now: fn() -> u64,
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
        let cache = Arc::new(Cache::new());
        cache.install(snapshot);
        Ok(ContractSet {
            cache,
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
}

impl Contracts for ContractSet {
    fn resolve(&self, caller: Option<&str>, callee: &str) -> Option<Resolved> {
        // No identity, no contract. This is the line that decides an unauthenticated caller is
        // not a permitted one, and it is first so nothing below can accidentally reach past it.
        //
        // The identity arrives already authenticated: `PeerSource::Mesh` resolved it from the
        // XFCC header AND checked the origin the header came from, which is the half that makes
        // it authentication rather than a request field with a hyphen in it.
        let caller = caller?;
        let caller = EntityId::new(caller).ok()?;
        let callee = EntityId::new(callee).ok()?;
        let contract = self.cache.resolve(None, &caller, &callee).ok()?;

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
        let admitted = contract.admit_context(&ctx).ok()?;
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

    fn now() -> u64 {
        T_NOW
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
        )
        .unwrap();
        assert_eq!(s.len(), 0, "a contract from another plane was installed");
    }
}
