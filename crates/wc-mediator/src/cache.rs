//! The contract cache and revocation set (`docs/08-lld.md` §8.6.2).
//!
//! Contracts are verified **once**, when a snapshot is built, and looked up by a
//! hash map on the connection path. That is what makes §8.10's latency budget
//! comfortable rather than tight: steady-state establishment is a map lookup, not
//! an ECDSA verification.
//!
//! Readers take an `Arc<Snapshot>` and never block on a refresh — the refresh
//! builds a whole new snapshot and swaps the pointer. A mediator serving traffic
//! must not pause because the control plane published a new contract set.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};

#[cfg(test)]
use wc_core::contract::IssuerKeys;
use wc_core::contract::{self, RevocationView, VerifiedContract, VerifyOpts};
use wc_core::error::{Code, Result, WcError};
use wc_core::model::EntityId;

/// The in-memory revocation set: deny-only, so a stale or unreadable feed can
/// never grant.
///
/// Three subject kinds, matching Warden core's feed format plus the two
/// warden-connect adds (§8.6.2): `jti`, `cid`, `party`.
#[derive(Debug, Default, Clone)]
pub struct Revocations {
    jtis: HashSet<String>,
    cids: HashSet<String>,
    parties: HashSet<String>,
    distrusted: Option<String>,
}

impl Revocations {
    /// An empty set.
    #[must_use]
    pub fn new() -> Revocations {
        Revocations::default()
    }

    /// Revoke one artifact.
    pub fn revoke_jti(&mut self, jti: impl Into<String>) {
        self.jtis.insert(jti.into());
    }

    /// Revoke one connection.
    pub fn revoke_cid(&mut self, cid: impl Into<String>) {
        self.cids.insert(cid.into());
    }

    /// Revoke every connection naming a party, in either direction.
    pub fn revoke_party(&mut self, party: impl Into<String>) {
        self.parties.insert(party.into());
    }

    /// Mark the set unusable, so nothing may be admitted against it.
    ///
    /// A revocation set is only ever consulted to answer *is this still allowed?*,
    /// so an answer it cannot give is not "no revocations" — it is "unknown", and
    /// unknown must read as revoked. Without this a corrupted feed, or one with a
    /// hole in its sequence, leaves the mediator serving happily against whatever
    /// it last managed to verify: the containment order that landed in the missing
    /// range is simply never applied, and the report saying so goes nowhere
    /// (§8.15.5, WC-6002).
    ///
    /// Deliberately not clearable by hand. It clears when a pull verifies clean and
    /// contiguous, which is the only evidence that would justify clearing it.
    pub fn distrust(&mut self, reason: impl Into<String>) {
        self.distrusted = Some(reason.into());
    }

    /// Clear the distrust. `pub(crate)` on purpose: the only thing entitled to do
    /// this is [`crate::client::apply_revocations`] after a pull that verified clean
    /// and contiguous, and a knob an operator could turn to make the alarm stop is
    /// not a control.
    pub(crate) fn trust(&mut self) {
        self.distrusted = None;
    }

    /// Why this set may not be relied on, if it may not.
    #[must_use]
    pub fn distrusted(&self) -> Option<&str> {
        self.distrusted.as_deref()
    }

    /// How many subjects are revoked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.jtis.len() + self.cids.len() + self.parties.len()
    }

    /// Whether nothing is revoked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl RevocationView for Revocations {
    fn jti_revoked(&self, jti: &str) -> bool {
        self.jtis.contains(jti)
    }
    fn cid_revoked(&self, cid: &str) -> bool {
        self.cids.contains(cid)
    }
    fn party_revoked(&self, party: &str) -> bool {
        self.parties.contains(party)
    }
}

/// Re-exported because this is where a mediator meets it: `Snapshot::build` takes one, and a
/// deployment reading this module should not have to know it is defined next to `VerifyOpts`.
/// It lives in `wc-core` because the air-gapped bundle importer needs the same type and
/// `wc-control` cannot depend on this crate.
pub use wc_core::contract::Trust;

/// A verified contract set, immutable once built.
#[derive(Debug, Default)]
pub struct Snapshot {
    /// Monotonic set version from the control plane.
    pub seq: u64,
    /// Hash over the set, echoed in the ACK so "contained" is an attested claim
    /// rather than an HTTP 200 (§8.7.7).
    pub set_hash: String,
    /// Verified contracts by connection id.
    by_cid: BTreeMap<String, Arc<VerifiedContract>>,
    /// Verified contracts by authenticated party pair — how a connection is found
    /// when the agent carries no `cid`.
    by_pair: HashMap<(String, String), Arc<VerifiedContract>>,
    /// Artifacts that failed verification when the snapshot was built, with the
    /// reason. Kept so a mediator can report *why* it has no contract, rather
    /// than only that it has none.
    pub rejected: Vec<(String, Code)>,
}

impl Snapshot {
    /// Build a snapshot by verifying every artifact once.
    ///
    /// An artifact that fails verification is recorded in `rejected` and omitted
    /// — one bad contract in a published set must not cost the mediator every
    /// other contract in it.
    pub fn build(artifacts: &[String], trust: &Trust<'_>, now: u64) -> Snapshot {
        let mut snapshot = Snapshot::default();
        let mut digest_input = String::new();

        for jws in artifacts {
            // Revocation is applied at lookup time, not here: a snapshot outlives
            // the feed state it was built under.
            let opts = VerifyOpts::trusting(trust, now);
            match contract::verify_artifact(jws, &opts) {
                Ok(verified) => {
                    let cid = verified.payload.cid.as_str().to_string();
                    let pair = (
                        verified.payload.caller.id.as_str().to_string(),
                        verified.payload.callee.id.as_str().to_string(),
                    );
                    digest_input.push_str(&cid);
                    digest_input.push('\n');
                    let shared = Arc::new(verified);
                    snapshot.by_cid.insert(cid, Arc::clone(&shared));
                    snapshot.by_pair.insert(pair, shared);
                }
                Err(e) => {
                    let label = jws.chars().take(24).collect::<String>();
                    snapshot.rejected.push((label, e.code()));
                }
            }
        }
        snapshot.set_hash = format!("sha256:{}", wc_core::util::sha256_hex(&digest_input));
        snapshot
    }

    /// Look up by connection id.
    #[must_use]
    pub fn by_cid(&self, cid: &str) -> Option<&Arc<VerifiedContract>> {
        self.by_cid.get(cid)
    }

    /// Whether this snapshot holds the exact artifact a connection was admitted under.
    ///
    /// `jti` and not just `cid`, because the control plane may re-issue a connection with
    /// a narrower surface or tighter terms under the same `cid`. A live session holding
    /// the *previous* artifact's allowlist would then be running on terms nobody
    /// currently grants, which is a widening dressed as continuity.
    #[must_use]
    pub fn holds_artifact(&self, cid: &str, jti: &str) -> bool {
        self.by_cid
            .get(cid)
            .is_some_and(|c| c.payload.jti.as_str() == jti)
    }

    /// Look up by the authenticated party pair.
    #[must_use]
    pub fn by_pair(&self, caller: &EntityId, callee: &EntityId) -> Option<&Arc<VerifiedContract>> {
        self.by_pair
            .get(&(caller.as_str().to_string(), callee.as_str().to_string()))
    }

    /// How many contracts are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_cid.len()
    }

    /// Whether any held contract carries a rate or spend ceiling.
    ///
    /// Exists so the startup banner can say the one thing a signed
    /// `max_calls_per_hour` does not: [`crate::ceiling::Ceilings`] counts **in this
    /// process**, so a mediator that lives less than an hour enforces a fraction of an
    /// hourly ceiling and the next process starts from zero. Measured: a 3-per-hour
    /// contract executed three calls per process and nine across three, in the same hour.
    ///
    /// A long-lived sidecar in front of a long-running agent enforces it as written; a
    /// per-task invocation does not. The mediator cannot know which it is, and the
    /// operator can — so it is stated rather than assumed either way.
    #[must_use]
    pub fn has_rate_or_spend_ceiling(&self) -> bool {
        self.by_cid.values().any(|c| {
            let terms = &c.payload.terms;
            terms.max_calls_per_hour.is_some() || terms.max_spend_usd_per_day.is_some()
        })
    }

    /// Whether the set is empty — a mediator in this state admits nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_cid.is_empty()
    }
}

/// The live contract set plus the revocation set.
///
/// Readers clone an `Arc<Snapshot>`; a refresh swaps the pointer. So a refresh
/// never blocks a connection, and a connection never sees a half-applied set.
#[derive(Debug)]
pub struct Cache {
    live: RwLock<Arc<Snapshot>>,
    revocations: RwLock<Arc<Revocations>>,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            live: RwLock::new(Arc::new(Snapshot::default())),
            revocations: RwLock::new(Arc::new(Revocations::default())),
        }
    }
}

impl Cache {
    /// An empty cache. A mediator with an empty cache admits nothing.
    #[must_use]
    pub fn new() -> Cache {
        Cache::default()
    }

    /// Install a verified snapshot, replacing whatever was live.
    pub fn install(&self, snapshot: Snapshot) {
        // A poisoned lock means a previous holder panicked. Rebuilding from the
        // new snapshot is safe because a snapshot is immutable and self-contained.
        let mut live = match self.live.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *live = Arc::new(snapshot);
    }

    /// Replace the revocation set.
    pub fn set_revocations(&self, revocations: Revocations) {
        let mut current = match self.revocations.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *current = Arc::new(revocations);
    }

    /// The live snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        match self.live.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// The live revocation set.
    #[must_use]
    pub fn revocations(&self) -> Arc<Revocations> {
        match self.revocations.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Find the contract for an authenticated pair, optionally pinned to a `cid`.
    ///
    /// Applies revocation at lookup time, so a revocation takes effect on the very
    /// next connection without rebuilding the snapshot.
    pub fn resolve(
        &self,
        cid: Option<&str>,
        caller: &EntityId,
        callee: &EntityId,
    ) -> Result<Arc<VerifiedContract>> {
        let snapshot = self.snapshot();
        let found = match cid {
            Some(cid) => snapshot.by_cid(cid).cloned(),
            None => snapshot.by_pair(caller, callee).cloned(),
        };

        let contract = found.ok_or_else(|| {
            WcError::with_detail(
                Code::NO_CONTRACT,
                match cid {
                    Some(cid) => format!("no contract {cid} in the current set"),
                    None => format!("no contract for {caller} -> {callee}"),
                },
            )
        })?;

        let revoked = self.revocations();
        if let Some(why) = revoked.distrusted() {
            // Not "no revocations known" — *revocation status unknown*, which is the
            // one condition that must read as revoked.
            return Err(WcError::with_detail(
                Code::CONTRACT_REVOKED,
                format!("revocation state cannot be relied on ({why}), so nothing is admitted"),
            ));
        }
        let p = &contract.payload;
        for (what, hit) in [
            ("artifact", revoked.jti_revoked(p.jti.as_str())),
            ("connection", revoked.cid_revoked(p.cid.as_str())),
            ("caller", revoked.party_revoked(p.caller.id.as_str())),
            ("callee", revoked.party_revoked(p.callee.id.as_str())),
        ] {
            if hit {
                return Err(WcError::with_detail(
                    Code::CONTRACT_REVOKED,
                    format!("{what} is revoked"),
                ));
            }
        }
        Ok(contract)
    }

    /// Re-check a connection admitted earlier: is the artifact it runs on still in force?
    ///
    /// This is the containment seam, and it exists because the mediator did not have one.
    /// [`Self::resolve`] runs once per connection at `initialize`; every later call used the
    /// `Admitted` cached from it, so a contract that had been revoked, withdrawn or replaced
    /// went on being served until it expired. `scripts/rotation-drill.sh` measured both
    /// halves of that: withdrawing the issuer key changed nothing, and quarantining the
    /// callee changed nothing while the mediator's own log said `1 rejected`.
    ///
    /// Nothing here verifies a signature. The snapshot is built and verified once at install
    /// time, so this is an index lookup and a handful of set-membership tests — which is why
    /// it can sit on the per-call path inside §7.10's sub-millisecond budget. That cost was
    /// the stated reason for caching the admission, and it turns out only the *verification*
    /// was ever expensive, not the *lookup*.
    ///
    /// Deliberately narrower than re-admission: zones, the token binding and the pin were
    /// settled against evidence this call does not have (the presented catalogue). The
    /// per-call question is only whether the contract still stands.
    pub fn still_in_force(
        &self,
        cid: &str,
        jti: &str,
        caller: &EntityId,
        callee: &EntityId,
    ) -> Result<()> {
        // By `cid` and never by pair: a session admitted under one contract must not
        // silently continue on whatever contract now happens to cover the same two
        // parties. A replacement is a new connection, not a continuation of this one.
        let contract = self.resolve(Some(cid), caller, callee)?;
        if contract.payload.jti.as_str() != jti {
            return Err(WcError::with_detail(
                Code::CONTRACT_REVOKED,
                format!(
                    "connection {cid} is now served by artifact {} and this session was \
                     admitted under {jti}; reconnect to pick up the current terms",
                    contract.payload.jti.as_str()
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use wc_core::canon::{self, Limits, SurfaceKind};
    use wc_core::contract::{
        Algorithm, ApprovalRef, Assurance, ContractPayload, IssuerKey, Party, Surface, Terms,
    };
    use wc_core::model::{Cid, Jti, Pin, Tier, ZoneId};

    const PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");
    const PUB: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_pub.pem");
    const KID: &str = "wc-test-es256";
    const MEDIATOR: &str = "warden:mediator:apac-ops";
    const NOW: u64 = 1_785_312_500;
    const ISS: &str = "https://connect.internal/t/apac";

    /// The trust a test mediator verifies under. Named once, so a test cannot quietly
    /// stop checking `iss` — which is what the check existing at all is for.
    fn trusting(keys: &IssuerKeys) -> Trust<'_> {
        Trust {
            keys,
            mediator_id: MEDIATOR,
            issuer: ISS,
        }
    }

    fn keys() -> IssuerKeys {
        let mut k = IssuerKeys::new();
        k.add_ec_pem(KID, PUB, Algorithm::ES256).unwrap();
        k
    }

    fn signer() -> IssuerKey {
        IssuerKey::ec_pem(KID, PRIV, Algorithm::ES256).unwrap()
    }

    pub(crate) fn agent() -> EntityId {
        EntityId::new("spiffe://org/ns/agents/sa/recon-bot-7").unwrap()
    }

    pub(crate) fn server() -> EntityId {
        EntityId::new("spiffe://org/ns/tools/sa/payments-mcp").unwrap()
    }

    pub(crate) fn server_pin() -> Pin {
        canon::pin(
            SurfaceKind::McpTools,
            &server(),
            &serde_json::json!({"tools": [
                {"name": "get_balance", "description": "Read an account balance."},
                {"name": "list_transactions", "description": "List recent transactions."},
                {"name": "wire_funds", "description": "Move money between accounts."}
            ]}),
            &Limits::default(),
            NOW - 100,
        )
        .unwrap()
    }

    /// A contract for `tools`, minted for the given cid.
    pub(crate) fn contract_for(cid: &str, tools: &[&str], exp: u64) -> String {
        let pin = server_pin();
        let surface = Surface {
            tools: tools.iter().map(|t| (*t).to_string()).collect(),
            skills: Vec::new(),
            resources: Vec::new(),
        };
        let digest = pin.surface_digest(&surface.items()).unwrap();
        let mut p = ContractPayload::new(
            Cid::new(cid).unwrap(),
            Jti::new(format!("cx_{}", &cid[5..13])).unwrap(),
            "https://connect.internal/t/apac",
            MEDIATOR,
            Party {
                id: agent(),
                zone: ZoneId::new("internal.apac-ops").unwrap(),
                tier: Tier::TWO,
                card: None,
                manifest: None,
                surface_digest: None,
            },
            Party {
                id: server(),
                zone: ZoneId::new("internal.payments").unwrap(),
                tier: Tier::TWO,
                card: None,
                manifest: Some(pin.manifest.clone()),
                surface_digest: Some(digest),
            },
        );
        p.iat = NOW - 100;
        p.nbf = NOW - 100;
        p.exp = exp;
        p.surface = surface;
        p.terms = Terms::default();
        p.assurance = Assurance::default();
        p.approval = ApprovalRef::standing();
        p.policy_version = "connect-policy@v1".to_string();
        contract::mint(&p, &signer()).unwrap()
    }

    #[test]
    fn a_snapshot_verifies_once_and_indexes_both_ways() {
        let jws = contract_for("conn_11111111", &["get_balance"], NOW + 3_600);
        let snapshot = Snapshot::build(&[jws], &trusting(&keys()), NOW);

        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.rejected.is_empty());
        assert!(snapshot.by_cid("conn_11111111").is_some());
        assert!(snapshot.by_pair(&agent(), &server()).is_some());
        assert!(snapshot.set_hash.starts_with("sha256:"));
    }

    #[test]
    fn one_bad_artifact_does_not_cost_the_others() {
        // A published set with a stale contract in it must still deliver the rest.
        let good = contract_for("conn_11111111", &["get_balance"], NOW + 3_600);
        let expired = contract_for("conn_22222222", &["get_balance"], NOW - 1);
        let snapshot = Snapshot::build(&[good, expired], &trusting(&keys()), NOW);

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot.rejected.len(), 1);
        assert_eq!(snapshot.rejected[0].1, Code::CONTRACT_EXPIRED);
    }

    #[test]
    fn a_snapshot_refuses_another_planes_contract_and_the_cache_never_holds_it() {
        // The mediator's own version of the plane boundary, asserted here because
        // `Snapshot::build` is where a real mediator applies it and a `wc-core` test of
        // `verify_artifact` does not reach it. Dropping `.issued_by` from
        // `VerifyOpts::trusting` leaves every core test green.
        //
        // Same keys, same `aud` — `mediator_id` is commonly templated to one string across
        // planes — so `iss` is the only difference. The keyring holding both planes' keys is
        // what a copied JWKS or a federation import produces.
        let jws = contract_for("conn_11111111", &["get_balance"], NOW + 3_600);
        let keys = keys();
        let other_plane = Trust {
            keys: &keys,
            mediator_id: MEDIATOR,
            issuer: "https://connect.internal/t/emea",
        };

        let snapshot = Snapshot::build(std::slice::from_ref(&jws), &other_plane, NOW);
        assert_eq!(
            snapshot.len(),
            0,
            "the other plane's contract was installed"
        );
        assert_eq!(snapshot.rejected.len(), 1);
        assert_eq!(snapshot.rejected[0].1, Code::ISSUER_MISMATCH);

        // And through the cache, because "not in the snapshot" is only half the claim: what a
        // caller sees has to be a refusal, not a contract from a plane this mediator does not
        // obey.
        let cache = Cache::new();
        cache.install(snapshot);
        assert_eq!(
            cache.resolve(None, &agent(), &server()).unwrap_err().code(),
            Code::NO_CONTRACT
        );

        // Its own plane still installs it, or this test would pass for a build that rejects
        // everything.
        let own = Snapshot::build(std::slice::from_ref(&jws), &trusting(&keys), NOW);
        assert_eq!(own.len(), 1);
        assert!(own.rejected.is_empty());
    }

    #[test]
    fn an_empty_cache_admits_nothing() {
        let cache = Cache::new();
        assert!(cache.snapshot().is_empty());
        let err = cache.resolve(None, &agent(), &server()).unwrap_err();
        assert_eq!(err.code(), Code::NO_CONTRACT);
    }

    #[test]
    fn resolution_works_by_cid_and_by_pair() {
        let cache = Cache::new();
        cache.install(Snapshot::build(
            &[contract_for("conn_11111111", &["get_balance"], NOW + 3_600)],
            &trusting(&keys()),
            NOW,
        ));

        assert!(cache
            .resolve(Some("conn_11111111"), &agent(), &server())
            .is_ok());
        assert!(cache.resolve(None, &agent(), &server()).is_ok());
        assert_eq!(
            cache
                .resolve(Some("conn_99999999"), &agent(), &server())
                .unwrap_err()
                .code(),
            Code::NO_CONTRACT
        );
    }

    #[test]
    fn revocation_takes_effect_without_rebuilding_the_snapshot() {
        // The containment path: a revocation must bite on the next connection, not
        // on the next contract-set publication.
        let cache = Cache::new();
        cache.install(Snapshot::build(
            &[contract_for("conn_11111111", &["get_balance"], NOW + 3_600)],
            &trusting(&keys()),
            NOW,
        ));
        assert!(cache.resolve(None, &agent(), &server()).is_ok());

        let mut revoked = Revocations::new();
        revoked.revoke_cid("conn_11111111");
        cache.set_revocations(revoked);

        assert_eq!(
            cache.resolve(None, &agent(), &server()).unwrap_err().code(),
            Code::CONTRACT_REVOKED
        );
    }

    #[test]
    fn revoking_a_party_cuts_both_directions() {
        let cache = Cache::new();
        cache.install(Snapshot::build(
            &[contract_for("conn_11111111", &["get_balance"], NOW + 3_600)],
            &trusting(&keys()),
            NOW,
        ));

        for subject in [server().as_str().to_string(), agent().as_str().to_string()] {
            let mut revoked = Revocations::new();
            revoked.revoke_party(subject.clone());
            cache.set_revocations(revoked);
            assert_eq!(
                cache.resolve(None, &agent(), &server()).unwrap_err().code(),
                Code::CONTRACT_REVOKED,
                "revoking {subject} must cut the connection"
            );
        }
    }

    #[test]
    fn revoking_an_artifact_id_cuts_it() {
        let cache = Cache::new();
        cache.install(Snapshot::build(
            &[contract_for("conn_11111111", &["get_balance"], NOW + 3_600)],
            &trusting(&keys()),
            NOW,
        ));
        let mut revoked = Revocations::new();
        revoked.revoke_jti("cx_11111111");
        cache.set_revocations(revoked);
        assert_eq!(
            cache.resolve(None, &agent(), &server()).unwrap_err().code(),
            Code::CONTRACT_REVOKED
        );
    }

    #[test]
    fn installing_a_new_snapshot_replaces_the_old_one() {
        let cache = Cache::new();
        cache.install(Snapshot::build(
            &[contract_for("conn_11111111", &["get_balance"], NOW + 3_600)],
            &trusting(&keys()),
            NOW,
        ));
        let first = cache.snapshot().set_hash.clone();

        cache.install(Snapshot::build(
            &[contract_for("conn_22222222", &["get_balance"], NOW + 3_600)],
            &trusting(&keys()),
            NOW,
        ));
        assert_ne!(cache.snapshot().set_hash, first);
        assert!(cache
            .resolve(Some("conn_11111111"), &agent(), &server())
            .is_err());
        assert!(cache
            .resolve(Some("conn_22222222"), &agent(), &server())
            .is_ok());
    }

    #[test]
    fn readers_hold_a_snapshot_across_a_refresh() {
        // A connection established under one set must not observe a set change
        // half-way through.
        let cache = Cache::new();
        cache.install(Snapshot::build(
            &[contract_for("conn_11111111", &["get_balance"], NOW + 3_600)],
            &trusting(&keys()),
            NOW,
        ));
        let held = cache.snapshot();
        cache.install(Snapshot::default());

        assert_eq!(held.len(), 1, "the held snapshot is immutable");
        assert!(cache.snapshot().is_empty());
    }

    #[test]
    fn an_untrusted_key_yields_an_empty_snapshot() {
        let jws = contract_for("conn_11111111", &["get_balance"], NOW + 3_600);
        let snapshot = Snapshot::build(&[jws], &trusting(&IssuerKeys::new()), NOW);
        assert!(snapshot.is_empty());
        assert_eq!(snapshot.rejected[0].1, Code::SIGNATURE_INVALID);
    }
}
