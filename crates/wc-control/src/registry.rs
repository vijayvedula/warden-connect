//! The registry write path (`docs/08-lld.md` §8.5.3).
//!
//! Every state change goes through here, and here is where the domain rules are
//! enforced. [`crate::store::Projection::apply`] deliberately does **not**
//! re-check them: a logged event is an already-validated fact, and replay must be
//! total or a single historical oddity would make the control plane unbootable.
//! So validation lives on the write path exactly once, and replay is dumb.
//!
//! # What this module refuses to provide
//!
//! There is no `list()` for agent principals. Enumeration is reconnaissance
//! (T2.4), so bulk reads are [`Registry::enumerate_for_operator`] — named to make
//! the audit obligation obvious, and gated on an operator role at the API layer.

use wc_core::contract::ContractStatus;
use wc_core::error::{Code, Mode, Result, WcError};
use wc_core::model::{Cid, Entity, EntityId, HumanRef, Lifecycle, Pin, Posture, Tier};

use crate::store::{Actor, Durability, Event, RepinCause, Store, SuspendCause};

/// A write facade over the state layer.
///
/// Borrows the store mutably for the duration of one operation, which is what
/// keeps "validate, log, apply" from being interleaved with anything else.
#[derive(Debug)]
pub struct Registry<'a> {
    store: &'a mut Store,
    now: u64,
    actor: Actor,
}

impl Store {
    /// Start a registry operation as `actor` at time `now`.
    pub fn registry(&mut self, actor: Actor, now: u64) -> Registry<'_> {
        Registry {
            store: self,
            now,
            actor,
        }
    }
}

/// What a quarantine actually cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineOutcome {
    /// The contained party.
    pub party: EntityId,
    /// Contracts revoked, in either direction.
    pub revoked: Vec<Cid>,
    /// Business services that lose a connection — what the change manager asks
    /// for before approving containment (UC-07 A2).
    pub impacted_services: Vec<String>,
}

impl Registry<'_> {
    // -----------------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------------

    /// Look up one entity.
    #[must_use]
    pub fn get(&self, id: &EntityId) -> Option<&Entity> {
        self.store.projection.entities.get(id)
    }

    /// Look up one entity or fail with [`Code::ENTITY_NOT_FOUND`].
    pub fn require(&self, id: &EntityId) -> Result<&Entity> {
        self.get(id).ok_or_else(|| {
            WcError::with_detail(Code::ENTITY_NOT_FOUND, format!("{id} is not registered"))
        })
    }

    /// A bulk read of the estate, for exports, posture reports and the operator
    /// portal.
    ///
    /// Deliberately not called `list`: this is the enumeration an agent principal
    /// must never be able to perform, so every caller should be visibly an
    /// operator path.
    #[must_use]
    pub fn enumerate_for_operator(&self) -> Vec<&Entity> {
        let mut out: Vec<&Entity> = self.store.projection.entities.values().collect();
        out.sort_unstable_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        out
    }

    /// Entities whose re-attestation interval has lapsed — the assurance loop's work
    /// queue (§8.5.7).
    #[must_use]
    pub fn reattest_due(&self, now: u64) -> Vec<EntityId> {
        let mut out: Vec<EntityId> = self
            .store
            .projection
            .entities
            .values()
            .filter(|e| e.lifecycle == Lifecycle::Active && e.reattest_overdue(now))
            .map(|e| e.id.clone())
            .collect();
        out.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        out
    }

    // -----------------------------------------------------------------------
    // Writes
    // -----------------------------------------------------------------------

    /// Write an entity record.
    ///
    /// Creates when absent. When the id already exists this is a **re-admission**
    /// and is permitted only while the existing record is `Pending` — the state
    /// `clear_quarantine` and a failed admission leave behind. `created_at` is
    /// preserved so the record keeps its true age.
    ///
    /// A re-registration over an `Active` record is refused with
    /// [`Code::ENTITY_DUPLICATE`]: a changed card on a live party is drift, not an
    /// update (UC-01 A4), and must go through [`Registry::repin`] so contracts are
    /// reassessed.
    pub fn put(&mut self, mut entity: Entity) -> Result<Entity> {
        if let Some(existing) = self.get(&entity.id) {
            if existing.lifecycle != Lifecycle::Pending {
                return Err(WcError::with_detail(
                    Code::ENTITY_DUPLICATE,
                    format!(
                        "{} already exists as {:?}; a changed surface on a live party is drift, not an update",
                        entity.id, existing.lifecycle
                    ),
                ));
            }
            entity.created_at = existing.created_at;
        }
        entity.updated_at = self.now;

        let id = entity.id.clone();
        self.store.commit(
            Event::EntityPut {
                entity: Box::new(entity),
                actor: self.actor.clone(),
            },
            self.now,
            Durability::Durable,
        )?;

        // The projection is the authority on what was stored, so read it back
        // rather than returning the caller's copy.
        self.require(&id).cloned()
    }

    /// Apply a lifecycle transition, enforcing the §8.5.1 table and the
    /// quarantine guard.
    pub fn transition(&mut self, id: &EntityId, to: Lifecycle, why: &str) -> Result<()> {
        // Validate against a scratch copy so a rejected transition leaves no
        // trace anywhere — not in the log, not in memory.
        let mut probe = self.require(id)?.clone();
        probe.transition_to(to, self.now)?;

        self.store.commit(
            Event::EntityTransition {
                id: id.clone(),
                to,
                why: why.to_string(),
                actor: self.actor.clone(),
            },
            self.now,
            Durability::Durable,
        )?;
        Ok(())
    }

    /// Record a re-scored posture.
    ///
    /// Cannot set [`Posture::Quarantined`]: containment is a dual-controlled,
    /// separately-evidenced act, not a score update. A low score degrades a party
    /// automatically; only [`Registry::quarantine`] contains one (§8.7.6).
    pub fn set_posture(&mut self, id: &EntityId, posture: Posture, score: u8) -> Result<()> {
        let existing = self.require(id)?;
        if posture == Posture::Quarantined {
            return Err(WcError::with_detail(
                Code::ILLEGAL_TRANSITION,
                "quarantine is not a posture update; use quarantine()",
            ));
        }
        if existing.posture == Posture::Quarantined {
            return Err(WcError::with_detail(
                Code::ENTITY_QUARANTINED,
                format!("{id} is quarantined; re-admission is required"),
            ));
        }

        self.store.commit(
            Event::EntityPosture {
                id: id.clone(),
                posture,
                score,
            },
            self.now,
            // Posture is re-derivable from the next re-attestation, so it rides
            // the batched path (§8.5.2).
            Durability::Batched,
        )?;
        Ok(())
    }

    /// Record a new pin, returning the contracts that were pinned to the **old**
    /// surface.
    ///
    /// Those are the contracts a material change must suspend. The caller
    /// classifies (§8.7.5) and decides; this method only reports the fan-out,
    /// which is an O(1) index lookup rather than a scan.
    pub fn repin(&mut self, id: &EntityId, pin: Pin, cause: RepinCause) -> Result<Vec<Cid>> {
        let mut probe = self.require(id)?.clone();
        let old_manifest = probe.pin.manifest.clone();
        let diff = probe.repin(pin.clone(), self.now)?;

        let affected = if old_manifest.is_empty() {
            Vec::new()
        } else {
            self.store.projection.contracts_for_pin(&old_manifest)
        };

        self.store.commit(
            Event::EntityRepin {
                id: id.clone(),
                pin: Box::new(pin),
                cause,
                diff,
            },
            self.now,
            Durability::Durable,
        )?;
        Ok(affected)
    }

    /// Suspend a contract pending re-approval.
    pub fn suspend_contract(&mut self, cid: &Cid, cause: SuspendCause) -> Result<()> {
        let contract = self.store.projection.contracts.get(cid).ok_or_else(|| {
            WcError::with_detail(Code::CONTRACT_NOT_FOUND, format!("{cid} is not known"))
        })?;
        if contract.status == ContractStatus::Revoked {
            return Err(WcError::with_detail(
                Code::CONTRACT_ALREADY_ENDED,
                format!("{cid} is revoked; suspension is meaningless"),
            ));
        }

        self.store.commit(
            Event::ContractSuspend {
                cid: cid.clone(),
                cause,
            },
            self.now,
            Durability::Durable,
        )?;
        Ok(())
    }

    /// Revoke a contract. Terminal.
    pub fn revoke_contract(&mut self, cid: &Cid, reason: &str) -> Result<()> {
        if !self.store.projection.contracts.contains_key(cid) {
            return Err(WcError::with_detail(
                Code::CONTRACT_NOT_FOUND,
                format!("{cid} is not known"),
            ));
        }
        self.store.commit(
            Event::ContractRevoke {
                cid: cid.clone(),
                reason: reason.to_string(),
                actor: self.actor.clone(),
            },
            self.now,
            Durability::Durable,
        )?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Containment
    // -----------------------------------------------------------------------

    /// Contain a party: posture becomes terminal and every contract it holds, in
    /// either direction, is revoked.
    ///
    /// Dual control is required for tier 1 (§8.7.3). `approvers` must contain two
    /// **distinct** humans, or the order is refused with
    /// [`Code::QUARANTINE_DUAL_CONTROL_MISSING`].
    ///
    /// The returned outcome names the impacted business services, so containment
    /// can be a decision made with its cost visible rather than one discovered
    /// afterwards.
    pub fn quarantine(
        &mut self,
        party: &EntityId,
        reason: &str,
        approvers: &[HumanRef],
    ) -> Result<QuarantineOutcome> {
        let entity = self.require(party)?;
        require_dual_control(entity.tier, approvers)?;

        let revoked = self.store.projection.contracts_for(party);
        let impacted_services = self.impacted_services(&revoked);

        self.store.commit(
            Event::QuarantineOrder {
                party: party.clone(),
                reason: reason.to_string(),
                actor: self.actor.clone(),
                dual_control: approvers.to_vec(),
            },
            self.now,
            Durability::Durable,
        )?;

        Ok(QuarantineOutcome {
            party: party.clone(),
            revoked,
            impacted_services,
        })
    }

    /// Lift quarantine by returning the party to `Pending`, which forces the full
    /// admission pipeline to run again (UC-07 A3).
    ///
    /// Also dual-controlled: clearing containment is at least as consequential as
    /// applying it.
    /// Returns how long the party was contained, for
    /// [`crate::obs::quarantine_duration`] — `None` when the quarantine predates
    /// `Entity::quarantined_at`, because a fabricated duration is worse than a gap.
    ///
    /// Read here rather than observed inside the projection: `Projection::apply` runs on
    /// every rebuild, so a metric there would re-observe every quarantine in the log each
    /// time the state is replayed.
    pub fn clear_quarantine(
        &mut self,
        party: &EntityId,
        approvers: &[HumanRef],
    ) -> Result<Option<u64>> {
        let entity = self.require(party)?;
        if entity.posture != Posture::Quarantined {
            return Err(WcError::with_detail(
                Code::ILLEGAL_TRANSITION,
                format!("{party} is not quarantined"),
            ));
        }
        let held_for =
            (entity.quarantined_at > 0).then(|| self.now.saturating_sub(entity.quarantined_at));
        require_dual_control(Tier::ONE, approvers)?;

        self.store.commit(
            Event::QuarantineCleared {
                party: party.clone(),
                actor: self.actor.clone(),
                dual_control: approvers.to_vec(),
            },
            self.now,
            Durability::Durable,
        )?;
        Ok(held_for)
    }

    /// Whether this party may currently be one end of a new connection.
    pub fn assert_connectable(&self, id: &EntityId, mode: Mode) -> Result<()> {
        self.require(id)?.assert_connectable(mode)
    }

    /// Business services touched by a set of contracts.
    fn impacted_services(&self, cids: &[Cid]) -> Vec<String> {
        let mut out: Vec<String> = cids
            .iter()
            .filter_map(|cid| self.store.projection.contracts.get(cid))
            .flat_map(|c| [c.caller.clone(), c.callee.clone()])
            .filter_map(|id| self.store.projection.entities.get(&id))
            .filter_map(|e| e.service.clone())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// Two distinct humans, where the tier demands it.
fn require_dual_control(tier: Tier, approvers: &[HumanRef]) -> Result<()> {
    if !tier.requires_dual_control() {
        return Ok(());
    }
    let mut distinct: Vec<&HumanRef> = approvers.iter().collect();
    distinct.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
    distinct.dedup();
    if distinct.len() >= 2 {
        return Ok(());
    }
    Err(WcError::with_detail(
        Code::QUARANTINE_DUAL_CONTROL_MISSING,
        format!(
            "{tier} requires two distinct approvers, got {}",
            distinct.len()
        ),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    use wc_core::contract::{ApprovalRef, ContractRecord, Surface, Terms, CONTRACT_SCHEMA};
    use wc_core::model::{Jti, Kind, ZoneId, PIN_ALG};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> TmpDir {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("wc-reg-{}-{tag}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            TmpDir(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn priya() -> HumanRef {
        HumanRef::new("human:priya@org").unwrap()
    }

    fn cecil() -> HumanRef {
        HumanRef::new("human:cecil@org").unwrap()
    }

    fn actor() -> Actor {
        Actor::Human { id: priya() }
    }

    fn agent_id() -> EntityId {
        EntityId::new("spiffe://org/ns/agents/sa/recon-bot-7").unwrap()
    }

    fn server_id() -> EntityId {
        EntityId::new("spiffe://org/ns/tools/sa/payments-mcp").unwrap()
    }

    fn entity_at(id: &EntityId, kind: Kind, tier: Tier, now: u64) -> Entity {
        let mut e = Entity::pending(
            id.clone(),
            kind,
            priya(),
            ZoneId::new("internal.payments").unwrap(),
            tier,
            now,
        );
        e.service = Some("payments-recon".to_string());
        e
    }

    fn pin(manifest: &str, items: &[(&str, &str)]) -> Pin {
        Pin {
            alg: PIN_ALG.to_string(),
            manifest: manifest.to_string(),
            items: items
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<BTreeMap<_, _>>(),
            pinned_at: 1,
        }
    }

    fn contract(cid: &str, caller: EntityId, callee: EntityId, manifest: &str) -> ContractRecord {
        ContractRecord {
            cid: Cid::new(cid).unwrap(),
            jti: Jti::new("cx_84be0011").unwrap(),
            caller,
            callee,
            caller_zone: ZoneId::new("internal.apac-ops").unwrap(),
            callee_zone: ZoneId::new("internal.payments").unwrap(),
            callee_tier: Tier::TWO,
            callee_manifest: manifest.to_string(),
            surface_digest: "sha256:digest".to_string(),
            surface: Surface {
                tools: vec!["get_balance".to_string()],
                ..Default::default()
            },
            terms: Terms::default(),
            aud: vec!["warden:mediator:apac-ops".to_string()],
            jws_sha256: "sha256:deadbeef".to_string(),
            status: ContractStatus::Active,
            approval: ApprovalRef::standing(),
            policy_version: "connect-policy@v37".to_string(),
            iat: 1_000,
            exp: 9_000,
            schema: CONTRACT_SCHEMA,
        }
    }

    /// A store with two active, attested entities and one contract between them.
    fn seeded(tmp: &TmpDir) -> Store {
        let (mut store, _) = Store::open(tmp.path()).unwrap();
        {
            let mut reg = store.registry(actor(), 1_000);
            for (id, kind, tier) in [
                (agent_id(), Kind::Agent, Tier::TWO),
                (server_id(), Kind::McpServer, Tier::TWO),
            ] {
                reg.put(entity_at(&id, kind, tier, 1_000)).unwrap();
                reg.transition(&id, Lifecycle::Active, "admitted").unwrap();
                reg.set_posture(&id, Posture::Attested, 95).unwrap();
            }
            reg.repin(
                &server_id(),
                pin("sha256:m1", &[("get_balance", "sha256:aa")]),
                RepinCause::Admission,
            )
            .unwrap();
        }
        store
            .commit(
                Event::ContractMint {
                    record: Box::new(contract(
                        "conn_11111111",
                        agent_id(),
                        server_id(),
                        "sha256:m1",
                    )),
                },
                1_001,
                Durability::Durable,
            )
            .unwrap();
        store
    }

    // --- put ---

    #[test]
    fn put_creates_then_refuses_a_live_duplicate() {
        let tmp = TmpDir::new("put");
        let (mut store, _) = Store::open(tmp.path()).unwrap();
        let mut reg = store.registry(actor(), 1_000);

        let created = reg
            .put(entity_at(&agent_id(), Kind::Agent, Tier::TWO, 1_000))
            .unwrap();
        assert_eq!(created.lifecycle, Lifecycle::Pending);
        assert_eq!(created.posture, Posture::Unattested);

        // Still Pending: re-admission is allowed.
        assert!(reg
            .put(entity_at(&agent_id(), Kind::Agent, Tier::TWO, 2_000))
            .is_ok());

        reg.transition(&agent_id(), Lifecycle::Active, "admitted")
            .unwrap();
        let err = reg
            .put(entity_at(&agent_id(), Kind::Agent, Tier::TWO, 3_000))
            .unwrap_err();
        assert_eq!(err.code(), Code::ENTITY_DUPLICATE);
        assert!(err.detail().contains("drift, not an update"));
    }

    #[test]
    fn re_admission_preserves_the_original_age() {
        let tmp = TmpDir::new("age");
        let (mut store, _) = Store::open(tmp.path()).unwrap();
        let mut reg = store.registry(actor(), 1_000);
        reg.put(entity_at(&agent_id(), Kind::Agent, Tier::TWO, 1_000))
            .unwrap();

        let mut reg = store.registry(actor(), 5_000);
        let again = reg
            .put(entity_at(&agent_id(), Kind::Agent, Tier::TWO, 5_000))
            .unwrap();
        assert_eq!(again.created_at, 1_000, "age must not be reset");
        assert_eq!(again.updated_at, 5_000);
    }

    #[test]
    fn require_names_the_missing_entity() {
        let tmp = TmpDir::new("missing");
        let (mut store, _) = Store::open(tmp.path()).unwrap();
        let reg = store.registry(actor(), 1_000);
        assert!(reg.get(&agent_id()).is_none());
        let err = reg.require(&agent_id()).unwrap_err();
        assert_eq!(err.code(), Code::ENTITY_NOT_FOUND);
    }

    // --- transitions ---

    #[test]
    fn a_rejected_transition_leaves_no_trace() {
        let tmp = TmpDir::new("reject");
        let mut store = seeded(&tmp);
        let seq_before = store.log.last_seq();

        let err = store
            .registry(actor(), 2_000)
            .transition(&agent_id(), Lifecycle::Pending, "backwards")
            .unwrap_err();
        assert_eq!(err.code(), Code::ILLEGAL_TRANSITION);

        assert_eq!(store.log.last_seq(), seq_before, "nothing may be appended");
        assert_eq!(
            store.projection.entities[&agent_id()].lifecycle,
            Lifecycle::Active
        );
    }

    #[test]
    fn transitions_are_durable_across_reopen() {
        let tmp = TmpDir::new("durable");
        {
            let mut store = seeded(&tmp);
            store
                .registry(actor(), 2_000)
                .transition(&agent_id(), Lifecycle::Suspended, "owner left")
                .unwrap();
        }
        let (store, report) = Store::open(tmp.path()).unwrap();
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(
            store.projection.entities[&agent_id()].lifecycle,
            Lifecycle::Suspended
        );
    }

    // --- posture ---

    #[test]
    fn posture_cannot_be_used_to_quarantine() {
        // Containment must go through the dual-controlled, separately-evidenced
        // path, or an automated scorer becomes an estate-wide kill switch.
        let tmp = TmpDir::new("posture");
        let mut store = seeded(&tmp);
        let err = store
            .registry(actor(), 2_000)
            .set_posture(&agent_id(), Posture::Quarantined, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::ILLEGAL_TRANSITION);
        assert!(err.detail().contains("use quarantine()"));
    }

    #[test]
    fn posture_degrades_and_persists() {
        let tmp = TmpDir::new("degrade");
        let mut store = seeded(&tmp);
        {
            let mut reg = store.registry(actor(), 2_000);
            reg.set_posture(&server_id(), Posture::Degraded, 55)
                .unwrap();
        }
        store.log.sync().unwrap();
        assert_eq!(
            store.projection.entities[&server_id()].posture,
            Posture::Degraded
        );
        assert_eq!(store.projection.entities[&server_id()].posture_score, 55);
    }

    #[test]
    fn a_quarantined_party_rejects_posture_updates() {
        let tmp = TmpDir::new("qposture");
        let mut store = seeded(&tmp);
        store
            .registry(actor(), 2_000)
            .quarantine(&server_id(), "SOC-1", &[])
            .unwrap();
        let err = store
            .registry(actor(), 2_001)
            .set_posture(&server_id(), Posture::Attested, 100)
            .unwrap_err();
        assert_eq!(err.code(), Code::ENTITY_QUARANTINED);
    }

    // --- repin ---

    #[test]
    fn repin_reports_the_contracts_on_the_old_pin() {
        let tmp = TmpDir::new("repin");
        let mut store = seeded(&tmp);

        let affected = store
            .registry(actor(), 2_000)
            .repin(
                &server_id(),
                pin("sha256:m2", &[("get_balance", "sha256:ff")]),
                RepinCause::Material,
            )
            .unwrap();

        assert_eq!(affected, vec![Cid::new("conn_11111111").unwrap()]);
        assert_eq!(
            store.projection.entities[&server_id()].pin.manifest,
            "sha256:m2"
        );
    }

    #[test]
    fn the_first_pin_affects_nothing() {
        let tmp = TmpDir::new("firstpin");
        let (mut store, _) = Store::open(tmp.path()).unwrap();
        let mut reg = store.registry(actor(), 1_000);
        reg.put(entity_at(&server_id(), Kind::McpServer, Tier::TWO, 1_000))
            .unwrap();
        let affected = reg
            .repin(
                &server_id(),
                pin("sha256:m1", &[("t", "sha256:aa")]),
                RepinCause::Admission,
            )
            .unwrap();
        assert!(affected.is_empty());
    }

    #[test]
    fn repin_rejects_a_foreign_algorithm() {
        let tmp = TmpDir::new("alg");
        let mut store = seeded(&tmp);
        let mut bad = pin("sha256:m2", &[("t", "sha256:aa")]);
        bad.alg = "wcs2".to_string();
        let err = store
            .registry(actor(), 2_000)
            .repin(&server_id(), bad, RepinCause::Benign)
            .unwrap_err();
        assert_eq!(err.code(), Code::PIN_WRITE_FAILED);
    }

    // --- contracts ---

    #[test]
    fn suspend_then_revoke_a_contract() {
        let tmp = TmpDir::new("contract");
        let mut store = seeded(&tmp);
        let cid = Cid::new("conn_11111111").unwrap();

        store
            .registry(actor(), 2_000)
            .suspend_contract(&cid, SuspendCause::Drift)
            .unwrap();
        assert_eq!(
            store.projection.contracts[&cid].status,
            ContractStatus::Suspended
        );

        store
            .registry(actor(), 2_001)
            .revoke_contract(&cid, "SOC-2291")
            .unwrap();
        assert_eq!(
            store.projection.contracts[&cid].status,
            ContractStatus::Revoked
        );

        // Suspending a revoked contract is meaningless, not merely redundant.
        let err = store
            .registry(actor(), 2_002)
            .suspend_contract(&cid, SuspendCause::Drift)
            .unwrap_err();
        assert_eq!(err.code(), Code::CONTRACT_ALREADY_ENDED);
    }

    #[test]
    fn unknown_contracts_are_rejected() {
        let tmp = TmpDir::new("unknown");
        let mut store = seeded(&tmp);
        let ghost = Cid::new("conn_99999999").unwrap();
        assert_eq!(
            store
                .registry(actor(), 2_000)
                .revoke_contract(&ghost, "x")
                .unwrap_err()
                .code(),
            Code::CONTRACT_NOT_FOUND
        );
        assert_eq!(
            store
                .registry(actor(), 2_000)
                .suspend_contract(&ghost, SuspendCause::Drift)
                .unwrap_err()
                .code(),
            Code::CONTRACT_NOT_FOUND
        );
    }

    // --- quarantine ---

    #[test]
    fn quarantine_cuts_contracts_and_names_the_cost() {
        let tmp = TmpDir::new("quarantine");
        let mut store = seeded(&tmp);

        let outcome = store
            .registry(actor(), 2_000)
            .quarantine(&server_id(), "SOC-2291 credential theft", &[])
            .unwrap();

        assert_eq!(outcome.party, server_id());
        assert_eq!(outcome.revoked, vec![Cid::new("conn_11111111").unwrap()]);
        assert_eq!(
            outcome.impacted_services,
            vec!["payments-recon".to_string()]
        );

        let e = &store.projection.entities[&server_id()];
        assert_eq!(e.posture, Posture::Quarantined);
        assert_eq!(e.lifecycle, Lifecycle::Suspended);
        assert!(e.assert_connectable(Mode::Observe).is_err());
    }

    #[test]
    fn tier_one_quarantine_requires_two_distinct_approvers() {
        let tmp = TmpDir::new("dual");
        let (mut store, _) = Store::open(tmp.path()).unwrap();
        {
            let mut reg = store.registry(actor(), 1_000);
            reg.put(entity_at(&server_id(), Kind::McpServer, Tier::ONE, 1_000))
                .unwrap();
            reg.transition(&server_id(), Lifecycle::Active, "admitted")
                .unwrap();
        }

        for approvers in [vec![], vec![priya()], vec![priya(), priya()]] {
            let err = store
                .registry(actor(), 2_000)
                .quarantine(&server_id(), "SOC-1", &approvers)
                .unwrap_err();
            assert_eq!(err.code(), Code::QUARANTINE_DUAL_CONTROL_MISSING);
        }

        assert!(store
            .registry(actor(), 2_000)
            .quarantine(&server_id(), "SOC-1", &[priya(), cecil()])
            .is_ok());
    }

    #[test]
    fn clearing_quarantine_forces_full_re_admission() {
        let tmp = TmpDir::new("clear");
        let mut store = seeded(&tmp);
        store
            .registry(actor(), 2_000)
            .quarantine(&server_id(), "SOC-1", &[])
            .unwrap();

        // Always dual-controlled, whatever the tier.
        let err = store
            .registry(actor(), 2_001)
            .clear_quarantine(&server_id(), &[priya()])
            .unwrap_err();
        assert_eq!(err.code(), Code::QUARANTINE_DUAL_CONTROL_MISSING);

        store
            .registry(actor(), 2_002)
            .clear_quarantine(&server_id(), &[priya(), cecil()])
            .unwrap();

        let e = &store.projection.entities[&server_id()];
        assert_eq!(e.lifecycle, Lifecycle::Pending, "must re-run admission");
        assert_eq!(e.posture, Posture::Unattested);

        // And it is not a repeatable operation.
        assert_eq!(
            store
                .registry(actor(), 2_003)
                .clear_quarantine(&server_id(), &[priya(), cecil()])
                .unwrap_err()
                .code(),
            Code::ILLEGAL_TRANSITION
        );
    }

    #[test]
    fn clearing_reports_how_long_the_party_was_held() {
        // The input to `wc_quarantine_duration_seconds`. Measured from an explicit
        // `quarantined_at` rather than from `updated_at`, so an unrelated change in
        // between cannot shorten it — which is what the second half of this test pins.
        let tmp = TmpDir::new("qduration");
        let mut store = seeded(&tmp);
        store
            .registry(actor(), 1_000)
            .quarantine(&server_id(), "SOC-1", &[])
            .unwrap();

        let held = store
            .registry(actor(), 4_600)
            .clear_quarantine(&server_id(), &[priya(), cecil()])
            .unwrap();
        assert_eq!(held, Some(3_600), "held from 1_000 to 4_600");

        // Cleared, so nothing is being held any more.
        assert_eq!(store.projection.entities[&server_id()].quarantined_at, 0);
    }

    #[test]
    fn an_unrelated_update_does_not_shorten_the_measured_containment() {
        // `updated_at` was the tempting field and it is the wrong one: any write moves
        // it, so a re-pin or a rescore between the order and the clearing would report a
        // containment shorter than it was — an under-report on exactly the number an
        // incident review reads.
        let tmp = TmpDir::new("qduration-touch");
        let mut store = seeded(&tmp);
        store
            .registry(actor(), 1_000)
            .quarantine(&server_id(), "SOC-1", &[])
            .unwrap();

        // Something touches the entity midway.
        {
            let e = store.projection.entities.get_mut(&server_id()).unwrap();
            e.updated_at = 4_000;
            assert_eq!(
                e.quarantined_at, 1_000,
                "the quarantine instant is its own field"
            );
        }

        let held = store
            .registry(actor(), 4_600)
            .clear_quarantine(&server_id(), &[priya(), cecil()])
            .unwrap();
        assert_eq!(
            held,
            Some(3_600),
            "the duration must be measured from the order, not from the last write"
        );
    }

    #[test]
    fn a_quarantine_predating_the_field_reports_no_duration() {
        // A state log written before `quarantined_at` existed rebuilds with zero there.
        // `None` rather than a duration measured from the epoch: a fabricated 56-year
        // containment on a dashboard is worse than a gap, because somebody would act on it.
        let tmp = TmpDir::new("qduration-legacy");
        let mut store = seeded(&tmp);
        store
            .registry(actor(), 1_000)
            .quarantine(&server_id(), "SOC-1", &[])
            .unwrap();
        store
            .projection
            .entities
            .get_mut(&server_id())
            .unwrap()
            .quarantined_at = 0;

        let held = store
            .registry(actor(), 4_600)
            .clear_quarantine(&server_id(), &[priya(), cecil()])
            .unwrap();
        assert_eq!(held, None);
    }

    #[test]
    fn quarantine_survives_reopen() {
        let tmp = TmpDir::new("qdurable");
        {
            let mut store = seeded(&tmp);
            store
                .registry(actor(), 2_000)
                .quarantine(&server_id(), "SOC-1", &[])
                .unwrap();
        }
        let (store, report) = Store::open(tmp.path()).unwrap();
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(
            store.projection.entities[&server_id()].posture,
            Posture::Quarantined
        );
        assert_eq!(
            store.projection.contracts[&Cid::new("conn_11111111").unwrap()].status,
            ContractStatus::Revoked
        );
    }

    // --- reads ---

    #[test]
    fn enumeration_is_sorted_and_operator_scoped() {
        let tmp = TmpDir::new("enumerate");
        let mut store = seeded(&tmp);
        let reg = store.registry(actor(), 2_000);
        let all = reg.enumerate_for_operator();
        assert_eq!(all.len(), 2);
        assert!(all[0].id.as_str() < all[1].id.as_str());
    }

    #[test]
    fn reattest_due_ignores_inactive_parties() {
        let tmp = TmpDir::new("reattest");
        let mut store = seeded(&tmp);
        {
            // Tier 2 => 6h interval. Mark one as freshly attested.
            let mut reg = store.registry(actor(), 2_000);
            reg.set_posture(&agent_id(), Posture::Attested, 95).unwrap();
        }
        if let Some(e) = store.projection.entities.get_mut(&agent_id()) {
            e.reattested_at = 100_000;
        }

        // Tier 2 re-attests every 6h (21_600s); 15_000s elapsed is inside that.
        let reg = store.registry(actor(), 115_000);
        let due = reg.reattest_due(115_000);
        assert!(due.contains(&server_id()), "never attested => overdue");
        assert!(!due.contains(&agent_id()), "within its interval");

        // A suspended party is not a re-attestation candidate.
        drop(reg);
        store
            .registry(actor(), 115_001)
            .transition(&server_id(), Lifecycle::Suspended, "drift")
            .unwrap();
        let reg = store.registry(actor(), 115_002);
        assert!(reg.reattest_due(115_002).is_empty());
    }

    #[test]
    fn connectability_is_checked_through_the_registry() {
        let tmp = TmpDir::new("connectable");
        let mut store = seeded(&tmp);
        let reg = store.registry(actor(), 2_000);
        assert!(reg.assert_connectable(&agent_id(), Mode::Enforce).is_ok());

        drop(reg);
        store
            .registry(actor(), 2_001)
            .transition(&agent_id(), Lifecycle::Suspended, "drift")
            .unwrap();
        let reg = store.registry(actor(), 2_002);
        assert!(reg.assert_connectable(&agent_id(), Mode::Enforce).is_err());
    }

    #[test]
    fn the_write_path_records_no_anomalies() {
        // Every write above went through validation, so the projection must never
        // have reported an inconsistency.
        let tmp = TmpDir::new("anomalies");
        let mut store = seeded(&tmp);
        store
            .registry(actor(), 2_000)
            .quarantine(&server_id(), "SOC-1", &[])
            .unwrap();
        assert!(store.anomalies().is_empty(), "{:?}", store.anomalies());
    }
}
